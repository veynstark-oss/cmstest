"""
HashCrack Panel — distributed hashcat orchestrator for Vast.ai
Full-featured web dashboard with real-time monitoring.
v3.0 — Advanced orchestration: potfile sync, GPU telemetry, mask attacks,
       state persistence, job history, pause/resume, SSH resilience.
"""

import os, json, time, threading, shutil, zipfile, tarfile, logging, traceback, tempfile, re as _re, hashlib, secrets, asyncio
from collections import deque
from pathlib import Path
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI, Form, HTTPException, Query, UploadFile, File as FastFile, Depends, Request, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from lib.config import (
    REMOTE_WORK_DIR, REMOTE_WORDLIST, REMOTE_RULES,
    REMOTE_HASHES, REMOTE_OUTFILE, REMOTE_POTFILE,
    HASHCAT_CMD_TEMPLATE, HASHCAT_CMD_MASK_TEMPLATE,
    POTFILE_SYNC_INTERVAL, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID,
    STATE_DIR, STATE_FILE, HISTORY_FILE,
)
from lib.vastai import vastai
from lib.ssh import SSHManager

try:
    from starlette.formparsers import MultiPartParser
    MultiPartParser.max_file_size = 1024 * 1024 * 1024 * 10
except:
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("hashcrack")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Graceful startup/shutdown: restore state, clean up SSH pool and httpx client."""
    global _ws_loop
    _ws_loop = asyncio.get_event_loop()
    logger.info("HashCrack Panel starting up...")
    _auto_resume = False  # flag for auto-resume after yield
    # Restore previous job state (display only, doesn't re-run)
    try:
        saved = load_state()
        if saved:
            with job_lock:
                for k, v in saved.items():
                    if k in job and k != "cracked_lines":
                        job[k] = v
                # If the saved state was active, check for auto-resume
                if job.get("active") and job.get("phase") not in ("done", "stopped", "error", "idle"):
                    saved_phase = saved.get("phase", "?")
                    machines = job.get("machines", [])
                    hashes_file = job.get("hashes_file", "")
                    hashcat_mode = job.get("hashcat_mode", 0)
                    if machines and hashes_file and hashcat_mode:
                        # Mark as reconnecting — will auto-resume after startup
                        job["phase"] = "reconnecting"
                        job["active"] = True
                        _auto_resume = True
                        _log_msg = f"Restored state (phase={saved_phase}) — will auto-resume with {len(machines)} machines"
                    else:
                        job["phase"] = "stopped"
                        job["active"] = False
                        job["error"] = "Server restarted — job was interrupted (no machines/hashes to resume)"
                        _log_msg = f"Restored previous state (phase was: {saved_phase}) — cannot auto-resume"
                else:
                    _log_msg = "Restored previous state (phase was: " + saved.get("phase", "?") + ")"
            # Log OUTSIDE the lock to avoid deadlock (log_event also acquires job_lock)
            log_event(_log_msg)
        # Restore cracked_lines from disk so list matches the counter
        merged = CRACKED_DIR / "cracked_all.txt"
        if merged.exists():
            lines = [l.strip() for l in merged.read_text().splitlines() if l.strip()]
            if lines:
                with job_lock:
                    job["cracked_lines"] = lines
                    # Sync counter with what we actually have on disk
                    if job["total_cracked"] > 0:
                        job["total_cracked"] = max(len(lines), job["total_cracked"])
                    elif len(lines) > 0:
                        job["total_cracked"] = len(lines)
                logger.info(f"Restored {len(lines)} cracked lines from disk")
    except Exception as e:
        logger.warning(f"State restore failed: {e}")

    # Auto-resume: launch reconnect in background thread after startup
    if _auto_resume:
        def _auto_resume_thread():
            """Wait for server to be ready, then reconnect to running instances."""
            time.sleep(5)  # let FastAPI finish startup
            try:
                machines = job.get("machines", [])
                machine_ids = [m["id"] for m in machines if m.get("id")]
                if not machine_ids:
                    log_event("Auto-resume: no machine IDs found", "error")
                    with job_lock:
                        job["phase"] = "stopped"
                        job["active"] = False
                        job["error"] = "Auto-resume failed: no machine IDs"
                    return

                # Check if any instances are still alive on Vast.ai
                alive_ids = []
                for mid in machine_ids:
                    try:
                        inst = vastai.get_instance(mid)
                        if inst and inst.get("actual_status") in ("running", "loading"):
                            alive_ids.append(mid)
                    except Exception:
                        pass

                if not alive_ids:
                    log_event("Auto-resume: no live instances found on Vast.ai — job stopped", "error")
                    with job_lock:
                        job["phase"] = "stopped"
                        job["active"] = False
                        job["error"] = "Auto-resume: all instances destroyed"
                    save_state()
                    return

                log_event(f"Auto-resume: {len(alive_ids)}/{len(machine_ids)} instances alive — reconnecting...")

                hashes_path = job.get("hashes_file", "")
                hashcat_mode = job.get("hashcat_mode", 1710)
                attack_mode = job.get("attack_mode", 0)
                mask_val = job.get("mask", "")
                wordlist_url = job.get("wordlist_url", "")
                rules_url = job.get("rules_url", "")
                archive_path = job.get("archive_file", "")
                prev_cracked = job.get("total_cracked", 0)

                with job_lock:
                    job["prev_cracked"] = prev_cracked

                _reconnect_job(
                    machine_ids, hashes_path, hashcat_mode,
                    attack_mode=attack_mode,
                    mask=mask_val,
                    wordlist_url=wordlist_url,
                    rules_url=rules_url,
                    archive_path=archive_path,
                )
            except Exception as e:
                logger.error(f"Auto-resume failed: {e}")
                log_event(f"Auto-resume failed: {e}", "error")
                with job_lock:
                    job["phase"] = "stopped"
                    job["active"] = False
                    job["error"] = f"Auto-resume failed: {e}"
                save_state()

        threading.Thread(target=_auto_resume_thread, daemon=True, name="auto-resume").start()
        logger.info("Auto-resume thread launched")

    yield
    logger.info("HashCrack Panel shutting down — cleaning up...")
    # Close all SSH connections
    with pool_lock:
        for ssh in _ssh_pool.values():
            try:
                ssh.close()
            except Exception:
                pass
        _ssh_pool.clear()
    # Close httpx client
    try:
        vastai.client.close()
    except Exception:
        pass
    # Save final state
    try:
        save_state(force=True)
    except Exception:
        pass
    logger.info("Cleanup complete.")


app = FastAPI(title="HashCrack Panel", lifespan=lifespan)

# ══════════════════════════════════════════════════════════════════════════════
# PASSWORD AUTH MIDDLEWARE
# ══════════════════════════════════════════════════════════════════════════════
PANEL_PASSWORD = os.environ.get("PANEL_PASSWORD", "")

class BasicAuthMiddleware(BaseHTTPMiddleware):
    """Optional basic auth — set PANEL_PASSWORD env to enable."""
    async def dispatch(self, request: Request, call_next):
        if not PANEL_PASSWORD:
            return await call_next(request)
        # Skip auth for WebSocket upgrades (handled separately)
        if request.url.path == "/ws":
            return await call_next(request)
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Basic "):
            import base64
            try:
                decoded = base64.b64decode(auth[6:]).decode()
                user, pwd = decoded.split(":", 1)
                if pwd == PANEL_PASSWORD:
                    return await call_next(request)
            except Exception:
                pass
        return Response(
            content="Unauthorized",
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="HashCrack Panel"'},
        )

app.add_middleware(BasicAuthMiddleware)

# ══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET MANAGER
# ══════════════════════════════════════════════════════════════════════════════
_ws_clients: list[WebSocket] = []
_ws_lock = threading.Lock()

async def ws_broadcast(data: dict):
    """Broadcast a message to all connected WebSocket clients."""
    if _ws_loop is None:
        return
    msg = json.dumps(data)
    with _ws_lock:
        dead = []
        for ws in _ws_clients:
            try:
                asyncio.run_coroutine_threadsafe(ws.send_text(msg), _ws_loop)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in _ws_clients:
                _ws_clients.remove(ws)

def ws_broadcast_sync(data: dict):
    """Thread-safe broadcast from background threads."""
    if _ws_loop is None or _ws_loop.is_closed():
        return
    msg = json.dumps(data)
    with _ws_lock:
        dead = []
        for ws in list(_ws_clients):
            try:
                asyncio.run_coroutine_threadsafe(ws.send_text(msg), _ws_loop)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in _ws_clients:
                _ws_clients.remove(ws)

_ws_loop = None  # set at startup

UPLOAD_DIR = Path(__file__).parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
CHUNKS_DIR = UPLOAD_DIR / "chunks"
CHUNKS_DIR.mkdir(exist_ok=True)
CRACKED_DIR = UPLOAD_DIR / "cracked"
CRACKED_DIR.mkdir(exist_ok=True)
STATE_DIR.mkdir(exist_ok=True)
WORKSPACE = Path(__file__).parent

# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL STATE
# ══════════════════════════════════════════════════════════════════════════════

job = {
    "active": False,
    "phase": "idle",
    "error": "",
    "num_machines": 0,
    "machines": [],
    "total_hashes": 0,
    "total_cracked": 0,
    "started_at": 0,
    "finished_at": 0,
    "hashes_file": "",
    "archive_file": "",
    "cracked_lines": [],
    "total_cost": 0.0,
    "auto_destroy": False,
    "prev_cracked": 0,
    # v3 new fields
    "attack_mode": 0,       # 0=wordlist, 3=mask
    "mask": "",              # mask for -a 3
    "hashcat_mode": 0,      # hashcat hash mode (e.g. 1710)
    "total_speed_hs": 0,    # aggregated speed in H/s
    "total_speed": "",       # human-readable
    "gpu_stats": [],         # per-machine GPU telemetry
    "paused": False,
    "wordlist_url": "",      # download wordlist from URL
    "rules_url": "",         # download rules from URL
    "rules_path": "",        # local rules file path
    "budget_limit": 0.0,     # max budget in $, 0 = unlimited
    "extra_args": "",        # custom extra hashcat args
    "username_flag": "",     # --username flag if detected
}

event_log: deque = deque(maxlen=500)
job_lock = threading.Lock()
pool_lock = threading.Lock()  # protects _ssh_pool, _potfile_entries, _last_potfile_sync
_cost_last_ts: float = 0  # last time cost was accumulated
_job_generation: int = 0  # incremented on every new job; old threads check this to self-terminate

# Chart data: track speed/cracked history for realtime graphs
_chart_history: deque = deque(maxlen=360)  # (timestamp, speed_hs, total_cracked)

# Retry queue for failed machine replacements
_retry_queue: list = []  # [{idx, old_mid, ssh_conns, ready_ids, archive_path, hashcat_mode, kwargs, attempts, next_retry}]
_retry_lock = threading.Lock()
_MAX_RETRY_ATTEMPTS = 3
_replace_semaphore = threading.Semaphore(3)  # max 3 concurrent replacement threads

# Archive distribution: seed relay + upload throttle
_archive_upload_sem = threading.Semaphore(2)  # limit concurrent SFTP archive uploads (avoid saturating server upload pipe)
_archive_seed_lock = threading.Lock()
_archive_seed_url: str = ""  # URL on first deployed machine's HTTP server; others wget from it

# Keep SSH connections and potfile state for potfile sync
_ssh_pool: dict[int, SSHManager] = {}  # mid -> SSHManager
_potfile_entries: set = set()  # all known cracked potfile entries
_last_potfile_sync: float = 0
_last_hashes_file: str = ""  # persists across resets for username lookup


def _get_ssh_pubkey() -> str:
    """Read local SSH public key."""
    for name in ("id_ed25519.pub", "id_rsa.pub", "id_ecdsa.pub"):
        p = os.path.expanduser(f"~/.ssh/{name}")
        if os.path.isfile(p):
            with open(p) as f:
                return f.read().strip()
    return ""


def _safe_destroy(mid: int, verify: bool = True) -> bool:
    """Destroy instance with optional verification. Returns True if confirmed destroyed."""
    try:
        if verify:
            ok = vastai.destroy_instance_verified(mid, retries=3, delay=5.0)
            if not ok:
                log_event(f"[{mid}] Destroy verification FAILED — instance may still be running!", "error")
            return ok
        else:
            vastai.destroy_instance(mid)
            return True
    except Exception as e:
        log_event(f"[{mid}] Destroy error: {e}", "error")
        return False


def _make_onstart_cmd() -> str:
    """Build onstart script: SSH key + pre-install hashcat + OpenCL during boot.
    
    This runs DURING instance boot, so by the time we SSH in, hashcat is already
    installed. Saves ~60 seconds per machine during deploy phase.
    """
    pubkey = _get_ssh_pubkey()
    if not pubkey:
        return ""
    # Script: inject SSH key + install hashcat + OpenCL in background
    return (
        "mkdir -p /root/.ssh && chmod 700 /root/.ssh && "
        f"echo '{pubkey}' >> /root/.ssh/authorized_keys && "
        "chmod 600 /root/.ssh/authorized_keys && "
        "sort -u /root/.ssh/authorized_keys -o /root/.ssh/authorized_keys && "
        # Pre-install hashcat + OpenCL during boot (runs in background)
        "(apt-get update -qq && "
        "apt-get install -y -qq ocl-icd-libopencl1 hashcat 2>/dev/null; "
        "mkdir -p /etc/OpenCL/vendors && "
        "echo libnvidia-opencl.so.1 > /etc/OpenCL/vendors/nvidia.icd; "
        "mkdir -p /root/hashcrack; "
        "touch /root/.hashcat_ready) &"
    )


def log_event(msg: str, level: str = "info"):
    entry = {"ts": time.time(), "time": datetime.now().strftime("%H:%M:%S"), "level": level, "msg": msg}
    with job_lock:
        event_log.append(entry)
    if level == "error":
        logger.error(msg)
    else:
        logger.info(msg)
    # Push log via WebSocket
    try:
        ws_broadcast_sync({"type": "log", "ts": entry["ts"], "time": entry["time"], "level": level, "msg": msg})
    except Exception:
        pass


def _detect_username_flag(hashes_path: str) -> str:
    """Check if hash lines contain user/email prefix → return '--username' or ''."""
    try:
        with open(hashes_path, "r", errors="ignore") as f:
            for i, line in enumerate(f):
                if i >= 20:
                    break
                stripped = line.strip()
                if not stripped:
                    continue
                # Look for user:hash or email:hash pattern
                if ":" in stripped:
                    first_field = stripped.split(":", 1)[0]
                    if "@" in first_field:
                        return "--username"
    except Exception:
        pass
    return ""


def _build_hashcat_cmd(ssh, attack_mode: int, hashcat_mode: int, mask: str = "") -> str:
    """Build the hashcat invocation command string based on attack mode.
    
    For dictionary attack (mode 0): detects wordlist and rules on the remote machine.
    For mask attack (mode 3): uses the mask parameter.
    Returns the hashcat command string (without cd/redirect prefix).
    """
    uf = job.get("username_flag", "")
    extra = job.get("extra_args", "")
    if attack_mode == 3:
        return HASHCAT_CMD_MASK_TEMPLATE.format(
            mode=hashcat_mode, hashes=REMOTE_HASHES,
            mask=mask, outfile=REMOTE_OUTFILE,
            potfile=REMOTE_POTFILE,
            username_flag=uf,
            extra=extra,
        )
    else:
        # Detect wordlist and rules on remote machine
        _, wl_detect, _ = ssh._safe_run(
            f"ls {REMOTE_WORDLIST} 2>/dev/null && echo OK", timeout=5)
        wl = REMOTE_WORDLIST if "OK" in wl_detect else f"{REMOTE_WORK_DIR}/wordlist_dl.txt"
        _, rl_detect, _ = ssh._safe_run(
            f"find {REMOTE_WORK_DIR} -name '*.rule' -o -name '*.rules' | head -1", timeout=5)
        rl = rl_detect.strip() or REMOTE_RULES
        return HASHCAT_CMD_TEMPLATE.format(
            mode=hashcat_mode, hashes=REMOTE_HASHES,
            wordlist=wl, rules=rl,
            outfile=REMOTE_OUTFILE, potfile=REMOTE_POTFILE,
            username_flag=uf,
            extra=extra,
        )


def _restart_hashcat_on_machine(ssh, idx: int, mid: int, attack_mode: int,
                                 hashcat_mode: int, mask: str = "") -> bool:
    """Kill existing hashcat and restart it on a machine. Returns True on success."""
    try:
        restart_cmd = _build_hashcat_cmd(ssh, attack_mode, hashcat_mode, mask)
        full_cmd = f"cd {REMOTE_WORK_DIR} && {restart_cmd} >> hashcat_out.log 2>&1"
        ssh.run("pkill -9 hashcat 2>/dev/null", timeout=10)
        time.sleep(1)
        new_pid = ssh.run_background(full_cmd)
        if not ssh.is_alive():
            ssh.reconnect(retries=3, delay=5)
        update_machine(idx, status="running", pid=new_pid)
        log_event(f"[{mid}] Hashcat restarted (PID {new_pid}) ✓")
        return True
    except Exception as e:
        log_event(f"[{mid}] Restart failed: {e}", "error")
        return False


def reset_job():
    global _potfile_entries, _last_potfile_sync, _cost_last_ts, _last_hashes_file, _job_generation
    _job_generation += 1  # Invalidate any running old threads
    with job_lock:
        # Remember hashes_file before clearing for username enrichment
        if job.get("hashes_file"):
            _last_hashes_file = job["hashes_file"]
        job.update({
            "active": False, "phase": "idle", "error": "",
            "num_machines": 0, "machines": [], "total_hashes": 0,
            "total_cracked": 0, "started_at": 0, "finished_at": 0,
            "hashes_file": "", "archive_file": "", "cracked_lines": [],
            "total_cost": 0.0, "auto_destroy": False, "prev_cracked": 0,
            "attack_mode": 0, "mask": "", "hashcat_mode": 0,
            "total_speed_hs": 0,
            "total_speed": "", "gpu_stats": [], "paused": False,
            "wordlist_url": "", "rules_url": "", "rules_path": "",
            "budget_limit": 0.0, "extra_args": "", "username_flag": "",
        })
    with pool_lock:
        # Close leftover SSH connections from previous job
        for ssh in _ssh_pool.values():
            try:
                ssh.close()
            except Exception:
                pass
        _ssh_pool.clear()
        _potfile_entries = set()
        _last_potfile_sync = 0
    _cost_last_ts = 0
    # Remove cracked results file so it doesn't restore on next startup
    try:
        merged = CRACKED_DIR / "cracked_all.txt"
        if merged.exists():
            merged.unlink()
    except Exception:
        pass


def set_phase(phase, error=""):
    with job_lock:
        job["phase"] = phase
        if error:
            job["error"] = error
        # Mark job inactive on terminal phases
        if phase in ("done", "error", "stopped"):
            job["active"] = False
            job["finished_at"] = time.time()
            job["gpu_stats"] = []     # Clear stale GPU data
            job["total_speed_hs"] = 0
            job["total_speed"] = ""
    log_event(f"Phase → {phase}" + (f": {error}" if error else ""),
              "error" if error else "info")
    save_state(force=True)  # Phase transitions are critical — always persist
    # Push phase change via WebSocket
    try:
        ws_data = {"type": "status", "phase": phase, "cracked": job.get("total_cracked", 0), "speed": job.get("total_speed", "")}
        ws_broadcast_sync(ws_data)
        if phase == "done":
            ws_broadcast_sync({"type": "queue_done"})
    except Exception:
        pass


def update_machine(idx, **kw):
    with job_lock:
        if 0 <= idx < len(job["machines"]):
            job["machines"][idx].update(kw)


# ── State persistence ──────────────────────────────────────────────────────

_save_state_last: float = 0
_SAVE_STATE_MIN_INTERVAL: float = 10.0  # minimum seconds between state saves


def save_state(force: bool = False):
    """Save current job state to disk for crash recovery (atomic write).
    Rate-limited to avoid excessive disk I/O. Use force=True for critical saves.
    """
    global _save_state_last
    now = time.time()
    if not force and (now - _save_state_last) < _SAVE_STATE_MIN_INTERVAL:
        return
    _save_state_last = now
    try:
        with job_lock:
            state = {k: v for k, v in job.items() if k != "cracked_lines"}
            state["cracked_count"] = len(job.get("cracked_lines", []))
        STATE_DIR.mkdir(exist_ok=True)
        # Atomic write: write to temp file, then rename
        fd, tmp_path = tempfile.mkstemp(dir=str(STATE_DIR), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(state, f, default=str)
            os.replace(tmp_path, str(STATE_FILE))
        except Exception:
            # Clean up temp file on failure
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except Exception as e:
        logger.warning(f"Failed to save state: {e}")


def load_state() -> dict:
    """Load saved state from disk."""
    try:
        if STATE_FILE.exists():
            with open(STATE_FILE) as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"Failed to load state: {e}")
    return {}


def save_job_history(job_info: dict):
    """Append completed job to history file (atomic write)."""
    try:
        STATE_DIR.mkdir(exist_ok=True)
        history = []
        if HISTORY_FILE.exists():
            with open(HISTORY_FILE) as f:
                history = json.load(f)
        history.append(job_info)
        # Keep last 100
        history = history[-100:]
        fd, tmp_path = tempfile.mkstemp(dir=str(STATE_DIR), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(history, f, default=str, indent=2)
            os.replace(tmp_path, str(HISTORY_FILE))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except Exception as e:
        logger.warning(f"Failed to save history: {e}")


def load_job_history() -> list:
    """Load job history."""
    try:
        if HISTORY_FILE.exists():
            with open(HISTORY_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return []


# ── Telegram notifications ─────────────────────────────────────────────────

def send_telegram(msg: str):
    """Send notification to Telegram (if configured)."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        import httpx
        httpx.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "HTML"},
            timeout=10,
        )
    except Exception as e:
        logger.warning(f"Telegram send failed: {e}")


def _persist_cracked_to_disk(merged_lines):
    """Atomically persist cracked results to disk, merging with existing file.
    Also updates in-memory counter if disk has more results.
    """
    if not merged_lines:
        return
    try:
        CRACKED_DIR.mkdir(exist_ok=True)
        merged_path = CRACKED_DIR / "cracked_all.txt"
        # Read existing lines from disk first
        existing = set()
        if merged_path.exists():
            existing = {l.strip() for l in merged_path.read_text().splitlines() if l.strip()}
        all_on_disk = existing | {c.strip() for c in merged_lines if c.strip()}
        # Atomic write: write to temp file, then rename
        fd, tmp_path = tempfile.mkstemp(dir=str(CRACKED_DIR), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as out:
                for cline in all_on_disk:
                    out.write(cline + "\n")
            os.replace(tmp_path, str(merged_path))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        # Update counter if disk has more
        if len(all_on_disk) > job.get("total_cracked", 0):
            with job_lock:
                job["total_cracked"] = len(all_on_disk)
                job["cracked_lines"] = list(all_on_disk)
    except Exception as e:
        logger.warning(f"Failed to persist cracked to disk: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# API — PAGES
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/")
def index():
    return FileResponse("static/index.html")


# ══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET ENDPOINT
# ══════════════════════════════════════════════════════════════════════════════

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """WebSocket for live push updates."""
    # Check password for WS if set
    if PANEL_PASSWORD:
        # Accept WS first (can't send 401 on WS)
        pass
    await ws.accept()
    with _ws_lock:
        _ws_clients.append(ws)
    try:
        while True:
            # Keep connection alive, read any messages (ping/pong)
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        with _ws_lock:
            if ws in _ws_clients:
                _ws_clients.remove(ws)


# ══════════════════════════════════════════════════════════════════════════════
# API — STATUS & INFO
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/status")
def api_status():
    global _cost_last_ts

    # Fetch credit OUTSIDE the lock — this is an HTTP call that can be slow
    credit = 0
    try:
        credit = vastai.whoami().get("credit", 0)
    except Exception:
        pass

    with job_lock:
        burn = sum(m.get("dph", 0) for m in job["machines"]
                   if m.get("status") in ("running", "ready", "deploying", "loading", "rented"))

        # Elapsed: stop counting when job is finished
        if job.get("finished_at") and not job["active"]:
            elapsed = int(job["finished_at"] - job["started_at"]) if job["started_at"] else 0
        else:
            elapsed = int(time.time() - job["started_at"]) if job["started_at"] else 0

        # Accumulate cost using actual time delta (not assumed interval)
        # Primary cost tracking is in monitor loop; this is fallback for when monitor is idle
        now = time.time()
        if job["active"] and burn > 0 and _cost_last_ts > 0:
            dt = now - _cost_last_ts
            dt = min(dt, 15)  # cap at 15s — monitor loop updates every ~5-10s
            job["total_cost"] += burn * dt / 3600
        _cost_last_ts = now

        new_cracked = job["total_cracked"]
        # Milestone notification: only fire at every 5000 boundary
        prev = job.get("prev_cracked", 0)
        crack_event = (new_cracked // 5000) > (prev // 5000) and new_cracked > 0
        job["prev_cracked"] = new_cracked

        # Calculate overall ETA from machine-level hashcat progress + elapsed time
        # This is correct because progress = % of keyspace searched, not % of hashes cracked
        overall_eta = ""
        speed_hs = job.get("total_speed_hs", 0)
        if job["active"] and job["started_at"] and elapsed > 30:
            # Use average progress across running machines
            running_progress = [
                m.get("progress", 0) for m in job["machines"]
                if m.get("status") == "running" and m.get("progress", 0) > 0
            ]
            if running_progress:
                avg_progress = sum(running_progress) / len(running_progress)
                if 0 < avg_progress < 100:
                    eta_sec = int(elapsed * (100 - avg_progress) / avg_progress)
                    if eta_sec > 86400:
                        overall_eta = f"{eta_sec // 86400}d {(eta_sec % 86400) // 3600}h"
                    elif eta_sec > 3600:
                        overall_eta = f"{eta_sec // 3600}h {(eta_sec % 3600) // 60}m"
                    elif eta_sec > 0:
                        overall_eta = f"{eta_sec // 60}m {eta_sec % 60}s"
            elif speed_hs > 0:
                # Fallback: show per-machine ETA if available
                machine_etas = [m.get("eta", "") for m in job["machines"]
                                if m.get("status") == "running" and m.get("eta") and m.get("eta") != "done"]
                if machine_etas:
                    overall_eta = machine_etas[0]  # show first machine's ETA

        result = {
            **{k: v for k, v in job.items() if k != "cracked_lines"},
            "credit": round(credit, 2),
            "burn_rate": round(burn, 2),
            "elapsed": elapsed,
            "total_cost": round(job["total_cost"], 3),
            "new_crack": crack_event,
            "total_speed": job.get("total_speed", ""),
            "total_speed_hs": job.get("total_speed_hs", 0),
            "gpu_stats": job.get("gpu_stats", []),
            "paused": job.get("paused", False),
            "overall_eta": overall_eta,
            "budget_limit": job.get("budget_limit", 0),
            "chart_history": list(_chart_history)[-60:],
        }

    return result


@app.get("/api/logs")
def api_logs(after: float = Query(0)):
    with job_lock:
        entries = [e for e in event_log if e["ts"] > after] if after else list(event_log)
    return {"logs": entries}


@app.get("/api/files")
def api_files():
    exts_archive = {".zip", ".tar.gz", ".tgz", ".7z"}
    exts_hashes = {".txt", ".hash", ".hashes"}
    exts_rules = {".rule", ".rules"}
    skip_names = {"requirements.txt", "README.txt", "test_hashes.txt"}
    skip_dirs = {"node_modules", "__pycache__", "lib", "static", ".git", "chunks", "cracked", "data"}
    skip_prefixes = {"chunk_", "cracked_"}
    archives, hashes, rules = [], [], []
    # Scan only uploads directory
    scan_dirs = [UPLOAD_DIR]
    seen_paths = set()
    for scan_dir in scan_dirs:
        if not scan_dir.exists():
            continue
        for f in sorted(scan_dir.rglob("*")):
            if f.is_dir() or f.name.startswith("."):
                continue
            if any(d in f.parts for d in skip_dirs):
                continue
            if f.name in skip_names:
                continue
            if any(f.name.startswith(p) for p in skip_prefixes):
                continue
            rp = str(f.resolve())
            if rp in seen_paths:
                continue
            seen_paths.add(rp)
            suffixes = "".join(f.suffixes).lower()
            if any(suffixes.endswith(e) for e in exts_archive):
                archives.append({"path": str(f), "name": f.name, "size": f.stat().st_size})
            elif any(suffixes.endswith(e) for e in exts_rules):
                rules.append({"path": str(f), "name": f.name, "size": f.stat().st_size})
            elif any(suffixes.endswith(e) for e in exts_hashes):
                hashes.append({"path": str(f), "name": f.name, "size": f.stat().st_size})
    return {"archives": archives, "hashes": hashes, "rules": rules}


@app.get("/api/files/all")
def api_files_all():
    """Full file listing for file manager — includes all files with metadata."""
    exts_archive = {".zip", ".tar.gz", ".tgz", ".7z", ".rar"}
    exts_hashes = {".txt", ".hash", ".hashes"}
    exts_rules = {".rule", ".rules"}
    skip_names = {"requirements.txt", "README.txt"}
    skip_dirs = {"node_modules", "__pycache__", "lib", "static", ".git", "data", "chunks", "cracked"}
    files = []
    scan_dirs = [UPLOAD_DIR]
    seen_paths = set()
    for scan_dir in scan_dirs:
        if not scan_dir.exists():
            continue
        for f in sorted(scan_dir.rglob("*")):
            if f.is_dir() or f.name.startswith("."):
                continue
            if any(d in f.parts for d in skip_dirs):
                continue
            if f.name in skip_names:
                continue
            rp = str(f.resolve())
            if rp in seen_paths:
                continue
            seen_paths.add(rp)
            stat = f.stat()
            suffixes = "".join(f.suffixes).lower()
            if any(suffixes.endswith(e) for e in exts_archive):
                ftype = "archive"
            elif any(suffixes.endswith(e) for e in exts_rules):
                ftype = "rules"
            elif any(suffixes.endswith(e) for e in exts_hashes):
                ftype = "hashes"
            else:
                ftype = "other"
            # Count lines for text files
            lines = 0
            if ftype == "hashes" and stat.st_size < 500_000_000:
                try:
                    with open(f, "rb") as fh:
                        lines = sum(1 for _ in fh)
                except Exception:
                    pass
            # Relative path for display
            try:
                rel = str(f.relative_to(WORKSPACE))
            except ValueError:
                rel = f.name
            files.append({
                "path": str(f),
                "name": f.name,
                "rel": rel,
                "size": stat.st_size,
                "modified": int(stat.st_mtime),
                "type": ftype,
                "lines": lines,
            })
    files.sort(key=lambda x: x["modified"], reverse=True)
    # Disk usage
    total_size = sum(f["size"] for f in files)
    return {"files": files, "total_size": total_size, "count": len(files)}


@app.delete("/api/files")
async def api_files_delete(request: Request):
    """Delete a file by path."""
    body = await request.json()
    path = body.get("path", "")
    if not path:
        raise HTTPException(400, "No path")
    fp = Path(path)
    # Security: only allow deleting from workspace or uploads
    try:
        fp.resolve().relative_to(WORKSPACE.resolve())
    except ValueError:
        try:
            fp.resolve().relative_to(UPLOAD_DIR.resolve())
        except ValueError:
            raise HTTPException(403, "Access denied — file outside allowed dirs")
    if not fp.exists():
        raise HTTPException(404, "File not found")
    # Don't allow deleting code files
    protected = {"app.py", "requirements.txt", ".env"}
    protected_dirs = {"lib", "static", ".git", "data"}
    if fp.name in protected:
        raise HTTPException(403, f"Cannot delete protected file: {fp.name}")
    if any(d in fp.parts for d in protected_dirs):
        raise HTTPException(403, f"Cannot delete files in protected directory")
    try:
        size = fp.stat().st_size
        fp.unlink()
        log_event(f"File deleted: {fp.name} ({size // 1024}KB)")
        return {"ok": True, "name": fp.name}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/api/files/rename")
async def api_files_rename(request: Request):
    """Rename a file."""
    body = await request.json()
    old_path = body.get("path", "")
    new_name = body.get("new_name", "").strip()
    if not old_path or not new_name:
        raise HTTPException(400, "path and new_name required")
    import re as _rename_re
    new_name = _rename_re.sub(r'[^\w.\-]', '_', new_name)
    fp = Path(old_path)
    if not fp.exists():
        raise HTTPException(404, "File not found")
    new_fp = fp.parent / new_name
    if new_fp.exists():
        raise HTTPException(409, f"File {new_name} already exists")
    try:
        fp.rename(new_fp)
        log_event(f"File renamed: {fp.name} → {new_name}")
        return {"ok": True, "old_name": fp.name, "new_name": new_name, "new_path": str(new_fp)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# API — PASTE HASHES
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/paste-hashes")
async def api_paste_hashes(request: Request):
    """Save pasted hashes text as a file."""
    body = await request.json()
    hashes_text = body.get("hashes", "").strip()
    if not hashes_text:
        return {"ok": False, "error": "No hashes provided"}
    lines = [l.strip() for l in hashes_text.splitlines() if l.strip()]
    if not lines:
        return {"ok": False, "error": "No valid lines"}
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"pasted_{ts}.txt"
    filepath = WORKSPACE / filename
    with open(filepath, "w") as f:
        for line in lines:
            f.write(line + "\n")
    return {"ok": True, "count": len(lines), "filename": filename, "path": str(filepath)}


# ══════════════════════════════════════════════════════════════════════════════
# API — AUTO-DETECT HASH MODE
# ══════════════════════════════════════════════════════════════════════════════

HASH_PATTERNS = [
    # (regex, mode, name)
    (_re.compile(r'^[a-f0-9]{32}$', _re.I), 0, "MD5"),
    (_re.compile(r'^[a-f0-9]{40}$', _re.I), 100, "SHA1"),
    (_re.compile(r'^[a-f0-9]{64}$', _re.I), 1400, "SHA-256"),
    (_re.compile(r'^[a-f0-9]{128}$', _re.I), 1700, "SHA-512"),
    (_re.compile(r'^[a-f0-9]{128}:[a-f0-9]+$', _re.I), 1710, "sha512($pass.$salt)"),
    (_re.compile(r'^[a-f0-9]{40}:[a-f0-9]+$', _re.I), 110, "sha1($pass.$salt)"),
    (_re.compile(r'^[a-f0-9]{32}:[a-f0-9]+$', _re.I), 10, "md5($pass.$salt)"),
    (_re.compile(r'^[a-f0-9]{64}:[a-f0-9]+$', _re.I), 1410, "sha256($pass.$salt)"),
    (_re.compile(r'^\$2[aby]\$\d{2}\$.{53}$'), 3200, "bcrypt"),
    (_re.compile(r'^\$6\$'), 1800, "sha512crypt $6$"),
    (_re.compile(r'^\$5\$'), 7400, "sha256crypt $5$"),
    (_re.compile(r'^\$1\$'), 500, "md5crypt $1$"),
    (_re.compile(r'^\{SSHA512\}', _re.I), 1711, "SSHA-512(Base64)"),
    (_re.compile(r'^\{SSHA\}', _re.I), 111, "SSHA(Base64)"),
    (_re.compile(r'^[a-f0-9]{32}:[a-f0-9]{32}$', _re.I), 2611, "vBulletin"),
    (_re.compile(r'::[^:]+:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]+$', _re.I), 5600, "NetNTLMv2"),
    (_re.compile(r'^\$krb5tgs\$', _re.I), 13100, "Kerberoast TGS-REP"),
    (_re.compile(r'^\$krb5asrep\$', _re.I), 18200, "Kerberos 5 AS-REP"),
    (_re.compile(r'^WPA\*', _re.I), 22000, "WPA-PBKDF2-PMKID+EAPOL"),
]

@app.get("/api/detect-hash-mode")
def api_detect_hash_mode(path: str = Query(...)):
    """Detect hash mode from the first few lines of a hash file."""
    if not os.path.isfile(path):
        return {"modes": [], "error": "File not found"}
    try:
        with open(path) as f:
            sample_lines = []
            for i, line in enumerate(f):
                if i >= 10:
                    break
                stripped = line.strip()
                if stripped:
                    sample_lines.append(stripped)
        if not sample_lines:
            return {"modes": [], "error": "File is empty"}

        # For each line, check for user:hash format (strip username)
        matches = {}
        for line in sample_lines:
            # Check if it has a username prefix: user:hash or user:hash:salt
            parts = line.split(":", 1)
            test_parts = [line]
            if len(parts) == 2:
                test_parts.append(parts[1])  # try without username

            for test in test_parts:
                for pattern, mode, name in HASH_PATTERNS:
                    if pattern.search(test):
                        matches[mode] = matches.get(mode, 0) + 1
                        break

        if not matches:
            return {"modes": []}

        sorted_modes = sorted(matches.items(), key=lambda x: -x[1])
        result = []
        for mode, count in sorted_modes[:3]:
            name = next((n for p, m, n in HASH_PATTERNS if m == mode), f"Mode {mode}")
            result.append({"mode": mode, "name": name, "confidence": count})
        return {"modes": result}
    except Exception as e:
        return {"modes": [], "error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# API — JOB QUEUE
# ══════════════════════════════════════════════════════════════════════════════

_job_queue: list = []  # [{form_data_dict}]
_job_queue_lock = threading.Lock()

@app.get("/api/queue")
def api_queue():
    """Get job queue."""
    with _job_queue_lock:
        return {"queue": list(_job_queue)}

@app.post("/api/queue/add")
async def api_queue_add(request: Request):
    """Add a job to the queue (same params as /api/start)."""
    body = await request.json()
    with _job_queue_lock:
        _job_queue.append(body)
    return {"ok": True, "position": len(_job_queue)}

@app.post("/api/queue/clear")
def api_queue_clear():
    """Clear job queue."""
    with _job_queue_lock:
        _job_queue.clear()
    return {"ok": True}


_username_map_cache: dict = {}
_username_map_key: str = ""  # cache key: hashes_file path
_username_map_ts: float = 0  # cache timestamp


def _build_username_map(hashes_file: str = "") -> dict:
    """Build map: hash:salt -> email from hash files. Cached for 30s per hashes_file."""
    global _username_map_cache, _username_map_key, _username_map_ts
    cache_key = hashes_file or _last_hashes_file or ""
    now = time.time()
    if cache_key == _username_map_key and (now - _username_map_ts) < 30 and _username_map_cache:
        return _username_map_cache

    username_map = {}
    lookup_files = []
    if hashes_file and os.path.isfile(hashes_file):
        lookup_files.append(hashes_file)
    if _last_hashes_file and os.path.isfile(_last_hashes_file) and _last_hashes_file not in lookup_files:
        lookup_files.append(_last_hashes_file)
    # Scan uploads dir instead of workspace root
    for candidate in UPLOAD_DIR.glob("*.txt"):
        cp = str(candidate)
        if cp in lookup_files or candidate.name in ("requirements.txt",):
            continue
        if candidate.stat().st_size > 10000:
            try:
                first_line = candidate.open().readline().strip()
                if ":" in first_line and len(first_line) > 50:
                    lookup_files.append(cp)
            except Exception:
                pass
    for lf in lookup_files:
        try:
            with open(lf) as f:
                for line in f:
                    parts = line.strip().split(":", 1)
                    if len(parts) == 2:
                        username_map[parts[1]] = parts[0]
        except Exception:
            pass

    _username_map_cache = username_map
    _username_map_key = cache_key
    _username_map_ts = now
    return username_map


@app.get("/api/cracked")
def api_cracked():
    merged = CRACKED_DIR / "cracked_all.txt"
    lines = []
    if merged.exists():
        lines = [l.strip() for l in merged.read_text().splitlines() if l.strip()]
    with job_lock:
        live = list(job.get("cracked_lines", []))
        hashes_file = job.get("hashes_file", "")
    all_lines = list(set(lines + live))

    username_map = _build_username_map(hashes_file)

    # Convert to email:pass format
    email_pass = []
    for line in all_lines:
        hash_pass = line.rsplit(":", 1)
        if len(hash_pass) == 2 and hash_pass[0] in username_map:
            email_pass.append(f"{username_map[hash_pass[0]]}:{hash_pass[1]}")
        else:
            email_pass.append(line)

    return {"count": len(email_pass), "lines": email_pass[:2000]}


@app.get("/api/cracked/download")
def api_cracked_download():
    """Download cracked results as email:pass format."""
    # Get all cracked lines
    merged = CRACKED_DIR / "cracked_all.txt"
    lines = []
    if merged.exists():
        lines = [l.strip() for l in merged.read_text().splitlines() if l.strip()]
    with job_lock:
        live = list(job.get("cracked_lines", []))
        hashes_file = job.get("hashes_file", "")
    all_lines = list(set(lines + live))
    if not all_lines:
        return PlainTextResponse("No results yet", status_code=404)

    # Build username lookup
    username_map = _build_username_map(hashes_file)

    # Convert to email:pass
    result = []
    for line in all_lines:
        hash_pass = line.rsplit(":", 1)
        if len(hash_pass) == 2 and hash_pass[0] in username_map:
            result.append(f"{username_map[hash_pass[0]]}:{hash_pass[1]}")
        else:
            result.append(line)

    content = "\n".join(result) + "\n"
    return StreamingResponse(
        iter([content]),
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=cracked_{len(result)}.txt"}
    )


@app.get("/api/cracked/csv")
def api_cracked_csv():
    """Download cracked results as CSV (email,password)."""
    merged = CRACKED_DIR / "cracked_all.txt"
    lines = []
    if merged.exists():
        lines = [l.strip() for l in merged.read_text().splitlines() if l.strip()]
    with job_lock:
        live = list(job.get("cracked_lines", []))
        hashes_file = job.get("hashes_file", "")
    all_lines = list(set(lines + live))
    if not all_lines:
        return PlainTextResponse("No results yet", status_code=404)
    username_map = _build_username_map(hashes_file)
    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["email", "password"])
    for line in all_lines:
        hash_pass = line.rsplit(":", 1)
        if len(hash_pass) == 2 and hash_pass[0] in username_map:
            writer.writerow([username_map[hash_pass[0]], hash_pass[1]])
        else:
            writer.writerow([line, ""])
    csv_content = output.getvalue()
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=cracked_{len(all_lines)}.csv"}
    )


# ══════════════════════════════════════════════════════════════════════════════
# API — INSTANCES
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/instances")
def api_instances():
    try:
        instances = vastai.get_instances()
        result = []
        for i in instances:
            result.append({
                "id": i.get("id"),
                "gpu": i.get("gpu_name", "?"),
                "num_gpus": i.get("num_gpus", 1),
                "status": i.get("actual_status", "?"),
                "status_msg": (i.get("status_msg") or "")[:100],
                "ssh_host": i.get("ssh_host", ""),
                "ssh_port": i.get("ssh_port", 0),
                "dph": round(i.get("dph_total", 0), 3),
                "disk_gb": round(i.get("disk_space", 0), 1),
                "gpu_ram": round(i.get("gpu_ram", 0) / 1024, 1) if i.get("gpu_ram") else 0,
                "image": (i.get("image_uuid") or i.get("image") or "")[:40],
                "start_date": i.get("start_date", ""),
            })
        return {"instances": result}
    except Exception as e:
        return {"instances": [], "error": str(e)}


@app.get("/api/marketplace")
def api_marketplace(
    gpu: str = Query("RTX 5090"),
    num_gpus: int = Query(1),
    min_price: float = Query(0.0),
    max_price: float = Query(50.0),
    min_gpu_ram: int = Query(0),
    min_inet_down: int = Query(0),
    min_inet_up: int = Query(0),
    min_disk: int = Query(0),
    min_cpu: int = Query(0),
    min_ram: int = Query(0),
    min_reliability: float = Query(0.0),
    min_dlperf: float = Query(0.0),
    cuda_ver: float = Query(0.0),
    verified: bool = Query(True),
    sort: str = Query("-dph_total"),
    limit: int = Query(50),
):
    try:
        offers = vastai.search_offers(
            gpu_name=gpu if gpu != "any" else None,
            num_gpus=num_gpus,
            min_dph=min_price,
            max_dph=max_price,
            min_gpu_ram_gb=min_gpu_ram,
            min_inet_down=min_inet_down,
            min_inet_up=min_inet_up,
            min_disk_gb=min_disk,
            min_cpu_cores=min_cpu,
            min_ram_gb=min_ram,
            min_reliability=min_reliability,
            min_dlperf=min_dlperf,
            cuda_version=cuda_ver,
            verified_only=verified,
            order=sort,
            limit=limit,
        )
        result = []
        for o in offers:
            result.append({
                "id": o.get("id"),
                "gpu": o.get("gpu_name", "?"),
                "num_gpus": o.get("num_gpus", 1),
                "gpu_ram": round(o.get("gpu_ram", 0) / 1024, 1) if o.get("gpu_ram") else 0,
                "dph": round(o.get("dph_total", 0), 3),
                "inet_down": round(o.get("inet_down", 0), 0),
                "inet_up": round(o.get("inet_up", 0), 0),
                "reliability": round(o.get("reliability2", 0) * 100, 1),
                "disk": round(o.get("disk_space", 0), 0),
                "dlperf": round(o.get("dlperf", 0), 1),
                "cpu_cores": o.get("cpu_cores_effective", 0),
                "cpu_ram": round(o.get("cpu_ram", 0) / 1024, 1) if o.get("cpu_ram") else 0,
                "cuda": o.get("cuda_max_good", 0),
                "location": o.get("geolocation", ""),
                "verified": o.get("verified", False),
                "score": round(o.get("score", 0), 2),
            })
        return {"offers": result}
    except Exception as e:
        return {"offers": [], "error": str(e)}


@app.post("/api/instances/rent")
def api_rent(offer_id: int = Form(...), disk_gb: int = Form(50)):
    try:
        result = vastai.rent_instance(offer_id, disk_gb=disk_gb, onstart_cmd=_make_onstart_cmd())
        new_id = result.get("new_contract")
        log_event(f"Manually rented instance {new_id} from offer {offer_id}")
        return {"ok": True, "instance_id": new_id}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/api/instances/{instance_id}/destroy")
def api_destroy_one(instance_id: int):
    try:
        vastai.destroy_instance(instance_id)
        log_event(f"Destroyed instance {instance_id}")
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/api/instances/destroy-all")
def api_destroy_all():
    try:
        instances = vastai.get_instances()
        destroyed, errors = [], []
        for i in instances:
            try:
                vastai.destroy_instance(i["id"])
                destroyed.append(i["id"])
            except Exception as e:
                errors.append(f"{i['id']}: {e}")
        log_event(f"Destroyed {len(destroyed)} instances")
        return {"ok": True, "destroyed": destroyed, "errors": errors}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.post("/api/instances/{instance_id}/exec")
def api_exec_on_instance(instance_id: int, cmd: str = Form(...)):
    try:
        inst = vastai.get_instance(instance_id)
        if inst.get("actual_status") != "running":
            return {"ok": False, "error": "Instance not running"}
        ssh = SSHManager(inst["ssh_host"], inst["ssh_port"])
        ssh.connect(retries=2, delay=5)
        code, stdout, stderr = ssh.run(cmd, timeout=30)
        ssh.close()
        return {"ok": True, "exit_code": code, "stdout": stdout[:5000], "stderr": stderr[:2000]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get("/api/account")
def api_account():
    try:
        info = vastai.whoami()
        return {
            "credit": round(info.get("credit", 0), 2),
            "email": info.get("email", ""),
            "username": info.get("username", ""),
            "ssh_key": info.get("ssh_key", ""),
        }
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/ssh-key/sync")
def api_sync_ssh_key():
    """Auto-sync local SSH public key to Vast.ai account via /ssh/ endpoint."""
    try:
        key_paths = [
            os.path.expanduser("~/.ssh/id_ed25519.pub"),
            os.path.expanduser("~/.ssh/id_rsa.pub"),
            os.path.expanduser("~/.ssh/id_ecdsa.pub"),
        ]
        local_key = ""
        for kp in key_paths:
            if os.path.isfile(kp):
                with open(kp) as f:
                    local_key = f.read().strip()
                break
        if not local_key:
            return {"ok": False, "error": "No SSH public key found locally (~/.ssh/id_*.pub)"}

        # Check if already registered
        remote_keys_str = vastai.get_ssh_key()
        if local_key in (remote_keys_str or ""):
            return {"ok": True, "status": "already_synced", "key": local_key[:60] + "..."}

        # Add key via POST /ssh/
        vastai.update_ssh_key(local_key)
        log_event(f"SSH key synced to Vast.ai: {local_key[:40]}...")
        return {"ok": True, "status": "synced", "key": local_key[:60] + "..."}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get("/api/ssh-key/check")
def api_check_ssh_key():
    """Check if local SSH key is registered on Vast.ai."""
    try:
        key_paths = [
            os.path.expanduser("~/.ssh/id_ed25519.pub"),
            os.path.expanduser("~/.ssh/id_rsa.pub"),
            os.path.expanduser("~/.ssh/id_ecdsa.pub"),
        ]
        local_key = ""
        key_file = ""
        for kp in key_paths:
            if os.path.isfile(kp):
                with open(kp) as f:
                    local_key = f.read().strip()
                key_file = kp
                break
        if not local_key:
            return {"has_local": False, "synced": False, "key_file": ""}

        remote_keys_str = vastai.get_ssh_key()
        synced = local_key in (remote_keys_str or "")
        return {"has_local": True, "synced": synced, "key_file": key_file, "local_key_short": local_key[:60] + "..."}
    except Exception as e:
        return {"has_local": False, "synced": False, "error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# API — JOB HISTORY & GPU STATS
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/history")
def api_history():
    return {"history": load_job_history()}


@app.get("/api/gpu-stats")
def api_gpu_stats():
    """Get GPU telemetry for all active machines."""
    with job_lock:
        return {"stats": job.get("gpu_stats", [])}


@app.post("/api/pause")
def api_pause():
    """Pause all hashcat instances (checkpoint)."""
    if not job["active"] or job["phase"] != "running":
        raise HTTPException(400, "No running job to pause")
    errors = []
    with pool_lock:
        pool_snapshot = dict(_ssh_pool)
    for mid, ssh in pool_snapshot.items():
        try:
            ssh.pause_hashcat()
        except Exception as e:
            errors.append(f"{mid}: {e}")
    with job_lock:
        job["paused"] = True
    log_event("Job paused (checkpoint saved)")
    return {"ok": True, "errors": errors}


@app.post("/api/resume")
def api_resume():
    """Resume paused hashcat instances."""
    if not job["active"]:
        raise HTTPException(400, "No active job")
    errors = []
    with pool_lock:
        pool_snapshot = list(_ssh_pool.items())
    for mid, ssh in pool_snapshot:
        try:
            ok = ssh.resume_hashcat()
            if ok:
                # Get new PID — wait briefly then verify
                time.sleep(2)
                _, pid_out, _ = ssh._safe_run("pgrep -f hashcat | head -1", timeout=10)
                try:
                    new_pid = int(pid_out.strip())
                    # Find correct machine index by ID
                    with job_lock:
                        machine_idx = next((j for j, m in enumerate(job["machines"]) if m.get("id") == mid), -1)
                    if machine_idx >= 0:
                        update_machine(machine_idx, pid=new_pid, status="running")
                except ValueError:
                    pass
            else:
                errors.append(f"{mid}: resume failed")
        except Exception as e:
            errors.append(f"{mid}: {e}")
    with job_lock:
        job["paused"] = False
    log_event("Job resumed from checkpoint")
    return {"ok": True, "errors": errors}


@app.post("/api/reconnect")
def api_reconnect(hashcat_mode: int = Form(1710)):
    """Reconnect to running instances after codespace crash.

    Reads saved machine list from state, connects SSH to each,
    checks if hashcat is still running, and starts monitor loop
    WITHOUT re-deploying or re-uploading.
    """
    if job.get("active") and job.get("phase") == "running":
        raise HTTPException(400, "Job is already running")

    machines = job.get("machines", [])
    if not machines:
        raise HTTPException(400, "No machines in saved state to reconnect to")

    # Gather info from state
    machine_ids = [m["id"] for m in machines]
    hashes_path = job.get("hashes_file", "")
    archive_path = job.get("archive_file", "")
    attack_mode = job.get("attack_mode", 0)
    mask_val = job.get("mask", "")
    wordlist_url = job.get("wordlist_url", "")
    rules_url = job.get("rules_url", "")
    prev_cracked = job.get("total_cracked", 0)

    if not hashes_path:
        raise HTTPException(400, "No hashes_file in saved state")

    # Re-activate job
    with job_lock:
        job["active"] = True
        job["phase"] = "reconnecting"
        job["prev_cracked"] = prev_cracked
        job["hashcat_mode"] = hashcat_mode

    log_event(f"Reconnecting to {len(machine_ids)} machines...")

    threading.Thread(
        target=_reconnect_job,
        args=(machine_ids, hashes_path, hashcat_mode),
        kwargs={
            "attack_mode": attack_mode,
            "mask": mask_val,
            "wordlist_url": wordlist_url,
            "rules_url": rules_url,
            "archive_path": archive_path,
        },
        daemon=True,
        name="reconnect-job",
    ).start()

    return {"ok": True, "machines": len(machine_ids)}


def _reconnect_job(machine_ids, hashes_path, hashcat_mode,
                   attack_mode=0, mask="", wordlist_url="", rules_url="", archive_path=""):
    """Background thread: reconnect SSH and resume monitoring."""
    global _last_potfile_sync
    my_gen = _job_generation  # Snapshot generation — detect stale threads

    def _stale():
        return _job_generation != my_gen

    try:
        ssh_conns: dict[int, SSHManager] = {}
        ready_ids = []

        failed_machines = []  # (index, machine_id) — failed to reconnect

        for i, mid in enumerate(machine_ids):
            try:
                inst = vastai.get_instance(mid)
                if inst is None:
                    log_event(f"[{mid}] Instance not found (destroyed?), will replace", "error")
                    update_machine(i, status="destroyed")
                    failed_machines.append((i, mid))
                    continue
                actual_status = inst.get("actual_status", "")
                if actual_status not in ("running",):
                    log_event(f"[{mid}] Status={actual_status}, skipping", "error")
                    update_machine(i, status=f"skip:{actual_status}")
                    failed_machines.append((i, mid))
                    continue

                ssh_host = inst.get("ssh_host", "")
                ssh_port = inst.get("ssh_port", 0)
                if not ssh_host or not ssh_port:
                    log_event(f"[{mid}] No SSH info, skipping", "error")
                    update_machine(i, status="no_ssh")
                    continue

                update_machine(i, status="connecting",
                               ssh=f"{ssh_host}:{ssh_port}")

                ssh = SSHManager(ssh_host, ssh_port)
                ssh.connect(retries=3, delay=10)

                # Check if hashcat is still running
                saved_pid = job["machines"][i].get("pid", 0) if i < len(job["machines"]) else 0
                if saved_pid:
                    _, pid_check, _ = ssh._safe_run(
                        f"kill -0 {saved_pid} 2>/dev/null && echo RUNNING || echo DONE", timeout=10)
                else:
                    _, pid_check, _ = ssh._safe_run(
                        "pgrep -f hashcat >/dev/null && echo RUNNING || echo DONE", timeout=10)

                is_running = "RUNNING" in pid_check

                # If not running with saved PID, try pgrep
                if not is_running and saved_pid:
                    _, pgrep_out, _ = ssh._safe_run("pgrep -f hashcat | head -1", timeout=10)
                    if pgrep_out.strip():
                        try:
                            new_pid = int(pgrep_out.strip())
                            update_machine(i, pid=new_pid)
                            is_running = True
                            log_event(f"[{mid}] Hashcat found under PID {new_pid}")
                        except ValueError:
                            pass

                if is_running:
                    update_machine(i, status="running")
                    log_event(f"[{mid}] Reconnected — hashcat still running ✓")
                else:
                    # Hashcat finished while we were offline — check results
                    out_count = ssh.remote_line_count(REMOTE_OUTFILE)
                    if out_count > 0:
                        update_machine(i, status="done", cracked=out_count)
                        log_event(f"[{mid}] Hashcat already finished ({out_count} cracked)")
                    else:
                        # Restart hashcat on this machine
                        log_event(f"[{mid}] Hashcat not running — restarting...")
                        if _restart_hashcat_on_machine(ssh, i, mid, attack_mode, hashcat_mode, mask):
                            is_running = True
                        else:
                            update_machine(i, status="error")

                ssh_conns[mid] = ssh
                ready_ids.append(mid)

            except Exception as e:
                log_event(f"[{mid}] Reconnect failed: {e}", "error")
                update_machine(i, status=f"err: {str(e)[:40]}")
                failed_machines.append((i, mid))

        if not ssh_conns:
            set_phase("error", "Could not reconnect to any machine")
            return

        # Update global SSH pool
        with pool_lock:
            _ssh_pool.clear()
            _ssh_pool.update(ssh_conns)

        log_event(f"Reconnected to {len(ssh_conns)}/{len(machine_ids)} machines")

        # ── Enter monitor loop (same as _run_job) ──
        set_phase("running")
        log_event("Monitoring hashcat progress...")
        save_state()

        time.sleep(15)
        monitor_start = time.time()
        consecutive_done = 0
        _last_potfile_sync = time.time()
        _replacing: set = set()
        _logged_errors: set = set()
        _destroyed: set = set()  # machines already destroyed after completion
        _combo_done: set = set()  # machines that already switched to mask attack
        _gpu_warned: set = set()  # machines warned about high temp

        if failed_machines and archive_path:
            for fm_i, fm_mid in failed_machines:
                if fm_mid not in _replacing:
                    _replacing.add(fm_mid)
                    log_event(f"[{fm_mid}] Replacing failed machine...")
                    threading.Thread(
                        target=_replace_aborted_machine,
                        args=(fm_i, fm_mid, ssh_conns, ready_ids,
                              archive_path, hashcat_mode),
                        kwargs={"attack_mode": attack_mode, "mask": mask,
                                "wordlist_url": wordlist_url, "rules_url": rules_url,
                                "rented_ids": machine_ids},
                        daemon=True,
                    ).start()
            # Destroy failed machines that we're NOT replacing (no archive/no chunk)
            else:
                for fm_i, fm_mid in failed_machines:
                    ok = _safe_destroy(fm_mid, verify=True)
                    if ok:
                        log_event(f"[{fm_mid}] Failed machine destroyed ✓")
                    else:
                        log_event(f"[{fm_mid}] Failed machine destroy UNVERIFIED!", "error")

        while job["active"] and job["phase"] == "running":
            if _stale():
                log_event("Stale reconnect thread detected — exiting")
                return
            if job.get("paused"):
                time.sleep(5)
                continue

            time.sleep(10)
            if _stale():
                log_event("Stale reconnect thread detected — exiting")
                return
            all_done = True
            total_cracked = 0
            all_cracked_lines = []
            total_speed_hs = 0.0
            gpu_telemetry = []

            for i, mid in enumerate(ready_ids):
                idx = machine_ids.index(mid) if mid in machine_ids else i
                if mid in _replacing:
                    all_done = False
                    continue
                if mid in _destroyed:
                    continue
                if mid not in ssh_conns:
                    all_done = False
                    continue
                ssh = ssh_conns[mid]
                try:
                    if not ssh.is_alive():
                        log_event(f"[{mid}] SSH dropped, reconnecting...", "error")
                        if not ssh.reconnect(retries=3, delay=10):
                            update_machine(idx, status="ssh_lost")
                            all_done = False
                            continue

                    machine_pid = job["machines"][idx].get("pid", 0) if idx < len(job["machines"]) else 0
                    if machine_pid:
                        _, proc_out, _ = ssh._safe_run(
                            f"kill -0 {machine_pid} 2>/dev/null && "
                            f"grep -q hashcat /proc/{machine_pid}/comm 2>/dev/null && "
                            f"echo RUNNING || echo DONE", timeout=10)
                    else:
                        _, proc_out, _ = ssh._safe_run(
                            "pgrep -f hashcat >/dev/null && echo RUNNING || echo DONE", timeout=10)
                    is_running = "RUNNING" in proc_out

                    hstat = ssh.get_hashcat_status() or {}

                    # Override: terminal hashcat states mean done regardless of PID
                    if hstat.get("hashcat_status") in ("Exhausted", "Cracked"):
                        is_running = False
                    cracked = hstat.get("cracked", 0)
                    out_count = ssh.remote_line_count(REMOTE_OUTFILE)
                    cracked = max(cracked, out_count)
                    total_cracked += cracked

                    machine_speed = hstat.get("speed_hs", 0)
                    total_speed_hs += machine_speed

                    if out_count > 0:
                        content = ssh.read_remote_file(REMOTE_OUTFILE)
                        if content:
                            all_cracked_lines.extend(content.strip().splitlines())

                    update_machine(idx,
                        status="running" if is_running else "done",
                        progress=hstat.get("progress", 100 if not is_running else 0),
                        speed=hstat.get("speed", ""),
                        speed_hs=machine_speed,
                        cracked=cracked,
                        eta=hstat.get("eta", "done" if not is_running else ""),
                        log=hstat.get("hashcat_status", ""),
                    )

                    try:
                        gpus = ssh.get_gpu_stats()
                        if gpus:
                            gpu_telemetry.append({"id": mid, "gpus": gpus})
                            # GPU temperature alert (warn once per machine)
                            for g in gpus:
                                if g.get("temp", 0) >= 90 and mid not in _gpu_warned:
                                    _gpu_warned.add(mid)
                                    log_event(f"[{mid}] ⚠ GPU #{g['index']} temp {g['temp']}°C — throttling likely!", "error")
                    except Exception:
                        pass

                    if is_running:
                        all_done = False

                    # Auto-destroy completed machines to save money
                    # Combo attack: if dict exhausted AND mask is provided, switch to mask attack
                    if not is_running and hstat.get("hashcat_status", "") == "Exhausted" and mid not in _destroyed:
                        if attack_mode == 0 and mask and mid not in _combo_done:
                            _combo_done.add(mid)
                            log_event(f"[{mid}] Dict exhausted → switching to mask attack ({mask})...")
                            all_done = False
                            try:
                                if not ssh.is_alive():
                                    ssh.reconnect(retries=3, delay=5)
                                _restart_hashcat_on_machine(ssh, idx, mid, 3, hashcat_mode, mask)
                                update_machine(idx, progress=0)
                            except Exception as combo_err:
                                log_event(f"[{mid}] Combo mask start failed: {combo_err}", "error")
                        else:
                            _destroyed.add(mid)
                            try:
                                ssh.close()
                            except Exception:
                                pass
                            if mid in ssh_conns:
                                del ssh_conns[mid]
                            with pool_lock:
                                _ssh_pool.pop(mid, None)
                            try:
                                vastai.destroy_instance(mid)
                                log_event(f"[{mid}] Exhausted — instance destroyed to save cost ✓")
                            except Exception as de:
                                log_event(f"[{mid}] Destroy failed: {de}", "error")
                    elif not is_running and hstat.get("hashcat_status", "") == "Cracked" and mid not in _destroyed:
                        _destroyed.add(mid)
                        try:
                            ssh.close()
                        except Exception:
                            pass
                        if mid in ssh_conns:
                            del ssh_conns[mid]
                        with pool_lock:
                            _ssh_pool.pop(mid, None)
                        try:
                            vastai.destroy_instance(mid)
                            log_event(f"[{mid}] All cracked — instance destroyed ✓")
                        except Exception as de:
                            log_event(f"[{mid}] Destroy failed: {de}", "error")

                    # If machine finished abnormally — replace only on Aborted/Quit
                    if not is_running and hstat.get("hashcat_status", "") not in ("Exhausted", "Cracked", ""):
                        hc_status = hstat.get("hashcat_status", "?")
                        if hc_status in ("Aborted", "Quit") and mid not in _replacing:
                            _replacing.add(mid)
                            all_done = False
                            log_event(f"[{mid}] Hashcat {hc_status} — replacing machine...", "error")
                            threading.Thread(
                                target=_replace_aborted_machine,
                                args=(idx, mid, ssh_conns, ready_ids, archive_path,
                                      hashcat_mode),
                                kwargs={"attack_mode": attack_mode, "mask": mask,
                                        "wordlist_url": wordlist_url, "rules_url": rules_url,
                                        "rented_ids": machine_ids},
                                daemon=True,
                            ).start()
                        elif mid not in _logged_errors:
                            # Other status (e.g. Running) — just restart hashcat
                            _logged_errors.add(mid)
                            log_event(f"[{mid}] Hashcat ended ({hc_status}) — restarting...", "error")
                            if _restart_hashcat_on_machine(ssh, idx, mid, attack_mode, hashcat_mode, mask):
                                all_done = False
                            else:
                                all_done = False

                except Exception as e:
                    update_machine(idx, status=f"err: {str(e)[:40]}")
                    all_done = False

            # Merge new cracked lines with previously known ones
            with job_lock:
                prev_lines = set(job.get("cracked_lines", []))
                merged_lines = prev_lines | set(all_cracked_lines)
                job["cracked_lines"] = list(merged_lines)
                job["total_cracked"] = max(total_cracked, len(merged_lines))
                job["total_speed_hs"] = total_speed_hs
                job["total_speed"] = SSHManager.format_speed(total_speed_hs)
                job["gpu_stats"] = gpu_telemetry

            # Push live status to all WS clients + chart data
            try:
                _chart_history.append({
                    "ts": int(time.time()),
                    "speed": total_speed_hs,
                    "cracked": job.get("total_cracked", 0),
                })
                ws_push = {
                    "type": "full_status",
                    "total_cracked": job.get("total_cracked", 0),
                    "total_hashes": job.get("total_hashes", 0),
                    "total_speed": job.get("total_speed", ""),
                    "total_speed_hs": total_speed_hs,
                    "total_cost": round(job.get("total_cost", 0), 3),
                    "machines": job.get("machines", []),
                    "gpu_stats": gpu_telemetry,
                    "phase": job.get("phase", "running"),
                    "chart_history": list(_chart_history)[-60:],
                }
                ws_broadcast_sync(ws_push)
            except Exception:
                pass

            # Persist cracked results (atomic merge with existing file)
            _persist_cracked_to_disk(merged_lines)

            # Milestone notifications
            if total_cracked > job.get("prev_cracked", 0):
                prev = job.get("prev_cracked", 0)
                prev_milestone = prev // 5000
                curr_milestone = total_cracked // 5000
                if curr_milestone > prev_milestone:
                    send_telegram(f"🔓 <b>{total_cracked} cracked!</b>\nTotal: {total_cracked}/{job['total_hashes']}")

            if all_done:
                consecutive_done += 1
                if consecutive_done >= 2 and (time.time() - monitor_start) > 30:
                    log_event("All machines finished")
                    break
            else:
                consecutive_done = 0

            # Potfile sync (non-blocking)
            now = time.time()
            if now - _last_potfile_sync > POTFILE_SYNC_INTERVAL and total_cracked > 0:
                _last_potfile_sync = now
                _sync_snap = dict(ssh_conns)
                threading.Thread(
                    target=_do_potfile_sync, args=(_sync_snap, list(ready_ids)), daemon=True
                ).start()

            # Process retry queue for failed replacements
            _process_retry_queue()

            save_state()

        # ── COLLECT ──
        if _stale():
            log_event("Stale reconnect thread — exiting before collection")
            return
        if not job.get("active") or job.get("phase") in ("stopped", "idle"):
            log_event("Job was stopped, skipping collection")
        else:
            log_event("Collecting results...")
            results = []
            for i, mid in enumerate(ready_ids):
                if mid not in ssh_conns:
                    continue
                try:
                    local_out = str(CRACKED_DIR / f"cracked_{mid}.txt")
                    if ssh_conns[mid].download_file(REMOTE_OUTFILE, local_out):
                        results.append(local_out)
                except Exception as e:
                    log_event(f"Download error from {mid}: {e}", "error")

            if results:
                # Merge with existing cracked_all.txt (preserves results from auto-destroyed machines)
                seen = set()
                merged = CRACKED_DIR / "cracked_all.txt"
                if merged.exists():
                    with open(merged) as existing:
                        for line in existing:
                            if line.strip():
                                seen.add(line)
                for rf in results:
                    with open(rf) as inp:
                        for line in inp:
                            if line.strip() and line not in seen:
                                seen.add(line)
                with open(merged, "w") as out:
                    for line in seen:
                        out.write(line if line.endswith("\n") else line + "\n")
                with job_lock:
                    job["total_cracked"] = len(seen)
                    job["cracked_lines"] = [l.strip() for l in seen]
                log_event(f"Total cracked: {len(seen)}")

        if job.get("phase") in ("stopped", "idle"):
            return
        set_phase("done")
        log_event("Job complete ✓")

        elapsed = int(time.time() - job["started_at"]) if job["started_at"] else 0

        # Save to job history
        save_job_history({
            "finished_at": datetime.now().isoformat(),
            "total_hashes": job["total_hashes"],
            "total_cracked": job["total_cracked"],
            "elapsed_sec": elapsed,
            "total_cost": round(job["total_cost"], 3),
            "num_machines": len(ready_ids),
            "gpu": job["machines"][0].get("gpu", "?") if job.get("machines") else "?",
            "hashcat_mode": hashcat_mode,
            "attack_mode": attack_mode,
            "reconnected": True,
        })

        send_telegram(
            f"✅ <b>Job Complete</b>\n"
            f"Cracked: {job['total_cracked']}/{job['total_hashes']}\n"
            f"Time: {elapsed//3600}h {(elapsed%3600)//60}m\n"
            f"Cost: ${job['total_cost']:.2f}"
        )
        save_state()

        if job.get("auto_destroy", True):
            log_event("Auto-destroying all instances (with verification)...")
            # Destroy ALL machine_ids, not just ready_ids
            all_destroy_ids = set(machine_ids) | set(ready_ids)
            for mid in all_destroy_ids:
                if mid in _destroyed:
                    continue
                ok = _safe_destroy(mid, verify=True)
                if ok:
                    log_event(f"Auto-destroyed {mid} ✓")
                else:
                    log_event(f"[{mid}] Destroy UNVERIFIED — may still be billing!", "error")

        if not _stale():
            with pool_lock:
                for ssh in _ssh_pool.values():
                    try:
                        ssh.close()
                    except:
                        pass
                _ssh_pool.clear()

    except Exception as e:
        logger.error(traceback.format_exc())
        set_phase("error", str(e))


# ══════════════════════════════════════════════════════════════════════════════
# API — JOB CONTROL
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/start")
async def api_start(
    archive_path: str = Form(""),
    hashes_path: str = Form(...),
    num_machines: int = Form(5),
    gpu_name: str = Form("RTX 5090"),
    hashcat_mode: int = Form(1710),
    auto_destroy: bool = Form(True),
    mode: str = Form("rent"),
    instance_ids: str = Form(""),
    attack_mode: int = Form(0),
    mask: str = Form(""),
    wordlist_url: str = Form(""),
    rules_url: str = Form(""),
    rules_path: str = Form(""),
    budget_limit: float = Form(0.0),
    extra_args: str = Form(""),
    archive_url: str = Form(""),
):
    if job["active"]:
        raise HTTPException(400, "Job already running")

    # Validate: mask attack needs mask, dictionary needs archive
    if attack_mode == 3:
        if not mask:
            raise HTTPException(400, "Mask is required for mask attack (-a 3)")
        # Validate mask: only allow hashcat charset placeholders and literals
        if not _re.match(r'^[\?ludasHhb0-9a-zA-Z!@#$%^&*()\-_=+\[\]{};:,.<>/|~` ]+$', mask):
            raise HTTPException(400, "Invalid mask format — use hashcat charset placeholders (?l, ?u, ?d, ?a, ?s, ?H, ?h, ?b)")
    else:
        if not archive_path and not wordlist_url and not archive_url:
            raise HTTPException(400, "Archive path, wordlist URL, or archive URL required for dictionary attack")
        if archive_path and not os.path.isfile(archive_path):
            raise HTTPException(400, f"Archive not found: {archive_path}")

    # Validate wordlist URL if provided
    if wordlist_url:
        if not wordlist_url.startswith(("http://", "https://", "ftp://")):
            raise HTTPException(400, "Wordlist URL must start with http://, https://, or ftp://")
        if len(wordlist_url) > 2048:
            raise HTTPException(400, "Wordlist URL too long")

    # Validate rules URL if provided
    if rules_url:
        if not rules_url.startswith(("http://", "https://", "ftp://")):
            raise HTTPException(400, "Rules URL must start with http://, https://, or ftp://")
        if len(rules_url) > 2048:
            raise HTTPException(400, "Rules URL too long")

    # Validate archive URL if provided
    if archive_url:
        if not archive_url.startswith(("http://", "https://", "ftp://")):
            raise HTTPException(400, "Archive URL must start with http://, https://, or ftp://")
        if len(archive_url) > 2048:
            raise HTTPException(400, "Archive URL too long")

    # Validate rules_path if provided
    if rules_path and not os.path.isfile(rules_path):
        raise HTTPException(400, f"Rules file not found: {rules_path}")

    if not os.path.isfile(hashes_path):
        raise HTTPException(400, f"Hashes file not found: {hashes_path}")

    # Deduplicate hash lines
    try:
        with open(hashes_path) as f:
            original_lines = f.readlines()
        seen_hashes = set()
        unique_lines = []
        for line in original_lines:
            stripped = line.strip()
            if stripped and stripped not in seen_hashes:
                seen_hashes.add(stripped)
                unique_lines.append(stripped)
        dedup_removed = len(original_lines) - len(unique_lines)
        if dedup_removed > 0:
            with open(hashes_path, "w") as f:
                for ul in unique_lines:
                    f.write(ul + "\n")
            log_event(f"Hash dedup: removed {dedup_removed} duplicates, {len(unique_lines)} unique")
    except Exception as e:
        logger.warning(f"Hash dedup failed: {e}")

    # Parse instance IDs for existing mode
    existing_ids = []
    if mode == "existing" and instance_ids:
        existing_ids = [int(x.strip()) for x in instance_ids.split(",") if x.strip().isdigit()]
        if not existing_ids:
            raise HTTPException(400, "No valid instance IDs provided")
        num_machines = len(existing_ids)

    reset_job()  # increments _job_generation → old threads will self-terminate
    event_log.clear()

    # Destroy all existing Vast.ai instances to prevent orphans from previous jobs (verified)
    if mode == "rent":
        try:
            existing = vastai.get_instances()
            if existing:
                failed = 0
                for inst in existing:
                    if not _safe_destroy(inst["id"], verify=True):
                        failed += 1
                log_event(f"Cleaned up {len(existing)} orphan instances" + (f" ({failed} unverified!)" if failed else " ✓"))
        except Exception as e:
            logger.warning(f"Failed to clean up orphan instances: {e}")

    with open(hashes_path) as f:
        total = sum(1 for line in f if line.strip())

    with job_lock:
        job["active"] = True
        job["phase"] = "renting" if mode == "rent" else "booting"
        job["num_machines"] = num_machines
        job["total_hashes"] = total
        job["started_at"] = time.time()
        job["hashes_file"] = hashes_path
        job["archive_file"] = archive_path
        job["auto_destroy"] = auto_destroy
        job["attack_mode"] = attack_mode
        job["mask"] = mask
        job["wordlist_url"] = wordlist_url
        job["rules_url"] = rules_url
        job["rules_path"] = rules_path
        job["budget_limit"] = budget_limit
        job["extra_args"] = extra_args
        job["archive_url"] = archive_url
        # Auto-detect --username flag
        uf = _detect_username_flag(hashes_path)
        job["username_flag"] = uf

    # Log outside lock to avoid deadlock (log_event also acquires job_lock)
    if uf:
        log_event(f"Auto-detected email:hash format → adding {uf}")

    global _cost_last_ts
    _cost_last_ts = time.time()

    attack_desc = f"mask={mask}" if attack_mode == 3 else f"wordlist{'_url' if wordlist_url else ''}"
    if mode == "existing":
        log_event(f"Job started (existing): {total} hashes, {len(existing_ids)} machines, hmode={hashcat_mode}, attack={attack_desc}")
    else:
        log_event(f"Job started: {total} hashes, {num_machines}× {gpu_name}, hmode={hashcat_mode}, attack={attack_desc}")

    send_telegram(f"🚀 <b>HashCrack Job Started</b>\nHashes: {total}\nMachines: {num_machines}\nGPU: {gpu_name}\nMode: {hashcat_mode}")
    save_state()

    threading.Thread(
        target=run_job,
        args=(archive_path, hashes_path, num_machines, gpu_name, hashcat_mode),
        kwargs={
            "use_existing": existing_ids if mode == "existing" else None,
            "attack_mode": attack_mode,
            "mask": mask,
            "wordlist_url": wordlist_url,
            "rules_url": rules_url,
            "rules_path": rules_path,
            "archive_url": archive_url,
        },
        daemon=True,
        name="job-engine",
    ).start()

    return {"ok": True, "total_hashes": total}


@app.post("/api/stop")
def api_stop():
    """Stop job: kill hashcat, destroy all instances, close SSH."""
    errors = []
    # Snapshot pool and machine IDs under lock
    with pool_lock:
        pool_snapshot = list(_ssh_pool.items())
    with job_lock:
        machine_ids = [m["id"] for m in job.get("machines", []) if m.get("id")]
        job["active"] = False
    set_phase("stopped")
    # Kill hashcat processes via SSH (outside lock — SSH calls can be slow)
    for mid, ssh in pool_snapshot:
        try:
            ssh.run("pkill -f hashcat || true", timeout=10)
        except Exception as e:
            errors.append(f"{mid}: kill {e}")
    # Close SSH connections
    with pool_lock:
        for ssh in _ssh_pool.values():
            try:
                ssh.close()
            except Exception:
                pass
        _ssh_pool.clear()
    # Destroy ALL instances (pool + any not in pool but in machines list)
    all_mids = set(mid for mid, _ in pool_snapshot) | set(machine_ids)
    destroyed = 0
    for mid in all_mids:
        if mid:
            ok = _safe_destroy(mid, verify=True)
            if ok:
                destroyed += 1
                log_event(f"Destroyed instance {mid} ✓")
            else:
                errors.append(f"{mid}: destroy unverified")
                log_event(f"[{mid}] Destroy UNVERIFIED!", "error")
    log_event(f"Job stopped — destroyed {destroyed}/{len(all_mids)} instances")
    return {"ok": True, "errors": errors}


@app.post("/api/reset")
def api_reset():
    """Reset job state — clear dashboard, allow new job start."""
    if job.get("active") and job.get("phase") == "running":
        raise HTTPException(400, "Cannot reset while job is running. Stop it first.")
    reset_job()
    event_log.clear()
    log_event("Job state reset ✓")
    save_state(force=True)
    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# BACKGROUND JOB ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def run_job(archive_path, hashes_path, num_machines, gpu_name, hashcat_mode,
            use_existing=None, attack_mode=0, mask="", wordlist_url="", rules_url="", rules_path="",
            archive_url=""):
    try:
        _run_job(archive_path, hashes_path, num_machines, gpu_name, hashcat_mode,
                 use_existing=use_existing, attack_mode=attack_mode, mask=mask,
                 wordlist_url=wordlist_url, rules_url=rules_url, rules_path=rules_path,
                 archive_url=archive_url)
    except Exception as e:
        logger.error(traceback.format_exc())
        set_phase("error", str(e))


def _rent_replacement(gpu_name, existing_ids):
    try:
        offers = vastai.search_offers(gpu_name=gpu_name, num_gpus=1, max_dph=50.0, order="-dph_total", limit=20)
        for offer in offers:
            try:
                result = vastai.rent_instance(offer["id"], disk_gb=50, onstart_cmd=_make_onstart_cmd())
                new_id = result.get("new_contract")
                if new_id and new_id not in existing_ids:
                    log_event(f"Rented replacement instance {new_id}")
                    return new_id
            except:
                continue
    except Exception as e:
        log_event(f"Failed to find replacement: {e}", "error")
    return None


def _run_job(archive_path, hashes_path, num_machines, gpu_name, hashcat_mode,
             use_existing=None, attack_mode=0, mask="", wordlist_url="", rules_url="", rules_path="",
             archive_url=""):
    global _last_potfile_sync, _archive_seed_url
    _archive_seed_url = ""  # Reset seed for new job
    my_gen = _job_generation  # Snapshot generation at thread start

    def _stale():
        """Check if this thread's job has been superseded by a newer one."""
        return _job_generation != my_gen

    # ── 1. GET MACHINES ────────────────────────────────────────────────
    if use_existing:
        # Use already-rented instances
        set_phase("booting")
        log_event(f"Using {len(use_existing)} existing instances: {use_existing}")
        rented_ids = list(use_existing)
        for mid in rented_ids:
            try:
                inst = vastai.get_instance(mid)
                with job_lock:
                    job["machines"].append({
                        "id": mid,
                        "gpu": inst.get("gpu_name", "?"),
                        "num_gpus": inst.get("num_gpus", 1),
                        "ssh": f"{inst.get('ssh_host', '')}:{inst.get('ssh_port', 0)}",
                        "status": inst.get("actual_status", "?"),
                        "progress": 0, "speed": "",
                        "cracked": 0, "eta": "",
                        "dph": inst.get("dph_total", 0),
                        "log": "",
                    })
            except Exception as e:
                log_event(f"Failed to get instance {mid}: {e}", "error")
    else:
        # Rent new instances
        if _stale():
            log_event("Old job thread detected — exiting renting phase")
            return
        set_phase("renting")
        log_event(f"Searching for {num_machines}× {gpu_name} offers...")

        offers = vastai.search_offers(
            gpu_name=gpu_name, num_gpus=1, max_dph=50.0,
            order="-dph_total", limit=num_machines + 10,
        )

        if len(offers) < num_machines:
            set_phase("error", f"Only {len(offers)} offers for {gpu_name}, need {num_machines}")
            return

        log_event(f"Found {len(offers)} offers, renting {num_machines}...")
        rented_ids = []

        for i, offer in enumerate(offers[:num_machines]):
            try:
                result = vastai.rent_instance(offer["id"], disk_gb=50, onstart_cmd=_make_onstart_cmd())
                new_id = result.get("new_contract")
                if new_id:
                    rented_ids.append(new_id)
                    with job_lock:
                        job["machines"].append({
                            "id": new_id, "gpu": offer.get("gpu_name", gpu_name),
                            "num_gpus": offer.get("num_gpus", 1), "ssh": "",
                            "status": "rented", "progress": 0, "speed": "",
                            "cracked": 0, "eta": "", "dph": offer.get("dph_total", 0),
                            "log": "",
                        })
                    log_event(f"Rented #{i+1}: instance {new_id} ({offer.get('gpu_name')}) ${offer.get('dph_total', 0):.2f}/hr")
            except Exception as e:
                log_event(f"Rent failed for offer {offer['id']}: {e}", "error")

        if not rented_ids:
            set_phase("error", "Failed to rent any machines")
            return

        # Retry renting if we didn't get enough
        if len(rented_ids) < num_machines:
            deficit = num_machines - len(rented_ids)
            log_event(f"Only rented {len(rented_ids)}/{num_machines}, retrying {deficit} more...", "error")
            for _ in range(deficit * 2):
                if len(rented_ids) >= num_machines:
                    break
                repl = _rent_replacement(gpu_name, rented_ids)
                if repl:
                    rented_ids.append(repl)
                    with job_lock:
                        job["machines"].append({
                            "id": repl, "gpu": gpu_name,
                            "num_gpus": 1, "ssh": "",
                            "status": "rented", "progress": 0, "speed": "",
                            "cracked": 0, "eta": "", "dph": 0, "log": "",
                        })

        log_event(f"Rented {len(rented_ids)} machines, waiting for boot...")

    # ── 2. BOOT WAIT + STREAMING DEPLOY ──────────────────────────────
    # Instead of waiting for ALL machines then deploying, we deploy each
    # machine as soon as it gets SSH — no waiting for slow ones.
    # KEY OPTIMIZATION: batch API calls (1 instead of N) + parallel SSH probes.
    set_phase("booting")
    ssh_conns = {}
    stuck_timers = {}
    MAX_LOADING = 180
    BOOT_TIMEOUT = 360  # 6min max total boot wait
    EARLY_START_THRESHOLD = 0.6  # start work when 60% machines ready
    boot_start = time.time()
    _straggler_replaced = False  # one round of replacement allowed

    # Pre-read hashes for splitting
    with open(hashes_path) as f:
        all_lines = [l for l in f if l.strip()]

    # Track which machines have been deployed already
    _deployed_mids: set = set()
    _deploy_threads: list = []
    _ssh_probe_lock = threading.Lock()

    def _deploy_machine_streaming(idx, mid, ssh_conn, chunk_lines, hashcat_mode_val,
                                   attack_mode_val, mask_val, wordlist_url_val, rules_url_val):
        """Deploy & start hashcat on a single machine immediately."""
        try:
            if _stale():
                return
            # Write chunk for this machine
            CHUNKS_DIR.mkdir(exist_ok=True)
            chunk_path = CHUNKS_DIR / f"chunk_{idx}.txt"
            with open(chunk_path, "w") as cf:
                cf.writelines(chunk_lines)
            deploy_and_start(idx, mid, ssh_conn, archive_path, str(chunk_path), hashcat_mode_val,
                             attack_mode=attack_mode_val, mask=mask_val,
                             wordlist_url=wordlist_url_val, rules_url=rules_url_val,
                             rules_path=job.get("rules_path", ""),
                             extra_args=job.get("extra_args", ""))
        except Exception as e:
            log_event(f"[{mid}] Streaming deploy failed: {e}", "error")

    def _maybe_deploy_ready_machines():
        """Check for newly-ready machines and deploy them immediately."""
        nonlocal _deploy_threads
        if _stale():
            return
        ready_not_deployed = [mid for mid in ssh_conns if mid not in _deployed_mids]
        if not ready_not_deployed:
            return

        total_machines_expected = len(rented_ids)
        hashes_per_machine = max(1, len(all_lines) // total_machines_expected)

        for mid in ready_not_deployed:
            idx = rented_ids.index(mid) if mid in rented_ids else -1
            if idx < 0:
                continue
            _deployed_mids.add(mid)

            start = idx * hashes_per_machine
            end = start + hashes_per_machine if idx < total_machines_expected - 1 else len(all_lines)
            chunk = all_lines[start:end]
            if not chunk:
                # More machines than hashes — this machine has no work
                log_event(f"[{mid}] No hashes to assign (index {idx}/{total_machines_expected}) — destroying")
                _safe_destroy(mid, verify=True)
                update_machine(idx, status="done", log="no hashes — destroyed ✓")
                with _ssh_probe_lock:
                    ssh_conns.pop(mid, None)
                continue

            log_event(f"[{mid}] Ready → deploying immediately ({len(chunk)} hashes)")
            with pool_lock:
                _ssh_pool[mid] = ssh_conns[mid]

            t = threading.Thread(
                target=_deploy_machine_streaming,
                args=(idx, mid, ssh_conns[mid], chunk, hashcat_mode,
                      attack_mode, mask, wordlist_url, rules_url),
                daemon=True,
            )
            _deploy_threads.append(t)
            t.start()

    def _try_ssh_connect(mid, ssh_host, ssh_port, idx):
        """Try SSH connection to a single machine in a thread."""
        try:
            ssh = SSHManager(ssh_host, ssh_port)
            ssh.connect(retries=2, delay=8)
            with _ssh_probe_lock:
                ssh_conns[mid] = ssh
            update_machine(idx, status="ready")
            log_event(f"Instance {mid} SSH connected ✓")
            with _ssh_probe_lock:
                stuck_timers.pop(f"ssh_first_{mid}", None)
        except Exception as e:
            ssh_wait = time.time() - stuck_timers.get(f"ssh_first_{mid}", time.time())
            update_machine(idx, status="connecting", log=f"SSH retry ({int(ssh_wait)}s)...")

    for attempt in range(120):
        if _stale():
            log_event("Old job thread detected — exiting booting phase")
            return
        if time.time() - boot_start > BOOT_TIMEOUT:
            log_event(f"Boot timeout reached ({BOOT_TIMEOUT//60}min), proceeding with {len(ssh_conns)}/{len(rented_ids)} machines", "error")
            break

        time.sleep(5)

        if _stale():
            log_event("Old job thread detected — exiting booting phase")
            return

        # ── BATCH API CALL: fetch ALL instances at once (1 call vs N) ──
        try:
            all_instances_raw = vastai.get_instances()
            instances_by_id = {i.get("id"): i for i in all_instances_raw}
        except Exception as e:
            log_event(f"Failed to fetch instances batch: {e}", "error")
            instances_by_id = {}

        # ── Parallel SSH connection probes ──
        ssh_threads = []

        for idx, mid in enumerate(list(rented_ids)):
            if mid in ssh_conns:
                continue

            inst = instances_by_id.get(mid)
            if not inst:
                # Instance not in list — might be destroyed
                stuck_timers.setdefault(f"missing_{mid}", time.time())
                if time.time() - stuck_timers[f"missing_{mid}"] > 60:
                    log_event(f"Instance {mid} not found in API. Replacing...", "error")
                    repl = _rent_replacement(gpu_name, rented_ids)
                    if repl:
                        rented_ids[idx] = repl
                        update_machine(idx, id=repl, status="rented", ssh="", log="replacement")
                        stuck_timers.pop(f"missing_{mid}", None)
                        # Prevent replacement from triggering missing_ immediately
                        stuck_timers[f"missing_{repl}"] = time.time() + 120
                continue

            status = inst.get("actual_status", "?")
            status_msg = str(inst.get("status_msg", ""))
            update_machine(idx, status=status, log=status_msg[:80])

            # Handle destroyed/exited instances
            if status in ("destroyed", "exited", "offline", "inactive"):
                log_event(f"Instance {mid} is {status}. Replacing...", "error")
                repl = _rent_replacement(gpu_name, rented_ids)
                if repl:
                    rented_ids[idx] = repl
                    update_machine(idx, id=repl, status="rented", ssh="", log="replacement")
                    stuck_timers.pop(mid, None)
                    stuck_timers.pop(f"ssh_first_{mid}", None)
                continue

            if any(kw in status_msg.lower() for kw in ["error", "lookup", "timeout", "dial tcp"]):
                log_event(f"Instance {mid} docker error: {status_msg[:60]}. Replacing...", "error")
                _safe_destroy(mid, verify=True)
                repl = _rent_replacement(gpu_name, rented_ids)
                if repl:
                    rented_ids[idx] = repl
                    update_machine(idx, id=repl, status="rented", ssh="", log="")
                    stuck_timers.pop(mid, None)
                continue

            if status == "loading":
                stuck_timers.setdefault(mid, time.time())
                if time.time() - stuck_timers[mid] > MAX_LOADING:
                    log_event(f"Instance {mid} stuck loading {int(time.time()-stuck_timers[mid])}s. Replacing...", "error")
                    _safe_destroy(mid, verify=True)
                    repl = _rent_replacement(gpu_name, rented_ids)
                    if repl:
                        rented_ids[idx] = repl
                        update_machine(idx, id=repl, status="rented", ssh="", log="")
                        stuck_timers.pop(mid, None)
                    continue

            if status == "created":
                stuck_timers.setdefault(f"created_{mid}", time.time())
                if time.time() - stuck_timers[f"created_{mid}"] > 180:
                    log_event(f"Instance {mid} stuck in 'created' for 3min. Replacing...", "error")
                    _safe_destroy(mid, verify=True)
                    repl = _rent_replacement(gpu_name, rented_ids)
                    if repl:
                        rented_ids[idx] = repl
                        update_machine(idx, id=repl, status="rented", ssh="", log="")
                        stuck_timers.pop(f"created_{mid}", None)
                    continue

            if status == "running" and inst.get("ssh_host"):
                ssh_info = f"{inst['ssh_host']}:{inst['ssh_port']}"
                ssh_attempt_key = f"ssh_first_{mid}"
                if ssh_attempt_key not in stuck_timers:
                    stuck_timers[ssh_attempt_key] = time.time()
                    update_machine(idx, ssh=ssh_info, status="connecting")
                    log_event(f"Instance {mid} running, SSH → {ssh_info}")

                ssh_wait = time.time() - stuck_timers.get(ssh_attempt_key, time.time())
                if ssh_wait > 120:
                    # Gave up on SSH — destroy and replace
                    log_event(f"Instance {mid} SSH failed after {int(ssh_wait)}s. Replacing...", "error")
                    _safe_destroy(mid, verify=True)
                    repl = _rent_replacement(gpu_name, rented_ids)
                    if repl:
                        rented_ids[idx] = repl
                        update_machine(idx, id=repl, status="rented", ssh="", log="replacement")
                        stuck_timers.pop(ssh_attempt_key, None)
                    else:
                        log_event(f"No replacement found for {mid}", "error")
                else:
                    # Launch SSH probe in thread (parallel — all probes run at once)
                    t = threading.Thread(
                        target=_try_ssh_connect,
                        args=(mid, inst["ssh_host"], inst["ssh_port"], idx),
                        daemon=True,
                    )
                    ssh_threads.append(t)
                    t.start()

        # Wait for all SSH probe threads (max 25s — faster than serial 50×30s)
        for t in ssh_threads:
            t.join(timeout=25)

        # ── Deploy ready machines immediately ──
        _maybe_deploy_ready_machines()

        # If ALL machines connected, stop waiting
        if len(ssh_conns) == len(rented_ids):
            break

        # If enough machines ready and we've been waiting > 2min,
        # stop waiting for stragglers — replace them with new rentals
        ready_ratio = len(ssh_conns) / max(len(rented_ids), 1)
        waited = time.time() - boot_start
        if ready_ratio >= EARLY_START_THRESHOLD and waited > 120 and len(ssh_conns) >= 2:
            not_ready = [mid for mid in rented_ids if mid not in ssh_conns]
            if not not_ready:
                break

            if not _straggler_replaced:
                # ── First time: destroy stragglers and rent replacements ──
                log_event(f"⚡ {len(ssh_conns)}/{len(rented_ids)} ready — replacing {len(not_ready)} slow machines")
                any_replaced = False
                for straggler_mid in not_ready:
                    strag_idx = rented_ids.index(straggler_mid)
                    ok = _safe_destroy(straggler_mid, verify=True)
                    if ok:
                        log_event(f"[{straggler_mid}] Too slow to boot — destroyed (verified) ✓")
                    else:
                        log_event(f"[{straggler_mid}] Destroy unverified!", "error")
                    # Rent replacement
                    repl = _rent_replacement(gpu_name, rented_ids)
                    if repl:
                        rented_ids[strag_idx] = repl
                        update_machine(strag_idx, id=repl, status="rented", ssh="", log="replacement")
                        log_event(f"[{straggler_mid}] → Replaced with {repl}")
                        any_replaced = True
                        stuck_timers.pop(straggler_mid, None)
                        stuck_timers.pop(f"ssh_first_{straggler_mid}", None)
                        stuck_timers.pop(f"missing_{straggler_mid}", None)
                        stuck_timers.pop(f"created_{straggler_mid}", None)
                    else:
                        update_machine(strag_idx, status="skipped", log="no replacement available")
                        log_event(f"[{straggler_mid}] No replacement available", "error")
                _straggler_replaced = True
                if any_replaced:
                    # Give replacements 3 more minutes to boot
                    boot_start = time.time() - (BOOT_TIMEOUT - 180)
                    log_event(f"Waiting up to 3 min for replacement machines...")
                    continue  # keep looping for replacements
                else:
                    break  # no replacements found, proceed with what we have
            else:
                # ── Second time: replacements also failed, just skip and go ──
                log_event(f"⚡ Replacement machines also slow. Proceeding with {len(ssh_conns)} machines.")
                for straggler_mid in not_ready:
                    strag_idx = rented_ids.index(straggler_mid)
                    # Only destroy if this is not a freshly rented replacement
                    # (replacing it again would be wasteful)
                    ok = _safe_destroy(straggler_mid, verify=True)
                    update_machine(strag_idx, status="skipped",
                                   log="too slow → destroyed ✓" if ok else "destroy unverified!")
                    if ok:
                        log_event(f"[{straggler_mid}] Too slow to boot — destroyed (verified) ✓")
                break

    if not ssh_conns:
        set_phase("error", "No machines became ready")
        # Destroy ALL rented machines to stop billing
        for mid in rented_ids:
            _safe_destroy(mid, verify=True)
        return

    # Destroy any machines that never connected (to stop billing)
    orphan_mids = [mid for mid in rented_ids if mid not in ssh_conns]
    for mid in orphan_mids:
        # Check if already destroyed/skipped
        with job_lock:
            idx_check = rented_ids.index(mid) if mid in rented_ids else -1
            m_status = job["machines"][idx_check].get("status", "") if 0 <= idx_check < len(job["machines"]) else ""
        if m_status in ("skipped",):
            continue  # already handled by straggler logic
        ok = _safe_destroy(mid, verify=True)
        if ok:
            log_event(f"[{mid}] Never connected — destroyed ✓")
        else:
            log_event(f"[{mid}] Never connected — destroy UNVERIFIED!", "error")
        if 0 <= idx_check < len(job.get("machines", [])):
            update_machine(idx_check, status="skipped", log="never connected → destroyed")

    actual_count = len(ssh_conns)
    log_event(f"{actual_count}/{len(rented_ids)} machines ready")

    # ── 3. DEPLOY REMAINING (if not streamed yet) ─────────────────────
    set_phase("deploying")
    _maybe_deploy_ready_machines()  # deploy any that weren't deployed during boot loop

    # ── Finalize deploys & redistribute orphan hashes in background ──
    def _finalize_deploys():
        """Wait for deploy threads and redistribute orphan hashes."""
        if _stale():
            return
        deploy_deadline = time.time() + 300
        for t in _deploy_threads:
            remaining = max(1, deploy_deadline - time.time())
            t.join(timeout=remaining)
            if _stale():
                return
            if time.time() >= deploy_deadline:
                log_event("Deploy deadline reached", "error")
                break
        if _stale():
            return
        # Redistribute chunks from skipped machines
        # Take snapshot to avoid dict mutation during iteration
        _sc_snapshot = dict(ssh_conns)
        skipped_indices = [si for si, smid in enumerate(rented_ids) if smid not in _sc_snapshot]
        if skipped_indices and _sc_snapshot:
            total_me = len(rented_ids)
            hpm = max(1, len(all_lines) // total_me)
            orphan_lines = []
            for si in skipped_indices:
                s = si * hpm
                e = s + hpm if si < total_me - 1 else len(all_lines)
                orphan_lines.extend(all_lines[s:e])
            if orphan_lines:
                ready_list = [m for m in rented_ids if m in _sc_snapshot]
                opp = max(1, len(orphan_lines) // len(ready_list))
                log_event(f"Redistributing {len(orphan_lines)} hashes from {len(skipped_indices)} skipped machines")
                for ri, rmid in enumerate(ready_list):
                    os_ = ri * opp
                    oe_ = os_ + opp if ri < len(ready_list) - 1 else len(orphan_lines)
                    extra = orphan_lines[os_:oe_]
                    if not extra:
                        continue
                    try:
                        sc = _sc_snapshot.get(rmid)
                        if sc and sc.is_alive():
                            sc.run(f"cat >> {REMOTE_HASHES} << 'HASHEOF'\n{''.join(extra)}HASHEOF", timeout=30)
                            log_event(f"[{rmid}] +{len(extra)} orphan hashes appended")
                    except Exception as re:
                        log_event(f"[{rmid}] Failed to append orphan hashes: {re}", "error")
        log_event("All deploy threads finished")

    threading.Thread(target=_finalize_deploys, daemon=True, name="deploy-finalizer").start()

    # ── Wait for at least 1 machine to start hashcat (max 5 min) ──
    log_event("Waiting for first machine to start hashcat...")
    _first_deploy_wait = time.time()
    while time.time() - _first_deploy_wait < 300:
        if _stale():
            return
        with job_lock:
            running_count = sum(1 for m in job.get("machines", [])
                                if m.get("status") in ("running", "done", "error"))
        if running_count > 0:
            log_event(f"First machine started hashcat ({running_count} running)")
            break
        time.sleep(3)
    else:
        # Check one more time
        with job_lock:
            running_count = sum(1 for m in job.get("machines", [])
                                if m.get("status") in ("running", "done", "error"))
        if running_count == 0:
            set_phase("error", "No machines deployed successfully")
            return

    # ── 5. MONITOR (with potfile sync & GPU telemetry) ────────────────
    set_phase("running")
    log_event("Monitoring hashcat progress...")
    save_state()

    # Short grace period (machines already running hashcat)
    time.sleep(5)
    monitor_start = time.time()
    consecutive_done = 0  # require N consecutive "done" checks
    _last_potfile_sync = time.time()
    _replacing: set = set()  # mids currently being replaced (in background thread)
    _logged_errors: set = set()  # mids already logged as error
    _destroyed: set = set()  # machines already destroyed after completion
    _combo_done: set = set()  # machines that already switched to mask attack
    _gpu_warned: set = set()  # machines warned about high temp

    while job["active"] and job["phase"] == "running":
        if _stale():
            log_event("Old job thread detected — exiting monitoring phase")
            return
        if job.get("paused"):
            time.sleep(3)
            continue

        time.sleep(5)
        all_done = True
        total_cracked = 0
        all_cracked_lines = []
        total_speed_hs = 0.0
        gpu_telemetry = []

        # Dynamic ready_ids — picks up machines as they finish deploying
        ready_ids = [mid for mid in rented_ids if mid in ssh_conns]

        for mid in ready_ids:
            idx = rented_ids.index(mid)  # correct index into job["machines"]
            # Skip machines still deploying (hashcat not started yet)
            m_status = job["machines"][idx].get("status", "") if idx < len(job["machines"]) else ""
            if m_status in ("deploying", "rented", "booting", "connecting", "ready"):
                # Safety net: if machine stuck in "ready" > 120s into running phase, destroy it
                if m_status == "ready" and (time.time() - monitor_start) > 120:
                    log_event(f"[{mid}] Stuck in 'ready' — destroying (safety net)", "error")
                    _safe_destroy(mid, verify=True)
                    update_machine(idx, status="done", log="stuck ready — destroyed ✓")
                    _destroyed.add(mid)
                    ssh_conns.pop(mid, None)
                    continue
                all_done = False
                continue
            # Skip machines currently being replaced
            if mid in _replacing:
                all_done = False
                continue
            if mid in _destroyed:
                continue
            if mid not in ssh_conns:
                all_done = False
                continue
            ssh = ssh_conns[mid]
            try:
                # Check SSH connectivity, reconnect if needed
                if not ssh.is_alive():
                    log_event(f"[{mid}] SSH dropped, reconnecting...", "error")
                    if not ssh.reconnect(retries=3, delay=10):
                        update_machine(idx, status="ssh_lost")
                        log_event(f"[{mid}] SSH reconnect failed!", "error")
                        # Don't mark all_done - keep trying
                        all_done = False
                        continue

                # Use PID-based check with pgrep fallback
                # IMPORTANT: verify PID is actually hashcat via /proc/PID/comm
                # to avoid false positives from PID reuse after hashcat exits
                machine_pid = job["machines"][idx].get("pid", 0) if idx < len(job["machines"]) else 0
                if machine_pid:
                    _, proc_out, _ = ssh._safe_run(
                        f"kill -0 {machine_pid} 2>/dev/null && "
                        f"grep -q hashcat /proc/{machine_pid}/comm 2>/dev/null && "
                        f"echo RUNNING || echo DONE",
                        timeout=10,
                    )
                else:
                    proc_out = "DONE"
                is_running = "RUNNING" in proc_out
                # Fallback: if PID check says DONE, double-check with pgrep
                if not is_running:
                    _, pgrep_out, _ = ssh._safe_run("pgrep -f 'hashcat.*--session' >/dev/null && echo RUNNING || echo DONE", timeout=10)
                    is_running = "RUNNING" in pgrep_out

                hstat = ssh.get_hashcat_status() or {}

                # Override: if hashcat reported a terminal state, it's done
                # regardless of PID status (handles PID reuse edge cases)
                if hstat.get("hashcat_status") in ("Exhausted", "Cracked"):
                    is_running = False
                cracked = hstat.get("cracked", 0)
                out_count = ssh.remote_line_count(REMOTE_OUTFILE)
                cracked = max(cracked, out_count)
                total_cracked += cracked

                # Aggregate speed
                machine_speed = hstat.get("speed_hs", 0)
                total_speed_hs += machine_speed

                if out_count > 0:
                    content = ssh.read_remote_file(REMOTE_OUTFILE)
                    if content:
                        all_cracked_lines.extend(content.strip().splitlines())

                update_machine(idx,
                    status="running" if is_running else "done",
                    progress=hstat.get("progress", 100 if not is_running else 0),
                    speed=hstat.get("speed", ""),
                    speed_hs=machine_speed,
                    cracked=cracked,
                    eta=hstat.get("eta", "done" if not is_running else ""),
                    log=hstat.get("hashcat_status", ""),
                )

                # GPU telemetry
                try:
                    gpus = ssh.get_gpu_stats()
                    if gpus:
                        gpu_telemetry.append({"id": mid, "gpus": gpus})
                        # GPU temperature alert (warn once per machine)
                        for g in gpus:
                            if g.get("temp", 0) >= 90 and mid not in _gpu_warned:
                                _gpu_warned.add(mid)
                                log_event(f"[{mid}] ⚠ GPU #{g['index']} temp {g['temp']}°C — throttling likely!", "error")
                except Exception:
                    pass

                if is_running:
                    all_done = False

                # Auto-destroy completed machines to save money (verified)
                # But first: combo attack — if dict exhausted AND mask is provided, switch to mask
                if not is_running and hstat.get("hashcat_status", "") == "Exhausted" and mid not in _destroyed:
                    if attack_mode == 0 and mask and mid not in _combo_done:
                        _combo_done.add(mid)
                        log_event(f"[{mid}] Dict exhausted → switching to mask attack ({mask})...")
                        all_done = False
                        try:
                            if not ssh.is_alive():
                                ssh.reconnect(retries=3, delay=5)
                            _restart_hashcat_on_machine(ssh, idx, mid, 3, hashcat_mode, mask)
                            update_machine(idx, progress=0)
                        except Exception as combo_err:
                            log_event(f"[{mid}] Combo mask start failed: {combo_err}", "error")
                    else:
                        _destroyed.add(mid)
                        update_machine(idx, log="hashcat: Exhausted")
                        try:
                            ssh.close()
                        except Exception:
                            pass
                        if mid in ssh_conns:
                            del ssh_conns[mid]
                        with pool_lock:
                            _ssh_pool.pop(mid, None)
                        ok = _safe_destroy(mid, verify=True)
                        if ok:
                            log_event(f"[{mid}] Exhausted — destroyed (verified) ✓")
                        else:
                            log_event(f"[{mid}] Exhausted — destroy UNVERIFIED!", "error")
                elif not is_running and hstat.get("hashcat_status", "") == "Cracked" and mid not in _destroyed:
                    _destroyed.add(mid)
                    update_machine(idx, log="hashcat: Cracked")
                    try:
                        ssh.close()
                    except Exception:
                        pass
                    if mid in ssh_conns:
                        del ssh_conns[mid]
                    with pool_lock:
                        _ssh_pool.pop(mid, None)
                    ok = _safe_destroy(mid, verify=True)
                    if ok:
                        log_event(f"[{mid}] All cracked — destroyed (verified) ✓")
                    else:
                        log_event(f"[{mid}] Cracked — destroy UNVERIFIED!", "error")

                # If machine finished abnormally — replace only on Aborted/Quit
                # "Running" and "Paused" are normal statuses — stale log data, don't restart
                if not is_running and hstat.get("hashcat_status", "") not in ("Exhausted", "Cracked", "", "Running", "Paused"):
                    hc_status = hstat.get("hashcat_status", "?")
                    # Fetch hashcat errors for diagnostics
                    try:
                        hc_err = ssh.get_hashcat_errors()
                        # Extract last meaningful error lines
                        err_lines = [l for l in (hc_err or "").split("\n") if l.strip() and not l.startswith("Session")]
                        err_summary = "; ".join(err_lines[-3:])[:200] if err_lines else ""
                        update_machine(idx, log=f"hashcat {hc_status}: {err_summary}" if err_summary else f"hashcat {hc_status}")
                    except Exception:
                        pass
                    if hc_status in ("Aborted", "Quit") and mid not in _replacing:
                        _replacing.add(mid)
                        all_done = False
                        log_event(f"[{mid}] Hashcat {hc_status} — replacing machine...", "error")
                        threading.Thread(
                            target=_replace_aborted_machine,
                            args=(idx, mid, ssh_conns, ready_ids, archive_path,
                                  hashcat_mode),
                            kwargs={"attack_mode": attack_mode, "mask": mask,
                                    "wordlist_url": wordlist_url, "rules_url": rules_url,
                                    "rented_ids": rented_ids},
                            daemon=True,
                        ).start()
                    elif mid not in _logged_errors:
                        # Other status (e.g. Running) — just restart hashcat
                        _logged_errors.add(mid)
                        log_event(f"[{mid}] Hashcat ended ({hc_status}) — restarting...", "error")
                        if _restart_hashcat_on_machine(ssh, idx, mid, attack_mode, hashcat_mode, mask):
                            all_done = False
                        else:
                            all_done = False

            except Exception as e:
                # Try reconnecting SSH on error
                try:
                    if mid in ssh_conns and ssh_conns[mid]:
                        ssh_conns[mid].reconnect(retries=2, delay=5)
                except Exception:
                    pass
                update_machine(idx, status=f"err: {str(e)[:40]}")
                all_done = False  # Don't finish on error

        # Merge new cracked lines with previously known ones
        with job_lock:
            prev_lines = set(job.get("cracked_lines", []))
            merged_lines = prev_lines | set(all_cracked_lines)
            job["cracked_lines"] = list(merged_lines)
            job["total_cracked"] = max(total_cracked, len(merged_lines))
            job["total_speed_hs"] = total_speed_hs
            job["total_speed"] = SSHManager.format_speed(total_speed_hs)
            job["gpu_stats"] = gpu_telemetry

            # Accumulate cost in monitor loop (reliable, doesn't depend on frontend polling)
            burn = sum(m.get("dph", 0) for m in job["machines"]
                       if m.get("status") in ("running", "ready", "deploying", "loading", "rented"))
            now_ts = time.time()
            global _cost_last_ts
            if burn > 0 and _cost_last_ts > 0:
                dt = min(now_ts - _cost_last_ts, 30)
                job["total_cost"] += burn * dt / 3600
            _cost_last_ts = now_ts

        # Push live status to all WS clients every monitoring cycle
        try:
            _chart_history.append({
                "ts": int(time.time()),
                "speed": total_speed_hs,
                "cracked": job.get("total_cracked", 0),
            })
            ws_push = {
                "type": "full_status",
                "total_cracked": job.get("total_cracked", 0),
                "total_hashes": job.get("total_hashes", 0),
                "total_speed": job.get("total_speed", ""),
                "total_speed_hs": total_speed_hs,
                "total_cost": round(job.get("total_cost", 0), 3),
                "machines": job.get("machines", []),
                "gpu_stats": gpu_telemetry,
                "phase": job.get("phase", "running"),
                "chart_history": list(_chart_history)[-60:],
            }
            ws_broadcast_sync(ws_push)
        except Exception:
            pass

        # Persist cracked results to disk every cycle (crash-safe, atomic merge)
        _persist_cracked_to_disk(merged_lines)

        # ── Budget limit check ──
        with job_lock:
            budget = job.get("budget_limit", 0)
            current_cost = job.get("total_cost", 0)
            machine_ids_to_destroy = [m["id"] for m in job["machines"]] if (budget > 0 and current_cost >= budget) else []
        if machine_ids_to_destroy:
            log_event(f"💰 Budget limit reached: ${current_cost:.2f} >= ${budget:.2f}. Auto-stopping!", "error")
            send_telegram(f"💰 <b>Budget Limit Reached</b>\nSpent: ${current_cost:.2f} / ${budget:.2f}\nAuto-stopping job...")
            # Destroy instances with verification
            for mid_to_destroy in machine_ids_to_destroy:
                ok = _safe_destroy(mid_to_destroy, verify=True)
                if ok:
                    log_event(f"[{mid_to_destroy}] Budget-stop destroyed ✓")
                else:
                    log_event(f"[{mid_to_destroy}] Budget-stop destroy UNVERIFIED!", "error")
            with job_lock:
                job["phase"] = "stopped"
                job["active"] = False
            with pool_lock:
                for ssh in _ssh_pool.values():
                    try: ssh.close()
                    except: pass
                _ssh_pool.clear()
            save_state()
            return

        # ── Potfile cross-sync (non-blocking) ──
        # Every POTFILE_SYNC_INTERVAL, collect potfile from all machines
        # and distribute new entries to other machines so they skip cracked hashes
        now = time.time()
        if now - _last_potfile_sync > POTFILE_SYNC_INTERVAL and total_cracked > 0:
            _last_potfile_sync = now
            # Fire-and-forget: don't block monitor loop waiting for sync
            # Use snapshot of ssh_conns to avoid dict mutation during iteration
            _sync_snapshot = dict(ssh_conns)
            threading.Thread(
                target=_do_potfile_sync, args=(_sync_snapshot, list(ready_ids)), daemon=True
            ).start()

        # Send telegram on milestone cracks (every 5000)
        if total_cracked > job.get("prev_cracked", 0):
            prev = job.get("prev_cracked", 0)
            # Check if we crossed a 5000-milestone boundary
            prev_milestone = prev // 5000
            curr_milestone = total_cracked // 5000
            if curr_milestone > prev_milestone:
                send_telegram(f"🔓 <b>{total_cracked} cracked!</b>\nTotal: {total_cracked}/{job['total_hashes']}")

        if all_done:
            consecutive_done += 1
            # Require 2 consecutive "done" checks and at least 30s elapsed
            if consecutive_done >= 2 and (time.time() - monitor_start) > 30:
                log_event("All machines finished")
                break
        else:
            consecutive_done = 0

        # Periodic state save
        save_state()

    # ── 6. COLLECT ────────────────────────────────────────────────────
    if _stale():
        log_event("Old job thread detected — exiting before result collection")
        return
    # Skip collect if job was externally stopped/reset (instances may be destroyed)
    if not job.get("active") or job.get("phase") in ("stopped", "idle"):
        log_event("Job was stopped externally, skipping result collection")
    else:
        log_event("Collecting results...")
        results = []
        for i, mid in enumerate(ready_ids):
            if mid not in ssh_conns:
                continue
            try:
                local_out = str(CRACKED_DIR / f"cracked_{mid}.txt")
                if ssh_conns[mid].download_file(REMOTE_OUTFILE, local_out):
                    results.append(local_out)
                    log_event(f"Downloaded results from {mid}")
            except Exception as e:
                log_event(f"Download error from {mid}: {e}", "error")

        if results:
            # Merge with existing cracked_all.txt (preserves results from auto-destroyed machines)
            seen = set()
            merged = CRACKED_DIR / "cracked_all.txt"
            if merged.exists():
                with open(merged) as existing:
                    for line in existing:
                        if line.strip():
                            seen.add(line)
            for rf in results:
                with open(rf) as inp:
                    for line in inp:
                        if line.strip() and line not in seen:
                            seen.add(line)
            with open(merged, "w") as out:
                for line in seen:
                    out.write(line if line.endswith("\n") else line + "\n")
            with job_lock:
                job["total_cracked"] = len(seen)
                job["cracked_lines"] = [l.strip() for l in seen]
            log_event(f"Total cracked: {len(seen)}")

    elapsed = int(time.time() - job["started_at"]) if job["started_at"] else 0
    if _stale():
        log_event("Old job thread detected — exiting before marking done")
        return
    if job.get("phase") in ("stopped", "idle"):
        log_event("Previous job thread exiting (job was stopped)")
        return
    set_phase("done")
    log_event("Job complete ✓")

    # Save to job history
    save_job_history({
        "finished_at": datetime.now().isoformat(),
        "total_hashes": job["total_hashes"],
        "total_cracked": job["total_cracked"],
        "elapsed_sec": elapsed,
        "total_cost": round(job["total_cost"], 3),
        "num_machines": len(ready_ids),
        "gpu": gpu_name,
        "hashcat_mode": hashcat_mode,
        "attack_mode": attack_mode,
    })

    send_telegram(
        f"✅ <b>Job Complete</b>\n"
        f"Cracked: {job['total_cracked']}/{job['total_hashes']}\n"
        f"Time: {elapsed//3600}h {(elapsed%3600)//60}m\n"
        f"Cost: ${job['total_cost']:.2f}"
    )
    save_state()

    # Auto-destroy all rented instances to save money (verified)
    if job.get("auto_destroy", True):
        log_event("Auto-destroying all instances (with verification)...")
        # Destroy ALL rented_ids, not just ready_ids (covers replacements too)
        all_destroy_ids = set(rented_ids)
        for mid in all_destroy_ids:
            ok = _safe_destroy(mid, verify=True)
            if ok:
                log_event(f"Auto-destroyed {mid} ✓")
            else:
                log_event(f"[{mid}] Destroy UNVERIFIED — may still be billing!", "error")

    # Close SSH pool (only if we're still the current job thread)
    if not _stale():
        with pool_lock:
            for ssh in _ssh_pool.values():
                try:
                    ssh.close()
                except:
                    pass
            _ssh_pool.clear()

    # Clear retry queue
    with _retry_lock:
        _retry_queue.clear()


def _process_retry_queue():
    """Check retry queue for failed replacements and attempt to re-rent."""
    now = time.time()
    with _retry_lock:
        pending = [r for r in _retry_queue if r["next_retry"] <= now]
    if not pending:
        return
    for item in pending:
        if not job.get("active"):
            break
        idx = item["idx"]
        gpu_name = item["gpu_name"]
        chunk_path = item["chunk_path"]
        ssh_conns = item["ssh_conns"]
        ready_ids = item["ready_ids"]
        archive_path = item["archive_path"]
        hashcat_mode = item["hashcat_mode"]
        kwargs = item["kwargs"]
        attempts = item["attempts"]

        log_event(f"[retry] Attempt {attempts + 1}/{_MAX_RETRY_ATTEMPTS} for chunk {idx}...")
        new_mid = _rent_replacement(gpu_name, list(ssh_conns.keys()))
        if new_mid:
            with _retry_lock:
                if item in _retry_queue:
                    _retry_queue.remove(item)
            # Run deploy in separate thread
            def _retry_deploy(idx_=idx, new_mid_=new_mid, _ssh_conns=ssh_conns, _ready_ids=ready_ids):
                update_machine(idx_, id=new_mid_, status="rented", ssh="", log="retry",
                               progress=0, speed="", cracked=0, eta="", pid=0)
                log_event(f"[retry] Rented replacement {new_mid_} for slot {idx_}")
                ssh = None
                for wait_attempt in range(24):
                    time.sleep(5)
                    if not job.get("active"):
                        return
                    try:
                        inst = vastai.get_instance(new_mid_)
                        if not inst:
                            continue
                        status = inst.get("actual_status", "")
                        if status == "running" and inst.get("ssh_host"):
                            try:
                                ssh = SSHManager(inst["ssh_host"], inst["ssh_port"])
                                ssh.connect(retries=3, delay=10)
                                break
                            except Exception:
                                ssh = None
                    except Exception:
                        pass
                if not ssh:
                    log_event(f"[retry] SSH timeout for {new_mid_}", "error")
                    update_machine(idx_, status="retry_failed")
                    return
                _ssh_conns[new_mid_] = ssh
                _ready_ids.append(new_mid_)
                with pool_lock:
                    _ssh_pool[new_mid_] = ssh
                deploy_and_start(idx_, new_mid_, ssh, archive_path, chunk_path, hashcat_mode,
                                 extra_args=job.get("extra_args", ""), **kwargs)
            threading.Thread(target=_retry_deploy, daemon=True).start()
        else:
            if attempts + 1 >= _MAX_RETRY_ATTEMPTS:
                with _retry_lock:
                    if item in _retry_queue:
                        _retry_queue.remove(item)
                log_event(f"[retry] Gave up on slot {idx} after {_MAX_RETRY_ATTEMPTS} attempts", "error")
                update_machine(idx, status="no_replacement")
            else:
                item["attempts"] = attempts + 1
                item["next_retry"] = now + 180  # retry in 3 min
                log_event(f"[retry] No offers for slot {idx}, next retry in 3min")


def _do_potfile_sync(ssh_conns, ready_ids):
    """Cross-sync potfile entries between machines.
    Collect cracked entries from all machines, then distribute
    new entries to machines that don't have them yet.
    This prevents machines from working on already-cracked hashes.
    Uses pool_lock for thread-safe potfile_entries access.
    Each SSH operation is wrapped with individual timeout protection.
    """
    global _potfile_entries
    new_entries_by_machine = {}

    # 1. Collect potfile from each machine (with per-machine error handling)
    for mid in ready_ids:
        if mid not in ssh_conns:
            continue
        try:
            content = ssh_conns[mid].get_potfile_content()
            if content:
                machine_entries = set(content.strip().splitlines())
                with pool_lock:
                    new_for_pool = machine_entries - _potfile_entries
                    if new_for_pool:
                        new_entries_by_machine[mid] = new_for_pool
                        _potfile_entries.update(new_for_pool)
        except Exception as e:
            logger.warning(f"Potfile collect from {mid} failed: {e}")

    if not new_entries_by_machine:
        return  # nothing new

    # 2. For each machine, figure out what entries it's missing
    total_new = sum(len(v) for v in new_entries_by_machine.values())
    log_event(f"Potfile sync: {total_new} new entries cross-syncing to {len(ready_ids)} machines")

    for mid in ready_ids:
        if mid not in ssh_conns:
            continue
        # Collect entries this machine doesn't have (from other machines)
        missing = set()
        for source_mid, entries in new_entries_by_machine.items():
            if source_mid != mid:
                missing.update(entries)
        if missing:
            try:
                append_data = "\n".join(missing) + "\n"
                ssh_conns[mid].append_potfile(append_data)
            except Exception as e:
                logger.warning(f"Potfile sync to {mid} failed: {e}")


def _replace_aborted_machine(idx, old_mid, ssh_conns, ready_ids, archive_path,
                              hashcat_mode, attack_mode=0, mask="", wordlist_url="", rules_url="",
                              rented_ids=None):
    """Replace a failed machine: destroy old, rent new, deploy same chunk, start hashcat.
    
    Runs in a separate thread. Updates ssh_conns, ready_ids, and rented_ids in-place.
    """
    # Limit concurrent replacements to avoid API flooding
    with _replace_semaphore:
        _replace_aborted_machine_inner(idx, old_mid, ssh_conns, ready_ids, archive_path,
                                        hashcat_mode, attack_mode=attack_mode, mask=mask,
                                        wordlist_url=wordlist_url, rules_url=rules_url,
                                        rented_ids=rented_ids)


def _replace_aborted_machine_inner(idx, old_mid, ssh_conns, ready_ids, archive_path,
                                    hashcat_mode, attack_mode=0, mask="", wordlist_url="", rules_url="",
                                    rented_ids=None):
    """Inner implementation of machine replacement (runs under semaphore)."""
    chunk_path = str(CHUNKS_DIR / f"chunk_{idx}.txt")
    if not os.path.isfile(chunk_path):
        log_event(f"[{old_mid}] Cannot replace — chunk file chunk_{idx}.txt not found!", "error")
        return

    # Filter out already-cracked hashes from the chunk before sending to new machine
    try:
        cracked_keys = set()
        # Collect cracked hash:salt keys from memory
        with job_lock:
            for cl in job.get("cracked_lines", []):
                parts = cl.strip().rsplit(":", 1)  # hash:salt:pass → key = hash:salt
                if parts:
                    cracked_keys.add(parts[0])
        # Also from disk
        merged_path = CRACKED_DIR / "cracked_all.txt"
        if merged_path.exists():
            for cl in merged_path.read_text().splitlines():
                parts = cl.strip().rsplit(":", 1)
                if parts:
                    cracked_keys.add(parts[0])

        if cracked_keys:
            with open(chunk_path) as f:
                original_lines = [l.strip() for l in f if l.strip()]
            # Chunk format: email:hash:salt → key for comparison is hash:salt (after first ':')
            filtered = []
            for line in original_lines:
                line_parts = line.split(":", 1)
                if len(line_parts) == 2 and line_parts[1] in cracked_keys:
                    continue  # already cracked — skip
                filtered.append(line)
            removed = len(original_lines) - len(filtered)
            if removed > 0:
                # Write filtered chunk
                with open(chunk_path, "w") as f:
                    for fl in filtered:
                        f.write(fl + "\n")
                log_event(f"[{old_mid}] Filtered chunk: removed {removed} cracked, {len(filtered)} remaining")
    except Exception as e:
        logger.warning(f"Failed to filter chunk for {old_mid}: {e}")

    log_event(f"[{old_mid}] Replacing machine (destroying old, renting new)...")
    update_machine(idx, status="replacing", speed="", eta="")

    # 1. Close old SSH & destroy (verified)
    if old_mid in ssh_conns:
        try:
            ssh_conns[old_mid].close()
        except Exception:
            pass
        del ssh_conns[old_mid]
    if old_mid in ready_ids:
        ready_ids.remove(old_mid)

    ok = _safe_destroy(old_mid, verify=True)
    if ok:
        log_event(f"[{old_mid}] Destroyed (verified) ✓")
    else:
        log_event(f"[{old_mid}] Destroy UNVERIFIED!", "error")

    # 2. Rent replacement — try to find similar GPU
    gpu_name = "RTX 5090"  # default
    with job_lock:
        if idx < len(job["machines"]):
            gpu_name = job["machines"][idx].get("gpu", "RTX 5090").replace("RTX ", "RTX ")
    
    new_mid = _rent_replacement(gpu_name, list(ssh_conns.keys()))
    if not new_mid:
        log_event(f"[{old_mid}] No replacement available — queued for retry", "error")
        update_machine(idx, status="retry_queued")
        with _retry_lock:
            _retry_queue.append({
                "idx": idx, "old_mid": old_mid,
                "ssh_conns": ssh_conns, "ready_ids": ready_ids,
                "archive_path": archive_path, "hashcat_mode": hashcat_mode,
                "gpu_name": gpu_name, "chunk_path": chunk_path,
                "kwargs": {"attack_mode": attack_mode, "mask": mask,
                           "wordlist_url": wordlist_url, "rules_url": rules_url,
                           "rules_path": job.get("rules_path", "")},
                "attempts": 1, "next_retry": time.time() + 120,
            })
        return

    update_machine(idx, id=new_mid, status="rented", ssh="", log="replacement",
                   progress=0, speed="", cracked=0, eta="", pid=0)
    log_event(f"[{old_mid}] → Replacement: {new_mid}")

    # 3. Wait for SSH (up to 120s)
    ssh = None
    for wait_attempt in range(24):  # 24 * 5s = 120s
        time.sleep(5)
        if not job.get("active"):
            return
        try:
            inst = vastai.get_instance(new_mid)
            status = inst.get("actual_status", "")
            if status in ("destroyed", "exited", "offline"):
                log_event(f"[{new_mid}] Replacement died ({status}), giving up", "error")
                update_machine(idx, status=f"dead:{status}")
                return
            if status == "running" and inst.get("ssh_host"):
                ssh_host = inst["ssh_host"]
                ssh_port = inst["ssh_port"]
                update_machine(idx, ssh=f"{ssh_host}:{ssh_port}", status="connecting")
                try:
                    ssh = SSHManager(ssh_host, ssh_port)
                    ssh.connect(retries=3, delay=10)
                    log_event(f"[{new_mid}] SSH connected ✓")
                    break
                except Exception as ssh_err:
                    log_event(f"[{new_mid}] SSH attempt failed: {ssh_err}", "error")
                    ssh = None
            else:
                update_machine(idx, status=f"waiting:{status}")
        except Exception:
            pass

    if not ssh:
        log_event(f"[{new_mid}] SSH timeout — replacement failed", "error")
        update_machine(idx, status="ssh_timeout")
        return

    # 4. Deploy and start hashcat
    ssh_conns[new_mid] = ssh
    ready_ids.append(new_mid)
    # Also add to rented_ids so monitor loop picks it up
    # Ensure new_mid is trackable by monitor (inject into rented_ids)
    _rids = rented_ids if rented_ids is not None else ready_ids
    if new_mid not in _rids:
        if old_mid in _rids:
            _rids[_rids.index(old_mid)] = new_mid
        else:
            _rids.append(new_mid)
    with pool_lock:
        _ssh_pool[new_mid] = ssh

    deploy_and_start(idx, new_mid, ssh, archive_path, chunk_path, hashcat_mode,
                     attack_mode=attack_mode, mask=mask, wordlist_url=wordlist_url,
                     rules_url=rules_url, rules_path=job.get("rules_path", ""),
                     extra_args=job.get("extra_args", ""))


def deploy_and_start(idx, mid, ssh, archive_path, chunk_path, hashcat_mode,
                     attack_mode=0, mask="", wordlist_url="", rules_url="", rules_path="", extra_args=""):
    global _archive_seed_url
    MAX_DEPLOY_RETRIES = 4
    for deploy_attempt in range(1, MAX_DEPLOY_RETRIES + 1):
        try:
            update_machine(idx, status="deploying")
            log_event(f"[{mid}] Setting up (attempt {deploy_attempt})...")

            # Ensure SSH is alive before starting
            if not ssh.is_alive():
                log_event(f"[{mid}] SSH not alive, reconnecting...", "error")
                if not ssh.reconnect(retries=3, delay=10):
                    raise ConnectionError(f"Cannot establish SSH to {mid}")

            ssh.run(f"mkdir -p {REMOTE_WORK_DIR}", timeout=10)

            log_event(f"[{mid}] Installing hashcat...")
            if not ssh.install_hashcat():
                raise RuntimeError("hashcat installation failed")
            # Log installed version
            _, ver_out, _ = ssh.run("hashcat --version 2>/dev/null || /usr/local/bin/hashcat --version 2>/dev/null", timeout=10)
            log_event(f"[{mid}] Hashcat version: {ver_out.strip()}")

            wordlist = REMOTE_WORDLIST
            rules = REMOTE_RULES

            if attack_mode == 0:
                # Dictionary attack — need wordlist + rules
                if wordlist_url:
                    # Download wordlist directly on the remote machine
                    wl_name = wordlist_url.split('/')[-1][:40]
                    log_event(f"[{mid}] ⬇ Downloading wordlist: {wl_name}...")
                    update_machine(idx, log=f"Downloading {wl_name}...")
                    remote_wl = f"{REMOTE_WORK_DIR}/wordlist_dl.txt"
                    ok, wl_size = ssh.download_url(wordlist_url, remote_wl, timeout=1800)
                    if ok:
                        wl_mb = wl_size / 1024 / 1024
                        wordlist = remote_wl
                        log_event(f"[{mid}] ✅ Wordlist downloaded: {wl_name} ({wl_mb:.1f}MB)")
                        update_machine(idx, log=f"WL: {wl_name} ({wl_mb:.1f}MB) ✓")
                    else:
                        log_event(f"[{mid}] ❌ Wordlist download FAILED: {wl_name}", "error")
                        update_machine(idx, log=f"WL download failed!")

                # Download rules from URL if provided
                if rules_url:
                    rl_name = rules_url.split('/')[-1][:40]
                    log_event(f"[{mid}] ⬇ Downloading rules: {rl_name}...")
                    remote_rl = f"{REMOTE_WORK_DIR}/rules_dl.rule"
                    ok, rl_size = ssh.download_url(rules_url, remote_rl, timeout=600)
                    if ok:
                        rl_mb = rl_size / 1024 / 1024
                        rules = remote_rl
                        log_event(f"[{mid}] ✅ Rules downloaded: {rl_name} ({rl_mb:.1f}MB)")
                    else:
                        log_event(f"[{mid}] ❌ Rules download failed: {rl_name}", "error")
                elif rules_path and os.path.isfile(rules_path):
                    # Upload local rules file
                    rl_name = os.path.basename(rules_path)
                    log_event(f"[{mid}] ⬆ Uploading rules: {rl_name}...")
                    remote_rl = f"{REMOTE_WORK_DIR}/{rl_name}"
                    ssh.upload_file(rules_path, remote_rl)
                    rules = remote_rl
                    rl_kb = os.path.getsize(rules_path) / 1024
                    log_event(f"[{mid}] ✅ Rules uploaded: {rl_name} ({rl_kb:.1f}KB)")

                archive_url_val = job.get("archive_url", "") or ""
                has_local_archive = archive_path and os.path.isfile(archive_path)

                if has_local_archive or archive_url_val:
                    if has_local_archive:
                        archive_name = os.path.basename(archive_path)
                        sz = os.path.getsize(archive_path) // 1024 // 1024
                    else:
                        # No local file — derive name from URL
                        archive_name = archive_url_val.rstrip('/').split('/')[-1].split('?')[0] or "archive.zip"
                        sz = 0  # unknown size
                    remote_archive = f"{REMOTE_WORK_DIR}/{archive_name}"
                    got_archive = False

                    # ── Strategy 1: Direct URL download (fastest — user-provided URL)
                    if archive_url_val:
                        log_event(f"[{mid}] ⬇ Downloading archive from URL...")
                        update_machine(idx, log=f"Downloading archive from URL...")
                        rc, dl_out, dl_err = ssh.run(
                            f"wget -q --timeout=120 --tries=3 '{archive_url_val}' -O {remote_archive} 2>&1",
                            timeout=300)
                        if rc == 0:
                            # Get downloaded size
                            _, sz_out, _ = ssh.run(f"stat -c%s {remote_archive} 2>/dev/null", timeout=5)
                            dl_sz = int(sz_out.strip()) // 1024 // 1024 if sz_out.strip().isdigit() else sz
                            got_archive = True
                            log_event(f"[{mid}] ✅ Archive from URL ({dl_sz}MB) ⚡")
                            # Set up seed relay for machines that can't use URL directly
                            with _archive_seed_lock:
                                if not _archive_seed_url:
                                    try:
                                        ssh.run(f"cd {REMOTE_WORK_DIR} && nohup python3 -m http.server 19876 > /dev/null 2>&1 &",
                                                timeout=5)
                                        rc2, ip_out, _ = ssh.run(
                                            "curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || "
                                            "curl -s --connect-timeout 5 icanhazip.com 2>/dev/null",
                                            timeout=15)
                                        seed_ip = ip_out.strip().split('\n')[0].strip() if rc2 == 0 else ""
                                        if seed_ip and len(seed_ip) < 50:
                                            _archive_seed_url = f"http://{seed_ip}:19876/{archive_name}"
                                            log_event(f"[{mid}] 🌐 Seed relay started: {_archive_seed_url}")
                                    except Exception:
                                        pass
                        else:
                            log_event(f"[{mid}] ⚠ URL download failed (rc={rc}), trying other methods...")

                    # ── Strategy 2: Peer seed relay (fast — download from first deployed machine)
                    if not got_archive:
                        with _archive_seed_lock:
                            seed_url = _archive_seed_url
                        if seed_url:
                            log_event(f"[{mid}] ⬇ Downloading archive from peer seed...")
                            update_machine(idx, log=f"Downloading from peer...")
                            try:
                                rc, _, _ = ssh.run(
                                    f"wget -q --timeout=60 --tries=2 '{seed_url}' -O {remote_archive} 2>&1",
                                    timeout=120)
                                if rc == 0:
                                    # Verify file size if local file available
                                    _, sz_out, _ = ssh.run(f"stat -c%s {remote_archive} 2>/dev/null", timeout=5)
                                    remote_sz = int(sz_out.strip()) if sz_out.strip().isdigit() else 0
                                    if has_local_archive:
                                        local_sz = os.path.getsize(archive_path)
                                        if abs(remote_sz - local_sz) < 1024:
                                            got_archive = True
                                            log_event(f"[{mid}] ✅ Archive from peer ({remote_sz//1024//1024}MB) ⚡")
                                        else:
                                            log_event(f"[{mid}] ⚠ Peer size mismatch ({remote_sz} vs {local_sz}), fallback...")
                                            ssh.run(f"rm -f {remote_archive}", timeout=5)
                                    elif remote_sz > 0:
                                        got_archive = True
                                        log_event(f"[{mid}] ✅ Archive from peer ({remote_sz//1024//1024}MB) ⚡")
                                else:
                                    log_event(f"[{mid}] ⚠ Peer download failed (rc={rc}), fallback...")
                            except Exception as e:
                                log_event(f"[{mid}] ⚠ Peer download error: {e}, fallback...")

                    # ── Strategy 3: SFTP upload (fallback — only if local file exists)
                    if not got_archive and has_local_archive:
                        log_event(f"[{mid}] ⬆ Uploading archive ({sz}MB) via SFTP...")
                        update_machine(idx, log=f"Uploading archive ({sz}MB)...")
                        with _archive_upload_sem:
                            t0 = time.time()
                            ssh.upload_file(archive_path, remote_archive)
                            elapsed = time.time() - t0
                            speed = sz / elapsed if elapsed > 0 else 0
                            log_event(f"[{mid}] ✅ Archive uploaded ({sz}MB in {elapsed:.0f}s, {speed:.1f}MB/s)")

                        # First SFTP uploader becomes the seed for others
                        with _archive_seed_lock:
                            if not _archive_seed_url:
                                try:
                                    # Start HTTP server for other machines to download from
                                    ssh.run(f"cd {REMOTE_WORK_DIR} && nohup python3 -m http.server 19876 > /dev/null 2>&1 &",
                                            timeout=5)
                                    # Get machine's public IP
                                    rc, ip_out, _ = ssh.run(
                                        "curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || "
                                        "curl -s --connect-timeout 5 icanhazip.com 2>/dev/null",
                                        timeout=15)
                                    seed_ip = ip_out.strip().split('\n')[0].strip() if rc == 0 else ""
                                    if seed_ip and len(seed_ip) < 50:
                                        _archive_seed_url = f"http://{seed_ip}:19876/{archive_name}"
                                        log_event(f"[{mid}] 🌐 Seed relay started: {_archive_seed_url}")
                                    else:
                                        log_event(f"[{mid}] ⚠ Could not get public IP for seed relay")
                                except Exception as e:
                                    log_event(f"[{mid}] Seed setup failed (non-critical): {e}")

                    if not got_archive:
                        raise RuntimeError(f"Failed to get archive via any method (URL/peer/SFTP)")

                    # ── Extract archive
                    name = archive_name.lower()
                    log_event(f"[{mid}] Extracting...")
                    if name.endswith(".zip"):
                        ssh.run("which unzip || apt-get install -y -qq unzip", timeout=60)
                        ssh.run(f"cd {REMOTE_WORK_DIR} && unzip -o {remote_archive}", timeout=300)
                    elif name.endswith((".tar.gz", ".tgz")):
                        ssh.run(f"cd {REMOTE_WORK_DIR} && tar xzf {remote_archive}", timeout=300)
                    elif name.endswith(".7z"):
                        ssh.run("which 7z || apt-get install -y -qq p7zip-full", timeout=60)
                        ssh.run(f"cd {REMOTE_WORK_DIR} && 7z x -y {remote_archive}", timeout=300)
                    ssh.run(f"rm -f {remote_archive}", timeout=10)

                    _, wl_out, _ = ssh.run(f"find {REMOTE_WORK_DIR} -name '*.txt' -not -name 'hashes*' -not -name 'cracked*' -not -name 'wordlist_dl*' | head -1", timeout=10)
                    _, rl_out, _ = ssh.run(f"find {REMOTE_WORK_DIR} -name '*.rule' -o -name '*.rules' | head -1", timeout=10)
                    if wl_out.strip() and not wordlist_url:
                        wordlist = wl_out.strip()
                    if rl_out.strip() and not rules_url and not rules_path:
                        rules = rl_out.strip()

                log_event(f"[{mid}] WL: {os.path.basename(wordlist)}, Rules: {os.path.basename(rules)}")

            # Upload hash chunk
            ssh.upload_file(chunk_path, REMOTE_HASHES)
            devices = ssh.detect_gpus()
            log_event(f"[{mid}] GPUs: {devices}")

            # Build hashcat command based on attack mode
            uf_val = job.get("username_flag", "")
            if attack_mode == 3:
                # Mask attack
                cmd = HASHCAT_CMD_MASK_TEMPLATE.format(
                    mode=hashcat_mode, hashes=REMOTE_HASHES,
                    mask=mask, outfile=REMOTE_OUTFILE,
                    potfile=REMOTE_POTFILE,
                    username_flag=uf_val,
                    extra=extra_args or "",
                )
            else:
                # Dictionary attack
                cmd = HASHCAT_CMD_TEMPLATE.format(
                    mode=hashcat_mode, hashes=REMOTE_HASHES,
                    wordlist=wordlist, rules=rules,
                    outfile=REMOTE_OUTFILE, potfile=REMOTE_POTFILE,
                    username_flag=uf_val,
                    extra=extra_args or "",
                )

            ssh.run("pkill -9 hashcat 2>/dev/null", timeout=10)
            time.sleep(1)
            ssh.run(f"rm -f {REMOTE_POTFILE} {REMOTE_OUTFILE} {REMOTE_WORK_DIR}/hashcat_out.log", timeout=5)

            full_cmd = f"cd {REMOTE_WORK_DIR} && {cmd} >> hashcat_out.log 2>&1"
            log_event(f"[{mid}] CMD: {cmd[:200]}")
            pid = ssh.run_background(full_cmd)
            update_machine(idx, status="running", pid=pid)
            log_event(f"[{mid}] Hashcat started (PID {pid}) ✓")

            # Quick check: wait for GPU init (multi-GPU can take 30-60s)
            # Don't let a check failure cause a full retry — hashcat IS running
            time.sleep(10)
            try:
                # Reconnect SSH since run_background closed the channel
                if not ssh.is_alive():
                    ssh.reconnect(retries=3, delay=5)
                _, alive_out, _ = ssh.run(f"kill -0 {pid} 2>/dev/null && echo ALIVE || echo DEAD", timeout=15)
                if "DEAD" in alive_out:
                    # Double-check: maybe hashcat runs under a different PID
                    _, pgrep_out, _ = ssh.run("pgrep -f hashcat | head -1", timeout=10)
                    if pgrep_out.strip():
                        new_pid = int(pgrep_out.strip())
                        update_machine(idx, pid=new_pid)
                        log_event(f"[{mid}] Hashcat running under PID {new_pid}")
                    else:
                        err_log = ssh.get_hashcat_errors()
                        log_event(f"[{mid}] WARNING: Hashcat may have exited!", "error")
                        if err_log:
                            log_event(f"[{mid}] Log: {err_log[-300:]}", "error")
                        update_machine(idx, status="error", log=err_log[-200:] if err_log else "exited")
            except Exception as check_err:
                # Alive check failed but hashcat WAS started — don't retry deploy
                log_event(f"[{mid}] Post-launch check failed ({check_err}), but hashcat was started", "error")
            return  # success — exit retry loop

        except Exception as e:
            err_msg = str(e) or type(e).__name__
            log_event(f"[{mid}] Deploy attempt {deploy_attempt} failed: {err_msg}", "error")
            if deploy_attempt < MAX_DEPLOY_RETRIES:
                log_event(f"[{mid}] Retrying deploy in 10s...", "error")
                time.sleep(10)
                # Try reconnecting SSH before retry
                try:
                    ssh.reconnect(retries=3, delay=10)
                except Exception:
                    pass
            else:
                update_machine(idx, status=f"err: {str(e)[:50]}")
                log_event(f"[{mid}] Deploy failed after {MAX_DEPLOY_RETRIES} attempts: {e}", "error")


# ══════════════════════════════════════════════════════════════════════════════
# API — FILE UPLOAD, EXPORT, HEALTH
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/upload")
async def api_upload(file: UploadFile = FastFile(...)):
    """Upload a file (hashes, archive) via browser drag-and-drop."""
    if not file.filename:
        raise HTTPException(400, "No filename")
    # Sanitize filename
    safe_name = _re.sub(r'[^\w.\-]', '_', file.filename)
    dest = UPLOAD_DIR / safe_name
    try:
        with open(dest, "wb") as f:
            while chunk := await file.read(1024 * 1024):
                f.write(chunk)
        size = dest.stat().st_size
        # Determine file type
        suffixes = "".join(Path(safe_name).suffixes).lower()
        exts_archive = {".zip", ".tar.gz", ".tgz", ".7z"}
        exts_rules = {".rule", ".rules"}
        if any(suffixes.endswith(e) for e in exts_archive):
            file_type = "archive"
        elif any(suffixes.endswith(e) for e in exts_rules):
            file_type = "rules"
        else:
            file_type = "hashes"
        log_event(f"File uploaded: {safe_name} ({size // 1024}KB) [{file_type}]")
        return {"ok": True, "path": str(dest), "name": safe_name, "size": size, "type": file_type}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get("/api/uncracked")
def api_uncracked():
    """Export hashes that haven't been cracked yet."""
    with job_lock:
        hashes_file = job.get("hashes_file", "")
        cracked_lines = list(job.get("cracked_lines", []))

    # If job was reset, try to find the hashes file from workspace
    if not hashes_file or not os.path.isfile(hashes_file):
        hashes_file = _last_hashes_file
    if not hashes_file or not os.path.isfile(hashes_file):
        # Search for largest txt file with ':' separated data
        for candidate in sorted(UPLOAD_DIR.glob("*.txt"), key=lambda p: p.stat().st_size, reverse=True):
            if candidate.stat().st_size > 10000 and candidate.name not in ("requirements.txt",):
                try:
                    first_line = candidate.open().readline().strip()
                    if ":" in first_line and len(first_line) > 50:
                        hashes_file = str(candidate)
                        break
                except Exception:
                    pass
    if not hashes_file or not os.path.isfile(hashes_file):
        raise HTTPException(404, "No hashes file found — upload hashes first")

    # Build map: hash:salt → full_line (email:hash:salt)
    all_hashes = {}  # hash:salt → original line
    with open(hashes_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Format: email:hash:salt → key is hash:salt
            parts = line.split(":", 1)
            if len(parts) == 2:
                all_hashes[parts[1]] = line  # key=hash:salt, val=email:hash:salt
            else:
                all_hashes[line] = line

    # Build set of cracked hash:salt keys
    cracked_hashes = set()
    for line in cracked_lines:
        # Format: hash:salt:pass → key is hash:salt
        parts = line.strip().rsplit(":", 1)
        if parts:
            cracked_hashes.add(parts[0])

    # Also check merged cracked file
    merged = CRACKED_DIR / "cracked_all.txt"
    if merged.exists():
        for line in merged.read_text().splitlines():
            parts = line.strip().rsplit(":", 1)
            if parts:
                cracked_hashes.add(parts[0])

    uncracked = [orig_line for key, orig_line in all_hashes.items() if key not in cracked_hashes]
    content = "\n".join(uncracked) + "\n"

    return StreamingResponse(
        iter([content]),
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=uncracked_{len(uncracked)}.txt"}
    )


@app.get("/api/health")
def api_health():
    """Health check endpoint for monitoring."""
    with job_lock:
        phase = job["phase"]
        active = job["active"]
    return {
        "status": "ok",
        "phase": phase,
        "active": active,
        "uptime": int(time.time()),
    }


@app.get("/api/logs/download")
def api_logs_download():
    """Export all logs as a text file."""
    with job_lock:
        entries = list(event_log)
    lines = [f"[{e['time']}] [{e['level']}] {e['msg']}" for e in entries]
    content = "\n".join(lines) + "\n"
    return StreamingResponse(
        iter([content]),
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=hashcrack_logs.txt"}
    )


app.mount("/static", StaticFiles(directory="static"), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
