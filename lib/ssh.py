"""SSH manager — upload files, run commands, download results."""

from __future__ import annotations

import io
import logging
import os
import re
import subprocess
import time
import socket
from typing import Optional

import paramiko

from lib.config import REMOTE_WORK_DIR, REMOTE_POTFILE

logger = logging.getLogger("hashcrack")


class SSHManager:
    """Manages SSH connection to a single GPU instance."""

    def __init__(self, host: str, port: int, user: str = "root", connect_timeout: int = 60):
        self.host = host
        self.port = port
        self.user = user
        self.connect_timeout = connect_timeout
        self._client: Optional[paramiko.SSHClient] = None

    @property
    def label(self) -> str:
        return f"{self.host}:{self.port}"

    def connect(self, retries: int = 5, delay: int = 15) -> None:
        """Establish SSH connection with retries for instances that are still booting."""
        if self._client:
            try:
                self._client.exec_command("echo ok", timeout=5)
                return  # already connected
            except Exception:
                self.close()

        last_err = None
        for attempt in range(1, retries + 1):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.user,
                    look_for_keys=True,
                    allow_agent=True,
                    timeout=self.connect_timeout,
                    banner_timeout=30,
                )
                # Enable TCP keepalive to detect dead connections early
                transport = client.get_transport()
                if transport:
                    transport.set_keepalive(30)  # send keepalive every 30s
                self._client = client
                return
            except Exception as e:
                last_err = e
                if attempt < retries:
                    time.sleep(delay)
        raise last_err  # type: ignore[misc]

    def close(self) -> None:
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def is_alive(self) -> bool:
        """Check if connection is alive."""
        if not self._client:
            return False
        try:
            transport = self._client.get_transport()
            if transport and transport.is_active():
                transport.send_ignore()
                return True
        except Exception:
            pass
        return False

    def reconnect(self, retries: int = 3, delay: int = 10) -> bool:
        """Try to reconnect. Returns True on success."""
        self.close()
        try:
            self.connect(retries=retries, delay=delay)
            return True
        except Exception:
            return False

    def _safe_run(self, cmd: str, timeout: int = 30) -> tuple[int, str, str]:
        """Run command with auto-reconnect on failure."""
        try:
            return self.run(cmd, timeout=timeout)
        except Exception:
            if self.reconnect(retries=2, delay=5):
                return self.run(cmd, timeout=timeout)
            raise

    def run(self, cmd: str, timeout: int = 30) -> tuple[int, str, str]:
        """Run command, return (exit_code, stdout, stderr)."""
        self.connect()
        _, stdout_ch, stderr_ch = self._client.exec_command(cmd, timeout=timeout)
        exit_code = stdout_ch.channel.recv_exit_status()
        stdout = stdout_ch.read().decode(errors="replace")
        stderr = stderr_ch.read().decode(errors="replace")
        return exit_code, stdout, stderr

    def run_background(self, cmd: str) -> int:
        """Run command in background via nohup, return PID.
        
        Key: redirect nohup's stdin/stdout/stderr to /dev/null so it doesn't
        inherit the SSH channel's FDs. Without this, paramiko's channel stays
        open until hashcat finishes, causing TimeoutError on read().
        """
        self.connect()
        pid_file = f"{REMOTE_WORK_DIR}/.bg_pid"
        # Escape single quotes in command for bash -c
        escaped = cmd.replace(chr(39), chr(39) + chr(92) + chr(39) + chr(39))
        # Critical: </dev/null >/dev/null 2>&1 detaches bg process from channel FDs
        bg_cmd = (
            f"nohup bash -c '{escaped}' </dev/null >/dev/null 2>&1 & "
            f"echo $! > {pid_file} && cat {pid_file}"
        )
        
        # Use channel-level read with short timeout instead of stdout.read()
        # which blocks until EOF (never comes with inherited FDs)
        transport = self._client.get_transport()
        channel = transport.open_session()
        channel.settimeout(15)
        channel.exec_command(bg_cmd)
        
        # Read PID output — should arrive within 1-2 seconds
        output = b""
        deadline = time.time() + 10
        try:
            while time.time() < deadline:
                chunk = channel.recv(4096)
                if not chunk:
                    break  # EOF
                output += chunk
                # PID is a number followed by newline — once we have it, done
                decoded = output.decode(errors="replace").strip()
                if decoded and decoded.split()[-1].isdigit():
                    break
        except socket.timeout:
            pass  # Fine — we might already have the PID
        
        channel.close()
        
        raw = output.decode(errors="replace").strip()
        pid_str = raw.split('\n')[-1].strip() if raw else ""
        try:
            pid = int(pid_str)
            if pid > 0:
                return pid
        except ValueError:
            pass
        
        # Fallback: read PID from file
        time.sleep(1)
        _, pidfile_out, _ = self._safe_run(f"cat {pid_file} 2>/dev/null", timeout=5)
        try:
            return int(pidfile_out.strip())
        except ValueError:
            pass
        
        # Last resort: find hashcat PID via pgrep
        _, pgrep_out, _ = self._safe_run("pgrep -f hashcat | head -1", timeout=5)
        try:
            return int(pgrep_out.strip())
        except ValueError:
            return 0

    def is_process_running(self, pid: int) -> bool:
        """Check if process with given PID is still running."""
        _, out, _ = self._safe_run(f"kill -0 {pid} 2>/dev/null && echo ALIVE || echo DEAD", timeout=10)
        return "ALIVE" in out

    def upload_file(self, local_path: str, remote_path: str, progress_callback=None) -> None:
        """Upload a file using the most reliable method available.
        Strategy: SCP subprocess → cat-pipe via SSH exec → SFTP (last resort).
        """
        file_size = os.path.getsize(local_path)
        size_mb = file_size / (1024 * 1024)

        # For large files (>5MB), prefer SCP subprocess — much more reliable through proxies
        if size_mb > 5:
            try:
                self._upload_scp(local_path, remote_path)
                logger.info(f"Uploaded {size_mb:.0f}MB via SCP ✓")
                return
            except Exception as e:
                logger.warning(f"SCP failed ({e}), trying cat-pipe...")

            try:
                self._upload_cat_pipe(local_path, remote_path)
                logger.info(f"Uploaded {size_mb:.0f}MB via cat-pipe ✓")
                return
            except Exception as e:
                logger.warning(f"cat-pipe failed ({e}), trying SFTP...")

        # Small files or last resort: SFTP
        self._upload_sftp(local_path, remote_path, progress_callback)
        logger.info(f"Uploaded {size_mb:.1f}MB via SFTP ✓")

    def _find_ssh_key(self) -> str:
        """Find the SSH private key path."""
        for name in ("id_ed25519", "id_rsa", "id_ecdsa"):
            path = os.path.expanduser(f"~/.ssh/{name}")
            if os.path.isfile(path):
                return path
        return ""

    def _upload_scp(self, local_path: str, remote_path: str) -> None:
        """Upload via SCP subprocess — reliable for large files through SSH proxies."""
        key_path = self._find_ssh_key()
        cmd = [
            "scp",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", f"ConnectTimeout={self.connect_timeout}",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=6",
        ]
        if key_path:
            cmd.extend(["-i", key_path])
        cmd.extend([
            "-P", str(self.port),
            local_path,
            f"{self.user}@{self.host}:{remote_path}",
        ])
        result = subprocess.run(cmd, timeout=600, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"SCP exit {result.returncode}: {result.stderr[:200]}")

    def _upload_cat_pipe(self, local_path: str, remote_path: str) -> None:
        """Upload by piping file data through SSH exec channel with cat."""
        self.connect()
        # Ensure directory exists
        remote_dir = os.path.dirname(remote_path)
        if remote_dir:
            self.run(f"mkdir -p {remote_dir}", timeout=10)

        transport = self._client.get_transport()
        channel = transport.open_session()
        channel.settimeout(600)  # 10 min timeout
        channel.exec_command(f"cat > {remote_path}")

        # Send file data in chunks
        chunk_size = 65536  # 64KB chunks
        sent = 0
        file_size = os.path.getsize(local_path)
        with open(local_path, "rb") as f:
            while True:
                data = f.read(chunk_size)
                if not data:
                    break
                channel.sendall(data)
                sent += len(data)

        channel.shutdown_write()
        # Wait for command to finish
        exit_status = channel.recv_exit_status()
        channel.close()

        if exit_status != 0:
            raise RuntimeError(f"cat-pipe exited with {exit_status}")

        # Verify file size on remote
        _, out, _ = self.run(f"wc -c < {remote_path}", timeout=10)
        remote_size = int(out.strip()) if out.strip().isdigit() else 0
        if remote_size != file_size:
            raise RuntimeError(f"Size mismatch: local={file_size}, remote={remote_size}")

    def _upload_sftp(self, local_path: str, remote_path: str, progress_callback=None) -> None:
        """Upload via SFTP — fallback for small files."""
        self.connect()
        sftp = self._client.open_sftp()
        try:
            sftp.get_channel().settimeout(300)
            remote_dir = os.path.dirname(remote_path)
            self._mkdir_p(sftp, remote_dir)
            sftp.put(local_path, remote_path, callback=progress_callback)
        finally:
            sftp.close()

    def upload_string(self, content: str, remote_path: str) -> None:
        """Upload string content directly to a remote file."""
        self.connect()
        sftp = self._client.open_sftp()
        try:
            remote_dir = os.path.dirname(remote_path)
            self._mkdir_p(sftp, remote_dir)
            with sftp.file(remote_path, 'w') as f:
                f.write(content)
        finally:
            sftp.close()

    def download_file(self, remote_path: str, local_path: str) -> bool:
        """Download a file via SFTP. Returns True on success."""
        self.connect()
        sftp = self._client.open_sftp()
        try:
            sftp.stat(remote_path)  # check exists
            os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
            sftp.get(remote_path, local_path)
            return True
        except FileNotFoundError:
            return False
        finally:
            sftp.close()

    def read_remote_file(self, remote_path: str, tail_lines: int = 0) -> str:
        """Read remote file content. If tail_lines > 0, only last N lines."""
        if tail_lines > 0:
            _, out, _ = self._safe_run(f"tail -n {tail_lines} {remote_path} 2>/dev/null", timeout=10)
            return out
        _, out, _ = self._safe_run(f"cat {remote_path} 2>/dev/null", timeout=30)
        return out

    def remote_file_exists(self, remote_path: str) -> bool:
        """Check if a remote file exists."""
        _, out, _ = self._safe_run(f"test -f {remote_path} && echo YES || echo NO", timeout=10)
        return "YES" in out

    def remote_line_count(self, remote_path: str) -> int:
        """Count lines in remote file."""
        _, out, _ = self._safe_run(f"wc -l < {remote_path} 2>/dev/null", timeout=30)
        try:
            return int(out.strip())
        except ValueError:
            return 0

    def detect_gpus(self) -> str:
        """Detect available GPUs via nvidia-smi, return comma-separated 1-indexed IDs."""
        _, out, _ = self.run("nvidia-smi -L 2>/dev/null | wc -l", timeout=15)
        try:
            count = int(out.strip())
            if count > 0:
                return ",".join(str(i) for i in range(1, count + 1))
        except ValueError:
            pass
        return "1"

    def get_gpu_stats(self) -> list[dict]:
        """Get GPU temperature, utilization, memory usage from nvidia-smi."""
        _, out, _ = self._safe_run(
            "nvidia-smi --query-gpu=index,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw "
            "--format=csv,noheader,nounits 2>/dev/null",
            timeout=10,
        )
        gpus = []
        for line in out.strip().split('\n'):
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 5:
                try:
                    gpus.append({
                        "index": int(parts[0]),
                        "temp": int(parts[1]) if parts[1] not in ('[Not Supported]', 'N/A') else 0,
                        "util": int(parts[2]) if parts[2] not in ('[Not Supported]', 'N/A') else 0,
                        "mem_used": int(float(parts[3])) if parts[3] not in ('[Not Supported]', 'N/A') else 0,
                        "mem_total": int(float(parts[4])) if parts[4] not in ('[Not Supported]', 'N/A') else 0,
                        "power": float(parts[5]) if len(parts) > 5 and parts[5] not in ('[Not Supported]', 'N/A') else 0,
                    })
                except (ValueError, IndexError):
                    pass
        return gpus

    def install_hashcat(self) -> bool:
        """Install hashcat and OpenCL support for NVIDIA GPUs.
        
        If the onstart_cmd already pre-installed hashcat (marker /root/.hashcat_ready),
        skip the slow apt-get install entirely.
        """
        # Check if onstart already installed everything
        code, _, _ = self.run("test -f /root/.hashcat_ready", timeout=5)
        if code == 0:
            # Verify hashcat is actually there
            code2, out2, _ = self.run("which hashcat", timeout=5)
            if code2 == 0 and out2.strip():
                return True
            # Marker exists but hashcat not ready yet — wait for onstart to finish
            for _ in range(12):  # wait up to 60s
                import time; time.sleep(5)
                code3, out3, _ = self.run("which hashcat", timeout=5)
                if code3 == 0 and out3.strip():
                    return True
            # Fall through to manual install

        # Install OpenCL ICD loader + NVIDIA OpenCL support
        self.run(
            "apt-get update -qq && "
            "apt-get install -y -qq ocl-icd-libopencl1 2>&1 | tail -3",
            timeout=60,
        )
        # Create NVIDIA OpenCL ICD if missing
        self.run(
            "mkdir -p /etc/OpenCL/vendors && "
            "echo libnvidia-opencl.so.1 > /etc/OpenCL/vendors/nvidia.icd",
            timeout=10,
        )
        # Install hashcat
        code, out, _ = self.run("which hashcat", timeout=10)
        if code == 0 and out.strip():
            return True
        code, _, _ = self.run(
            "apt-get install -y -qq hashcat 2>&1 | tail -3",
            timeout=120,
        )
        return code == 0

    def get_hashcat_status(self) -> Optional[dict]:
        """Parse hashcat status from the running process output.
        
        hashcat status blocks can be 70-90+ lines on multi-GPU systems
        (16 GPUs = 16 Speed + 16 Candidates + 16 Hardware lines + headers).
        We extract the last complete status block by finding the last 'Session'
        marker and reading from there.
        """
        # Get last status block: find last 'Session' line number, read from there
        _, out, _ = self._safe_run(
            "awk '/^Session/{start=NR} END{if(start) print start}' /root/hashcrack/hashcat_out.log 2>/dev/null",
            timeout=10,
        )
        start_line = out.strip()
        if start_line and start_line.isdigit():
            _, out, _ = self._safe_run(
                f"sed -n '{start_line},$p' /root/hashcrack/hashcat_out.log 2>/dev/null",
                timeout=10,
            )
        else:
            # Fallback: grab a large chunk from the end
            _, out, _ = self._safe_run(
                "tail -120 /root/hashcrack/hashcat_out.log 2>/dev/null",
                timeout=10,
            )
        if not out:
            return None
        return self._parse_status(out)

    def get_hashcat_errors(self) -> str:
        """Get last 50 lines of hashcat log for error display."""
        _, out, _ = self._safe_run(
            f"tail -50 {REMOTE_WORK_DIR}/hashcat_out.log 2>/dev/null",
            timeout=10,
        )
        return out.strip()

    def append_potfile(self, entries: str) -> None:
        """Append cracked entries to the potfile via SFTP (no shell injection risk)."""
        if not entries.strip():
            return
        self.connect()
        sftp = self._client.open_sftp()
        try:
            # Read existing content
            existing = ""
            try:
                with sftp.file(REMOTE_POTFILE, 'r') as f:
                    existing = f.read().decode(errors='replace')
            except FileNotFoundError:
                pass
            # Append new entries
            with sftp.file(REMOTE_POTFILE, 'w') as f:
                if existing and not existing.endswith('\n'):
                    existing += '\n'
                f.write((existing + entries).encode())
        finally:
            sftp.close()

    def get_potfile_content(self) -> str:
        """Read current potfile content."""
        _, out, _ = self._safe_run(f"cat {REMOTE_POTFILE} 2>/dev/null", timeout=10)
        return out.strip()

    def pause_hashcat(self) -> bool:
        """Pause hashcat by sending checkpoint signal."""
        code, _, _ = self._safe_run(f"pkill -USR1 hashcat 2>/dev/null", timeout=10)
        return code == 0

    def resume_hashcat(self) -> bool:
        """Resume hashcat from checkpoint."""
        _, out, _ = self._safe_run(f"cd {REMOTE_WORK_DIR} && hashcat --session=hcjob --restore >> hashcat_out.log 2>&1 & echo $!", timeout=10)
        try:
            pid = int(out.strip().split('\n')[-1])
            return pid > 0
        except ValueError:
            return False

    def download_url(self, url: str, dest_path: str, timeout: int = 600) -> tuple[bool, int]:
        """Download a file from URL directly on the remote machine.
        Returns (success, file_size_bytes)."""
        import shlex
        safe_url = shlex.quote(url)
        safe_dest = shlex.quote(dest_path)
        code, _, _ = self._safe_run(
            f"wget -q -O {safe_dest} {safe_url}",
            timeout=timeout,
        )
        if code != 0:
            return False, 0
        # Get downloaded file size
        code2, out2, _ = self._safe_run(f"stat -c%s {safe_dest} 2>/dev/null", timeout=5)
        size = int(out2.strip()) if code2 == 0 and out2.strip().isdigit() else 0
        return True, size

    def _parse_status(self, text: str) -> dict:
        """Parse hashcat --status output."""
        result = {}
        per_gpu_speeds = []
        for line in text.split("\n"):
            line = line.strip()
            if line.startswith("Progress"):
                m = re.search(r"\((\d+\.?\d*)%\)", line)
                if m:
                    result["progress"] = float(m.group(1))
            elif line.startswith("Speed.#*"):
                # Aggregate speed line (e.g. "Speed.#*.........: 80562.3 MH/s")
                result["speed"] = line.split(":", 1)[-1].strip() if ":" in line else ""
                result["speed_hs"] = self._parse_speed_to_hs(result["speed"])
            elif line.startswith("Speed.#"):
                # Per-GPU speed — collect in case there's no aggregate line (single GPU)
                spd_text = line.split(":", 1)[-1].strip() if ":" in line else ""
                per_gpu_speeds.append(self._parse_speed_to_hs(spd_text))
            elif "Recovered" in line and "Digests" in line:
                m = re.search(r"(\d+)/(\d+)", line)
                if m:
                    result["cracked"] = int(m.group(1))
                    result["total"] = int(m.group(2))
            elif line.startswith("Time.Estimated"):
                result["eta"] = line.split(":", 1)[-1].strip() if ":" in line else ""
            elif line.startswith("Status"):
                result["hashcat_status"] = line.split(":", 1)[-1].strip() if ":" in line else ""
        # Fallback: if no aggregate Speed.#* line (single GPU), sum per-GPU speeds
        if "speed_hs" not in result and per_gpu_speeds:
            total_hs = sum(per_gpu_speeds)
            result["speed_hs"] = total_hs
            result["speed"] = self.format_speed(total_hs)
        return result

    @staticmethod
    def _parse_speed_to_hs(speed_str: str) -> float:
        """Parse hashcat speed string to H/s float. E.g. '1234.5 MH/s' → 1234500000.0"""
        if not speed_str:
            return 0.0
        m = re.search(r'([\d.]+)\s*(k?M?G?T?)H/s', speed_str)
        if not m:
            return 0.0
        val = float(m.group(1))
        unit = m.group(2)
        multipliers = {'': 1, 'k': 1e3, 'M': 1e6, 'G': 1e9, 'T': 1e12}
        return val * multipliers.get(unit, 1)

    @staticmethod
    def format_speed(hs: float) -> str:
        """Format H/s to human-readable speed string."""
        if hs <= 0:
            return ""
        if hs >= 1e12:
            return f"{hs/1e12:.1f} TH/s"
        if hs >= 1e9:
            return f"{hs/1e9:.1f} GH/s"
        if hs >= 1e6:
            return f"{hs/1e6:.1f} MH/s"
        if hs >= 1e3:
            return f"{hs/1e3:.1f} kH/s"
        return f"{hs:.0f} H/s"

    def _mkdir_p(self, sftp: paramiko.SFTPClient, path: str) -> None:
        """Recursively create remote directory."""
        dirs_to_create = []
        while path and path != "/":
            try:
                sftp.stat(path)
                break
            except FileNotFoundError:
                dirs_to_create.insert(0, path)
                path = os.path.dirname(path)
        for d in dirs_to_create:
            try:
                sftp.mkdir(d)
            except IOError:
                pass

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self):
        return f"SSHManager({self.label})"
