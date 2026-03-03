"""Configuration — loads API key from .env."""

from __future__ import annotations
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

VASTAI_API_KEY: str = os.getenv("VASTAI_API_KEY", "")
VASTAI_BASE_URL: str = "https://cloud.vast.ai/api/v0"

# Remote paths on GPU instances
REMOTE_WORK_DIR = "/root/hashcrack"
REMOTE_WORDLIST = f"{REMOTE_WORK_DIR}/wordlist.txt"
REMOTE_RULES    = f"{REMOTE_WORK_DIR}/rules.rule"
REMOTE_HASHES   = f"{REMOTE_WORK_DIR}/hashes.txt"
REMOTE_OUTFILE  = f"{REMOTE_WORK_DIR}/cracked.txt"
REMOTE_POTFILE  = f"{REMOTE_WORK_DIR}/hashcat.potfile"

# State file
STATE_DIR = Path(__file__).resolve().parent.parent / "data"
STATE_FILE = STATE_DIR / "state.json"

# Job history
HISTORY_FILE = STATE_DIR / "history.json"

# Hashcat templates per attack mode
HASHCAT_MODE = 1710

# -a 0: dictionary attack (wordlist + rules)
HASHCAT_CMD_TEMPLATE = (
    "hashcat -m {mode} -a 0 {hashes} {wordlist}"
    " -w 4 --outfile {outfile} -r {rules}"
    " {username_flag}"
    " --potfile-path {potfile}"
    " --status --status-timer=10 --force"
    " --session=hcjob"
    " {extra}"
)

# -a 3: mask/brute-force attack
HASHCAT_CMD_MASK_TEMPLATE = (
    "hashcat -m {mode} -a 3 {hashes} {mask}"
    " -w 4 --outfile {outfile}"
    " {username_flag}"
    " --potfile-path {potfile}"
    " --status --status-timer=10 --force"
    " --session=hcjob"
    " {extra}"
)

# Potfile sync interval (seconds)
POTFILE_SYNC_INTERVAL = 60

# Telegram notifications (optional)
TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID: str = os.getenv("TELEGRAM_CHAT_ID", "")
