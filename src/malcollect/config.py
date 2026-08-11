import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = PROJECT_ROOT / "index.sqlite"

GITHUB_REPO = "ossf/malicious-packages"
GITHUB_BRANCH = "main"
GITHUB_MAL_PATH_PREFIX = "osv/malicious/"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")  # optional, raises rate limit from 60/hr to 5000/hr

OSV_API_BASE = "https://api.osv.dev/v1"

HTTP_TIMEOUT = 30
TRANSIENT_RETRY_COUNT = 2
TRANSIENT_RETRY_BACKOFF_SECONDS = 3
