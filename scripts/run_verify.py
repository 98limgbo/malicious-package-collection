import argparse
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from malcollect.verify import run  # noqa: E402

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OSV API 기반 재검증 (트랙 B)")
    parser.add_argument("--mal-id", help="특정 MAL-ID만 재검증", default=None)
    args = parser.parse_args()
    run(mal_id=args.mal_id)
