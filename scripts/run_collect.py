import argparse
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from malcollect.collect import run  # noqa: E402


def _print_hint_if_github_rate_limit(exc: Exception) -> None:
    resp = getattr(exc, "response", None)
    if not isinstance(exc, requests.exceptions.HTTPError) or resp is None:
        return
    if resp.status_code == 403 and "api.github.com" in resp.url:
        print(
            "[loop] 힌트: GitHub API 요청 한도(비인증 시 시간당 60회) 초과로 보임. "
            '완화하려면 실행 전 "$env:GITHUB_TOKEN = \'ghp_...\'" 설정 (시간당 5000회로 증가).',
            flush=True,
        )

LOOP_INTERVAL_SECONDS = 300


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="악성 패키지 수집 (트랙 A: 감지 + 다운로드)")
    parser.add_argument(
        "--since-days",
        type=int,
        default=None,
        help="테스트용: 첫 실행 시 전체 백필 대신 N일 전 커밋을 기준선으로 잡고 diff만 수행",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="한 번 실행 후 종료하지 않고, 5분마다 계속 반복 실행 (Ctrl+C로 종료)",
    )
    args = parser.parse_args()

    if not args.loop:
        run(test_since_days=args.since_days)
    else:
        print(f"[loop] 시작 ({LOOP_INTERVAL_SECONDS}초 주기, Ctrl+C로 종료)", flush=True)
        while True:
            print(f"[loop] {_now()} 사이클 시작", flush=True)
            try:
                run(test_since_days=args.since_days)
            except Exception as exc:
                print(f"[loop] {_now()} 사이클 중 오류 발생, 다음 사이클에 계속:", flush=True)
                traceback.print_exc()
                _print_hint_if_github_rate_limit(exc)
            print(f"[loop] {_now()} 사이클 종료, {LOOP_INTERVAL_SECONDS}초 대기", flush=True)
            time.sleep(LOOP_INTERVAL_SECONDS)
