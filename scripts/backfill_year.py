"""1회성: 특정 연도의 MAL 리포트를 OSV 벌크 zip에서 전부 조회해 수집한다.

최초 실행이 MAL-2026-* 만 백필했기 때문에(run 시점 기준 최신 연도), 다른 연도를
나중에 채우고 싶을 때 사용. collect.backfill()을 그대로 재사용하되 id_prefix만
연도별로 바꿔서 호출한다.

사용법: python scripts/backfill_year.py 2025
"""
import argparse
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from malcollect import db  # noqa: E402
from malcollect.collect import backfill, download_pending, finalize_reports  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="특정 연도의 MAL 리포트 전체를 1회성으로 백필")
    parser.add_argument("year", type=int, help="예: 2025")
    args = parser.parse_args()
    id_prefix = f"MAL-{args.year}-"

    db.init_db()
    with db.connect() as conn:
        touched = backfill(conn, id_prefix=id_prefix)
        print(f"[backfill-{args.year}] {len(touched)}건 신규/변경 감지")
        download_pending(conn)
        finalize_reports(conn)


if __name__ == "__main__":
    main()
