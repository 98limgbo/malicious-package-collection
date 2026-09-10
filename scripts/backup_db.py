"""index.sqlite를 안전하게 복사한다.

단순 파일 복사 대신 sqlite3의 온라인 백업 API(Connection.backup())를 사용 - 수집 루프가
동시에 쓰고 있어도(--loop 실행 중) 항상 커밋된 상태 기준의 일관된 스냅샷을 보장한다.
분석/조회는 원본 대신 이 복사본에서 하면 라이브 DB를 건드릴 걱정이 없다.

기본: backups/index_<타임스탬프>.sqlite 에 로컬 전용 스냅샷 생성 (.gitignore로 제외됨)
--publish: 위 스냅샷과 별개로 dataset/index.sqlite(공유용 고정 경로, git으로 추적)도 갱신.
  이 파일은 라이브 DB(루트 index.sqlite)와 별개 파일이라, 다른 사용자가 git pull해도
  각자의 라이브 DB에는 영향 없음 - 참고용 최신 배포본일 뿐.

사용법:
  python scripts/backup_db.py             # 로컬 스냅샷만
  python scripts/backup_db.py --publish   # 로컬 스냅샷 + 공유용 최신본 갱신
"""
import argparse
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from malcollect import config  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKUP_DIR = PROJECT_ROOT / "backups"
DATASET_PATH = PROJECT_ROOT / "dataset" / "index.sqlite"


def _backup_to(dest_path: Path) -> None:
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    src_conn = sqlite3.connect(f"file:{config.DB_PATH}?mode=ro", uri=True)
    dest_conn = sqlite3.connect(dest_path)
    try:
        src_conn.backup(dest_conn)
    finally:
        dest_conn.close()
        src_conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="index.sqlite 안전 백업")
    parser.add_argument(
        "--publish", action="store_true",
        help="로컬 스냅샷과 별개로 dataset/index.sqlite(공유용, git 추적)도 갱신",
    )
    args = parser.parse_args()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    snapshot_path = BACKUP_DIR / f"index_{timestamp}.sqlite"
    _backup_to(snapshot_path)
    print(f"로컬 스냅샷 완료: {snapshot_path}")

    if args.publish:
        _backup_to(DATASET_PATH)
        print(f"공유용 최신본 갱신: {DATASET_PATH}")


if __name__ == "__main__":
    main()
