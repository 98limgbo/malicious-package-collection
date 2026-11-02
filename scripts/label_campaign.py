"""캠페인 단위 패키지에 review_label을 규칙으로 일괄 부여한다. 사람이 직접 실행하는 스크립트이고
수집 루프는 이 라벨을 부여하지 않는다.

규칙: 리포트 설명문(report.json의 details)에 아래 문구가 있으면 그 리포트의 파일 전체에 라벨을 붙인다.
  tea_token : "tea.xyz"  (tea.xyz 토큰 보상 캠페인. 자동 발행 스크립트로 파생 패키지를 대량 생성하는 스팸)

review_label이 이미 채워진 파일은 건드리지 않는다 (사람이 검토한 라벨을 덮어쓰지 않는다).
문구가 없는 캠페인 패키지는 가려내지 못한다 (docs/review_notes.md 참고).
새로 수집된 파일은 라벨이 비어 있으므로 필요할 때 다시 실행하면 된다 (여러 번 실행해도 안전하다).

사용법:
  python scripts/label_campaign.py            # 집계만 하고 DB는 바꾸지 않음
  python scripts/label_campaign.py --apply    # 실제로 라벨을 부여
"""
import argparse
import json
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from malcollect import config  # noqa: E402
from malcollect.collect import _sanitize_path_component  # noqa: E402

CAMPAIGN_PHRASES = {"tea_token": "tea.xyz"}


def main() -> None:
    ap = argparse.ArgumentParser(description="캠페인 문구 규칙으로 review_label 일괄 부여")
    ap.add_argument("--apply", action="store_true", help="실제로 DB에 반영 (없으면 집계만)")
    args = ap.parse_args()

    conn = sqlite3.connect(config.DB_PATH, timeout=60)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT registry, mal_id, COUNT(*) AS files FROM collected_artifacts "
        "WHERE download_status = 'success' AND review_label IS NULL GROUP BY registry, mal_id"
    ).fetchall()
    print(f"라벨이 비어 있는 리포트: {len(rows)}건", flush=True)

    matched: dict[str, list[str]] = defaultdict(list)
    files: Counter = Counter()
    missing = 0
    for r in rows:
        path = config.DATA_DIR / _sanitize_path_component(r["registry"]) / r["mal_id"] / "report.json"
        try:
            details = (json.loads(path.read_text(encoding="utf-8")).get("details") or "").lower()
        except (OSError, json.JSONDecodeError):
            missing += 1
            continue
        for label, phrase in CAMPAIGN_PHRASES.items():
            if phrase in details:
                matched[label].append(r["mal_id"])
                files[label] += r["files"]
                break

    for label in CAMPAIGN_PHRASES:
        print(f"[{label}] 해당 리포트 {len(matched[label])}건, 파일 {files[label]}개")
    print(f"report.json을 읽지 못한 리포트: {missing}건")

    if not args.apply:
        print("\n집계만 했습니다. 실제 반영하려면 --apply")
        return

    updated = 0
    with conn:
        for label, mal_ids in matched.items():
            for mal_id in mal_ids:
                updated += conn.execute(
                    "UPDATE collected_artifacts SET review_label = ? "
                    "WHERE mal_id = ? AND download_status = 'success' AND review_label IS NULL",
                    (label, mal_id),
                ).rowcount
    print(f"\n반영 완료: 파일 {updated}개")
    print("현재 review_label 분포:", dict(conn.execute(
        "SELECT COALESCE(review_label, '(미검토)'), COUNT(*) FROM collected_artifacts GROUP BY review_label"
    ).fetchall()))
    conn.close()


if __name__ == "__main__":
    main()
