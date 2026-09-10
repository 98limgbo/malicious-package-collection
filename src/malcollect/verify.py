"""재검증: OSV API 기반 (on-demand 실행, 자동 스케줄 없음).

연구 데이터로 사용하기 전에 반드시 한 번 실행할 것 - collect.py는 철회(오탐)된 리포트도
그대로 수집하므로(docs/design.md "보존 정책" 참고), 재검증 없이는 오탐이 섞여 있을 수 있음.
collect.py(수집)는 osv_verification_status를 절대 건드리지 않음 - 이 파일만 관리.

사용법:
    python scripts/run_verify.py                # 파일을 확보한 리포트 전체 재검증
    python scripts/run_verify.py --mal-id MAL-2026-8013   # 특정 건만
"""
import argparse
import json
from datetime import datetime, timezone

import requests

from . import config, db


def _now() -> str:
    """우리 파이프라인이 직접 생성하는 시각. 초 단위로 단순화 (collect.py의 _now()와 동일 정책)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _mark_all_withdrawn(conn, mal_id: str) -> None:
    conn.execute(
        "UPDATE collected_artifacts SET osv_verification_status = 'withdrawn' WHERE mal_id = ?",
        (mal_id,),
    )


def _recheck_versions(conn, mal_id: str, report: dict) -> None:
    """철회 아닌 경우: 성공한 각 버전이 최신 리포트에도 여전히 있는지 확인."""
    current_versions = set()
    for entry in report.get("affected", []):
        pkg = entry.get("package", {})
        ecosystem = pkg.get("ecosystem")
        name = pkg.get("name")
        for version in entry.get("versions") or []:
            current_versions.add((name, version, ecosystem))

    rows = conn.execute(
        "SELECT rowid, package_name, version, registry FROM collected_artifacts "
        "WHERE mal_id = ? AND download_status = 'success'",
        (mal_id,),
    ).fetchall()
    for row in rows:
        key = (row["package_name"], row["version"], row["registry"])
        new_status = None if key in current_versions else "mismatch"
        conn.execute(
            "UPDATE collected_artifacts SET osv_verification_status = ? WHERE rowid = ?",
            (new_status, row["rowid"]),
        )


def _overwrite_report_json(conn, mal_id: str, report: dict) -> None:
    registry_rows = conn.execute(
        "SELECT DISTINCT registry FROM collected_artifacts WHERE mal_id = ?", (mal_id,)
    ).fetchall()
    for r in registry_rows:
        report_dir = config.DATA_DIR / r["registry"] / mal_id
        if not report_dir.exists():
            continue  # 파일 확보 못한 리포트는 폴더가 이미 없을 수 있음
        with open(report_dir / "report.json", "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)


def verify_one(conn, mal_id: str) -> None:
    url = f"{config.OSV_API_BASE}/vulns/{mal_id}"
    resp = requests.get(url, timeout=config.HTTP_TIMEOUT)
    now = _now()

    if resp.status_code == 404:
        conn.execute(
            "UPDATE mal_reports SET osv_last_checked_at = ? WHERE mal_id = ?", (now, mal_id)
        )
        conn.commit()
        print(f"[verify] {mal_id}: OSV API에서 404 (이미 완전히 제거된 것으로 보임)")
        return
    resp.raise_for_status()
    report = resp.json()

    # 확인 시각은 변경 여부와 무관하게 항상 갱신
    conn.execute(
        "UPDATE mal_reports SET osv_last_checked_at = ? WHERE mal_id = ?", (now, mal_id)
    )

    stored = conn.execute(
        "SELECT osv_modified_at FROM mal_reports WHERE mal_id = ?", (mal_id,)
    ).fetchone()
    fresh_modified = report.get("modified")
    if stored is not None and stored["osv_modified_at"] == fresh_modified:
        conn.commit()
        print(f"[verify] {mal_id}: 변경 없음")
        return

    # 리포트가 업데이트됨 -> report.json 갱신 + mal_reports 갱신 + collected_artifacts 재검증
    _overwrite_report_json(conn, mal_id, report)

    withdrawn_at = report.get("withdrawn")
    conn.execute(
        "UPDATE mal_reports SET osv_modified_at = ?, osv_withdrawn_at = ? WHERE mal_id = ?",
        (fresh_modified, withdrawn_at, mal_id),
    )

    if withdrawn_at:
        _mark_all_withdrawn(conn, mal_id)
        print(f"[verify] {mal_id}: 리포트 철회됨 -> 관련 collected_artifacts 전부 withdrawn 처리")
    else:
        _recheck_versions(conn, mal_id, report)
        print(f"[verify] {mal_id}: 리포트 업데이트됨 -> 버전별 재검증 완료")

    conn.commit()


def run(mal_id: str | None = None) -> None:
    db.init_db()
    with db.connect() as conn:
        if mal_id:
            targets = [mal_id]
        else:
            targets = [
                row["mal_id"]
                for row in conn.execute(
                    "SELECT mal_id FROM mal_reports WHERE success_count > 0"
                ).fetchall()
            ]
        print(f"[verify] {len(targets)}건 재검증 시작 (파일 확보된 리포트만 대상)")
        for target in targets:
            verify_one(conn, target)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OSV API 기반 재검증")
    parser.add_argument("--mal-id", help="특정 MAL-ID만 재검증", default=None)
    args = parser.parse_args()
    run(mal_id=args.mal_id)
