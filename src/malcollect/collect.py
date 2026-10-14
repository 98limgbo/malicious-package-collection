"""수집: 감지(GitHub) + 다운로드(원본만, 미러 없음) 오케스트레이션.

실행: python scripts/run_collect.py [--since-days N] [--loop]
5분 주기로 반복 실행되는 것을 전제로 한다 (docs/design.md 참고).

동작 순서:
1. sync_state에 체크포인트가 없으면(첫 실행) -> OSV 벌크 zip(생태계별 all.zip)에서
   MAL-<올해>-* 전체 백필 (GitHub 트리 API는 대량 조회 시 잘려서 안 씀.
   개별 파일 조회보다 zip 통째로 받아 로컬 파싱하는 게 훨씬 빠름 - docs/design.md 참고)
   (--since-days N이 주어지면 테스트용으로 N일 전 커밋을 기준선으로 잡고 diff만 수행)
   리포트를 반영할 때 철회된 리포트는 수집하지 않고(기존 파일은 삭제), 상한 없는 범위 리포트는
   리포트 등록일 이후에 게시됐거나 게시일을 모르는 버전을 제외한다 (docs/design.md 참고)
2. collected_artifacts에서 download_status='pending'인 것들 다운로드 시도
   (성공 -> 'success'로 갱신 + 파일 보존 + mal_reports.success_count 증가 / 실패 -> 행 삭제, 재시도 없음)
   성공/실패 무관하게 게시일 조회를 시도해 mal_reports.earliest_registry_published_at 갱신
3. 파일 하나 처리할 때마다 그 자리에서 즉시 확인: 이 mal_id에 pending이 더 없으면
   download_attempted_at 기록, 성공 0건이면 report.json/폴더 삭제 (SQL의 mal_reports 행은 유지)
4. sync_state 체크포인트를 갱신 (다음 실행은 여기서부터 diff)
5. (안전망) 실행 끝에 아직 마무리 안 된 리포트가 남아있으면 한 번 더 훑어서 처리
   (이전 실행이 중간에 끊긴 경우 대비)

diff(5분 주기 정상 운영)는 그대로 GitHub compare API 기반을 유지함 - 빠른 감지가 목적이라
zip 방식(생태계 전체를 매번 다시 받음)은 안 맞음. zip은 백필(대량/재추격) 전용.
"""
import io
import json
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import requests

from . import config, db, github_source
from .registries import ArtifactNotFound, DOWNLOADERS, PlaceholderArtifact, get_downloader

STATE_LAST_SHA = "github_last_seen_sha"
OSV_BUCKET_BASE = "https://storage.googleapis.com/osv-vulnerabilities"


def _now() -> str:
    """우리 파이프라인이 직접 생성하는 시각. OSV/레지스트리 원본 시각과 달리 초 단위로
    단순화함 (마이크로초까지는 5분 주기 파이프라인에서 분석 가치가 없음)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _sanitize_path_component(s: str) -> str:
    """Windows 폴더명에 못 쓰는 문자를 치환. OSV 생태계명 중 일부(예: 'VSCode:https://...')가
    콜론/슬래시를 포함해서 그대로 쓰면 경로 생성이 깨짐."""
    illegal = '<>:"/\\|?*'
    return "".join("_" if ch in illegal else ch for ch in s)


def _report_dir(ecosystem: str, mal_id: str):
    d = config.DATA_DIR / _sanitize_path_component(ecosystem) / mal_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _extract_finder(report: dict) -> str | None:
    """report.json의 credits 중 type=FINDER인 항목의 이름. 없으면 None (다른 역할로 대체 안 함)."""
    for credit in report.get("credits", []):
        if credit.get("type") == "FINDER":
            return credit.get("name")
    return None


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _resolve_versions(
    entry: dict, downloader, report_published_at: str | None
) -> tuple[list[str], int]:
    """OSV affected 항목 하나에서 실제로 시도할 버전 목록과 is_explicit_version 값을 결정.
    - 명시적 versions가 있으면 그대로 사용 (is_explicit_version=1). 시간이 지나며 악성 버전이
      목록에 추가되므로 리포트 등록일 이후 게시된 버전도 정상이라 컷오프를 적용하지 않음.
    - 없고, 범위(ranges)에 상한(fixed/last_affected)이 하나라도 있으면 -> 일부 버전만
      악성이라는 뜻이라 위험, 스킵
    - 없고, 범위가 전부 상한 없음(introduced만 있음) -> 전 버전이 악성이라는 주장이므로
      레지스트리에서 버전 목록을 조회하되 (is_explicit_version=0), 리포트 등록일 이후에
      게시됐거나 게시일을 알 수 없는 버전은 제외. 리포트 작성자는 작성 시점에 존재하지 않던
      버전을 검토할 수 없으므로 그런 버전이 악성이라는 근거가 없음 (docs/design.md 참고)
    """
    explicit = entry.get("versions") or []
    if explicit:
        return explicit, 1

    ranges = entry.get("ranges", [])
    if not ranges:
        return [], 0

    for r in ranges:
        events = r.get("events", [])
        if any(("fixed" in e or "last_affected" in e) for e in events):
            return [], 0  # 상한 있음 -> 일부만 악성, 위험하니 스킵

    if downloader is None or not report_published_at:
        return [], 0
    name = entry.get("package", {}).get("name")
    try:
        candidates = downloader.list_versions_with_dates(name)
    except Exception as exc:
        print(f"[detect] list_versions failed for {name}: {exc}", flush=True)
        return [], 0

    cutoff = _parse_ts(report_published_at)
    kept = []
    for version, published_at in candidates:
        if not published_at:
            continue  # 리포트 등록일 이전인지 확인할 수 없으면 받지 않음
        try:
            if _parse_ts(published_at) <= cutoff:
                kept.append(version)
        except ValueError:
            continue
    skipped = len(candidates) - len(kept)
    if skipped:
        print(
            f"[detect] {name}: 전체 {len(candidates)}개 버전 중 리포트 등록일 이후/게시일 불명 "
            f"{skipped}개 제외",
            flush=True,
        )
    return kept, 0


def _purge_report_artifacts(conn, mal_id: str) -> int:
    """이 리포트의 수집 파일/행/폴더를 전부 삭제 (철회된 리포트용). 삭제한 파일 수를 반환."""
    rows = conn.execute(
        "SELECT file_path FROM collected_artifacts WHERE mal_id = ?", (mal_id,)
    ).fetchall()
    removed = 0
    for row in rows:
        if row["file_path"]:
            path = Path(row["file_path"])
            if path.exists():
                path.unlink()
                removed += 1
            path.with_name(path.name + ".sha256").unlink(missing_ok=True)
    conn.execute("DELETE FROM collected_artifacts WHERE mal_id = ?", (mal_id,))
    _delete_report_files(mal_id)
    return removed


def _insert_report_and_versions(conn, report: dict) -> str | None:
    """새/변경된 리포트를 mal_reports + collected_artifacts(pending)에 반영. report.json 저장."""
    mal_id = report.get("id")
    if not mal_id:
        return None

    existing = conn.execute(
        "SELECT osv_modified_at FROM mal_reports WHERE mal_id = ?", (mal_id,)
    ).fetchone()
    modified_at = report.get("modified")
    if existing is not None and existing["osv_modified_at"] == modified_at:
        return None  # 변경 없음, 스킵 (중복 처리 방지)

    affected = report.get("affected", [])
    ecosystems = sorted({a["package"]["ecosystem"] for a in affected if "package" in a})
    ecosystems_str = ",".join(ecosystems)  # 이 리포트가 다루는 생태계 전체 (손실 없이 기록)
    now = _now()
    finder = _extract_finder(report)

    if existing is None:
        conn.execute(
            "INSERT INTO mal_reports (mal_id, ecosystems, collected_at, download_attempted_at, "
            "success_count, osv_withdrawn_at, osv_last_checked_at, osv_modified_at, "
            "osv_credits_finder, osv_published_at, earliest_registry_published_at) "
            "VALUES (?, ?, ?, NULL, 0, ?, ?, ?, ?, ?, NULL)",
            (
                mal_id,
                ecosystems_str,
                now,
                report.get("withdrawn"),
                now,
                modified_at,
                finder,
                report.get("published"),
            ),
        )
    else:
        conn.execute(
            "UPDATE mal_reports SET ecosystems = ?, osv_modified_at = ?, osv_withdrawn_at = ?, "
            "osv_last_checked_at = ?, download_attempted_at = NULL, osv_credits_finder = ? "
            "WHERE mal_id = ?",
            (ecosystems_str, modified_at, report.get("withdrawn"), now, finder, mal_id),
        )

    if report.get("withdrawn"):
        # OSV가 오탐 등으로 철회한 리포트는 악성이라는 근거가 없으므로 수집하지 않고,
        # 이미 받아둔 파일이 있으면 삭제. mal_reports 행은 기록으로 남김 (docs/design.md 참고)
        removed = _purge_report_artifacts(conn, mal_id)
        conn.execute(
            "UPDATE mal_reports SET download_attempted_at = ?, success_count = 0 WHERE mal_id = ?",
            (now, mal_id),
        )
        print(f"[detect] {mal_id}: 철회된 리포트라 수집하지 않음 (기존 파일 {removed}개 삭제)", flush=True)
        return mal_id

    for entry in affected:
        pkg = entry.get("package", {})
        ecosystem = pkg.get("ecosystem")
        name = pkg.get("name")
        if not ecosystem or not name:
            continue
        versions, is_explicit = _resolve_versions(
            entry, get_downloader(ecosystem), report.get("published")
        )
        for version in versions:
            conn.execute(
                "INSERT OR IGNORE INTO collected_artifacts "
                "(mal_id, registry, package_name, version, is_explicit_version, download_status) "
                "VALUES (?, ?, ?, ?, ?, 'pending')",
                (mal_id, ecosystem, name, version, is_explicit),
            )

    for ecosystem in ecosystems:
        report_dir = _report_dir(ecosystem, mal_id)
        with open(report_dir / "report.json", "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

    return mal_id


def _current_year_prefix() -> str:
    return f"MAL-{datetime.now(timezone.utc).year}-"


def backfill(conn, id_prefix: str | None = None) -> list[str]:
    """첫 실행(또는 diff 잘림 대체): OSV 벌크 zip(생태계별 all.zip)에서
    id_prefix로 시작하는 리포트를 전부 조회. 개별 파일 조회보다 훨씬 빠름
    (실측: 개별 조회 292건 1시간+ vs zip 10개 생태계 전체 2분 미만).
    id_prefix를 주지 않으면 실행 시점의 올해(MAL-<올해>-)를 쓴다."""
    id_prefix = id_prefix or _current_year_prefix()
    head_sha = github_source.get_head_sha()  # 백필 후 diff 시작점으로 쓸 체크포인트

    touched = []
    seen_ids: set[str] = set()  # 같은 ID가 여러 생태계 zip에 중복 등장할 수 있어 방지

    for ecosystem in DOWNLOADERS:
        url = f"{OSV_BUCKET_BASE}/{ecosystem}/all.zip"
        print(f"[backfill] {ecosystem}: 조회 중...", flush=True)
        try:
            resp = requests.get(url, timeout=300)
            resp.raise_for_status()
        except Exception as exc:
            print(f"[backfill] {ecosystem}: zip 다운로드 실패: {exc}", flush=True)
            continue

        zf = zipfile.ZipFile(io.BytesIO(resp.content))
        mal_names = [
            n for n in zf.namelist()
            if Path(n).name.startswith(id_prefix) and n.endswith(".json")
        ]
        print(f"[backfill] {ecosystem}: {len(mal_names)}건 매칭", flush=True)

        for name in mal_names:
            with zf.open(name) as f:
                report = json.load(f)
            mal_id = report.get("id")
            if not mal_id or mal_id in seen_ids:
                continue
            seen_ids.add(mal_id)

            got_id = _insert_report_and_versions(conn, report)
            conn.commit()
            if got_id:
                touched.append(got_id)

    db.set_state(conn, STATE_LAST_SHA, head_sha)
    conn.commit()
    return touched


def detect_incremental(conn) -> list[str]:
    """diff 기반 증분 감지 (정상 5분 주기 운영).

    PC가 오래 꺼져있었던 경우 등으로 diff가 GitHub API 잘림 위험 수준까지 쌓였으면
    (DiffTooLargeError), diff를 신뢰하지 않고 OSV 벌크 백필로 대체해 놓치는 항목이
    없도록 함 (backfill()이 sync_state 갱신까지 처리)."""
    last_sha = db.get_state(conn, STATE_LAST_SHA)
    head_sha = github_source.get_head_sha()
    if last_sha is None:
        return []

    try:
        changed_files = github_source.list_changed_mal_files(last_sha, head_sha)
    except github_source.DiffTooLargeError as exc:
        print(f"[detect] {exc} -> 전체 백필로 대체", flush=True)
        return backfill(conn)

    touched = []
    for path in changed_files:
        try:
            report = github_source.fetch_raw_json(path, ref=head_sha)
        except Exception as exc:
            print(f"[detect] failed to fetch {path}: {exc}", flush=True)
            continue
        mal_id = _insert_report_and_versions(conn, report)
        conn.commit()
        if mal_id:
            touched.append(mal_id)

    db.set_state(conn, STATE_LAST_SHA, head_sha)
    conn.commit()
    return touched


def _delete_report_files(mal_id: str) -> None:
    """성공한 파일이 하나도 없는 리포트의 report.json/폴더를 전체 레지스트리 폴더에서 삭제."""
    if not config.DATA_DIR.exists():
        return
    for ecosystem_dir in config.DATA_DIR.iterdir():
        if not ecosystem_dir.is_dir():
            continue
        report_dir = ecosystem_dir / mal_id
        if report_dir.exists():
            shutil.rmtree(report_dir)


def _update_earliest_published(conn, mal_id: str, candidate: str | None) -> None:
    """다운로드 성공/실패와 무관하게, 이 리포트의 여러 버전 중 레지스트리 게시일이 가장
    이른 값을 mal_reports.earliest_registry_published_at에 반영 (문자열 비교 = ISO 8601이라 안전)."""
    if not candidate:
        return
    row = conn.execute(
        "SELECT earliest_registry_published_at FROM mal_reports WHERE mal_id = ?", (mal_id,)
    ).fetchone()
    current = row["earliest_registry_published_at"] if row else None
    if current is None or candidate < current:
        conn.execute(
            "UPDATE mal_reports SET earliest_registry_published_at = ? WHERE mal_id = ?",
            (candidate, mal_id),
        )


def _finalize_if_done(conn, mal_id: str) -> None:
    """이 mal_id에 더 이상 pending이 없으면 즉시 마무리: download_attempted_at 기록,
    성공 0건이면 파일/폴더 삭제 (mal_reports 행 자체는 유지). 이미 마무리된 건 재실행 안 함."""
    row = conn.execute(
        "SELECT download_attempted_at FROM mal_reports WHERE mal_id = ?", (mal_id,)
    ).fetchone()
    if row is None or row["download_attempted_at"] is not None:
        return  # 리포트가 없거나 이미 마무리됨

    still_pending = conn.execute(
        "SELECT COUNT(*) c FROM collected_artifacts WHERE mal_id = ? AND download_status = 'pending'",
        (mal_id,),
    ).fetchone()["c"]
    if still_pending > 0:
        return  # 이 리포트의 다른 버전이 아직 처리 중

    conn.execute(
        "UPDATE mal_reports SET download_attempted_at = ? WHERE mal_id = ?",
        (_now(), mal_id),
    )

    success_count = conn.execute(
        "SELECT COUNT(*) c FROM collected_artifacts WHERE mal_id = ? AND download_status = 'success'",
        (mal_id,),
    ).fetchone()["c"]
    if success_count == 0:
        _delete_report_files(mal_id)
        print(f"[cleanup] {mal_id}: no files obtained, folder removed (SQL kept)", flush=True)

    conn.commit()


def download_pending(conn) -> None:
    pending = conn.execute(
        "SELECT rowid, mal_id, package_name, version, registry FROM collected_artifacts "
        "WHERE download_status = 'pending'"
    ).fetchall()

    for row in pending:
        mal_id = row["mal_id"]
        downloader = get_downloader(row["registry"])
        if downloader is None:
            conn.execute("DELETE FROM collected_artifacts WHERE rowid = ?", (row["rowid"],))
            conn.commit()
            _finalize_if_done(conn, mal_id)
            continue

        try:
            result = downloader.download(row["package_name"], row["version"])
        except PlaceholderArtifact:
            # 레지스트리의 빈 플레이스홀더는 게시일도 악성 코드의 게시일이 아니라서 조회하지 않음
            conn.execute("DELETE FROM collected_artifacts WHERE rowid = ?", (row["rowid"],))
            conn.commit()
            print(
                f"[download] placeholder: {row['registry']} {row['package_name']}@{row['version']}",
                flush=True,
            )
            _finalize_if_done(conn, mal_id)
            continue
        except ArtifactNotFound:
            conn.execute("DELETE FROM collected_artifacts WHERE rowid = ?", (row["rowid"],))
            # 다운로드는 실패해도 게시일 메타데이터는 남아있는 경우가 있어 별도로 조회 시도
            # (실측: npm은 파일이 막혀도 time 이력은 남아있는 사례 확인됨)
            try:
                published_at = downloader.get_published_at(row["package_name"], row["version"])
            except Exception:
                published_at = None
            _update_earliest_published(conn, mal_id, published_at)
            conn.commit()
            print(f"[download] not_found: {row['registry']} {row['package_name']}@{row['version']}", flush=True)
            _finalize_if_done(conn, mal_id)
            continue
        except Exception as exc:
            conn.execute("DELETE FROM collected_artifacts WHERE rowid = ?", (row["rowid"],))
            conn.commit()
            print(f"[download] error: {row['registry']} {row['package_name']}@{row['version']}: {exc}", flush=True)
            _finalize_if_done(conn, mal_id)
            continue

        artifacts_dir = _report_dir(row["registry"], mal_id) / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        file_path = artifacts_dir / result.filename
        file_path.write_bytes(result.content)
        (artifacts_dir / f"{result.filename}.sha256").write_text(result.sha256)

        conn.execute(
            "UPDATE collected_artifacts SET download_status = 'success', file_path = ?, sha256 = ?, "
            "downloaded_at = ?, registry_published_at = ? WHERE rowid = ?",
            (str(file_path), result.sha256, _now(), result.published_at, row["rowid"]),
        )
        conn.execute(
            "UPDATE mal_reports SET success_count = success_count + 1 WHERE mal_id = ?",
            (mal_id,),
        )
        _update_earliest_published(conn, mal_id, result.published_at)
        conn.commit()
        print(f"[download] success: {row['registry']} {row['package_name']}@{row['version']}", flush=True)
        _finalize_if_done(conn, mal_id)


def finalize_reports(conn) -> None:
    """안전망: 이전 실행이 중간에 끊겨 즉시 마무리를 못 받은 리포트를 훑어서 처리."""
    candidates = conn.execute(
        "SELECT mal_id FROM mal_reports WHERE download_attempted_at IS NULL"
    ).fetchall()
    for row in candidates:
        _finalize_if_done(conn, row["mal_id"])


def run(test_since_days: int | None = None) -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    db.init_db()

    with db.connect() as conn:
        is_first_run = db.get_state(conn, STATE_LAST_SHA) is None

        if is_first_run:
            if test_since_days is not None:
                base_sha = github_source.get_commit_days_ago(test_since_days)
                db.set_state(conn, STATE_LAST_SHA, base_sha)
                conn.commit()
                print(f"[test] baseline set to commit ~{test_since_days} day(s) ago: {base_sha}", flush=True)
                touched = detect_incremental(conn)
            else:
                touched = backfill(conn)
        else:
            touched = detect_incremental(conn)

        if touched:
            print(f"[detect] {len(touched)} new/changed report(s)", flush=True)

        download_pending(conn)
        finalize_reports(conn)


if __name__ == "__main__":
    run()
