import sqlite3
from contextlib import contextmanager

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS mal_reports (
  mal_id TEXT PRIMARY KEY,
  ecosystems TEXT,              -- 이 리포트가 다루는 모든 생태계 (콤마 구분, 예: "npm,PyPI")
  collected_at TEXT,            -- 처음 감지한 시각 (우리 파이프라인, 초 단위)
  download_attempted_at TEXT,   -- 모든 버전 다운로드 시도가 끝난 시각 (NULL=진행중, 초 단위)
  success_count INTEGER DEFAULT 0,   -- 확보한 파일 개수 (collected_artifacts 조인 없이 조회용)
  osv_withdrawn_at TEXT,        -- NULL=유효, 값 있으면 철회(오탐 등) - verify.py만 갱신, OSV 원본값
  osv_last_checked_at TEXT,     -- 마지막 재검증 시각 (verify.py, 우리 파이프라인, 초 단위)
  osv_modified_at TEXT,         -- OSV 리포트 마지막 수정일 (중복 처리 방지, OSV 원본값)
  osv_credits_finder TEXT,      -- report.json의 credits 중 type=FINDER인 이름
  osv_published_at TEXT,        -- OSV 등록일 ("발견일"의 근사치, OSV 원본값)
  earliest_registry_published_at TEXT  -- 버전들 중 레지스트리 최초 게시일 (성공/실패 무관 수집, 레지스트리 원본값)
);

-- 실제로 다운로드에 성공한 (패키지, 버전) 조합만 존재 (실패는 즉시 삭제, 재시도 없음)
CREATE TABLE IF NOT EXISTS collected_artifacts (
  mal_id TEXT REFERENCES mal_reports(mal_id),
  registry TEXT,                 -- 이 샘플을 실제로 수집한 레지스트리 (예: npm)
  package_name TEXT,
  version TEXT,
  is_explicit_version INTEGER,   -- 1=OSV 리포트가 이 버전을 직접 명시, 0=상한 없는 range라서 우리가 list_versions()로 나열 (우리 파이프라인 판정값)
  download_status TEXT,          -- 'pending'(시도 전) 또는 'success'만 존재
  osv_verification_status TEXT,  -- NULL / 'withdrawn' / 'mismatch' - verify.py만 갱신
  review_label TEXT,             -- 사람이 이 파일을 검토한 결과. NULL=미검토 / 'confirmed_malicious' / 'false_positive'(위악성) / 'research_poc'(연구용 PoC). 수집 루프는 건드리지 않음, 근거는 docs/review_notes.md
  downloaded_at TEXT,            -- 우리가 이 파일을 다운로드한 시각 (초 단위)
  registry_published_at TEXT,    -- 레지스트리에 이 버전이 실제 게시된 시각 (레지스트리 원본값)
  file_path TEXT,
  sha256 TEXT,
  UNIQUE(mal_id, package_name, version, registry)
);

CREATE TABLE IF NOT EXISTS sync_state (
  key TEXT PRIMARY KEY,
  value TEXT
);
"""

# 컬럼 순서까지 바뀌는 마이그레이션이라 (SQLite는 컬럼 재배열을 직접 지원 안 함)
# "새 테이블 생성 -> 데이터 옮기며 변환 -> 기존 테이블 삭제 -> 새 테이블로 교체" 방식을 씀.
_MAL_REPORTS_OLD_COLS = [
    "mal_id", "registry", "osv_published_at", "osv_modified_at", "osv_withdrawn_at",
    "collected_at", "osv_last_checked_at", "download_attempted_at", "osv_credits_finder",
    "success_count", "earliest_registry_published_at",
]
_COLLECTED_ARTIFACTS_OLD_COLS = [
    "mal_id", "package_name", "version", "ecosystem", "download_status", "file_path",
    "sha256", "source", "downloaded_at", "registry_published_at", "osv_verification_status",
]


def _table_names(conn: sqlite3.Connection) -> set[str]:
    return {
        row["name"]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }


def _columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [row["name"] for row in conn.execute(f"PRAGMA table_info({table})")]


def _rebuild_mal_reports(conn: sqlite3.Connection) -> None:
    """이전 스키마(registry 단일값 등)의 mal_reports를 새 컬럼 순서/구조로 재생성."""
    old_cols = set(_columns(conn, "mal_reports"))
    if old_cols == set(c for c, _ in _MAL_REPORTS_NEW_COLS):
        return  # 이미 최신 구조

    conn.execute("ALTER TABLE mal_reports RENAME TO mal_reports_old")
    conn.execute(_MAL_REPORTS_CREATE)

    has_old_registry = "registry" in old_cols
    old_rows = conn.execute("SELECT * FROM mal_reports_old").fetchall()
    for r in old_rows:
        r = dict(r)
        # registry(대표 1개) -> ecosystems(리스트, 지금은 아는 값 하나로 초기화 - 향후 신규 리포트부터 정확한 전체 목록 채워짐)
        ecosystems = r.get("ecosystems") or r.get("registry") or ""
        conn.execute(
            "INSERT INTO mal_reports (mal_id, ecosystems, collected_at, download_attempted_at, "
            "success_count, osv_withdrawn_at, osv_last_checked_at, osv_modified_at, "
            "osv_credits_finder, osv_published_at, earliest_registry_published_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                r.get("mal_id"),
                ecosystems,
                r.get("collected_at"),
                r.get("download_attempted_at"),
                r.get("success_count", 0),
                r.get("osv_withdrawn_at"),
                r.get("osv_last_checked_at"),
                r.get("osv_modified_at"),
                r.get("osv_credits_finder"),
                r.get("osv_published_at"),
                r.get("earliest_registry_published_at"),
            ),
        )
    conn.execute("DROP TABLE mal_reports_old")


def _rebuild_collected_artifacts(conn: sqlite3.Connection) -> None:
    """이전 스키마(ecosystem/source 컬럼 등)의 collected_artifacts를 새 구조로 재생성."""
    old_cols = set(_columns(conn, "collected_artifacts"))
    if old_cols == set(c for c, _ in _COLLECTED_ARTIFACTS_NEW_COLS):
        return  # 이미 최신 구조

    conn.execute("ALTER TABLE collected_artifacts RENAME TO collected_artifacts_old")
    conn.execute(_COLLECTED_ARTIFACTS_CREATE)

    old_rows = conn.execute("SELECT * FROM collected_artifacts_old").fetchall()
    for r in old_rows:
        r = dict(r)
        registry = r.get("registry") or r.get("ecosystem")  # ecosystem -> registry 이름 변경
        conn.execute(
            "INSERT OR IGNORE INTO collected_artifacts (mal_id, registry, package_name, version, "
            "is_explicit_version, download_status, osv_verification_status, review_label, downloaded_at, "
            "registry_published_at, file_path, sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                r.get("mal_id"),
                registry,
                r.get("package_name"),
                r.get("version"),
                r.get("is_explicit_version"),
                r.get("download_status"),
                r.get("osv_verification_status"),
                r.get("review_label"),
                r.get("downloaded_at"),
                r.get("registry_published_at"),
                r.get("file_path"),
                r.get("sha256"),
            ),
        )
    conn.execute("DROP TABLE collected_artifacts_old")


_MAL_REPORTS_NEW_COLS = [
    ("mal_id", "TEXT"), ("ecosystems", "TEXT"), ("collected_at", "TEXT"),
    ("download_attempted_at", "TEXT"), ("success_count", "INTEGER"),
    ("osv_withdrawn_at", "TEXT"), ("osv_last_checked_at", "TEXT"), ("osv_modified_at", "TEXT"),
    ("osv_credits_finder", "TEXT"), ("osv_published_at", "TEXT"),
    ("earliest_registry_published_at", "TEXT"),
]
_COLLECTED_ARTIFACTS_NEW_COLS = [
    ("mal_id", "TEXT"), ("registry", "TEXT"), ("package_name", "TEXT"), ("version", "TEXT"),
    ("is_explicit_version", "INTEGER"),
    ("download_status", "TEXT"), ("osv_verification_status", "TEXT"), ("review_label", "TEXT"),
    ("downloaded_at", "TEXT"),
    ("registry_published_at", "TEXT"), ("file_path", "TEXT"), ("sha256", "TEXT"),
]
_MAL_REPORTS_CREATE = """
CREATE TABLE mal_reports (
  mal_id TEXT PRIMARY KEY,
  ecosystems TEXT,
  collected_at TEXT,
  download_attempted_at TEXT,
  success_count INTEGER DEFAULT 0,
  osv_withdrawn_at TEXT,
  osv_last_checked_at TEXT,
  osv_modified_at TEXT,
  osv_credits_finder TEXT,
  osv_published_at TEXT,
  earliest_registry_published_at TEXT
)
"""
_COLLECTED_ARTIFACTS_CREATE = """
CREATE TABLE collected_artifacts (
  mal_id TEXT REFERENCES mal_reports(mal_id),
  registry TEXT,
  package_name TEXT,
  version TEXT,
  is_explicit_version INTEGER,
  download_status TEXT,
  osv_verification_status TEXT,
  review_label TEXT,
  downloaded_at TEXT,
  registry_published_at TEXT,
  file_path TEXT,
  sha256 TEXT,
  UNIQUE(mal_id, package_name, version, registry)
)
"""


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    conn = get_conn()
    try:
        # 테이블 재생성(rename->recreate->drop) 도중엔 FK가 옛 테이블명을 참조하게 돼서
        # 잠깐 꺼둠 (마이그레이션 끝나면 다시 켬 - get_conn()이 매번 새로 켜므로 여기서만 임시 처리)
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.executescript(SCHEMA)
        conn.commit()  # DDL은 여기서 확정 (이후 단계 실패해도 SCHEMA 자체는 안전)
        if "mal_reports" in _table_names(conn):
            _rebuild_mal_reports(conn)
            conn.commit()
        if "collected_artifacts" in _table_names(conn):
            _rebuild_collected_artifacts(conn)
            conn.commit()
    finally:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.commit()
        conn.close()


@contextmanager
def connect():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def get_state(conn: sqlite3.Connection, key: str, default=None):
    row = conn.execute("SELECT value FROM sync_state WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_state(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO sync_state (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
