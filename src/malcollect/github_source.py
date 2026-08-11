"""트랙 A(감지): ossf/malicious-packages GitHub 저장소를 원본으로 직접 폴링한다.

OSV.dev API를 거치지 않는 이유는 docs/design.md의 "감지 신호" 섹션 참고 —
OSV.dev importer가 15분 주기로만 반영하는 구조적 지연이 있어 GitHub가 항상 더 빠르다.
"""
from datetime import datetime, timedelta, timezone

import requests

from . import config


def _headers():
    headers = {"Accept": "application/vnd.github+json"}
    if config.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {config.GITHUB_TOKEN}"
    return headers


def get_head_sha(branch: str = config.GITHUB_BRANCH) -> str:
    url = f"https://api.github.com/repos/{config.GITHUB_REPO}/commits/{branch}"
    resp = requests.get(url, headers=_headers(), timeout=config.HTTP_TIMEOUT)
    resp.raise_for_status()
    return resp.json()["sha"]


DIFF_TRUNCATION_SAFETY_THRESHOLD = 250  # GitHub compare API는 300개 근처에서 잘릴 수 있음


class DiffTooLargeError(Exception):
    """compare API 응답이 잘렸을 가능성이 있을 만큼 변경 파일이 많음 (PC가 오래 꺼져있었던 경우 등)."""


def list_changed_mal_files(base_sha: str, head_sha: str) -> list[str]:
    """base_sha와 head_sha 사이에 osv/malicious/ 아래에서 추가/수정된 JSON 파일 경로 목록.

    변경 파일 수가 DIFF_TRUNCATION_SAFETY_THRESHOLD 이상이면 GitHub API 자체 잘림(300개
    근처) 위험이 있다고 보고 DiffTooLargeError를 던짐 - 호출측(collect.detect_incremental)이
    이걸 잡아서 전체 백필로 대체 처리함.
    """
    if base_sha == head_sha:
        return []
    url = f"https://api.github.com/repos/{config.GITHUB_REPO}/compare/{base_sha}...{head_sha}"
    resp = requests.get(url, headers=_headers(), timeout=config.HTTP_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()

    all_files = data.get("files", [])
    if len(all_files) >= DIFF_TRUNCATION_SAFETY_THRESHOLD:
        raise DiffTooLargeError(
            f"{len(all_files)} file(s) changed between {base_sha[:8]}..{head_sha[:8]} "
            f"(>= {DIFF_TRUNCATION_SAFETY_THRESHOLD}), possible GitHub API truncation"
        )

    files = []
    for f in data.get("files", []):
        filename = f["filename"]
        if (
            filename.startswith(config.GITHUB_MAL_PATH_PREFIX)
            and filename.endswith(".json")
            and f["status"] in ("added", "modified", "renamed")
        ):
            files.append(filename)
    return files


def fetch_raw_json(path: str, ref: str = config.GITHUB_BRANCH) -> dict:
    url = f"https://raw.githubusercontent.com/{config.GITHUB_REPO}/{ref}/{path}"
    resp = requests.get(url, timeout=config.HTTP_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def list_all_mal_files(id_prefix: str, ref: str = config.GITHUB_BRANCH) -> list[str]:
    """백필용: 저장소 전체 트리에서 osv/malicious/ 아래 파일명이 id_prefix로 시작하는 것만 필터링.

    주의: GitHub tree API는 파일이 매우 많으면(수만 개) truncated=True로 잘릴 수 있음.
    현재 저장소 규모에서는 문제없지만, 커지면 디렉터리별로 나눠 조회하도록 보완 필요.
    """
    url = f"https://api.github.com/repos/{config.GITHUB_REPO}/git/trees/{ref}"
    resp = requests.get(
        url, headers=_headers(), params={"recursive": "1"}, timeout=config.HTTP_TIMEOUT
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("truncated"):
        print("[github_source] WARNING: tree listing truncated, some files may be missing")

    files = []
    for item in data.get("tree", []):
        path = item.get("path", "")
        if item.get("type") != "blob":
            continue
        if not path.startswith(config.GITHUB_MAL_PATH_PREFIX):
            continue
        basename = path.rsplit("/", 1)[-1]
        if basename.startswith(id_prefix) and basename.endswith(".json"):
            files.append(path)
    return files


def get_commit_days_ago(days: int, branch: str = config.GITHUB_BRANCH) -> str:
    """테스트용: 대략 N일 전 시점의 커밋 SHA를 찾음 (diff 기준선으로 사용)."""
    since_before = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    url = f"https://api.github.com/repos/{config.GITHUB_REPO}/commits"
    params = {"sha": branch, "path": config.GITHUB_MAL_PATH_PREFIX, "until": since_before, "per_page": 1}
    resp = requests.get(url, headers=_headers(), params=params, timeout=config.HTTP_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    if not data:
        raise RuntimeError(f"{days}일 전 근처의 커밋을 찾지 못함")
    return data[0]["sha"]
