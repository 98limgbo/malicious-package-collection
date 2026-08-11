from .base import ArtifactNotFound, DownloadResult, RegistryDownloader, get_with_retry


def _escape_module_path(path: str) -> str:
    """Go module proxy protocol: 대문자는 '!' + 소문자로 escape해야 함."""
    out = []
    for ch in path:
        if ch.isupper():
            out.append("!" + ch.lower())
        else:
            out.append(ch)
    return "".join(out)


class GoDownloader(RegistryDownloader):
    ecosystem = "Go"

    def download_origin(self, name: str, version: str) -> DownloadResult:
        # proxy.golang.org는 최초 요청 시 모듈을 영구/불변 캐시하므로,
        # 원본 저장소가 삭제돼도 대부분 계속 서빙됨 (사실상 원본=미러급 신뢰도).
        module = _escape_module_path(name)
        ver = _escape_module_path(version)
        url = f"https://proxy.golang.org/{module}/@v/{ver}.zip"
        resp = get_with_retry(url)
        if resp.status_code == 404:
            raise ArtifactNotFound(url)
        resp.raise_for_status()
        base = name.rsplit("/", 1)[-1]

        try:
            published_at = self.get_published_at(name, version)
        except Exception:
            published_at = None

        return DownloadResult(
            filename=f"{base}-{version}.zip",
            content=resp.content,
            published_at=published_at,
        )

    def list_versions(self, name: str) -> list[str]:
        module = _escape_module_path(name)
        url = f"https://proxy.golang.org/{module}/@v/list"
        resp = get_with_retry(url)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return [line.strip() for line in resp.text.splitlines() if line.strip()]

    def get_published_at(self, name: str, version: str) -> str | None:
        module = _escape_module_path(name)
        ver = _escape_module_path(version)
        resp = get_with_retry(f"https://proxy.golang.org/{module}/@v/{ver}.info")
        if resp.status_code != 200:
            return None
        return resp.json().get("Time")
