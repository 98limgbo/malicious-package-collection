from .base import ArtifactNotFound, DownloadResult, RegistryDownloader, get_with_retry

_HEADERS = {"User-Agent": "malicious-package-collection (research)"}  # crates.io API 필수


class CratesDownloader(RegistryDownloader):
    ecosystem = "crates.io"

    def download_origin(self, name: str, version: str) -> DownloadResult:
        # crates.io는 yank해도 파일이 영구 보존되므로 삭제 긴급성이 낮음
        url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
        resp = get_with_retry(url)
        if resp.status_code == 404:
            raise ArtifactNotFound(url)
        resp.raise_for_status()

        try:
            published_at = self.get_published_at(name, version)
        except Exception:
            published_at = None

        return DownloadResult(
            filename=f"{name}-{version}.crate",
            content=resp.content,
            published_at=published_at,
        )

    def list_versions(self, name: str) -> list[str]:
        url = f"https://crates.io/api/v1/crates/{name}"
        resp = get_with_retry(url, headers=_HEADERS)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return [v["num"] for v in resp.json().get("versions", [])]

    def get_published_at(self, name: str, version: str) -> str | None:
        resp = get_with_retry(f"https://crates.io/api/v1/crates/{name}/{version}", headers=_HEADERS)
        if resp.status_code != 200:
            return None
        return resp.json().get("version", {}).get("created_at")
