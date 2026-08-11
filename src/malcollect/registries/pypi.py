from .base import ArtifactNotFound, DownloadResult, RegistryDownloader, get_with_retry


class PypiDownloader(RegistryDownloader):
    ecosystem = "PyPI"

    def download_origin(self, name: str, version: str) -> DownloadResult:
        # PyPI 파일 URL은 해시 경로라 이름+버전만으로 유추 불가 -> 먼저 메타데이터 조회
        meta_url = f"https://pypi.org/pypi/{name}/{version}/json"
        resp = get_with_retry(meta_url)
        if resp.status_code == 404:
            raise ArtifactNotFound(meta_url)
        resp.raise_for_status()
        urls = resp.json().get("urls", [])
        if not urls:
            raise ArtifactNotFound(meta_url)

        # sdist를 우선 시도, 없으면 첫 번째(보통 wheel)
        target = next((u for u in urls if u.get("packagetype") == "sdist"), urls[0])
        file_url = target["url"]
        file_resp = get_with_retry(file_url)
        if file_resp.status_code == 404:
            raise ArtifactNotFound(file_url)
        file_resp.raise_for_status()
        filename = target.get("filename") or file_url.rsplit("/", 1)[-1]
        published_at = target.get("upload_time_iso_8601")
        return DownloadResult(
            filename=filename, content=file_resp.content, published_at=published_at
        )

    def list_versions(self, name: str) -> list[str]:
        url = f"https://pypi.org/pypi/{name}/json"
        resp = get_with_retry(url)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return list(resp.json().get("releases", {}).keys())

    def get_published_at(self, name: str, version: str) -> str | None:
        url = f"https://pypi.org/pypi/{name}/{version}/json"
        resp = get_with_retry(url)
        if resp.status_code != 200:
            return None
        urls = resp.json().get("urls", [])
        if not urls:
            return None
        target = next((u for u in urls if u.get("packagetype") == "sdist"), urls[0])
        return target.get("upload_time_iso_8601")
