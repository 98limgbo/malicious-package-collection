from .base import ArtifactNotFound, DownloadResult, RegistryDownloader, get_with_retry


class PubDownloader(RegistryDownloader):
    ecosystem = "Pub"

    def download_origin(self, name: str, version: str) -> DownloadResult:
        meta_url = f"https://pub.dev/api/packages/{name}"
        resp = get_with_retry(meta_url)
        if resp.status_code == 404:
            raise ArtifactNotFound(meta_url)
        resp.raise_for_status()
        data = resp.json()
        match = next(
            (v for v in data.get("versions", []) if v.get("version") == version), None
        )
        if not match or "archive_url" not in match:
            raise ArtifactNotFound(meta_url)

        file_url = match["archive_url"]
        file_resp = get_with_retry(file_url)
        if file_resp.status_code == 404:
            raise ArtifactNotFound(file_url)
        file_resp.raise_for_status()
        return DownloadResult(
            filename=f"{name}-{version}.tar.gz",
            content=file_resp.content,
            published_at=match.get("published"),
        )

    def list_versions(self, name: str) -> list[str]:
        url = f"https://pub.dev/api/packages/{name}"
        resp = get_with_retry(url)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return [v["version"] for v in resp.json().get("versions", []) if "version" in v]

    def get_published_at(self, name: str, version: str) -> str | None:
        url = f"https://pub.dev/api/packages/{name}"
        resp = get_with_retry(url)
        if resp.status_code != 200:
            return None
        match = next(
            (v for v in resp.json().get("versions", []) if v.get("version") == version), None
        )
        return match.get("published") if match else None
