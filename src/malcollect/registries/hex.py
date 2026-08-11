from .base import ArtifactNotFound, DownloadResult, RegistryDownloader, get_with_retry


class HexDownloader(RegistryDownloader):
    ecosystem = "Hex"

    def download_origin(self, name: str, version: str) -> DownloadResult:
        url = f"https://repo.hex.pm/tarballs/{name}-{version}.tar"
        resp = get_with_retry(url)
        if resp.status_code == 404:
            raise ArtifactNotFound(url)
        resp.raise_for_status()

        try:
            published_at = self.get_published_at(name, version)
        except Exception:
            published_at = None

        return DownloadResult(
            filename=f"{name}-{version}.tar",
            content=resp.content,
            published_at=published_at,
        )

    def list_versions(self, name: str) -> list[str]:
        url = f"https://hex.pm/api/packages/{name}"
        resp = get_with_retry(url)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return [r["version"] for r in resp.json().get("releases", [])]

    def get_published_at(self, name: str, version: str) -> str | None:
        resp = get_with_retry(f"https://hex.pm/api/packages/{name}/releases/{version}")
        if resp.status_code != 200:
            return None
        return resp.json().get("inserted_at")
