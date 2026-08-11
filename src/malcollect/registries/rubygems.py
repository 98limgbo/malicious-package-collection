from .base import ArtifactNotFound, DownloadResult, RegistryDownloader, get_with_retry


class RubyGemsDownloader(RegistryDownloader):
    ecosystem = "RubyGems"

    def download_origin(self, name: str, version: str) -> DownloadResult:
        url = f"https://rubygems.org/downloads/{name}-{version}.gem"
        resp = get_with_retry(url)
        if resp.status_code == 404:
            raise ArtifactNotFound(url)
        resp.raise_for_status()

        try:
            published_at = self.get_published_at(name, version)
        except Exception:
            published_at = None

        return DownloadResult(
            filename=f"{name}-{version}.gem",
            content=resp.content,
            published_at=published_at,
        )

    def list_versions(self, name: str) -> list[str]:
        url = f"https://rubygems.org/api/v1/versions/{name}.json"
        resp = get_with_retry(url)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return [v["number"] for v in resp.json()]

    def get_published_at(self, name: str, version: str) -> str | None:
        resp = get_with_retry(f"https://rubygems.org/api/v1/versions/{name}.json")
        if resp.status_code != 200:
            return None
        match = next((v for v in resp.json() if v.get("number") == version), None)
        return match.get("created_at") if match else None
