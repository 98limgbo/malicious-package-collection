from .base import ArtifactNotFound, DownloadResult, RegistryDownloader, get_with_retry


class NuGetDownloader(RegistryDownloader):
    ecosystem = "NuGet"

    def download_origin(self, name: str, version: str) -> DownloadResult:
        id_lower = name.lower()
        ver_lower = version.lower()
        url = (
            f"https://api.nuget.org/v3-flatcontainer/{id_lower}/{ver_lower}/"
            f"{id_lower}.{ver_lower}.nupkg"
        )
        resp = get_with_retry(url)
        if resp.status_code == 404:
            raise ArtifactNotFound(url)
        resp.raise_for_status()

        try:
            published_at = self.get_published_at(name, version)
        except Exception:
            published_at = None

        return DownloadResult(
            filename=f"{id_lower}.{ver_lower}.nupkg",
            content=resp.content,
            published_at=published_at,
        )

    def list_versions(self, name: str) -> list[str]:
        id_lower = name.lower()
        url = f"https://api.nuget.org/v3-flatcontainer/{id_lower}/index.json"
        resp = get_with_retry(url)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return resp.json().get("versions", [])

    def get_published_at(self, name: str, version: str) -> str | None:
        id_lower = name.lower()
        ver_lower = version.lower()
        url = f"https://api.nuget.org/v3/registration5-semver1/{id_lower}/{ver_lower}.json"
        resp = get_with_retry(url)
        if resp.status_code != 200:
            return None
        return resp.json().get("published")
