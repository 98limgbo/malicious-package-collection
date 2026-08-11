from .base import ArtifactNotFound, DownloadResult, RegistryDownloader, get_with_retry


class PackagistDownloader(RegistryDownloader):
    ecosystem = "Packagist"

    def download_origin(self, name: str, version: str) -> DownloadResult:
        # Packagist는 메타데이터만 서빙하고, 실제 dist(zip)는 GitHub 등 원 소스 URL을 가리킴.
        # 이 메타데이터 자체가 먼저 사라질 수 있어 최대한 먼저 확보해야 함.
        meta_url = f"https://repo.packagist.org/p2/{name}.json"
        resp = get_with_retry(meta_url)
        if resp.status_code == 404:
            raise ArtifactNotFound(meta_url)
        resp.raise_for_status()
        versions = resp.json().get("packages", {}).get(name, [])
        match = next((v for v in versions if v.get("version") == version), None)
        if not match or "dist" not in match:
            raise ArtifactNotFound(meta_url)

        dist_url = match["dist"]["url"]
        file_resp = get_with_retry(dist_url)
        if file_resp.status_code == 404:
            raise ArtifactNotFound(dist_url)
        file_resp.raise_for_status()
        ext = match["dist"].get("type", "zip")
        filename = f"{name.replace('/', '__')}-{version}.{ext}"
        return DownloadResult(
            filename=filename,
            content=file_resp.content,
            published_at=match.get("time"),
        )

    def list_versions(self, name: str) -> list[str]:
        meta_url = f"https://repo.packagist.org/p2/{name}.json"
        resp = get_with_retry(meta_url)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        versions = resp.json().get("packages", {}).get(name, [])
        return [v["version"] for v in versions if "version" in v]

    def get_published_at(self, name: str, version: str) -> str | None:
        meta_url = f"https://repo.packagist.org/p2/{name}.json"
        resp = get_with_retry(meta_url)
        if resp.status_code != 200:
            return None
        versions = resp.json().get("packages", {}).get(name, [])
        match = next((v for v in versions if v.get("version") == version), None)
        return match.get("time") if match else None
