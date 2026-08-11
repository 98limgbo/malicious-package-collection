from .base import ArtifactNotFound, DownloadResult, RegistryDownloader, get_with_retry


def _meta_url(name: str) -> str:
    if "/" in name:  # scoped package: @scope/base
        scope, base = name.split("/", 1)
        return f"https://registry.npmjs.org/{scope}/{base}"
    return f"https://registry.npmjs.org/{name}"


class NpmDownloader(RegistryDownloader):
    ecosystem = "npm"

    def download_origin(self, name: str, version: str) -> DownloadResult:
        if "/" in name:
            scope, base = name.split("/", 1)
            url = f"https://registry.npmjs.org/{scope}/{base}/-/{base}-{version}.tgz"
        else:
            url = f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"

        resp = get_with_retry(url)
        if resp.status_code == 404:
            raise ArtifactNotFound(url)
        resp.raise_for_status()
        filename = url.rsplit("/", 1)[-1]

        try:
            published_at = self.get_published_at(name, version)
        except Exception:
            published_at = None  # 게시일은 부가 정보라, 못 구해도 다운로드 자체는 성공으로 처리

        return DownloadResult(
            filename=filename, content=resp.content, published_at=published_at
        )

    def list_versions(self, name: str) -> list[str]:
        resp = get_with_retry(_meta_url(name))
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return list(resp.json().get("versions", {}).keys())

    def get_published_at(self, name: str, version: str) -> str | None:
        resp = get_with_retry(_meta_url(name))
        if resp.status_code != 200:
            return None
        return resp.json().get("time", {}).get(version)
