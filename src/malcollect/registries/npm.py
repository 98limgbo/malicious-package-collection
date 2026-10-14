import io
import json
import tarfile

from .base import (
    ArtifactNotFound,
    DownloadResult,
    PlaceholderArtifact,
    RegistryDownloader,
    get_with_retry,
)


def _meta_url(name: str) -> str:
    if "/" in name:  # scoped package: @scope/base
        scope, base = name.split("/", 1)
        return f"https://registry.npmjs.org/{scope}/{base}"
    return f"https://registry.npmjs.org/{name}"


def _is_security_holder(content: bytes) -> bool:
    """npm이 악성 패키지를 제거하며 같은 이름/버전 슬롯에 올려두는 빈 플레이스홀더인지 확인.
    (package.json에 description: "security holding package", repository: "npm/security-holder"
    마커가 있음 - 실제 코드는 없고 진짜 악성 코드가 아니므로 다운로드 성공으로 치면 안 됨.
    실측: 2025년 리포트 1년 지연 백필 시 npm 성공 다운로드의 63%가 이 플레이스홀더였음.)"""
    try:
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tf:
            for member in tf.getmembers():
                parts = member.name.split("/")
                if len(parts) == 2 and parts[1] == "package.json":
                    data = json.load(tf.extractfile(member))
                    repo = data.get("repository")
                    repo_str = repo if isinstance(repo, str) else json.dumps(repo or "")
                    desc = data.get("description") or ""
                    return "security-holder" in repo_str or "security holding package" in desc
    except Exception:
        return False
    return False


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
        if _is_security_holder(resp.content):
            raise PlaceholderArtifact(url)  # 진짜 악성 코드가 아니라 npm 보안 홀딩 더미
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

    def list_versions_with_dates(self, name: str) -> list[tuple[str, str | None]]:
        resp = get_with_retry(_meta_url(name))
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        data = resp.json()
        times = data.get("time", {})
        return [(version, times.get(version)) for version in data.get("versions", {})]

    def get_published_at(self, name: str, version: str) -> str | None:
        resp = get_with_retry(_meta_url(name))
        if resp.status_code != 200:
            return None
        return resp.json().get("time", {}).get(version)
