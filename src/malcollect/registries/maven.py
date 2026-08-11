import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime

import requests

from .base import ArtifactNotFound, DownloadResult, RegistryDownloader, get_with_retry
from .. import config


def _jar_url(name: str, version: str) -> str | None:
    group_id, _, artifact_id = name.partition(":")
    if not artifact_id:
        return None
    group_path = group_id.replace(".", "/")
    return (
        f"https://repo1.maven.org/maven2/{group_path}/{artifact_id}/{version}/"
        f"{artifact_id}-{version}.jar"
    )


def _parse_last_modified(headers) -> str | None:
    last_modified = headers.get("Last-Modified")
    if not last_modified:
        return None
    try:
        return parsedate_to_datetime(last_modified).isoformat()
    except Exception:
        return None


class MavenDownloader(RegistryDownloader):
    ecosystem = "Maven"

    def download_origin(self, name: str, version: str) -> DownloadResult:
        url = _jar_url(name, version)
        if url is None:
            raise ArtifactNotFound(f"unexpected Maven package name format: {name}")
        resp = get_with_retry(url)
        if resp.status_code == 404:
            raise ArtifactNotFound(url)
        resp.raise_for_status()
        artifact_id = name.partition(":")[2]

        # 게시일 전용 필드는 없어서 HTTP Last-Modified 헤더로 근사 (jar가 업로드된 시각)
        published_at = _parse_last_modified(resp.headers)

        return DownloadResult(
            filename=f"{artifact_id}-{version}.jar",
            content=resp.content,
            published_at=published_at,
        )

    def list_versions(self, name: str) -> list[str]:
        group_id, _, artifact_id = name.partition(":")
        if not artifact_id:
            return []
        group_path = group_id.replace(".", "/")
        url = f"https://repo1.maven.org/maven2/{group_path}/{artifact_id}/maven-metadata.xml"
        resp = get_with_retry(url)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        root = ET.fromstring(resp.content)
        return [v.text for v in root.findall(".//versions/version") if v.text]

    def get_published_at(self, name: str, version: str) -> str | None:
        url = _jar_url(name, version)
        if url is None:
            return None
        # 파일을 다시 받지 않고 헤더만 확인
        resp = requests.head(url, timeout=config.HTTP_TIMEOUT, allow_redirects=True)
        if resp.status_code != 200:
            return None
        return _parse_last_modified(resp.headers)
