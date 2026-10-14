import hashlib
import time
from dataclasses import dataclass

import requests

from .. import config


class ArtifactNotFound(Exception):
    """원본 레지스트리에서 아티팩트를 찾지 못함 (download_status='not_found')."""


class PlaceholderArtifact(ArtifactNotFound):
    """받긴 했지만 레지스트리가 악성 패키지를 제거하며 올려둔 빈 플레이스홀더라서 수집하지 않음.
    플레이스홀더의 게시일은 악성 코드의 게시일이 아니므로 호출 측이 게시일 조회도 건너뜀."""


@dataclass
class DownloadResult:
    filename: str
    content: bytes
    published_at: str | None = None  # 레지스트리에 이 버전이 게시된 시각 (OSV published와 다름)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


def get_with_retry(url: str, **kwargs) -> requests.Response:
    """일시적 오류(타임아웃/5xx)에 대해서만 짧게 재시도. 404 등은 즉시 그대로 반환."""
    kwargs.setdefault("timeout", config.HTTP_TIMEOUT)
    last_exc = None
    for attempt in range(config.TRANSIENT_RETRY_COUNT + 1):
        try:
            resp = requests.get(url, **kwargs)
            if resp.status_code >= 500:
                last_exc = requests.HTTPError(f"{resp.status_code} for {url}")
                raise last_exc
            return resp
        except (requests.Timeout, requests.ConnectionError, requests.HTTPError) as exc:
            last_exc = exc
            if attempt < config.TRANSIENT_RETRY_COUNT:
                time.sleep(config.TRANSIENT_RETRY_BACKOFF_SECONDS)
    raise last_exc


class RegistryDownloader:
    """원본 레지스트리에서만 다운로드. 미러 폴백은 실효성 없어 제거함
    (npm: jsDelivr, 범용: Software Heritage 둘 다 시도했으나 필요한 시점에 콘텐츠가
    없는 경우가 대부분이라 무의미했음 - docs/design.md 참고). 나중에 쓸만한 미러를
    찾으면 download() 자체를 다시 확장하면 됨."""

    ecosystem: str = ""

    def download(self, name: str, version: str) -> DownloadResult:
        return self.download_origin(name, version)

    def download_origin(self, name: str, version: str) -> DownloadResult:
        raise NotImplementedError

    def list_versions(self, name: str) -> list[str]:
        """레지스트리에 게시된 이 패키지의 전체 버전 목록.
        범위(전 버전 악성)로만 명시된 리포트를 처리할 때 사용. 기본은 빈 목록(미구현 시 스킵)."""
        return []

    def list_versions_with_dates(self, name: str) -> list[tuple[str, str | None]]:
        """(버전, 게시일) 목록. 리포트 등록일 이후 버전을 걸러내는 컷오프에 사용.
        기본 구현은 버전별로 get_published_at()을 호출하므로 느리다. 응답 한 번에 날짜까지 주는
        레지스트리(npm, PyPI)는 재정의해서 추가 호출을 없앤다. 날짜를 못 구한 버전은 None."""
        result = []
        for version in self.list_versions(name):
            try:
                published_at = self.get_published_at(name, version)
            except Exception:
                published_at = None
            result.append((version, published_at))
        return result

    def get_published_at(self, name: str, version: str) -> str | None:
        """이 버전이 레지스트리에 실제 게시된 시각. 파일을 다시 받지 않고 메타데이터만 조회
        (소급 백필용, scripts/backfill_published_at.py 참고). 기본은 None(미구현)."""
        return None
