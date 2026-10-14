from .base import ArtifactNotFound, DownloadResult, PlaceholderArtifact, RegistryDownloader
from .crates import CratesDownloader
from .go import GoDownloader
from .hex import HexDownloader
from .maven import MavenDownloader
from .npm import NpmDownloader
from .nuget import NuGetDownloader
from .packagist import PackagistDownloader
from .pub import PubDownloader
from .pypi import PypiDownloader
from .rubygems import RubyGemsDownloader

# OSV의 affected[].package.ecosystem 문자열 -> 다운로더 매핑
DOWNLOADERS: dict[str, RegistryDownloader] = {
    "npm": NpmDownloader(),
    "PyPI": PypiDownloader(),
    "RubyGems": RubyGemsDownloader(),
    "crates.io": CratesDownloader(),
    "Packagist": PackagistDownloader(),
    "Maven": MavenDownloader(),
    "NuGet": NuGetDownloader(),
    "Go": GoDownloader(),
    "Hex": HexDownloader(),
    "Pub": PubDownloader(),
}


def get_downloader(ecosystem: str) -> RegistryDownloader | None:
    return DOWNLOADERS.get(ecosystem)


__all__ = [
    "ArtifactNotFound",
    "PlaceholderArtifact",
    "DownloadResult",
    "RegistryDownloader",
    "DOWNLOADERS",
    "get_downloader",
]
