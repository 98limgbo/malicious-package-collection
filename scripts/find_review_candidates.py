"""위악성/연구용 PoC 후보 리포트를 찾아서 걸린 문장과 함께 출력한다. DB는 읽지도 쓰지도 않는다.

로컬 data/*/MAL-*/report.json의 details(탐지 도구가 쓴 설명문)에서 두 가지 표현을 찾는다.
  hedge      : 탐지 도구가 스스로 근거의 한계를 인정하는 표현 (위악성 후보)
  self-label : 패키지 작성자가 연구/PoC/카나리라고 표방했다는 언급 (연구용 PoC 후보)

이 스크립트는 판정이 아니라 후보를 좁히는 용도이다. 걸린 문장을 사람이 읽고 판단한 뒤
collected_artifacts.review_label을 직접 채운다 (근거는 docs/review_notes.md).

한계:
  - 파일을 확보한 리포트만 대상이다 (그렇지 않은 리포트는 report.json이 삭제되어 있다).
  - 영어 표현만 본다. 표현이 다르면 놓친다 (재현율이 낮다).
  - 걸린 문장이 후보와 무관한 경우가 있다 (정밀도는 docs/review_notes.md의 검증 절 참고).
  - 탐지 도구(주로 Amazon Inspector)가 쓴 문장에 의존하므로 도구의 서술 방식이 바뀌면 달라진다.

사용법:
  python scripts/find_review_candidates.py                     # 전체 후보
  python scripts/find_review_candidates.py --type hedge        # 한 종류만
  python scripts/find_review_candidates.py --sample 20 --seed 1   # 무작위 표본 (정밀도 검증용)
  python scripts/find_review_candidates.py --count             # 건수만
"""
import argparse
import json
import random
import re
import sys
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from malcollect import config  # noqa: E402

PATTERNS = {
    "hedge": [
        r"\bnot,? on (their|its) own,? evidence\b",
        r"\bdo(es)? not establish\b",
        r"\bwarrants? human review\b",
        r"\bconsistent with (a variety of )?legitimate\b",
        r"\bnot evidence of\b",
    ],
    "self-label": [
        r"\bauthori[sz]ed (poc|proof|research|security|test|benign)",
        r"\bbenign (poc|canary|proof)",
        r"\b(dependency[- ]confusion|benign|authori[sz]ed) canary\b",
        r"\bself-label(l)?ed\b",
        r"\bbug bounty\b",
        r"\bproof[- ]of[- ]concept\b",
        r"\bsecurity research\b",
    ],
}
CONTEXT = 150


def scan_report(path: Path) -> list[dict]:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    details = report.get("details") or ""
    if not details:
        return []
    origins = report.get("database_specific", {}).get("malicious-packages-origins") or []
    sources = sorted({o.get("source") for o in origins if o.get("source")})
    affected = report.get("affected") or []
    package = affected[0].get("package", {}).get("name", "?") if affected else "?"

    found = []
    for kind, regexes in PATTERNS.items():
        for regex in regexes:
            match = re.search(regex, details, flags=re.IGNORECASE)
            if match:
                start, end = max(0, match.start() - CONTEXT), match.end() + CONTEXT
                found.append(
                    {
                        "type": kind,
                        "mal_id": report.get("id"),
                        "package": package,
                        "sources": sources,
                        "matched": match.group(0),
                        "snippet": details[start:end].replace("\n", " ").strip(),
                    }
                )
                break  # 같은 종류는 리포트당 한 번만 기록
    return found


def main() -> None:
    ap = argparse.ArgumentParser(description="위악성/연구용 PoC 후보 탐색 (출력 전용)")
    ap.add_argument("--type", choices=["hedge", "self-label", "all"], default="all")
    ap.add_argument("--sample", type=int, default=None, help="무작위 표본 개수")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--count", action="store_true", help="건수만 출력")
    args = ap.parse_args()

    candidates, scanned = [], 0
    for path in config.DATA_DIR.glob("*/MAL-*/report.json"):
        scanned += 1
        candidates += scan_report(path)
    if args.type != "all":
        candidates = [c for c in candidates if c["type"] == args.type]

    counts = Counter(c["type"] for c in candidates)
    print(f"검사한 리포트 {scanned}건, 후보 {dict(counts)}", flush=True)
    if args.count:
        return

    if args.sample:
        random.Random(args.seed).shuffle(candidates)
        candidates = candidates[: args.sample]
    for c in candidates:
        print(f"\n[{c['type']}] {c['mal_id']} {c['package']} 출처={','.join(c['sources'])} 표현='{c['matched']}'")
        print(f"   ...{c['snippet']}...")


if __name__ == "__main__":
    main()
