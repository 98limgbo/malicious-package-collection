# 악성 패키지 수집 프로젝트 설계 문서

## 배경 / 목적
- 악성 패키지 탐지 연구의 타당성 검증을 위해 npm, PyPI, RubyGems 외 다양한 레지스트리(crates.io, Packagist, Go, Maven, NuGet, Hex, Pub)에서 악성 패키지 **원본 파일**을 수집한다.
- 데이터 소스: [ossf/malicious-packages](https://github.com/ossf/malicious-packages) (GitHub, 원본) / [OSV.dev](https://osv.dev) (재검증용 API)
- 핵심 제약: 악성 패키지는 보고된 후 원본 레지스트리에서 빠르게(수시간~수일 내) 삭제되는 경향이 있어, 최대한 빠르게 감지하고 다운로드해야 한다.

## 전체 구조 요약

```
[트랙 A: 수집 — collect.py]                    [트랙 B: 재검증 — verify.py]
  GitHub diff (5분 주기, append-only)             OSV API (on-demand, 수동 실행)
  또는 OSV 벌크 zip (백필/diff 잘림 시)              연구 데이터 사용 직전 필수 실행
  → mal_reports / collected_artifacts 갱신        → osv_withdrawn_at, osv_verification_status 갱신
```

- **감지·다운로드(트랙 A)**는 "새로운 게 생겼는지"만 판단하고 자동(5분 주기)으로 반복 실행됨.
- **재검증(트랙 B)**은 "지금도 유효한지"를 판단하며 자동 스케줄에 포함되지 않고 필요할 때 수동 실행됨.
- 두 트랙은 서로 독립적이며, 트랙 A만 계속 돌려도 정상 동작하지만 연구 데이터로 쓰기 전엔 트랙 B를 반드시 한 번 실행해야 함.

## 저장 구조

```
data/<registry>/<MAL-ID>/report.json     # OSV 원본 리포트. 파일을 하나도 못 구하면 폴더 자체가 없음
data/<registry>/<MAL-ID>/artifacts/      # 압축 원본 + sha256 (성공한 버전만, 실패는 아예 안 남음)
index.sqlite                             # mal_reports / collected_artifacts / sync_state
```

- 최상위 키는 MAL-ID: 리포트 하나가 여러 버전/생태계를 포함할 수 있어 재수집 시 덮어쓰기 기준이 명확함.
- 원본 아티팩트는 **압축 해제하지 않고 그대로 보관** (실행 위험 최소화). 분석이 필요하면 격리 환경에서만 압축 해제.
- **`npm install`, `pip install` 등 절대 실행 금지** — 진짜 악성 코드다.

## DB 스키마 (`index.sqlite`)

3개 테이블로 구성 (처음엔 5개였으나 실사용 중 통합·단순화함 — `affected_packages`+`artifacts`→`collected_artifacts`(구 `package_versions`), `verification_log`→`mal_reports` 컬럼으로 흡수, `meta`→`sync_state`로 개명).

컬럼명은 출처를 접두어로 명시함(`osv_*`=OSV 리포트에서 온 값, `registry_*`=패키지 레지스트리에서 온 값, 접두어 없음=우리 파이프라인 자체 값) — 두 개념이 섞이면서 `published_at`처럼 어느 쪽인지 모호한 이름이 계속 헷갈림을 유발해 전면 재정리함.

```sql
-- 리포트 단위 (mal_id당 1행, 다운로드 성공 여부와 무관하게 항상 유지)
-- 컬럼 순서: 식별 -> 우리 파이프라인 상태(성공 여부까지) -> OSV 정보(철회 여부부터) -> 레지스트리 정보
CREATE TABLE mal_reports (
  mal_id TEXT PRIMARY KEY,
  ecosystems TEXT,               -- 이 리포트가 다루는 전체 생태계 (콤마 구분, 예: "npm,PyPI") - 손실 없이 전부 기록
  collected_at TEXT,             -- 처음 감지한 시각 (우리 파이프라인 자체 값, 초 단위)
  download_attempted_at TEXT,    -- 이 리포트의 모든 버전 다운로드 시도가 끝난 시각 (NULL=진행중, 초 단위)
  success_count INTEGER DEFAULT 0,   -- 확보한 파일 개수 (collected_artifacts 조인 없이 조회용)
  osv_withdrawn_at TEXT,         -- NULL=유효, 값 있으면 철회(오탐 등) — verify.py만 갱신, OSV 원본값
  osv_last_checked_at TEXT,      -- 마지막 재검증 시각 (verify.py, 우리 파이프라인 자체 값, 초 단위)
  osv_modified_at TEXT,          -- OSV 리포트 마지막 수정일 (중복 처리 방지에 사용, OSV 원본값)
  osv_credits_finder TEXT,       -- report.json의 credits 중 type=FINDER인 이름
  osv_published_at TEXT,         -- OSV 등록일 ("발견일"의 근사치로 사용 — 정확한 발견일 필드는 OSV에 없음, OSV 원본값)
  earliest_registry_published_at TEXT  -- 이 리포트 버전들 중 레지스트리 최초 게시일 (성공/실패 무관하게 수집, 레지스트리 원본값)
);

-- 실제로 다운로드에 성공한 (패키지, 버전) 조합만 존재 (실패는 즉시 삭제, 재시도 없음)
CREATE TABLE collected_artifacts (
  mal_id TEXT REFERENCES mal_reports(mal_id),
  registry TEXT,                 -- 이 샘플을 실제로 수집한 레지스트리 (예: npm) - 미러 없이 원본만 쓰므로 source 컬럼은 제거함
  package_name TEXT,
  version TEXT,
  download_status TEXT,          -- 'pending'(시도 전) 또는 'success'만 존재
  osv_verification_status TEXT,  -- NULL / 'withdrawn' / 'mismatch' — verify.py만 갱신
  downloaded_at TEXT,             -- 우리가 이 파일을 다운로드한 시각 (초 단위)
  registry_published_at TEXT,    -- 레지스트리에 이 버전이 실제 게시된 시각 (osv_published_at과 다름, 원본 정밀도 유지)
  file_path TEXT,
  sha256 TEXT,
  UNIQUE(mal_id, package_name, version, registry)
);

-- GitHub diff 감지 체크포인트 (key-value)
CREATE TABLE sync_state (
  key TEXT PRIMARY KEY,        -- 'github_last_seen_sha'
  value TEXT
);
```

### `ecosystems`(mal_reports) vs `registry`(collected_artifacts) — 왜 이름이 다른가
초기엔 `mal_reports`에도 `registry`라는 단일값 컬럼을 뒀는데, 리포트가 여러 생태계에 걸칠 수 있어서(예: npm과 PyPI 양쪽에 같은 리포트가 걸리는 경우) 대표 1개만 저장하면 정보 손실이 생김. 그래서 `mal_reports.ecosystems`(복수형, 콤마로 구분된 전체 목록)로 교체하고, `collected_artifacts.registry`(단수형, 그 행 하나가 실제로 수집된 정확한 레지스트리)는 그대로 둬서 **이름 자체로 "요약값 vs 정확값"이 구분되게** 함.

### 타임스탬프 정밀도 원칙
- **OSV/레지스트리 원본값**(`osv_*`, `registry_published_at`, `earliest_registry_published_at`): 원본 그대로 보존 (마이크로초 등 원본 정밀도 유지 — 임의로 깎으면 원본과 비교/재검증 시 어긋날 수 있음)
- **우리 파이프라인이 직접 생성하는 값**(`collected_at`, `download_attempted_at`, `downloaded_at`, `osv_last_checked_at`): 초 단위로 단순화 (5분 주기 파이프라인에서 마이크로초 단위 구분은 분석 가치가 없음)

### `registry_published_at` / `earliest_registry_published_at`: 레지스트리 실제 게시일
`mal_reports.osv_published_at`(OSV 등록일)과는 별개로, **그 버전이 레지스트리에 실제 게시된 시각**을 기록한다. 레지스트리별 조회 방법(`registries/*.py`의 `get_published_at()`, 파일 재다운로드 없이 메타데이터만 조회):

| 레지스트리 | 방법 |
|---|---|
| PyPI, Packagist, Pub | 다운로드 URL을 찾으려고 이미 호출하는 메타데이터 응답에 포함돼 있어 추가 호출 없음 |
| npm, RubyGems, crates.io, NuGet, Go, Hex | 추가 API 호출 1회로 조회 |
| Maven | 전용 필드가 없어 HTTP `Last-Modified` 헤더(HEAD 요청)로 근사 |

**다운로드 성공/실패와 무관하게 조회를 시도한다** — 실사용 검증 결과, npm은 파일(tarball)이 막혀서 다운로드가 실패해도 버전 게시 이력(`time` 메타데이터)은 남아있는 경우가 확인됨. 그래서:
- `collected_artifacts.registry_published_at`: 다운로드 **성공한** 버전에 한해 기록
- `mal_reports.earliest_registry_published_at`: 그 리포트의 **모든 버전**(다운로드 성공/실패 무관)을 대상으로 게시일 조회를 시도해, 그중 가장 이른 값을 리포트 단위로 요약 기록 (`download_pending()`에서 매 버전 처리 시 자동 갱신)

부가 정보라 조회 실패해도 다운로드 자체의 성공/실패 판정에는 영향 없고, 값만 NULL로 남는다.

### 왜 실패한 버전을 남기지 않는가
목적이 "악성 패키지 **파일** 수집"이지 시도 기록 자체가 아니므로, 실패한 `collected_artifacts` 행은 즉시 삭제한다. "언제 시도했는지"는 `mal_reports.download_attempted_at` 하나로 충분히 추적 가능하다 (버전별로 남길 필요 없음). 다만 게시일만은 예외로, 위와 같이 실패해도 `mal_reports` 쪽에 요약 반영한다.

### 파일을 하나도 못 구한 리포트
`report.json`/폴더는 삭제하되(연구 대상이 아니므로), **`mal_reports` SQL 행은 유지**한다. 이유:
1. `report.json` 내용은 GitHub/OSV에 원본이 남아있어 `mal_id`만 기억하면 나중에 다시 조회 가능
2. GitHub diff 기반 감지는 체크포인트가 앞으로만 이동하므로 정상 운영 중엔 같은 리포트를 재감지할 일이 없지만, 수동으로 과거 구간을 재스캔할 경우 SQL 기록이 없으면 이미 실패한 걸 다시 시도하는 헛수고가 발생함

### 오탐(철회)된 리포트도 다운로드한다
`withdrawn` 값이 있어도 다운로드는 그대로 진행한다. 오탐 사례 자체가 연구에 참고 자료가 될 수 있기 때문. 철회 여부 판단은 온전히 트랙 B(`verify.py`)의 몫이며, 트랙 A(감지/다운로드)는 `withdrawn` 값을 다운로드 여부 결정에 사용하지 않는다.

## 트랙 A: 감지 & 다운로드 (`collect.py`)

### 감지 신호: GitHub 우선, OSV는 재검증 전용
OSV.dev의 importer는 GitHub 등 소스를 15분 주기로만 폴링해 반영하는 구조적 지연이 있다. `ossf/malicious-packages`(GitHub)가 원본(canonical)이므로 감지는 GitHub에서 직접 한다 (OSV.dev API는 트랙 B 전용).

### 첫 실행: 벌크 zip 백필
`sync_state`에 체크포인트가 없으면(첫 실행) 그해(`MAL-<연도>-*`) 리포트 전체를 백필한다.
- **방식**: 지원하는 10개 레지스트리 각각의 OSV 벌크 zip(`gs://osv-vulnerabilities/<생태계>/all.zip`)을 다운로드해 로컬에서 `MAL-<연도>-*.json`만 필터링.
- **왜 zip인가**: GitHub 트리 API는 대량 조회 시 응답이 잘릴(truncated) 수 있고, OSV 리포트를 개별 파일로 하나씩 요청하는 것도 왕복 지연시간 때문에 매우 느림 (실측: 292건 개별 조회는 1시간 넘게 걸림 vs zip 10개 생태계 전체는 2분 미만). `modified_id.csv` 색인을 거쳐 개별 조회하는 방식도 시도했으나 같은 이유로 zip으로 교체함.
- 백필이 끝나면 그 시점 GitHub HEAD 커밋을 체크포인트로 저장하고, 이후부터는 diff 모드로 전환.

### 정상 운영: GitHub diff (5분 주기)
`GET /compare/{last_sha}...{head_sha}`로 `osv/malicious/` 아래 변경 파일만 조회. 가볍고 빠름.

**잘림 방지**: 변경 파일이 250개 이상이면(GitHub API가 300개 근처에서 응답을 자를 수 있음) diff 결과를 신뢰하지 않고 자동으로 벌크 zip 백필로 대체한다 (PC가 오래 꺼져있던 경우 등 대비). 이미 처리된 리포트는 `osv_modified_at` 비교로 스킵되므로 안전하게 재실행 가능.

### 버전 결정 로직
리포트의 `affected[]` 항목마다:
1. **명시적 버전 목록**(`versions`)이 있으면 그대로 사용
2. 없고 범위(`ranges`)에 **상한**(`fixed`/`last_affected`)이 있으면 → 일부 버전만 악성이라는 뜻이므로 **스킵** (전체 버전을 받으면 정상 버전을 잘못 수집할 위험). 실측 기준 이런 케이스는 0.2%뿐.
3. 없고 범위에 상한이 없으면("전 버전이 악성") → 레지스트리에서 게시된 **전체 버전 목록을 조회해 전부 다운로드**. 실측 기준 이런 케이스의 99.8%가 여기 해당.

### 다운로드: 원본만, 미러 없음
`registries/*.py`가 레지스트리별 원본 다운로드 + `list_versions()`(위 3번 케이스용)를 구현. **미러 폴백은 없음** — jsDelivr(npm), Software Heritage(범용) 둘 다 검증해봤으나 필요한 시점에 콘텐츠가 없거나(SWH는 크롤링 주기가 삭제 속도를 못 따라감) 악성 코드가 이미 제거된 상태(jsDelivr, 12건 전수조사 100% 무해 파일만 남음)라 무의미했음.

### 다운로드 완료 판정 (즉시 처리)
`download_pending()`이 파일 하나를 처리할 때마다 그 자리에서 바로 확인: 그 리포트에 남은 `pending`이 없으면 즉시 `download_attempted_at` 기록 + 성공 0건이면 폴더 삭제. (전체 배치가 끝난 뒤 한꺼번에 처리하면 "처리 시각"이 부정확해지므로 인라인으로 처리) 실행이 중간에 끊겨 인라인 처리를 못 받은 리포트는 다음 실행 끝의 안전망(`finalize_reports`)이 훑어서 정리.

## 트랙 B: 재검증 (`verify.py`, on-demand)

**대상**: `success_count > 0`인 리포트만 (파일 없는 리포트는 검증할 대상이 없음).

각 대상마다:
1. OSV API로 최신 리포트 조회, `osv_last_checked_at`은 결과와 무관하게 항상 갱신
2. `mal_reports.osv_modified_at`과 비교해 변경 없으면 종료
3. 변경 있으면 `report.json` 갱신 + `mal_reports.osv_modified_at`/`osv_withdrawn_at` 갱신
4. 철회 상태면 → 이 mal_id의 `collected_artifacts` 전 행을 `osv_verification_status='withdrawn'`
5. 철회 아니면 → 성공한 각 버전이 최신 리포트의 버전 목록에도 있는지 확인 → 없으면 `mismatch`, 있으면 NULL로 리셋 (재검증마다 처음부터 다시 판정하므로 상태 복구도 자동으로 됨)

## 실행 방법

```powershell
python scripts/run_collect.py --loop        # 평소 운영: 5분 주기 반복 (Ctrl+C로 종료)
python scripts/run_collect.py               # 1회만 실행 (테스트/디버깅용)
python scripts/run_collect.py --since-days N  # 테스트용: N일 전 커밋을 기준선으로 diff만 수행
python scripts/run_verify.py                 # 재검증 전체 실행 (연구 사용 전 필수)
python scripts/run_verify.py --mal-id <ID>   # 특정 건만 재검증
```

## 보안 취급 방침
- VM/샌드박스 격리는 두지 않음. 원칙은 "압축 상태 그대로 저장 + 절대 실행/설치하지 않음"만 지키는 것.
- `data/` 폴더는 Windows Defender 검사 제외 대상으로 등록 권장 (안 하면 백신이 다운로드 직후 파일을 자동 삭제해 DB와 실제 파일이 어긋날 수 있음). 검사 제외 상태이므로 실행 금지 원칙을 더 엄격히 지켜야 함.
- `data/` 폴더는 OneDrive 등 클라우드 자동 동기화 폴더 밖에 위치해야 함.

## 알려진 제한사항 / 향후 검토 과제
- 파일 확인용 온디맨드 검증 트랙(DB엔 success로 기록됐는데 실제 파일이 없는 경우 재다운로드 시도)은 설계만 하고 아직 구현 안 함.
- GitHub compare API의 300개 파일 응답 잘림은 250개 임계값으로 회피하고 있으나, 임계값 자체는 근사치.
- 상한 있는 범위(bounded range) 리포트(0.2%)는 의도적으로 스킵 중 — 필요해지면 semver 비교 로직 추가 검토.
- npm 외 레지스트리는 아직 실제 트래픽이 적어(RubyGems/Go/Maven 등 성공 0건) 다운로더 코드의 실전 검증이 npm/PyPI만큼 되지 않음.

## 참고 자료
- ossf/malicious-packages: https://github.com/ossf/malicious-packages
- OSV Data sources: https://google.github.io/osv.dev/data/
- OSV API 사용 예시 (OpenSSF 블로그): https://openssf.org/blog/2026/05/20/detecting-malicious-packages-using-the-osv-api/
- OSV 오탐 철회 사례: https://socket.dev/blog/osv-withdraws-157-malware-reports
