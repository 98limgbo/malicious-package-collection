# 악성 패키지 수집 프로젝트 설계 문서

이 프로젝트의 설계 결정과 그 이유를 기록한 문서. 실행 방법·컬럼 목록 등은 [`README.md`](../README.md) 참고.

## 목차
- [배경 / 목적](#배경--목적)
- [전체 구조 요약](#전체-구조-요약)
- [저장 원칙](#저장-원칙)
- [보존 정책](#보존-정책)
- [수집 (collect.py)](#수집-collectpy)
- [재검증 (verify.py, on-demand)](#재검증-verifypy-on-demand)
- [참고 자료](#참고-자료)

## 배경 / 목적
- 악성 패키지 탐지 연구의 타당성 검증을 위해 npm, PyPI, RubyGems 외 다양한 레지스트리(crates.io, Packagist, Go, Maven, NuGet, Hex, Pub)에서 악성 패키지 **원본 파일**을 수집한다.
- 데이터 소스: [ossf/malicious-packages](https://github.com/ossf/malicious-packages) (GitHub, 원본) / [OSV.dev](https://osv.dev) (재검증용 API)
- 핵심 제약: 악성 패키지는 보고된 후 원본 레지스트리에서 빠르게(수시간~수일 내) 삭제되는 경향이 있어, 최대한 빠르게 감지하고 다운로드해야 한다.

## 전체 구조 요약

- **수집(`collect.py`)**: 새로운 악성 패키지 리포트가 보고됐는지 감지하고, 발견되면 즉시 다운로드 시도. GitHub diff로 5분 주기 자동 반복 실행한다.
- **재검증(`verify.py`)**: 이미 수집한 리포트가 철회되지 않았는지, 수집한 버전이 최신 리포트의 버전 목록과 여전히 일치하는지 OSV API로 확인. 자동 스케줄 없이 필요할 때 수동 실행한다.

## 저장 원칙
- `data/<registry>/<MAL-ID>/` 구조로 저장한다. 한 리포트가 여러 생태계·여러 버전의
  패키지를 포함할 수 있기 때문에, MAL-ID 단위 폴더로 나눠야 재수집 시 어떤 파일이
  어느 리포트에 속하는지 구분되고 덮어쓰기 기준도 명확해진다.
- 다운로드한 원본 파일(tarball/zip/jar 등)은 압축을 풀지 않고 그대로 저장한다.
  압축을 풀면 그 안의 실행 파일이 노출되어 실수로 실행될 위험이 커지기 때문이다.
- **OSV/레지스트리 원본값**(`osv_*`, `registry_published_at`, `earliest_registry_published_at`)은
  원본 그대로 보존한다 (마이크로초 등 원본 정밀도를 임의로 깎으면 원본과 비교/재검증 시 어긋날 수 있다).
- **우리 파이프라인이 직접 생성하는 값**(`collected_at`, `download_attempted_at`, `downloaded_at`,
  `osv_last_checked_at`)은 초 단위로 단순화한다 (5분 주기 파이프라인에서 마이크로초 단위 구분은
  분석 가치가 없다).

## 보존 정책

### 오탐(철회)된 리포트도 다운로드한다
`withdrawn` 값이 있어도 다운로드는 그대로 진행한다. 오탐 사례 자체가 연구에 참고
자료가 될 수 있기 때문이다. 철회 여부 판단은 온전히 재검증(`verify.py`)의 몫이며,
수집(`collect.py`)은 `withdrawn` 값을 다운로드 여부 결정에 사용하지 않는다.

### 실패한 버전은 남기지 않는다
목적이 "악성 패키지 **파일** 수집"이지 시도 기록 자체가 아니므로, 실패한
`collected_artifacts` 행은 즉시 삭제한다. "언제 시도했는지"는
`mal_reports.download_attempted_at` 하나로 충분히 추적 가능하다 (버전별로 남길
필요는 없다).

### 파일을 하나도 못 구한 리포트도 SQL 행은 유지한다
`report.json`/폴더는 삭제하되(연구 대상이 아니므로), `mal_reports` SQL 행은
유지한다. 이유:
1. `report.json` 내용은 GitHub/OSV에 원본이 남아있어 `mal_id`만 기억하면 나중에
   다시 조회할 수 있다.
2. GitHub diff 기반 감지는 체크포인트가 앞으로만 이동하므로 정상 운영 중엔 같은
   리포트를 재감지할 일이 없지만, 수동으로 과거 구간을 재스캔할 경우 SQL 기록이
   없으면 이미 실패한 걸 다시 시도하는 헛수고가 발생한다.

## 수집 (`collect.py`)

### 감지 신호: GitHub 우선, OSV는 재검증 전용
OSV.dev의 importer는 GitHub 등 소스를 15분 주기로만 폴링해 반영하는 구조적 지연이 있다. `ossf/malicious-packages`(GitHub)가 원본(canonical)이므로 감지는 GitHub에서 직접 한다 (OSV.dev API는 재검증 전용).

### 첫 실행: 벌크 zip 백필
`sync_state`에 체크포인트가 없으면(첫 실행) 그해(`MAL-<연도>-*`) 리포트 전체를 백필한다.
- **방식**: 지원하는 10개 레지스트리 각각의 OSV 벌크 zip(`gs://osv-vulnerabilities/<생태계>/all.zip`)을 다운로드해 로컬에서 `MAL-<연도>-*.json`만 필터링.
- **왜 zip인가**: GitHub 트리 API는 대량 조회 시 응답이 잘릴(truncated) 수 있고, OSV 리포트를 개별 파일로 하나씩 요청하는 것도 왕복 지연시간 때문에 매우 느림 (실측: 292건 개별 조회는 1시간 넘게 걸림 vs zip 10개 생태계 전체는 2분 미만). `modified_id.csv` 색인을 거쳐 개별 조회하는 방식도 시도했으나 같은 이유로 zip으로 교체함.
- 백필이 끝나면 그 시점 GitHub HEAD 커밋을 체크포인트로 저장하고, 이후부터는 diff 모드로 전환. 다른 연도를 나중에 채우고 싶으면 `scripts/backfill_year.py`(README 참고)로 별도 실행.

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

## 재검증 (`verify.py`, on-demand)

**대상**: `success_count > 0`인 리포트만 (파일 없는 리포트는 검증할 대상이 없음).

각 대상마다:
1. OSV API로 최신 리포트 조회, `osv_last_checked_at`은 결과와 무관하게 항상 갱신
2. `mal_reports.osv_modified_at`과 비교해 변경 없으면 종료
3. 변경 있으면 `report.json` 갱신 + `mal_reports.osv_modified_at`/`osv_withdrawn_at` 갱신
4. 철회 상태면 → 이 mal_id의 `collected_artifacts` 전 행을 `osv_verification_status='withdrawn'`
5. 철회 아니면 → 성공한 각 버전이 최신 리포트의 버전 목록에도 있는지 확인 → 없으면 `mismatch`, 있으면 NULL로 리셋 (재검증마다 처음부터 다시 판정하므로 상태 복구도 자동으로 됨)

## 참고 자료
- ossf/malicious-packages: https://github.com/ossf/malicious-packages
- OSV Data sources: https://google.github.io/osv.dev/data/
- OSV API 사용 예시 (OpenSSF 블로그): https://openssf.org/blog/2026/05/20/detecting-malicious-packages-using-the-osv-api/
- OSV 오탐 철회 사례: https://socket.dev/blog/osv-withdraws-157-malware-reports
