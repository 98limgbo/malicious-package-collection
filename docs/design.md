# 악성 패키지 수집 프로젝트 설계 문서

이 프로젝트의 설계 결정과 그 이유를 기록한 문서. 실행 방법·컬럼 목록 등은 [`README.md`](../README.md) 참고.

## 목차
- [배경 / 목적](#배경--목적)
- [전체 구조 요약](#전체-구조-요약)
- [저장 원칙](#저장-원칙)
- [보존 정책](#보존-정책)
  - [철회된 리포트는 다운로드하지 않는다](#철회된-리포트는-다운로드하지-않는다)
  - [실패한 버전은 남기지 않는다](#실패한-버전은-남기지-않는다)
  - [파일을 하나도 못 구한 리포트도 SQL 행은 유지한다](#파일을-하나도-못-구한-리포트도-sql-행은-유지한다)
- [수집 (collect.py)](#수집-collectpy)
  - [감지 신호: GitHub 우선](#감지-신호-github-우선)
  - [첫 실행: 벌크 zip 백필](#첫-실행-벌크-zip-백필)
  - [정상 운영: GitHub diff (5분 주기)](#정상-운영-github-diff-5분-주기)
  - [버전 결정 로직](#버전-결정-로직)
  - [다운로드 완료 판정](#다운로드-완료-판정)
- [백업](#백업)
- [참고 자료](#참고-자료)

## 배경 / 목적
- 악성 패키지 탐지 연구의 타당성 검증을 위해 npm, PyPI, RubyGems 외 다양한 레지스트리(crates.io, Packagist, Go, Maven, NuGet, Hex, Pub)에서 악성 패키지 **원본 파일**을 수집한다.
- 데이터 소스: [ossf/malicious-packages](https://github.com/ossf/malicious-packages) (GitHub, 원본) / [OSV.dev](https://osv.dev)
- 핵심 제약: 악성 패키지는 보고된 후 원본 레지스트리에서 빠르게(수시간~수일 내) 삭제되는 경향이 있어, 최대한 빠르게 감지하고 다운로드해야 한다.

## 전체 구조 요약

- **수집(`collect.py`)**: 새로운 악성 패키지 리포트가 보고됐는지 감지하고, 발견되면 즉시 다운로드 시도. GitHub diff로 5분 주기 자동 반복 실행한다.
- **시작 점검(`startup_checks()`)**: 프로그램을 시작할 때 한 번만, 수집한 파일의 버전이 현재 리포트의 명시 목록과 맞는지 대조해서 `osv_verification_status`에 기록한다.
- **검토 라벨(`review_label`)**: 파일이 실제로 악성인지, 어떤 종류인지를 확인하거나 규칙으로 분류한 결과이다. 후보 탐색(`find_review_candidates.py`)과 캠페인 일괄 부여(`label_campaign.py`)는 사람이 직접 실행하고, 수집 루프는 건드리지 않는다.
- **백업(`backup_db.py`)**: 수집 중에도 안전하게 DB 스냅샷을 만든다. ([백업](#백업) 참고)

## 저장 원칙
- `data/<registry>/<MAL-ID>/` 구조로 저장한다. 한 리포트가 여러 생태계·여러 버전의
  패키지를 포함할 수 있기 때문에, MAL-ID 단위 폴더로 나눠야 재수집 시 어떤 파일이
  어느 리포트에 속하는지 구분되고 덮어쓰기 기준도 명확해진다.
- 다운로드한 원본 파일(tarball/zip/jar 등)은 압축을 풀지 않고 그대로 저장한다.
- **OSV/레지스트리 원본값**(`osv_*`, `registry_published_at`, `earliest_registry_published_at`)은 원본 그대로 보존한다.
- **우리 파이프라인이 직접 생성하는 값**(`collected_at`, `download_attempted_at`, `downloaded_at`, `osv_last_checked_at`)은 초 단위로 기록한다.

## 보존 정책

### 철회된 리포트는 다운로드하지 않는다
`withdrawn` 값이 있는 리포트는 OSV가 오탐으로 인정한 것이므로 악성이라는 근거가 없다. 그래서 `mal_reports`에 기록만 남기고 `collected_artifacts`는 만들지 않으며 파일도 받지 않는다. 수집한 뒤에 리포트가 철회되면 갱신을 감지한 시점에 기존 파일과 폴더도 삭제한다. 철회 사실 자체는 `osv_withdrawn_at`에 남는다.

### 실패한 버전은 남기지 않는다
목적이 "악성 패키지 **파일** 수집"이지 시도 기록 자체가 아니므로, 실패한
`collected_artifacts` 행은 즉시 삭제한다. "언제 시도했는지"는
`mal_reports.download_attempted_at` 하나로 충분히 추적 가능하다.

### 파일을 하나도 못 구한 리포트도 SQL 행은 유지한다
`report.json`/폴더는 삭제하되, `mal_reports` SQL 행은 유지한다. 이유:
1. `report.json` 내용은 GitHub/OSV에 원본이 남아있어 `mal_id`만 기억하면 나중에
   다시 조회할 수 있다.
2. GitHub diff 기반 감지는 체크포인트가 앞으로만 이동하므로 정상 운영 중엔 같은
   리포트를 재감지할 일이 없지만, 수동으로 과거 구간을 재스캔할 경우 SQL 기록이
   없으면 이미 실패한 걸 다시 시도하는 헛수고가 발생한다.

## 수집 (`collect.py`)

### 감지 신호: GitHub 우선
OSV.dev의 importer는 GitHub 등 소스를 15분 주기로만 폴링해 반영하는 구조적 지연이 있다. `ossf/malicious-packages`(GitHub)가 원본(canonical)이므로 감지는 GitHub에서 직접 한다. OSV.dev API는 쓰지 않고, 백필에만 OSV 벌크 파일을 쓴다.

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
1. **명시적 버전 목록**(`versions`)이 있으면 그대로 사용한다. 이때 `collected_artifacts.is_explicit_version`은 1이다.
2. 없고 범위(`ranges`)에 **상한**(`fixed`/`last_affected`)이 있으면 → 일부 버전만 악성이라는 뜻이므로 **스킵**한다. 전체 버전을 받으면 정상 버전을 잘못 수집할 위험이 있다. 실측 기준 이런 케이스는 전체 리포트의 0.00%(5건)뿐이다.
3. 없고 범위에 상한이 없으면("전 버전이 악성") → 레지스트리에서 게시된 버전과 게시일을 함께 조회하되, **리포트 등록일(`osv_published_at`) 이후에 게시됐거나 게시일을 알 수 없는 버전은 제외**하고 나머지를 다운로드한다. 이때 `is_explicit_version`은 0이다.

#### 왜 등록일 이후 버전을 제외하는가
리포트를 작성한 쪽은 작성 시점에 존재하지 않던 버전을 검토할 수 없다. 그런데 전체조회는 수집 시점의 현재 버전을 모두 나열하기 때문에, 등록 이후에 나온 버전(예: 활발히 운영되는 정상 프로젝트의 이후 릴리스)까지 악성으로 수집한다. 게시일을 알 수 없는 버전은 등록일 이전인지 확인할 수 없으므로 보수적으로 제외한다.

#### 왜 버전 명시 리포트에는 적용하지 않는가
명시 리포트는 시간이 지나면서 악성 버전이 목록에 추가된다. 그래서 등록일 이후에 게시된 버전이 목록에 있는 것이 정상이고, 실제로 명시 방식 파일의 약 28%가 등록일 이후에 게시된 버전이다. OSV가 그 버전을 직접 확인해서 못박은 것이므로 날짜로 걸러내면 오히려 확실한 악성 데이터를 잃는다.

#### 왜 갱신일(`osv_modified_at`)이 아니라 등록일을 기준으로 하는가
갱신일은 "악성임을 다시 확인한 날"이라고 볼 수 없다.
- OSV의 일괄 작업이 여러 리포트의 갱신일을 같은 초로 한꺼번에 바꾸는 사례가 있었다.
- 철회처럼 악성이 아니라고 정정하는 경우에도 갱신일이 바뀐다.

### 다운로드 완료 판정
`download_pending()`이 파일 하나를 처리할 때마다 그 자리에서 바로 확인: 그 리포트에 남은 `pending`이 없으면 즉시 `download_attempted_at` 기록 + 성공 0건이면 폴더 삭제. 

## 백업

`scripts/backup_db.py`는 SQLite의 온라인 백업 API로 DB를 복사한다. 수집 루프가 쓰는 도중에도 커밋된 상태 기준의 일관된 복사본이 만들어지고, 단순 파일 복사처럼 쓰기 중간 상태가 섞일 위험이 없다.

- `backups/index_<날짜시각>.sqlite`는 로컬 스냅샷이고 git에서 제외한다. 분석은 라이브 DB 대신 이 복사본으로 하는 것을 권장한다.
- DB를 git으로 공유하는 기능은 두지 않는다. 필요할 때 스냅샷 하나를 직접 내보내면 되고, 저장소에 DB를 두면 받는 사람이 자신의 DB와 헷갈릴 수 있기 때문이다.

## 참고 자료
- ossf/malicious-packages: https://github.com/ossf/malicious-packages
- OSV Data sources: https://google.github.io/osv.dev/data/
- OSV API 사용 예시 (OpenSSF 블로그): https://openssf.org/blog/2026/05/20/detecting-malicious-packages-using-the-osv-api/
- OSV 오탐 철회 사례: https://socket.dev/blog/osv-withdraws-157-malware-reports
