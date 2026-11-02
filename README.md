# malicious-package-collection

악성 패키지 탐지 연구용 데이터셋 수집 도구. 설계 배경과 결정 근거, 수집하지 않는 대상은 [`docs/design.md`](docs/design.md)에 있다.

## 빠른 시작

```powershell
pip install -r requirements.txt
python scripts/run_collect.py --loop
```

## 스크립트

| 스크립트 | 용도 | 주요 옵션 | 자세한 설명 |
|---|---|---|---|
| `scripts/run_collect.py` | OSV 리포트를 감지해 패키지를 수집한다. 시작할 때 수집한 파일을 현재 리포트와 대조하는 점검(`osv_verification_status`)을 한 번 하고, 5분 주기 루프에서는 반복하지 않는다 | `--loop`: 5분마다 반복 (Ctrl+C로 종료)<br>옵션 없음: 1사이클만 실행<br>`--since-days N`: 첫 실행 시 전체 백필 대신 N일 전 커밋을 기준선으로 diff만 수행 | [`docs/design.md`](docs/design.md) |
| `scripts/backfill_year.py <연도>` | 최초 실행이 채우는 최신 연도 외에 다른 연도를 채운다 (예: `2025`). 수집 루프를 먼저 멈춰야 한다 | 연도 (위치 인자) | [`docs/design.md`](docs/design.md) |
| `scripts/backup_db.py` | `backups/`에 로컬 DB 스냅샷을 남긴다. `data/`의 패키지 파일은 백업하지 않는다 | 없음 | [`docs/design.md`](docs/design.md) |
| `scripts/find_review_candidates.py` | 리포트 설명문에서 위악성 후보를 찾는다. 판정이 아니라 후보를 좁히는 용도이며 읽기 전용이다 | `--sample N --seed S`: 무작위 표본<br>`--count`: 개수만 출력 | [`docs/review_notes.md`](docs/review_notes.md) |
| `scripts/label_campaign.py` | `tea.xyz` 캠페인처럼 양이 많은 패키지에 문구 규칙으로 `review_label`(`tea_token`)을 일괄 부여한다. 라벨이 빈 파일만 채우므로 새로 수집한 뒤 다시 실행하면 된다 | 기본: 집계만<br>`--apply`: 라벨 부여 | [`docs/review_notes.md`](docs/review_notes.md) |

## 데이터 구조

```
data/<registry>/<MAL-ID>/report.json     # OSV 원본. 파일을 하나도 못 구하면 이 폴더 자체가 없음
data/<registry>/<MAL-ID>/artifacts/      # 압축 원본 + sha256 (성공한 버전만)
index.sqlite                             # mal_reports / collected_artifacts / sync_state
backups/                                 # 로컬 DB 스냅샷 (git 제외)
```

### `mal_reports` (리포트 단위, mal_id당 1행)

- `mal_id`: OSV 리포트 ID (기본키)
- `ecosystems`: 이 리포트가 다루는 전체 생태계 목록 (콤마 구분, 예: `npm,PyPI`)
- `collected_at`: 이 리포트를 처음 감지한 시각
- `download_attempted_at`: 모든 버전 다운로드 시도가 끝난 시각 (NULL=아직 진행 중)
- `success_count`: 확보한 파일 개수
- `osv_withdrawn_at`: OSV가 철회한 시각이고 NULL이면 유효. 철회된 리포트는 수집하지 않으므로 파일이 없고 기록만 남는다. 수집 루프가 리포트를 처리할 때 갱신한다
- `osv_last_checked_at`: OSV 리포트를 마지막으로 처리(가져오거나 갱신을 다시 반영)한 시각
- `osv_modified_at`: OSV 리포트 마지막 수정일 (중복 처리 방지용)
- `osv_credits_finder`: report.json의 credits 중 type=FINDER인 이름
- `osv_published_at`: OSV 등록일 ("발견일"의 근사치)
- `earliest_registry_published_at`: 이 리포트가 다루는 버전들 중 레지스트리 최초 게시일 (다운로드 성공/실패와 무관하게 수집하고, npm 보안 홀딩 더미의 게시일은 제외)

### `collected_artifacts` (패키지-버전 단위, 파일 하나당 1행)

- `mal_id`: 소속 리포트 (mal_reports 참조)
- `registry`: 이 샘플을 실제로 수집한 레지스트리 (예: npm)
- `package_name`: 패키지 이름
- `version`: 버전
- `is_explicit_version`: 1이면 OSV 리포트가 이 버전을 직접 명시한 것이고, 0이면 상한 없는 범위라서 수집 시점에 레지스트리의 버전을 나열해서 받은 것
- `download_status`: `pending`(시도 전) 또는 `success`만 존재
- `osv_verification_status`: 이 파일이 현재 OSV 리포트와 맞는지를 나타낸다. NULL이면 맞거나 점검 대상이 아니고, `mismatch`는 리포트가 이 패키지의 버전을 직접 명시하는데 이 파일의 버전이 그 목록에 없다는 뜻이다.
- `review_label`: 이 파일을 검토하거나 분류한 결과. NULL이면 미검토이고, `confirmed_malicious`(악성이 맞음), `false_positive`(위악성), `research_poc`(동작은 악성이지만 의도는 승인된 연구), `tea_token`(`tea.xyz` 토큰 보상 캠페인 패키지) 중 하나이다. 수집 루프는 건드리지 않고, 판단 근거와 부여 규칙은 [`docs/review_notes.md`](docs/review_notes.md)에 기록한다
- `downloaded_at`: 우리가 이 파일을 다운로드한 시각
- `registry_published_at`: 레지스트리에 이 버전이 실제 게시된 시각
- `file_path`: 로컬 저장 경로
- `sha256`: 파일 해시

### `sync_state`

- `key`: 설정 키 (GitHub diff 감지 체크포인트 등)
- `value`: 값

**필드명 규칙**: `osv_*` 접두어=OSV 리포트에서 온 값, `registry_*`/`registry`=패키지 레지스트리에서 온 값, 접두어 없음=우리 파이프라인 자체 값. 우리 파이프라인이 생성하는 시각(`collected_at` 등)은 초 단위, OSV·레지스트리 원본 시각은 원본 정밀도 그대로 보존.

자세한 설계 근거는 [`docs/design.md`](docs/design.md), 데이터를 연구에 쓰기 전에 알아둘 품질 이슈는 [`docs/data_quality_notes.md`](docs/data_quality_notes.md) 참고.
