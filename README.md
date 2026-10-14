# malicious-package-collection

악성 패키지 탐지 연구용 데이터셋 수집 도구. 설계 배경·결정 근거는 [`docs/design.md`](docs/design.md) 참고.

> ⚠️ **경고**: 이 프로젝트를 실행하면 `data/` 폴더에 **실제 악성 코드가 담긴 패키지 원본**이
> 다운로드됩니다. 다운로드된 파일은 **절대 실행/설치하지 마세요** (`npm install`, `pip install`,
> 압축 해제 후 실행 등 금지). `data/` 폴더는 `.gitignore`로 제외되어 이 저장소엔 코드만 포함됩니다.

## 1. 설치

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 2. Windows Defender 검사 제외 (권장)

```powershell
Add-MpPreference -ExclusionPath "$PWD\data"
```

## 3. 수집 실행

```powershell
python scripts/run_collect.py --loop
```

| 옵션 | 동작 |
|---|---|
| `--loop` | 5분마다 계속 반복 실행 (Ctrl+C로 종료). 평소엔 이걸로 실행 |
| (옵션 없음) | 1사이클만 실행 후 종료 |
| `--since-days N` | 첫 실행 시 전체 백필 대신 N일 전 커밋을 기준선으로 diff만 수행 |

최초 실행은 실행 시점 기준 최신 연도(예: 2026)만 백필한다. 다른 연도를 추가로 채우고 싶으면:

```powershell
python scripts/backfill_year.py 2025
```

새해 초에 처음 설치하면 올해 리포트가 거의 없으므로, 지난해 리포트도 필요하면 `python scripts/backfill_year.py <지난해>`로 채운다.

`--loop`가 돌고 있다면 실행 전 잠깐 멈춰두는 것을 권장 (diff 체크포인트를 건드리기 때문. 끝나면 다시 `--loop` 재개).

악성이라는 근거가 없는 파일은 수집 단계에서 걸러진다.
- OSV가 철회한 리포트는 받지 않고, 수집한 뒤에 철회되면 기존 파일을 삭제한다.
- 버전 없이 "전체 버전 악성"으로 등록된 리포트는 리포트 등록일 이후에 게시됐거나 게시일을 알 수 없는 버전을 받지 않는다. 리포트가 버전을 직접 명시한 경우에는 이 기준을 적용하지 않는다.
- npm이 악성 패키지를 지우고 올려둔 빈 플레이스홀더(보안 홀딩 패키지)는 받지 않는다.

이유와 실측은 [`docs/data_quality_notes.md`](docs/data_quality_notes.md)에 있다.

## 4. 재검증

```powershell
python scripts/run_verify.py                          # 전체 재검증
python scripts/run_verify.py --mal-id MAL-2026-8013    # 특정 건만
```

```sql
-- 현재 유효(철회 안 됨)하고 파일이 있는 리포트만
SELECT * FROM mal_reports WHERE osv_withdrawn_at IS NULL AND success_count > 0;

-- 버전 단위 재검증 결과(철회/최신 리포트에서 빠짐)만
SELECT * FROM collected_artifacts WHERE osv_verification_status IS NOT NULL;
```

## 5. 백업과 공유

수집 루프가 DB를 쓰는 중에도 안전하게 복사본을 만들 수 있다. 분석은 원본 대신 이 복사본으로 하는 것을 권장한다.

```powershell
python scripts/backup_db.py             # backups/index_<날짜시각>.sqlite 에 로컬 스냅샷 (git 제외)
python scripts/backup_db.py --publish   # 위에 더해 dataset/index.sqlite(공유용 최신본, git 추적)도 갱신
```

## 6. 위악성 후보 찾기

```powershell
python scripts/find_review_candidates.py                       # 후보와 걸린 문장 출력 (DB는 건드리지 않음)
python scripts/find_review_candidates.py --sample 20 --seed 1  # 무작위 표본 (정밀도 검증용)
```

리포트 설명문에서 탐지 도구가 스스로 근거의 한계를 인정한 표현이나, 작성자가 연구용이라고 표방했다는 언급을 찾는다. 판정이 아니라 후보를 좁히는 용도이며, 검증 결과와 한계는 [`docs/review_notes.md`](docs/review_notes.md)에 있다. 사람이 후보를 확인한 뒤 `collected_artifacts.review_label`을 직접 채운다.

## 데이터 구조

```
data/<registry>/<MAL-ID>/report.json     # OSV 원본. 파일을 하나도 못 구하면 이 폴더 자체가 없음
data/<registry>/<MAL-ID>/artifacts/      # 압축 원본 + sha256 (성공한 버전만)
index.sqlite                             # mal_reports / collected_artifacts / sync_state
backups/                                 # 로컬 DB 스냅샷 (git 제외)
dataset/index.sqlite                     # 공유용 DB 최신본 (--publish로 갱신)
```

### `mal_reports` (리포트 단위, mal_id당 1행)

- `mal_id`: OSV 리포트 ID (기본키)
- `ecosystems`: 이 리포트가 다루는 전체 생태계 목록 (콤마 구분, 예: `npm,PyPI`)
- `collected_at`: 이 리포트를 처음 감지한 시각 (우리 파이프라인)
- `download_attempted_at`: 모든 버전 다운로드 시도가 끝난 시각 (NULL=아직 진행 중)
- `success_count`: 확보한 파일 개수
- `osv_withdrawn_at`: OSV가 철회(오탐 등)한 시각이고 NULL이면 유효. 철회된 리포트는 수집하지 않으므로 파일이 없고 기록만 남는다
- `osv_last_checked_at`: 마지막 재검증 시각 (`run_verify.py`)
- `osv_modified_at`: OSV 리포트 마지막 수정일 (중복 처리 방지용)
- `osv_credits_finder`: report.json의 credits 중 type=FINDER인 이름
- `osv_published_at`: OSV 등록일 ("발견일"의 근사치)
- `earliest_registry_published_at`: 이 리포트가 다루는 버전들 중 레지스트리 최초 게시일 (다운로드 성공/실패와 무관하게 수집하고, npm 보안 홀딩 더미의 게시일은 제외)

### `collected_artifacts` (다운로드 **성공한** "패키지-버전"만 존재)

- `mal_id`: 소속 리포트 (mal_reports 참조)
- `registry`: 이 샘플을 실제로 수집한 레지스트리 (예: npm)
- `package_name`: 패키지 이름
- `version`: 버전
- `is_explicit_version`: 1이면 OSV 리포트가 이 버전을 직접 명시한 것이고, 0이면 상한 없는 범위라서 수집 시점에 레지스트리의 버전을 나열해서 받은 것
- `download_status`: `pending`(시도 전) 또는 `success`만 존재
- `osv_verification_status`: NULL / `withdrawn` / `mismatch`. `run_verify.py`만 갱신
- `review_label`: 사람이 이 파일을 검토한 결과. NULL이면 미검토이고, `confirmed_malicious`(악성이 맞음), `false_positive`(위악성), `research_poc`(동작은 악성이지만 의도는 승인된 연구) 중 하나이다. 수집 루프는 건드리지 않고, 판단 근거는 [`docs/review_notes.md`](docs/review_notes.md)에 기록한다
- `downloaded_at`: 우리가 이 파일을 다운로드한 시각
- `registry_published_at`: 레지스트리에 이 버전이 실제 게시된 시각
- `file_path`: 로컬 저장 경로
- `sha256`: 파일 해시

### `sync_state`

- `key`: 설정 키 (GitHub diff 감지 체크포인트 등)
- `value`: 값

**필드명 규칙**: `osv_*` 접두어=OSV 리포트에서 온 값, `registry_*`/`registry`=패키지 레지스트리에서 온 값, 접두어 없음=우리 파이프라인 자체 값. 우리 파이프라인이 생성하는 시각(`collected_at` 등)은 초 단위, OSV·레지스트리 원본 시각은 원본 정밀도 그대로 보존.

자세한 설계 근거는 [`docs/design.md`](docs/design.md), 데이터를 연구에 쓰기 전에 알아둘 품질 이슈는 [`docs/data_quality_notes.md`](docs/data_quality_notes.md) 참고.
