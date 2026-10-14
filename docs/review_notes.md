# 검토 기록

`collected_artifacts.review_label`에 값을 넣은 리포트와 패키지별로 판단 근거를 기록한 문서이다. 라벨은 수집 루프가 만들지 않고, 사람이 리포트와 파일을 확인한 뒤 가끔 채운다. 판단 단위는 리포트가 아니라 파일(패키지-버전)이다. 한 리포트 안에 진짜 악성 버전과 오탐 버전이 섞일 수 있기 때문이다. 근거는 정적 점검(코드를 실행하지 않음)만으로 확인한 것이다. 더 일반적인 품질 이슈는 [`data_quality_notes.md`](data_quality_notes.md)를 참고한다.

## 라벨의 의미

| 값 | 의미 |
|---|---|
| `NULL` | 아직 검토하지 않음 |
| `confirmed_malicious` | 검토했고 악성이 맞음 |
| `false_positive` | 검토했고 이 파일에는 악성 동작이 없다고 판단함 (위악성) |
| `research_poc` | 검토했고 동작은 악성과 같지만 의도는 승인된 보안 연구임 |

## 위악성 (`false_positive`)

### MAL-2026-5186 `autotel-terminal` (22.0.0, 22.0.1, 23.0.0, 23.0.1, 23.0.2)

리포트는 탐지 출처 3개가 병합된 형태이다. ghsa-malware는 범위 `introduced: 0`만 있고 정형 문구뿐이다. google-open-source-security는 22개 버전(`2.1.1`~`23.0.3`)을 명시하며 `binding.gyp`를 악용하는 웜 Miasma로 설명한다. amazon-inspector는 27개 버전(`22.0.0`~`37.0.0`)을 개별 항목으로 지목한다.

- 보유한 5개 버전은 Google이 명시한 22개 버전에 들어 있지 않고 Inspector가 지목한 버전이다. Google이 명시한 버전은 하나도 받지 못했다.
- Inspector의 설명문이 스스로 한계를 밝힌다. 각 요소가 정상적인 CLI 동작과도 일치하고, 단독으로는 유출이나 원격 코드 실행의 증거가 아니며, 설치 단계의 비밀 정보 접근이 공격자 서버와 연결되지 않았고, 생명주기 스크립트가 해당 코드를 호출하지 않으며, 외부 C2 호스트도 없다고 적고 있다.
- 보유한 `22.0.1`의 tarball sha1과 sha512가 리포트의 패키지 무결성 값과 같다. 즉 Inspector가 평가한 파일과 같은 파일이다. 증거 파일로 지목된 `dist/cli.cjs`와 `dist/cli.js`의 sha256도 5개 버전 모두 리포트 값과 같다.
- 5개 버전에는 `binding.gyp`와 `preinstall`/`install`/`postinstall`/`prepare` 스크립트가 없다.
- Inspector가 든 세 단서는 `22.0.1`의 `dist/cli.js`에서 정상 코드로 설명된다. base64 디코딩 1곳은 식별자를 16진 문자열로 정규화하는 코드이다. POST 1곳은 `req.method !== "POST" || !OTLP_ROUTES.has(req.url)`이면 404를 돌려주는 로컬 OpenTelemetry 수신 서버의 요청 처리이다. 'ping' 2곳은 모두 `//# sourceMappingURL=cli.js.map`의 `Mapping` 안에 있는 부분 문자열이다.
- 게시 간격이 5/28, 5/29, 5/31, 6/1, 6/3으로 정상 프로젝트의 릴리스 주기이고, 패키지 저장소는 공개 GitHub(`jagreehal/autotel`)로 연결된다.

한계: 정적 점검만 했고, 코드 정황은 `22.0.1`의 `dist/cli.js`만 읽었다. 이 판단은 보유한 5개 버전에만 해당하며, Google이 지목한 22개 버전은 확인하지 못했다.

## 연구용 PoC (`research_poc`)

Ubiquiti 버그바운티(HackerOne)용 의존성 혼동(dependency confusion) 개념증명 4개 리포트이다. 보유 파일은 10개이고 모두 리포트가 버전을 직접 명시했다(`is_explicit_version=1`).

| 리포트 | 패키지 | 보유 버전 |
|---|---|---|
| MAL-2026-5286 | `encrypted-archive` | `0.0.2-security-research`, `99.0.0` |
| MAL-2026-5287 | `uhd-setup` | `0.0.1-security-research`, `99.0.0` |
| MAL-2026-5288 | `uisp-connector` | `0.0.1-security-research`, `0.0.2-security-research`, `99.0.0` |
| MAL-2026-5289 | `unifi-portal` | `0.0.1-security-research`, `0.0.2-security-research`, `99.0.0` |

- 10개 파일 모두 README에 "authorized security research"이고 "NOT malicious software"라는 문구와 HackerOne 연락처가 있다.
- 10개 파일 모두 `package.json`에 `preinstall: node index.js || true`가 있다. `unifi-portal`의 `index.js`는 설치 시점에 외부 수집 서버(`oast.me`, Interactsh)로 DNS 조회와 HTTPS 요청을 보낸다. 설치한 쪽의 공개 IP, 호스트명 기반 ID, 설치 시각이 동의 없이 전송된다.
- 버전을 `99.0.0`으로 높게 올려서 같은 이름의 내부 패키지보다 먼저 설치되게 하는 전형적인 의존성 혼동 방식이다.
- Amazon Inspector가 설명에서 연구 목적이라는 표방이 영향 범위를 제한하지 않는다고 명시한다. `MAL-2026-5289`는 OpenSSF Package Analysis도 지목했다.
- 따라서 이 파일들은 오탐이 아니다. 동작은 악성 패키지와 같고 의도만 연구이다. 라벨을 동작 기준으로 둘지 의도 기준으로 둘지에 따라 해석이 달라지므로 별도 값으로 구분했다.

## 후보 탐색 방법과 검증

`scripts/find_review_candidates.py`는 로컬에 남은 리포트의 `details`(탐지 도구가 쓴 설명문)에서 후보를 찾아 걸린 문장과 함께 출력한다. DB는 읽지도 쓰지도 않고, 라벨은 사람이 문장을 읽은 뒤 직접 채운다. 코드를 실행하지 않는 정적 분석이므로 판정이 아니라 후보를 좁히는 용도이다.

찾는 표현은 두 가지이다.
- 한계 인정 표현(`hedge`): 탐지 도구가 스스로 근거가 부족하다고 쓴 구절이다(`does not establish`, `not, on their own, evidence`, `warrants human review`, `consistent with legitimate`, `not evidence of`). 위악성 후보이다.
- 자기 표방 언급(`self-label`): 작성자가 연구나 PoC라고 표방했다는 언급이다(`authorized research`, `benign PoC`, `bug bounty`, `proof-of-concept`, `security research`, `self-labeled` 등). 연구용 PoC 후보이다.

2026-10-14에 로컬 리포트 63,881건을 대상으로 실행한 결과와 검증은 다음과 같다.

| 종류 | 후보 수 | 검증 | 정밀도 |
|---|---|---|---|
| `hedge` | 2건 | 전수 확인 | 2/2 |
| `self-label` | 68건 | 무작위 24건(`--sample 24 --seed 1`) 확인 | 21/24 (87.5%) |

`hedge` 후보는 `MAL-2026-5186`(`autotel-terminal`)과 `MAL-2026-5255`(`executable-stories-mcp`)이다. 두 번째는 아직 검토하지 않았다. `self-label` 표본 24건 중 3건은 작성자의 표방이 아니라 탐지 도구가 PoC로 추정한 문장이거나("any self-description as authorized research is contradicted by...") 가정 문장이었다.

해석할 때 주의할 점은 다음과 같다.
- 표방이 있다고 해서 승인된 연구용이라는 뜻이 아니다. 표본의 걸린 문장 대부분에서 탐지 도구가 "표방은 동작을 바꾸지 않는다"고 명시했고, 같은 문구("Security Research Testing Purpose")를 쓰면서 외부 서버의 코드를 내려받게 하는 실제 공격 사례(`modules-newline`, `css-import-order` 등)도 있었다. 승인 여부는 설치하는 쪽이 확인할 수 없다.
- 재현율은 모른다. 영어 표현만 보고 표현이 다르면 놓친다.
- 처음에 시도한 넓은 키워드는 노이즈가 많아서 버렸다. `benign`은 69건 중 65건이 "해석의 여지가 없다", "정상 유틸리티를 사칭" 같은 악성이라는 설명 속 단어였다. `dependency-confusion`은 연구용이 아니라 실제 정찰용 비콘의 공격 형태를 가리켰다. `authorized`는 `unauthorized`와 `rejectUnauthorized`에 걸렸다.

## 조회 예시

```sql
-- 위악성으로 판단한 파일 제외
SELECT * FROM collected_artifacts
WHERE download_status = 'success'
  AND (review_label IS NULL OR review_label NOT IN ('false_positive'));

-- 연구용 PoC까지 제외
SELECT * FROM collected_artifacts
WHERE download_status = 'success'
  AND (review_label IS NULL OR review_label = 'confirmed_malicious');
```
