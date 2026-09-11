# Burp Sensitive Scanner

Burp Suite에 쌓인 HTTP 트래픽에서 API key, access token, private key, database credential 같은 민감정보를 찾는 수동 분석용 Extension입니다.

Proxy History와 Site Map을 다시 읽을 수 있으며, Extension을 로드한 뒤 발생한 Burp 트래픽도 수집합니다. 과거 Logger 데이터는 Burp에서 내보낸 CSV 파일로 가져올 수 있습니다. 모든 분석은 **Scan Existing Traffic**을 눌렀을 때 시작됩니다.

Crawler나 Active Scanner는 포함하지 않습니다. 대상 서버로 요청을 만들거나 전송하지 않고, Burp가 이미 보유한 트래픽만 분석합니다.

## Requirements

- Burp Suite Professional 2026.2.x–2026.4.x
- Java 17 이상
- Windows, macOS 또는 Linux

Extension은 Montoya API `2026.2`를 기준으로 빌드됩니다. Montoya API는 `compileOnly` dependency이므로 배포 JAR에 포함되지 않습니다.

## Build

별도의 Gradle 설치는 필요하지 않습니다.

```powershell
# Windows
.\gradlew.bat clean build
```

```bash
# macOS / Linux
./gradlew clean build
```

빌드가 끝나면 다음 파일이 생성됩니다.

```text
build/libs/burp-sensitive-scanner-1.0.1.jar
```

Burp에서 **Extensions → Installed → Add → Java**를 선택하고 JAR 파일을 지정합니다. 설치가 완료되면 상단에 **Sensitive Scanner** 탭이 나타납니다.

## Traffic sources

Scan에 사용할 데이터 소스를 개별적으로 선택할 수 있습니다.

- **Proxy History** — 현재 Burp 프로젝트의 Proxy HTTP history
- **Site Map** — Proxy, Crawler, Scanner 등이 Target Site Map에 저장한 요청과 응답
- **Captured Burp Traffic** — Extension 로드 이후 global HTTP handler가 관찰한 완료된 트랜잭션
- **Imported Logger CSV** — Burp Logger에서 내보낸 CSV 파일

Proxy, Repeater, Intruder, Scanner, Sequencer 및 다른 Extension에서 발생한 HTTP 트래픽은 handler에서 가볍게 복사됩니다. 정규식 검사나 decoding 같은 작업은 HTTP processing thread에서 수행하지 않습니다.

기본 Scan 범위는 Burp Target scope입니다. **All traffic**을 선택하면 scope와 관계없이 선택한 소스를 분석합니다.

## Logger CSV import

Montoya API에서는 과거 Logger history 전체를 직접 조회할 수 없습니다. 필요한 항목을 Burp Logger에서 CSV로 export한 뒤 **Import Logger CSV**로 불러오면 됩니다.

Importer는 column 순서 대신 header 이름을 사용합니다. 다음 형식을 처리합니다.

- quoted comma와 escaped quote
- multiline request 및 response
- CRLF와 LF
- UTF-8
- 빈 response
- HTTP/1.x와 HTTP/2 텍스트
- Base64 또는 Base64URL 후보
- Excel 호환 export에 붙는 `'` prefix

Base64 여부가 확실하지 않은 값은 원문을 그대로 보관합니다. 형식 검증을 통과한 후보만 별도 representation으로 decode해 분석합니다. 잘못된 row는 격리되며 나머지 import는 계속 진행됩니다.

## Detection

기본 rule set은 다음 credential을 다룹니다.

- AWS access key ID, secret access key, session token
- Google API key와 GCP service account credential
- Azure client secret 후보
- GitHub, GitLab, Slack, Stripe token
- JWT, Bearer token, Basic Authorization
- API key, API secret, client secret, access/refresh/session token
- RSA, EC, OpenSSH, PKCS#8 및 일반 PEM private key
- JDBC, PostgreSQL, MySQL, MongoDB, Redis credential URI
- 민감한 field 이름과 결합된 generic secret

Request URL, query, header, cookie와 body를 검사하고 response header, Set-Cookie와 body도 분석합니다. JavaScript와 source map 응답은 별도 위치로 표시됩니다.

단순히 긴 문자열을 secret으로 간주하지 않습니다. 각 rule은 vendor prefix, token 구조, field 이름, 길이, 문자 집합과 Shannon entropy를 조합해 confidence를 계산합니다. UUID, 일반적인 hash, 긴 숫자 ID, frontend asset hash 및 placeholder는 별도로 걸러냅니다.

지원하는 normalization 단계는 URL encoding, HTML entity, JSON escape, Base64와 Base64URL입니다. 최대 입력 크기, 결과 크기, decoding 깊이와 cycle 제한을 적용하며 finding에는 다음과 같이 경로가 남습니다.

```text
Response Body -> Base64 decoded -> AWS Access Key ID
```

## Findings

결과에는 rule ID, category, severity, confidence, traffic source, Burp tool, URL, 위치, field 이름과 detection path가 포함됩니다. Finding을 선택하면 Burp native HTTP editor에서 원본 request와 response를 확인할 수 있습니다.

목록과 export 파일에서는 credential 원문을 노출하지 않습니다. 화면에는 마스킹한 evidence만 표시하며, 중복 판별에는 원문 대신 SHA-256 hash를 사용합니다.

Transaction 중복 제거에는 HTTP method, normalized URL, HTTP service, request bytes와 response bytes를 함께 사용합니다. 같은 URL이라도 request 또는 response 내용이 다르면 별도 트랜잭션으로 취급합니다.

결과는 JSON 또는 CSV로 내보낼 수 있습니다.

## Performance and settings

Scan은 Swing EDT 밖의 background worker에서 실행됩니다. 진행률을 확인할 수 있고 **Stop** 버튼으로 중단할 수 있습니다.

UI에서 다음 항목을 조정할 수 있습니다.

- Target scope 또는 전체 트래픽
- request/response 검사 여부
- 최대 body 크기
- entropy threshold
- 최대 decoding 깊이
- minimum confidence
- rule별 활성화 여부
- live capture 최대 entry 수

Live capture repository는 최대 20,000개 또는 64 MiB까지 보관합니다. Logger import 데이터는 별도 repository에서 최대 128 MiB까지 유지합니다. 어느 한도에든 도달하면 오래된 항목부터 제거하고 UI에 누적 수를 표시합니다.

Proxy History와 Site Map은 전체 메시지를 별도 목록에 복사하지 않습니다. 각 트랜잭션을 가져오는 즉시 중복 판별과 탐지를 수행하고, finding이 없는 원문은 다음 트랜잭션으로 넘어갈 때 해제합니다. Finding에 연결하는 request/response 원문도 Scan당 64 MiB로 제한됩니다.

## Project layout

```text
src/main/java/io/github/sensitivescanner/
├── burp/       Montoya integration, traffic adapters, lifecycle
├── traffic/    transaction model, repository, deduplication
├── importer/   Logger CSV import
├── scanner/    extraction, decoding, scan orchestration
├── rules/      detection rule API and built-in rules
├── model/      finding, severity, confidence, location
├── ui/         Swing UI and native HTTP viewers
└── export/     JSON and CSV reports
```

Detection engine, rules, CSV importer와 repository는 Burp API에 의존하지 않아 독립적으로 테스트할 수 있습니다.

## Montoya API compatibility

사용한 API는 `montoya-api:2026.2` artifact의 실제 class signature를 기준으로 확인했습니다.

- `proxy().history()`
- `siteMap().requestResponses()`
- `http().registerHttpHandler(HttpHandler)`
- `HttpResponseReceived.toolSource()`
- `userInterface().registerSuiteTab(...)`
- `createHttpRequestEditor(...)` / `createHttpResponseEditor(...)`
- `scope().isInScope(...)`
- `extension().registerUnloadingHandler(...)`
- `logging().logToOutput(...)` / `logToError(...)`

2026.2 이후에 추가된 Montoya 기능에는 의존하지 않습니다.

## Tests

```powershell
.\gradlew.bat test
```

JUnit corpus에는 실제 서비스에서 사용할 수 없는 dummy credential만 들어 있습니다. Vendor token, private key, database URI, generic secret과 encoded secret의 탐지를 검사하며 hash, UUID, trace ID, asset hash, placeholder, 일반 Base64 및 숫자 ID가 finding으로 남지 않는지도 확인합니다.

CSV test는 multiline field, quoted comma, escaped quote, UTF-8, empty response, Base64 message와 malformed row를 포함합니다. Transaction 및 finding deduplication도 별도로 검증합니다.

## Current limitations

- 과거 Logger history는 CSV export/import가 필요합니다.
- 응답을 받기 전에 중단된 live request는 capture repository에 저장하지 않습니다.
- binary body는 보존하지만 text representation으로 안전하게 다룰 수 있는 내용만 검사합니다.
- 설정은 현재 Burp 실행 동안만 유지됩니다.
- 자동으로 HTTP 요청을 보내거나 JavaScript bundle을 추가로 내려받지 않습니다.
