# 보안기능 시험계획서·결과서 및 증적관리 명세

## 1. 시험 목적

본 문서는 보안기능 확인서 시험기관이 동일 결과를 재현할 수 있도록 시험대상, 환경, 절차, 판정, 결함, 재시험 및 원본 증적 관리 방법을 정의한다. 기존 문서의 예상 결과나 예시 로그는 시험 결과로 인정하지 않으며, 실제 제출 build에서 새로 생성한 결과만 사용한다.

## 2. 시험대상 식별

시험 시작 전 다음 표를 확정하고 변경을 동결한다.

| 항목 | 기록값 |
|---|---|
| 제품명/버전/release | 현장 기입 |
| Git commit/tag | 현장 기입 |
| RPM/JAR/image SHA-256 | 현장 기입 |
| Engine/Host/DB/OS/JVM | 제품명과 전체 버전 기입 |
| Apache/OpenSSL/crypto provider | 패키지와 전체 버전 기입 |
| 브라우저/API client | 제품명과 전체 버전 기입 |
| AAA/CA/SIEM | 내장/외부 여부, 제품·버전 기입 |
| 설정 baseline ID | 승인번호와 hash 기입 |
| 시험망/시간원 | segment, NAT/proxy, NTP source 기입 |

시험 중 package, 설정, 인증서 또는 시간이 변경되면 변경시점 이후 결과의 유효성을 검토하고 필요 범위를 재시험한다.

## 3. 역할과 독립성

| 역할 | 책임 | 금지사항 |
|---|---|---|
| 시험책임자 | 범위·판정 승인, 기관 질의 대응 | 미시험 항목의 임의 적합 판정 |
| 시험수행자 | 절차 실행, 원본 출력 수집 | 출력 편집, secret 무마스킹 제출 |
| 제품담당자 | 설치·결함 분석·수정 제공 | 시험 결과 승인 단독 수행 |
| 증적관리자 | 시각·hash·서명·접근권한 관리 | 원본 덮어쓰기 또는 사후 재생성 |
| 보안검토자 | 편차·잔여위험·마스킹 검토 | FAIL/보류 항목 삭제 |

## 4. 시험케이스 표준 양식

```text
시험 ID:
공식 요구사항 ID/페이지:
보안기능/위협 ID:
시험 목적:
선행조건 및 초기 상태:
시험 계정/역할/출발지(식별자만 기록):
입력 데이터(비밀값은 별도 관리):
수행 절차와 정확한 명령:
기대 결과와 PASS 기준:
실제 결과/exit code/timestamp:
생성된 audit event 및 증적 ID:
환경 복원 절차:
판정(PASS/FAIL/BLOCKED/N/A):
결함 ID/재시험 ID:
수행자/검토자/일시/서명:
```

### 4.1 판정 규칙

* **PASS:** 모든 사전 정의 기준을 충족하고 필수 증적이 존재한다.
* **FAIL:** 기대 보안효과가 없거나 우회·노출·유실이 확인된다.
* **BLOCKED:** 환경 또는 도구 문제로 실행할 수 없다. PASS로 합산하지 않는다.
* **N/A:** 공식 요구사항 적용조건에 해당하지 않으며 시험책임자가 근거를 승인했다.
* 부분 성공 또는 WARN은 PASS가 아니다. 결함 수정 후 신규 build ID로 재시험한다.

## 5. 필수 시험 세트

| 영역 | 필수 시험 | 정상시험 | 경계·부정시험 | 핵심 증적 |
|---|---|---|---|---|
| DB 파일 암호화 | T-DB-01~05 | 정상 round-trip/서비스 DB 연결 | wrong key, 1-byte 변조, truncation, symlink, writable file, legacy CBC deny | header metadata, exit code, cmp hash, service log |
| WebAdmin 인증 | T-WA-01~04 | HTTPS 정상 login/logout | HTTP, 오류 PW, 잠금 전후, 만료 token, log/packet secret scan | HTTP trace, TLS capture, audit, token hash 비교 |
| 단말/IP | T-TA-01~04 | 허용 IP 접속 | 비허용 IP, 지시어 삽입, 무권한 변경, IPv4 경계값 | Apache response/log, Engine session 미생성, audit |
| 사설 SSL | T-SSL-01~08 | 올바른 chain/SAN으로 Engine·Host 연결 | expired, wrong SAN, unknown CA, wrong key, incomplete chain, Host enrollment 실패 | openssl/testssl 출력, browser/API, Host audit |
| 자체 시험 | T-ST-01~05 | audit runner PASS | missing script, timeout, 동시실행, invalid JSON, FAIL result | runner exit code, journal/syslog, JSON |
| 무결성 | T-IN-01~05 | 승인 baseline 일치 | JAR/config 변경·삭제·추가, AIDE 미설치/권한실패 | baseline hash, AIDE 출력, alert |
| 감사 저장 | T-AU-01~08 | login/변경/차단 기록·조회 | disk 70/85/95%, DB insert 실패, remote down, queue replay | event count/sequence, filesystem, mail/syslog/SIEM |
| 권한 | T-AC-01~06 | 관리자 허용 | 일반/조회전용 역할의 UI·직접 API 변경 시도 | HTTP status, command result, audit |

## 6. 상세 부정시험 절차

### 6.1 DB 암호화

1. 합성 credential만 포함한 시험용 허용 파일을 준비하고 원본 SHA-256을 기록한다.
2. 암호화 후 magic/version/파일권한을 확인한다. ciphertext나 passphrase 전체는 제출하지 않는다.
3. 별도 출력경로로 복호화하고 원본 hash와 비교한다.
4. ciphertext, header, wrapped key, tag 영역을 각각 1 byte 변경하여 모든 경우가 인증 실패하고 출력이 생성되지 않는지 확인한다.
5. wrong passphrase, 빈 secret, 0644 secret, symlink 및 group-writable 입력을 각각 거부하는지 확인한다.
6. 실패 후 원본·대상 파일과 service 설정이 변경되지 않았는지 hash로 확인한다.

### 6.2 WebAdmin/SSO

1. capture 시작 전에 시험자 외 접근을 차단하고 capture 파일을 민감정보로 분류한다.
2. 정상 login의 cookie/token 값을 직접 제출하지 않고 SHA-256 또는 앞뒤 일부를 마스킹한 식별자로 기록한다.
3. 연속 오류 인증에서 각 실패 audit와 임계치 잠금시각을 대조한다.
4. 잠금 중 올바른 PW도 거부되는지, 만료 후 unlock audit와 정상 인증이 발생하는지 확인한다.
5. logout 및 600초 무활동 후 이전 token으로 WebAdmin/API/websocket 각각을 호출해 거부를 확인한다.
6. application/access/audit/debug log와 packet에서 PW 원문을 검색하되 결과 제출 시 검색어 자체도 마스킹한다.

### 6.3 IP 차단

1. NAT 이전 원본 IP와 Apache가 관찰하는 IP를 기록하고 trusted proxy 설정을 확인한다.
2. 허용 IP에서는 동일 URL이 정상이고 비허용 IP에서는 Engine 도달 전에 거부되는지 확인한다.
3. Apache log의 IP·시각·URL·status와 Engine session/audit 존재 여부를 대조한다.
4. `Require all granted`, newline, IPv6, CIDR, 공백, 중복, 0.0.0.0, multicast/broadcast 입력을 관리경로별로 시험한다.
5. 변경 후 Apache syntax 검사 실패 시 원 설정이 보존되고 service가 계속 동작하는지 확인한다.

### 6.4 사설 SSL

1. 정상 certificate/key/chain의 public-key 일치, SAN, EKU, 유효기간과 signature를 검사한다.
2. unknown CA, 중간 CA 누락, wrong SAN, 만료/미개시 인증서, key mismatch를 각각 독립 시험한다.
3. 허용되지 않은 protocol/cipher 연결을 거부하고 승인된 조합만 협상하는지 확인한다.
4. private key owner/mode와 backup/임시파일 잔존을 검사한다.
5. Host 하나를 enrollment 실패 상태로 만들어 command 전체가 실패하고 해당 사실이 노출되는지 확인한다.
6. rollback 후 Engine/WebAdmin/API/모든 Host가 이전 신뢰상태로 복구되는지 확인한다.

### 6.5 감사저장 장애

시험망과 합성 audit 데이터에서만 수행한다.

1. override 또는 제한된 시험 filesystem으로 69/70/84/85/94/95% 경계값을 재현한다.
2. 각 경계의 PASS/WARN/FAIL, mail/syslog와 archive 생성 결과를 기록한다.
3. 95%에서 archive를 만들 공간이 없는 경우 원본이 삭제되지 않고 실패 경보가 발생하는지 확인한다.
4. remote log 수신지를 중지한 상태에서 N개의 식별 가능한 event를 생성한다.
5. 로컬 persistent queue의 증가를 확인하고 수신지 복구 후 sequence와 count N이 일치하는지 대조한다.
6. DB insert 실패와 read-only log filesystem을 각각 주입하여 별도 경보·서비스 영향·복구 후 누락을 확인한다.

## 7. 증적 수집 및 보전

### 7.1 증적 ID와 manifest

각 파일에 `EV-<영역>-<일련번호>`를 부여한다. 원본 수집 즉시 다음 manifest 행을 추가한다.

| 증적 ID | 시험 ID | 원본 파일명 | 생성 host/UTC 시각 | 수집 command/tool | SHA-256 | 크기 | 마스킹본 | 수집자/검토자 |
|---|---|---|---|---|---|---:|---|---|

원본은 읽기 전용 저장소에 보관하고 제출용 마스킹본은 별도 파일로 만든다. 마스킹본에도 새 hash를 부여하고 원본과의 관계를 기록한다.

### 7.2 시각과 상호대조

* 모든 host의 NTP source와 offset을 시험 시작·종료 시 기록한다.
* client, Apache, Engine, DB, Host, syslog/SIEM event를 correlation ID 또는 UTC timestamp로 대조한다.
* 화면 capture만 사용하지 않고 원본 HTTP/audit/log/DB 결과를 함께 보존한다.

### 7.3 마스킹 대상

PW/passphrase, private key, raw token/cookie, DB credential, 전체 암호문, 개인식별정보, 내부망 상세정보 및 기관이 지정한 비밀정보를 마스킹한다. certificate public 정보와 hash도 환경 분류정책을 적용한다. 마스킹 후에도 시험 판정에 필요한 길이, 형식, 전후 차이와 event 연계성은 유지한다.

## 8. 결함 및 재시험

| 결함 ID | 시험 ID | severity | 보안영향/재현조건 | 영향버전 | 조치 commit/build | 재시험범위 | 결과/증적 | 잔여위험 승인 |
|---|---|---|---|---|---|---|---|---|

결함 수정 후 해당 시험만 반복하지 않고 공통 모듈, 인접 신뢰경계 및 회귀영향을 분석한다. 암호/SSO/권한/audit 공통부 수정은 관련 전체 시험군을 재수행한다. 재시험 결과에는 최초 FAIL 증적을 그대로 연결한다.

## 9. 시험결과 요약 양식

| 영역 | 계획 | PASS | FAIL | BLOCKED | N/A | 미수행 | 주요 결함/잔여위험 |
|---|---:|---:|---:|---:|---:|---:|---|
| DB 암호화 | 기입 | | | | | | |
| WebAdmin/SSO | 기입 | | | | | | |
| 단말/IP | 기입 | | | | | | |
| 사설 SSL | 기입 | | | | | | |
| 자체시험/무결성 | 기입 | | | | | | |
| 감사/저장 | 기입 | | | | | | |
| 권한/관리 | 기입 | | | | | | |

최종 결론은 미수행·BLOCKED·FAIL을 제외하거나 조건부 항목을 PASS에 합산하지 않는다. 시험책임자와 보안승인자가 결과, 편차 및 잔여위험을 서명한 후 제출본을 동결한다.
