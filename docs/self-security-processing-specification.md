# 자체 보안 처리 명세서

## 1. 목적과 적용 범위

본 문서는 `docs/national-security-implementation-specification.md`의 4개 보안기능을 운영자가 설치·변경·점검·장애 조치하는 절차와 증적 생성 방법을 정의한다. 명령의 경로·service 명·DB 접속 방식은 실제 배포 환경에 맞게 확정한다. 실제 secret, PW, private key 내용은 증적에 포함하지 않는다.

## 2. 역할과 승인

| 역할 | 책임 |
|---|---|
| 보안관리자 | 정책 승인, 키/인증서 수명주기, 예외 승인, 결과 서명 |
| 시스템관리자 | 설정 적용, 서비스 재시작, 원본 증적 생성 |
| 시험담당자 | 성공/실패/변조 시나리오 독립 실행, PASS/FAIL 판정 |
| 개발담당자 | 소스·빌드 버전 추적, 결함 수정 |

보안관리자와 시스템관리자가 동일인이면 변경승인 티켓에 별도 검토자의 승인을 받는다.

## 3. DB 접속정보 파일 암·복호화 처리

### 3.1 최초 적용/키 교체

1. 변경승인 번호, 대상 host, 대상 파일 2개, 백업/복구 계획을 기록한다.
2. root만 접근 가능한 systemd encrypted credential을 발급한다. secret file을 임시 사용하면 소유자와 모드 `0600` 이하를 확인한다.
3. 대상 파일이 symbolic link가 아니고 group/other writable가 아닌지 확인한다.
4. 서비스 중단/재시작 순서에 따라 `encrypt_conf_files.py`를 실행한다. 출력 파일 앞 8 byte가 `OVENC001`인지 확인하되 암호문을 증적에 첨부하지 않는다.
5. 서비스를 재시작하고 Engine/DWH의 DB 접속 성공과 로그의 secret 미노출을 확인한다.
6. 키 교체 시 이전 키로 복호화한 즉시 신규 키로 재암호화하고 임시 평문을 secure-delete 정책에 따라 폐기한다. 교체 후 이전 credential을 폐기한다.

### 3.2 자체 시험

| 시험 ID | 절차 | PASS 기준 | 주기 |
|---|---|---|---|
| T-DB-01 | 정상 키로 복호화해 원본과 `cmp` | 완전 일치 | 설치/교체 시 |
| T-DB-02 | 암호문 1 byte 변조 후 복호화 | 인증 실패, 출력 미생성 | 반기 |
| T-DB-03 | 잘못된 키로 복호화 | 인증 실패, 출력 미생성 | 반기 |
| T-DB-04 | symlink/그룹 writable 대상 시험 | 암호화 거부 | 연 1회 |
| T-DB-05 | `--deny-legacy-cbc`로 CBC 입력 복호 | 거부 | 이관 완료 후/반기 |

단위시험은 저장소 루트에서 `python3 packaging/tests/test_encryptor.py`를 수행하고 commit ID, Python/가상환경 버전, 전체 결과를 보존한다.

### 3.3 장애 처리

* GCM 인증 실패 시 재암호화나 강제 출력을 하지 않고 변조/키 오류 사고로 분류한다.
* DB 접속 실패 시 신규 평문 파일을 임의 생성하지 않고, 승인된 offline 복구 절차와 이중 통제로 원본을 복원한다.
* 키 분실은 복구 불가를 전제로 하므로 credential 백업은 별도 암호화 매체에 이중 통제로 보관한다.

## 4. WebAdmin ID/PW 보호 처리

### 4.1 운영 처리

1. HTTP에서 login form/SSO endpoint가 제공되지 않거나 HTTPS로 즉시 전환되는지 확인한다.
2. WebAdmin이 신뢰된 인증서를 사용하는지, cookie에 `Secure`/`HttpOnly` 등 필수 속성이 적용되었는지 실제 HTTP 응답으로 검사한다.
3. built-in admin 사용 시 `config.authn.user.password`의 실제 값을 노출하지 않고 verifier 포맷 여부만 확인한다. 외부 AAA는 해당 제품의 암호 저장 정책을 첨부한다.
4. PW, bearer token, session cookie를 application/access/audit log에 기록하지 않는다. 증적은 ID의 일부와 모든 credential을 마스킹한다.

### 4.2 자체 시험

| 시험 ID | 절차 | PASS 기준 |
|---|---|---|
| T-WA-01 | HTTP/HTTPS로 login URL 요청 | HTTP 평문 인증 불가, HTTPS 정상 |
| T-WA-02 | 패킷 capture 후 ID/PW 문자열 검색 | 평문 PW 미검출; ID는 TLS 페이로드 내부에만 존재 |
| T-WA-03 | 에러/debug/access log 검색 | PW/token/cookie 미검출 |
| T-WA-04 | 내장 admin 정상/오류 PW 인증 | 정상만 성공, 저장값과 입력 PW 불일치 |

## 5. 단말기 접속 제어 처리

### 5.1 IP allowlist

1. 최소 권한 원칙으로 관리망 IP/CIDR만 승인하고 loopback을 보존한다.
2. setup plugin 또는 WebAdmin 보안 관리 화면에서 허용 목록을 반영한다. WebAdmin 현 구현은 단일 IPv4 행만 지원하므로 CIDR/네트워크 변경은 setup 절차를 사용한다.
3. Apache configuration syntax 검사 후 graceful reload하고, 허용/비허용 단말에서 독립 접속 시험을 수행한다.
4. 변경자, 변경 전/후 목록, 승인 번호, 감사 이벤트, 허용/거부 HTTP 결과를 보존한다.

### 5.2 serial number 처리 제한

serial number는 관리자가 조회/변경하는 식별 설정값으로만 취급한다. 별도 enforcement module의 소스·배포·실행 증적을 제시하기 전에는 접속 인증요소로 인정하지 않는다. serial number가 header/cookie/form으로 전달되는 추가 구현은 위조·재전송 방지(인증서 또는 challenge-response)를 포함해야 한다.

### 5.3 자체 시험

| 시험 ID | 절차 | PASS 기준 |
|---|---|---|
| T-TA-01 | allowlist IP에서 WebAdmin/API 접속 | 정상 응답 |
| T-TA-02 | 비허용 IP에서 동일 URL 접속 | Apache 단에서 거부, Engine session 미생성 |
| T-TA-03 | `Require all granted`, IPv6, 문자열 삽입 등을 WebAdmin IP 입력에 제출 | 변경 거부, 설정 무변경 |
| T-TA-04 | 권한 없는 계정으로 변경 action 호출 | 거부 및 감사 기록 |

## 6. 사설 SSL 처리

### 6.1 발급/적용

1. 사설 CA의 CP/CPS에 따라 Engine FQDN이 SAN에 포함된 server certificate와 private key를 발급한다.
2. private key가 Engine 밖으로 노출되지 않도록 보안 전송하고, 원본/임시 파일의 소유자·권한을 확인한다.
3. 모든 Host를 허용 상태로 전환하고 변경 window와 rollback 계획을 승인받는다.
4. WebAdmin External SSL action을 실행하거나 동일한 승인 절차로 `ApplyExternalSsl` command를 호출한다.
5. httpd/Engine active, CA chain 검증, 각 Host enrollment 성공, 브라우저 trust, API/console 접속을 확인한다.

### 6.2 주기 점검·갱신

| 점검 | 기준 | 주기/조치 |
|---|---|---|
| 유효기간 | 30일 이상 남음 | 일 1회; 30일 미만 경고, 만료 즉시 FAIL |
| chain/hostname | 사설 root/intermediate 신뢰, SAN=FQDN | 월 1회/갱신 시 |
| protocol/cipher | 승인된 TLS 정책에만 합의 | 반기/변경 시 |
| private key | `0600`, 지정 owner, certificate와 modulus/public key 일치 | 월 1회 |
| 폐기 | 폐기 인증서 사용 불가 | CRL/OCSP 갱신 주기에 따름 |

### 6.3 장애/롤백

chain 검증 또는 Host enrollment이 하나라도 실패하면 변경을 성공 처리하지 않는다. 승인된 이전 certificate/key/config 세트로 복구하고 httpd/Engine을 재시작한 후 전 Host 접속을 재검증한다. private key 노출이 의심되면 롤백만으로 종결하지 않고 인증서 폐기·재발급·사고 보고를 수행한다.

## 7. 통합 자체 점검과 증적

### 7.1 자동 점검

`ov-works-security_audit.sh`는 설정 파일/.pgpass 권한, 인증서 만료, PostgreSQL SSL/password encryption, firewall/SELinux, AAA 설정 등을 점검하고 JSON 결과와 로그를 생성한다. `ovirt-engine-security-verification-runner.sh` 는 timeout/lock을 적용해 security audit과 AIDE를 실행하고 PASS/FAIL/ERROR를 exit code로 분리한다. 현장 설치 후 정기 timer/cron에 등록하고 실제 경로·권한·sudo 정책을 검증한다.

### 7.2 증적 목록

* 제품 version, RPM/package hash, Git commit ID, 시험 일시/host/수행자
* 변경승인서, 실행 command·exit code·stdout/stderr(비밀값 마스킹)
* 암호 포맷/version/권한 점검 결과, 복호 일치/변조 거부 결과
* TLS certificate subject/issuer/SAN/serial/fingerprint/validity, chain/hostname/cipher 시험
* 허용/비허용 IP 응답, 관리 변경 감사 이벤트
* 시험 결과서(PASS/FAIL/N/A, 실패 원인, 조치, 재시험, 검토자 서명)

### 7.3 보존·마스킹

증적은 조직의 국정원 제출/보안감사 보존 정책에 따라 읽기 전용 저장소에 해시와 전자서명을 붙여 보존한다. PW, passphrase, private key, session/token/cookie, DB 접속 암호, 전체 설정 파일은 제출물에서 제외하고 필요 항목만 마스킹한다.

## 8. 점검 체크리스트

- [ ] DB 파일은 allowlist 2개에만 한정되고 `OVENC001`/GCM으로 암호화되었다.
- [ ] systemd encrypted credential 또는 승인된 `0600` secret file을 사용했다.
- [ ] 오류 키/변조 파일은 복호 실패하고 평문 출력을 남기지 않았다.
- [ ] WebAdmin 인증은 HTTPS에서만 수행되고 PW/token이 패킷/로그에 노출되지 않았다.
- [ ] 현재 AAA 유형과 PW 저장/검증 증적을 확보했다.
- [ ] 허용 IP는 접속되고 비허용 IP는 Apache에서 차단되었다.
- [ ] serial number를 별도 enforcement 증적 없이 인증수단으로 신고하지 않았다.
- [ ] 사설 SSL chain/SAN/유효기간/protocol/cipher/private-key 권한을 확인했다.
- [ ] Engine 및 전체 Host의 인증서 적용/재등록과 rollback 가능성을 확인했다.
- [ ] 자동 점검, 단위시험, 현장 부정 시험의 원본 결과를 마스킹·서명해 보존했다.
