# 국정원 보안기능 확인서 제출용 보안 구현 명세서

## 1. 문서 개요

| 항목 | 내용 |
|---|---|
| 대상 제품 | oVirt Engine (OV-Works) |
| 검토 기준 | 본 저장소의 소스 코드(2026-08-05 기준) |
| 범위 | DB 접속정보 파일 암·복호화, WebAdmin ID/PW 보호, 단말기 인증, 사설 SSL |
| 문서 성격 | 소스 코드 추적성을 갖춘 구현 명세. 실제 구축 환경의 설정값·인증서·시험 결과는 별도 증적으로 제출한다. |

### 1.1 판정 용어

* **구현**: 요구기능의 제어 흐름이 본 소스에서 확인됨.
* **조건부 구현**: 기능은 존재하나 운영 설정, 외부 AAA 모듈 또는 배포 환경 증적이 필요함.
* **미확인**: 본 저장소만으로는 요구사항의 완전한 강제를 입증할 수 없음.

## 2. 보안기능 요약

| ID | 보안기능 | 주요 보호대상 | 적용 기술 | 소스 검토 판정 |
|---|---|---|---|---|
| SF-DB-01 | DB 접속정보 파일 암·복호화 | `10-setup-database.conf`, `10-setup-dwh-database.conf` | AES-256-GCM, PBKDF2-HMAC-SHA-256(600,000회), 랜덤 salt/nonce/data key | 구현 |
| SF-WA-01 | WebAdmin ID/PW 보호 | 로그인 ID/PW, 내장 admin 암호 검증값 | HTTPS 전송, `EnvelopePBE.check`, sensitive-key 마스킹 | 조건부 구현 |
| SF-TA-01 | 단말 접속 제어 | 허용 출발지 IP, 단말 일련번호 설정 | Apache `Require ip`, 관리 권한, 감사 이벤트 | IP: 구현 / 일련번호: 미확인 |
| SF-SSL-01 | 사설 PKI 기반 SSL | 브라우저↔Engine, Engine↔Host | 사설 CA 체인 검증, HTTPS 적용, Host 인증서 재등록 | 구현 |

## 3. SF-DB-01: DB 접속정보 파일 암·복호화

### 3.1 암호 방식

1. 파일 암호화 포맷은 8-byte magic `OVENC001`, 버전, 반복 횟수, 128-bit salt, key/data용 96-bit nonce 및 wrapped-key 길이를 헤더에 저장한다.
2. 256-bit 랜덤 data key로 평문을 AES-256-GCM 암호화한다.
3. 사용자 비밀문구와 랜덤 salt를 PBKDF2-HMAC-SHA-256 600,000회에 적용해 KEK를 생성하고, KEK로 data key를 AES-GCM wrapping한다.
4. 두 GCM 연산 모두 버전 헤더를 AAD로 인증한다. 태그, 키, 메타데이터 또는 암호문 변조 시 복호화는 실패한다.

### 3.2 대상 및 경계 통제

* 일괄 암호화 대상 파일명은 위 2개로 allowlist 처리되며, 허용 루트는 `/etc/ovirt-engine`, `/etc/ovirt-engine-dwh`이다.
* symbolic link, 일반 파일이 아닌 대상, group/other writable 파일은 거부한다.
* 출력은 동일 디렉터리의 임시 파일에 쓴 후 `os.replace` 방식으로 교체하며, 기본 모드는 `0600`이다.
* AAA JDBC의 `internal.properties`는 해당 extension이 로드 시 직접 읽기 때문에 파일 암호화 allowlist에서 명시적으로 제외된다. 이 파일은 OS 파일 권한과 내부 password verifier 보호를 적용하며, `OVENC001` 파일 암호화 대상으로 선전해서는 안 된다.

### 3.3 키 관리

키 자료는 ① systemd credential, ② 환경변수, ③ `0600` 이하 권한의 secret file, ④ TTY prompt 순서로 조회한다. 운영 환경은 `LoadCredentialEncrypted` 방식을 우선 사용하고, 환경변수는 권한 프로세스 노출 위험으로 인해 이행/비상용으로만 사용한다. MAC 주소 등 하드웨어 식별자는 키로 사용하지 않는다.

### 3.4 복호화 및 구형 이관

`decrypt_conf.py`/개별 tool은 인증 성공 후에만 평문 출력을 생성한다. AES-256-CBC 복호는 명시적 `legacy_cbc.enabled` 설정이 있는 이관 용도로만 허용되며 신규 쓰기는 항상 GCM을 사용한다. 이관 완료 후 `--deny-legacy-cbc`를 필수화한다.

## 4. SF-WA-01: WebAdmin ID/PW 보호

### 4.1 전송 구간

WebAdmin 인증정보는 HTTPS/TLS 채널 내에서 SSO 서비스로 전달되어야 한다. ID는 인증 및 감사에 필요한 식별자이므로 복호 불가 암호화 저장 대상이 아니며, TLS로 전송 기밀성을 보장한다. HTTP 우회 경로 차단은 배포된 Apache 설정으로 별도 확인한다.

### 4.2 PW 저장·검증

* 본 저장소의 built-in internal admin 구현은 `EnvelopePBE.check(저장 verifier, 입력 credential)`로 비밀번호를 검증하고, `config.authn.user.password`를 sensitive key로 등록한다.
* SSO는 사용자명·프로파일을 선택한 AAA extension에 전달한다. 외부 LDAP/Kerberos/AAA의 저장 알고리즘과 키 관리는 해당 배포 모듈의 별도 증적이 필요하다.
* 인증 성공 전의 PW는 평문 로그에 기록하지 않아야 하며, heap dump·debug log·HTTP capture는 민감정보 취급 절차를 적용한다.

### 4.3 제출 시 필수 증적

HTTPS 강제 설정, 실제 서버 인증서 chain, 내장/외부 AAA 유형, 저장소의 PW verifier 샘플(값은 마스킹), 로그인 패킷에서 PW 평문 미노출 결과를 제출한다. 본 소스만으로 “모든 WebAdmin 계정의 PW 저장 암호 규격”을 단일 알고리즘으로 선언하지 않는다.

## 5. SF-TA-01: 단말기 인증/접속 제어

### 5.1 IP 기반 접속 제어

1. setup plugin이 허용 IP/Network를 `ipaddress` 라이브러리로 정규화하고 loopback을 항상 보존한다.
2. Apache proxy 설정에 `Require ip <address-or-network>` 규칙을 쓴다. WebAdmin 관리 기능에서는 단일 IPv4만 허용하고, `Require` 지시어 삽입 등 비정상 입력을 거부한다.
3. 변경 command는 System object의 action group 권한 검사를 거치고 성공/실패 AuditLogType을 반환한다.

### 5.2 단말 일련번호

WebAdmin이 `serialNum`을 `/etc/ovirt-engine/encryptor/config.json`에 읽고 쓰며, 변경 command에 권한 검사와 감사 이벤트가 존재한다. 그러나 본 저장소 검토에서는 HTTP 요청의 단말 일련번호를 해당 설정값과 비교해 요청을 거부하는 enforcement point를 확인하지 못했다. 따라서 일련번호 단독을 “단말기 인증”으로 선언하지 않고, 현 버전의 강제 수단은 Apache 출발지 IP allowlist로 한정한다.

## 6. SF-SSL-01: 사설 SSL

* 관리자가 서버 private key, server certificate, 사설 CA chain의 파일 경로 또는 내용을 제공한다.
* 적용 전 필수 executable 및 파일 존재/가독성을 확인하고, `engine-setup --offline` HTTPS 설정 후 httpd/engine을 재시작한다.
* private key에 `0600`, `ovirt:ovirt`를 적용하고 `openssl x509` 메타데이터 검증 및 `openssl verify -CAfile <chain> <server-cert>` chain 검증을 수행한다.
* 모든 Host가 Maintenance/InstallFailed/NonResponsive 상태인지 선행 확인하고, Engine SSL 적용 후 각 Host의 certificate enrollment action을 수행한다. 하나라도 실패하면 전체 command를 실패로 판정한다.
* 제출 시에는 실제 TLS 버전/cipher, SAN/hostname 검증, 인증서 유효기간, CRL/OCSP 운영 및 HTTP→HTTPS 전환 결과를 배포 환경에서 별도 확인한다.

## 7. 소스 추적성 매트릭스

| 기능 | 핵심 소스 |
|---|---|
| DB 파일 암호 포맷/키/원자적 쓰기 | `packaging/encryptor/encryptor.py` |
| DB 암호화 대상 allowlist | `packaging/encryptor/encrypt_conf_files.py` |
| 암호 설계·운영 명령 | `packaging/encryptor/README.md` |
| built-in admin PW 검증/민감키 | `backend/manager/modules/builtin-extensions/src/main/java/org/ovirt/engine/extension/aaa/builtin/internal/InternalAuthn.java` |
| SSO credential→AAA 전달/인증 | `backend/manager/modules/enginesso/src/main/java/org/ovirt/engine/core/sso/service/AuthenticationService.java` |
| IP/serial setup | `packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/config/client_control.py` |
| WebAdmin IP/serial 관리 | `frontend/webadmin/modules/webadmin/src/main/java/org/ovirt/engine/ui/webadmin/section/main/view/popup/security/ClientManagementView.java` |
| IP 입력 검증/Apache 설정 | `backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll/TerminalIpConfigUtils.java` |
| 일련번호 설정 | `backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll/TerminalAuthConfigUtils.java` |
| 사설 SSL 적용/chain 검증/Host 재등록 | `backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll/ApplyExternalSslCommand.java` |

## 8. 검토 결론 및 제출 제한

DB 접속설정 2개 파일의 인증된 암호화와 사설 CA 기반 SSL 적용 흐름은 소스로 확인된다. WebAdmin PW 보호는 built-in AAA와 TLS 구성에 대해 확인되지만 외부 AAA의 저장 방식은 별도 확인이 필요하다. 단말 IP 제어는 Apache에서 강제되지만 serial number는 관리 설정만 확인되므로, 검사기관 제출서에 이를 인증 완료로 표기해서는 안 된다.

서버 공통보안 요구사항 9개 항목의 적합성, 소스 근거, 제한사항 및 현장 증적 요건은 `docs/nis-server-common-security-requirements-compliance.md`를 참조한다.

시험·인증기관 추가 제출 문서, 위협 모델, 상세 시험 및 증적관리 양식은 다음 문서를 참조한다.

* `docs/security-certification-submission-package-guide.md`
* `docs/security-architecture-threat-model.md`
* `docs/security-test-evidence-plan.md`
