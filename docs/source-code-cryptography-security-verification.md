# 소스 코드 기반 암호화 보안기능 확인서

## 1. 문서 개요

| 항목 | 내용 |
|---|---|
| 대상 제품 | oVirt Engine (OV-Works) 4.5.x |
| 분석 범위 | 사설 PKI 인증서, 주요 설정 파일 암호화, WebAdmin ID/PW 암복호화 |
| 분석 기준 | 현재 저장소의 실제 소스 코드 및 기본값 |
| 문서 버전 / 작성일 | 1.0 / 2026-07-29 |
| 작성자 / 검증자 / 승인자 | `[성명·직책] / [성명·직책] / [성명·직책]` |
| 최종 판정 | `[적합 / 조건부 적합 / 부적합]` |

본 문서는 권고사항만 나열하지 않고 **소스에서 확인되는 구현**, **운영 절차**, **소스만으로 확인할 수 없는 사항**을 구분한다. 대괄호(`[ ]`)는 제출 전에 실제 운영 결과로 대체하며 인증서 개인키, DB 비밀번호, 로그인 ID/PW, 복호화 키 및 세션 값은 증적에서 제외한다.

## 2. 소스 코드 확인 범위

| 영역 | 주요 근거 소스 | 확인 내용 |
|---|---|---|
| PKI 만료 판정 | `packaging/setup/ovirt_engine_setup/engine_common/pki_utils.py` | 갱신 임계일, SAN 검사, 내부 CA 서명 검사 |
| PKI 발급·갱신 | `packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/pki/ca.py` | 인증서 종류, 398일 단기 인증서, 키 재사용 여부 |
| 인증서 서명 | `packaging/bin/pki-enroll-request.sh` | 기본 1,827일, `openssl ca`, SAN/KU/EKU 적용 |
| CA 생성·갱신 | `packaging/bin/pki-create-ca.sh` | CA 7,300일, 기존 CA 개인키로 재서명 |
| 설정 파일 복호화 | `packaging/setup/plugins/ovirt-engine-common/ovirt-engine/db/connection.py` | 허용 파일, 외부 도구 호출, 실패 시 원본 복원 |
| 백업 연동 | `packaging/bin/engine-backup.sh.in` | 임시 복호화와 작업 후 암호문 복원 |
| 로그인 브라우저 암호화 | `backend/manager/modules/enginesso/src/main/webapp/WEB-INF/login.jsp` | Web Crypto RSA-OAEP/SHA-256, 평문 필드 삭제 |
| 로그인 서버 복호화 | `backend/manager/modules/enginesso/src/main/java/org/ovirt/engine/core/sso/utils/LoginEnvelopeCrypto.java` | RSA OAEP/MGF1 SHA-256, X.509·PKCS#8 형식 |
| 로그인 인증 연결 | `backend/manager/modules/enginesso/src/main/java/org/ovirt/engine/core/sso/servlets/InteractiveAuthServlet.java` | 암호화 ID/PW 복호화 및 인증 전달 |
| 공개키 API | `backend/manager/modules/enginesso/src/main/java/org/ovirt/engine/core/sso/servlets/RsaPublicKeyServlet.java` | 일련번호 검증, PEM 다운로드, no-store |

## 3. 사설 인증서 SSL/TLS 발급 및 갱신

### 3.1 소스에서 확인된 유효기간과 갱신 시점

| 인증서 | 소스 기본 유효기간 | 갱신 판정 시점 | 비고 |
|---|---:|---:|---|
| Apache HTTPS | 398일 | 만료 60일 전 | `shortLife=True`, 발급 시 `--days=398` |
| WebSocket Proxy | 398일 | 만료 60일 전 | `shortLife=True`, 발급 시 `--days=398` |
| Engine/JBoss/Reports 등 | 1,827일 | `CertExpirationWarnPeriodInDays` 이전 | DB 설정 조회 실패 시 365일 전으로 판정 |
| Engine 내부 CA | 7,300일(20년) | `CertExpirationWarnPeriodInDays` 이전 | 소스 주석의 “10년”과 실행 상수 7,300일이 불일치하므로 실행 상수를 기준으로 확인 |

`cert_expires()`는 단기 인증서를 60일 미만 잔여 시 갱신 대상으로 판단한다. 일반 인증서는 DB의 `CertExpirationWarnPeriodInDays`를 사용하고 조회 실패 시 365일을 사용한다. `ok_to_renew_cert()`는 만료 임박뿐 아니라 SAN이 없는 인증서도 갱신 대상으로 삼으며, 내부 CA 서명 인증서인지 확인한 뒤 교체한다.

> 위 값은 현재 소스 기본값이다. 외부 사설 CA가 발급한 Apache 인증서의 유효기간은 외부 CA 정책을 따르며, `engine-setup` 내부 CA 자동 갱신과 동일하다고 간주해서는 안 된다.

### 3.2 신규 발급 절차

1. 대상 FQDN, SAN, 인증서 용도, 키 길이, 담당자와 변경 티켓을 확정한다.
2. `engine-setup` 내부 CA를 쓰면 `_enrollCertificate()`가 PKCS#12 요청을 만들고 `pki-enroll-request.sh`가 `openssl ca`로 서명한다.
3. Apache와 WebSocket Proxy는 398일, 그 밖의 기본 인증서는 `pki-enroll-request.sh` 기본값 1,827일을 적용한다.
4. Subject에는 FQDN을 CN으로 넣고 `DNS:<FQDN>` SAN을 추가한다.
5. Apache처럼 `extract=True`인 항목은 PKCS#12에서 인증서와 키를 서비스 경로로 확장하고 소유자를 설정한다.
6. 외부 사설 CA 사용 시에는 대상 서버에서 키와 CSR을 생성하여 CA 승인을 받은 후 Apache 인증서·키·중간 체인 경로에 배포한다. 내부 CA 스크립트로 외부 CA 인증서를 덮어쓰지 않는다.
7. 배포 후 체인, SAN, 유효기간, 키 일치, TLS 1.2 이상 및 WebAdmin/API 동작을 확인한다.

```bash
openssl x509 -in /etc/pki/ovirt-engine/certs/apache.cer \
  -noout -subject -issuer -serial -dates -ext subjectAltName
openssl s_client -connect engine.example.internal:443 \
  -servername engine.example.internal -showcerts -verify_return_error </dev/null
```

### 3.3 갱신 절차

1. 일 1회 만료일을 점검하고 Apache/WebSocket은 늦어도 60일 전에 변경 티켓을 개시한다.
2. 인증서·키·체인·PKCS#12·truststore 및 관련 설정을 권한 제한 저장소에 백업한다.
3. `engine-setup`을 실행하여 갱신 안내를 확인하고 승인된 작업 창에서 `OVESETUP_PKI/renew` 절차를 수행한다.
4. 내부 CA 인증서가 갱신 대상이면 `pki-create-ca.sh --renew`가 기존 CA 개인키로 CA 인증서를 다시 서명한다.
5. End-entity 인증서는 `_enrollCertificates(True, ...)`가 종류별 만료·SAN·서명 상태를 평가한 뒤 재발급한다. Engine 인증서는 갱신 시 기존 키를 유지하도록 설정되어 있고, Apache·JBoss·WebSocket 등은 새 키를 생성한다.
6. 외부 사설 CA 인증서는 외부 CA의 CSR 승인·발급 절차로 갱신한 뒤 Apache에 반영한다.
7. 설정 검사, 서비스 reload/restart, 외부 SNI 접속, 체인·지문·SAN 및 주요 기능을 확인한다.
8. 실패 시 백업 인증서·키·체인을 복원하고 장애 및 롤백 증적을 남긴다.

```bash
apachectl configtest
systemctl reload httpd
systemctl --no-pager --full status httpd
```

### 3.4 확인 판정

- [ ] Apache/WebSocket 인증서 유효기간과 만료 60일 전 갱신 탐지가 확인된다.
- [ ] 일반 인증서의 `CertExpirationWarnPeriodInDays` 운영값을 확인했다.
- [ ] CN뿐 아니라 SAN에 서비스 FQDN이 존재한다.
- [ ] 외부 사설 CA 인증서와 내부 CA 인증서의 갱신 책임·절차가 분리되어 있다.
- [ ] 갱신 전 백업, 갱신 후 체인·키·TLS·서비스 검증 및 롤백 시험을 완료했다.

## 4. 주요 설정 파일 암호화

### 4.1 소스에서 확인된 대상과 동작

복호화 허용 목록은 다음 세 파일명이다.

1. `10-setup-database.conf`
2. `10-setup-dwh-database.conf`
3. `internal.properties`

`engine-setup`은 `/usr/share/ovirt-engine/encryptor/encryptor.py`가 존재할 때만 대상 파일에 `--decrypt`를 먼저 시도하고 실패하면 `-d`를 시도한다. 시도 전 파일 전체를 메모리에 보관하고, 실패하거나 Engine DB 파일의 복호화 결과에 `ENGINE_DB_PASSWORD`가 없으면 원본 암호문을 복원한다.

`engine-backup` 역시 basename 허용 목록을 확인하고 암호문을 임시 백업한 뒤 복호화하여 설정을 읽는다. 작업 종료 시 `restore_decrypted_configs()`가 암호문 원본을 되돌리고 임시 복원 파일을 삭제한다.

### 4.2 암호화 방법 및 알고리즘 판정

현재 저장소의 `packaging/encryptor/encryptor.py`는 설치 시 `/usr/share/ovirt-engine/encryptor/encryptor.py`에 배포된다. 소스에서 확인한 실제 형식은 다음과 같다.

| 확인 항목 | 실제 적용값 |
|---|---|
| 파일 형식 | `OVENC001` magic, 버전 1 |
| 본문 암호 | 임의 256비트 DEK를 사용하는 AES-256-GCM |
| 데이터 키 보호 | PBKDF2-HMAC-SHA-256으로 유도한 256비트 KEK와 AES-256-GCM |
| PBKDF2 | 무작위 128비트 salt, 600,000회 |
| Nonce와 태그 | 키·본문별 무작위 96비트 nonce, 각 128비트 GCM 태그 |
| 인증 범위 | 고정 헤더와 래핑된 데이터 키를 AAD로 인증 |
| 기본 키 공급 | systemd credential, 환경변수, 권한 0600 비밀 파일 순서 |
| 레거시 | AES-256-CBC 읽기 전용 마이그레이션; `--deny-legacy-cbc`로 차단 |

GCM 인증 태그 불일치는 암호문 변조, 잘못된 키 또는 손상으로 처리하여 출력 파일을 쓰지 않는다. 암호화 직후 메모리에서 자체 복호화하여 원문과 일치할 때만 `fsync()`와 `os.replace()`로 교체한다. MAC 주소 등 하드웨어 식별자는 키 재료로 사용하지 않는다.

### 4.3 적용 및 검증 절차

1. 세 파일과 암호화 키·설정을 분리 백업하고 소유자·권한·SELinux 컨텍스트를 기록한다.
2. 설치 도구의 `--help`, 패키지 버전, SHA-256과 알고리즘 구현을 확인한다.
3. 운영 ID/PW가 아닌 시험 사본에 도구가 제공하는 암호화 옵션을 적용한다.
4. 동일 평문을 두 번 암호화한 결과가 서로 다르고 모두 정상 복호화되는지 확인한다.
5. 암호문 1바이트 변조, 잘못된 키, 키 누락 및 권한 거부 시 평문 출력 없이 실패하는지 확인한다.
6. 원자적으로 운영 파일을 교체하고 Engine·DWH·AAA 인증 및 `engine-backup`을 시험한다.
7. 작업 후 세 파일이 다시 암호문 상태이며 평문 임시파일·로그·백업이 남지 않았는지 확인한다.

```bash
python3 /usr/share/ovirt-engine/encryptor/encryptor.py --help
rpm -qf /usr/share/ovirt-engine/encryptor/encryptor.py
sha256sum /usr/share/ovirt-engine/encryptor/encryptor.py
stat -c '%n %U:%G %a %s bytes' \
  /etc/ovirt-engine/engine.conf.d/10-setup-database.conf \
  /etc/ovirt-engine/engine.conf.d/10-setup-dwh-database.conf \
  /etc/ovirt-engine/aaa/internal.properties
```

## 5. WebAdmin ID/PW 공개키·개인키 암복호화

### 5.1 소스에서 확인된 알고리즘

| 항목 | 실제 구현 |
|---|---|
| 비대칭 알고리즘 | RSA |
| 암호화 방식 | RSA-OAEP |
| OAEP digest | SHA-256 |
| MGF | MGF1, SHA-256 |
| OAEP label | 빈 값 |
| 공개키 | X.509 SubjectPublicKeyInfo, `config.json`의 `rsaPublicKey` |
| 개인키 | PKCS#8 DER, `/etc/ovirt-engine/encryptor/private_pkcs8.der` |
| 암호문 인코딩 | Base64 |
| 문자 인코딩 | UTF-8 |

브라우저는 Web Crypto API로 공개키를 `spki`, `RSA-OAEP`, SHA-256으로 import한다. ID와 PW를 각각 별도로 암호화해 `encryptedUsername`, `encryptedPassword`에 저장한 뒤 평문 입력 필드를 빈 값으로 만들고 폼을 제출한다. 공개키 누락, Web Crypto 미지원 또는 암호화 오류 시 제출하지 않는다.

서버는 Base64 암호문을 해제하고 `RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING`과 명시적인 `MGF1ParameterSpec.SHA256`으로 복호화한다. 여기서 `ECB`는 RSA provider 변환 이름이며 블록암호 ECB 사용을 뜻하지 않는다. 개인키는 PKCS#8 DER로 읽는다.

### 5.2 처리 및 시험 절차

1. HTTPS 로그인 페이지가 승인된 `rsaPublicKey`를 포함하는지 확인한다.
2. 브라우저가 ID/PW를 각각 RSA-OAEP로 암호화하고 평문 필드를 지운 뒤 POST하는지 Network 탭에서 확인한다.
3. 서버가 개인키로 두 값을 복호화하고 기존 인증 처리에 전달하는지 시험 계정으로 확인한다.
4. 동일 입력을 반복 암호화했을 때 OAEP 특성에 따라 암호문이 달라지는지 확인한다.
5. 변조된 Base64·잘못된 키·허용 길이 초과 입력이 fail closed로 종료되고 ID/PW가 로그에 남지 않는지 확인한다.
6. `/ovirt-engine/sso/oauth/public-key`는 유효한 `X-Client-Serial` 요청만 허용하며, 누락·오류 값은 401인지 확인한다.
7. 공개키 응답이 X.509 PEM, `Cache-Control: no-store`인지 확인한다.

```bash
openssl pkey -inform DER \
  -in /etc/ovirt-engine/encryptor/private_pkcs8.der \
  -pubout -outform DER | sha256sum
openssl pkey -pubin -in public_key.pem -pubout -outform DER | sha256sum
```

두 지문은 일치해야 한다. RSA 키는 최소 2048비트, 운영 권고 3072비트이며 개인키는 Engine 서비스와 `root`에 필요한 최소 권한만 부여한다.

### 5.3 소스에서 확인된 제한

1. 응용계층 RSA 암호화는 TLS를 대체하지 않으며 공개키 치환 방지를 위해 HTTPS 서버 인증이 필수이다.
2. RSA-OAEP/SHA-256의 최대 입력은 `RSA 키 바이트 - 66`이므로 2048비트 키에서는 190바이트이다.
3. 암호문에 서버 nonce·timestamp가 없어 자체적인 재전송 방지 기능은 확인되지 않는다. TLS, 세션/CSRF 및 로그인 시도 제한을 병행해야 한다.
4. 서버는 암호화 필드가 없으면 기존 평문 `username`/`password`를 사용할 수 있다. WebAdmin에서 RSA 암호화를 필수로 요구하면 서버 측에서도 암호화 필드 누락 요청을 거부하도록 보완해야 한다.
5. 정적 RSA 키에는 순방향 비밀성이 없으므로 암호문을 로그·HAR에 보관하지 않고 키를 정기 교체해야 한다.

## 6. 종합 판정 및 제출 증적

| 번호 | 확인 사항 | 판정 | 증적 |
|:---:|---|:---:|---|
| SRC-01 | PKI 유효기간·갱신 임계일·SAN 판정이 소스와 일치한다. | `[ ]` | `[EV-01]` |
| SRC-02 | 내부 CA와 외부 사설 CA 발급·갱신 절차가 분리되어 있다. | `[ ]` | `[EV-02]` |
| SRC-03 | 세 설정 파일만 허용 목록으로 처리되고 실패 시 원본이 복원된다. | `[ ]` | `[EV-03]` |
| SRC-04 | `OVENC001` AES-256-GCM과 PBKDF2 600,000회 적용을 확인했다. | `[ ]` | `[EV-04]` |
| SRC-05 | WebAdmin RSA-OAEP/SHA-256/MGF1-SHA-256 상호운용이 확인된다. | `[ ]` | `[EV-05]` |
| SRC-06 | ID/PW 평문 미전송·미기록 및 개인키 최소 권한을 확인했다. | `[ ]` | `[EV-06]` |
| SRC-07 | 평문 fallback과 암호문 재전송 제한에 대한 보완 통제를 적용했다. | `[ ]` | `[EV-07]` |

| 결재 구분 | 성명 / 직책 | 의견 | 서명 | 일자 |
|---|---|---|---|---|
| 운영 확인 | `[ ]` | `[ ]` | `[ ]` | `[ ]` |
| 보안 검증 | `[ ]` | `[ ]` | `[ ]` | `[ ]` |
| 최종 승인 | `[ ]` | `[ ]` | `[ ]` | `[ ]` |
