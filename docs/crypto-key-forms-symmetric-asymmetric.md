# 암호키 작성 양식 — 대칭키(DEK, KEK) / 비대칭키(TLS, 로그인 키)

본 저장소의 현재 구현(소스)에서 확인한 값만 적는다. 난수발생기는 "CSPRNG"이라고 쓰지 않고 방식(Hash_DRBG 등)을 명시한다.
HashiCorp Vault는 더 이상 사용하지 않는다(engine-setup·engine-cleanup에서 제거, 예전 `OVVLT001` 파일은
`kek_agent.py --migrate` 전환용으로만 읽음). 예전 `OVENC001`(파일마다 DEK를 헤더에 저장) 형식도 읽기만 지원한다.

## 0. 암호 알고리즘 사용 현황

| 암호알고리즘 | 제품 구성요소 | 보호 대상 데이터 | 보호 대상 데이터 저장위치 | 제품 주체 |
|---|---|---|---|---|
| AES-256-GCM (DEK) | 가상화 서버 | DB 접속 정보(DB 계정 비밀번호) 설정파일 | `/etc/ovirt-engine/engine.conf.d/10-setup-database.conf`, `/etc/ovirt-engine/engine.conf.d/10-setup-dwh-database.conf`(DWH 설치 시), `/etc/ovirt-engine/aaa/internal.properties` (형식 `OVENC002`) | 설정파일 암호화 도구(`encryptor.py`, `encrypt_conf_files.py`), 엔진 기동 시 복호화(`configfile.py`) |
| AES-256-GCM (KEK) | 가상화 서버 | DEK | `/etc/ovirt-engine/encryptor/dek.enc` (KEK로 암호화된 DEK, 형식 `OVDEK001`) | 설정파일 암호화 도구. KEK는 PBKDF2로 유도, 패스프레이즈는 `ovirt-engine-kek-agent.service` 메모리에 보관 |
| RSAES-OAEP (로그인 키) | 가상화 서버 / 클라이언트(웹 브라우저) | 로그인 ID·비밀번호 (전송 구간) | 저장하지 않음 (전송 중에만 암호문, 서버 메모리에서 복호화) | 암호화: 브라우저 Web Crypto API / 복호화: SSO(`LoginEnvelopeCrypto`) |
| RSA (TLS) | 가상화 서버 | 관리자 웹·API 통신, 엔진↔호스트 통신 | 저장하지 않음 (통신 구간) | Apache(mod_ssl), 엔진(JSSE) |

---

## 1. 대칭키 양식

### 1.1 DEK (데이터 암호화 키)

| 항목 | 내용 |
|---|---|
| 암호알고리즘 | AES-256-GCM (NIST SP 800-38D). 논스 96비트(파일을 암호화할 때마다 새로 생성), 인증태그 128비트. 봉투 헤더(`OVENC002`‖버전‖DEK 식별값‖논스)를 추가 인증 데이터(AAD)로 함께 인증 |
| 해시 알고리즘 | 해당 없음 (암호화·인증에 해시를 쓰지 않음). 난수발생기 내부 SHA-256, DEK 식별값 HMAC-SHA256(앞 8바이트, DEK 비노출) |
| 비트 수 | 256비트 (32바이트) |
| 난수발생기 | Hash_DRBG (SHA-256, 보안강도 256비트, NIST SP 800-90A / 국정원 검증대상 난수발생기). OpenSSL 3 `EVP_RAND`, 운영체제 엔트로피(SEED-SRC)로 시드, 기동 시 기지답 시험(KAT) 통과 후 사용. DEK와 논스 모두 생성. 승인 난수발생기를 쓸 수 없으면 다른 난수로 대체하지 않고 생성 거부(감사기록 사유 `RNG_UNAVAILABLE`) |
| 반복 횟수 | 없음 (0회). 패스워드에서 유도하지 않고 난수로 직접 생성 |
| 생성 주기 | 설치당 1회 (최초 engine-setup closeup 또는 `kek_agent.py --migrate`). 이후 재실행 시 기존 DEK 사용 |
| 저장위치 | `/etc/ovirt-engine/encryptor/dek.enc` — KEK로 AES-256-GCM 암호화된 상태, `root:ovirt 0640`. 평문 DEK는 저장하지 않음(사용 시 메모리에서만, 사용 후 0으로 덮어씀) |

### 1.2 KEK (키 암호화 키)

| 항목 | 내용 |
|---|---|
| 암호알고리즘 | AES-256-GCM (DEK 암호화). `dek.enc` = `OVDEK001`‖버전‖반복횟수‖salt‖논스‖길이 헤더 + 암호화된 DEK + 태그, 헤더를 AAD로 인증. 논스 96비트 |
| 해시 알고리즘 | SHA-256 (키 유도 PBKDF2-HMAC-SHA256) |
| 비트 수 | 256비트 |
| 난수발생기 | salt(256비트)·논스(96비트): Hash_DRBG (SHA-256, 보안강도 256비트). salt는 DEK를 감쌀 때 생성해 `dek.enc` 헤더에 기록 → 같은 패스프레이즈라도 제품마다 다른 KEK |
| 반복 횟수 | 600,000회. engine-setup에서 운영자가 직접 입력한 패스프레이즈(6~256자, 2회 입력 확인)로부터 유도 |
| 저장위치 | KEK는 저장하지 않음(사용할 때마다 유도 후 폐기). 패스프레이즈는 `ovirt-engine-kek-agent.service` 프로세스 메모리에만 보관(디스크·스왑·코어덤프 없음, 접근은 root·ovirt 계정만). 재부팅 후 `kek_agent.py --unlock`으로 재입력 |

---

## 2. 비대칭키 양식

### 2.1 TLS 키

| 항목 | 내용 |
|---|---|
| 암호알고리즘 | RSA. 인증서 서명 RSA with SHA-256. TLS 1.2/1.3 서버 인증(핸드셰이크 서명)에 사용 |
| 해시 알고리즘 | SHA-256 (인증서 서명, `packaging/pki/openssl.conf` `default_md = sha256`) |
| 비트 수 | 2048비트 (`pki-enroll-pkcs12.sh`, `pki-create-ca.sh`의 `rsa_keygen_bits:2048`) |
| 난수발생기 | Hash_DRBG (SHA-256). 키 생성 시 OpenSSL을 Hash_DRBG로 설정해 사용 (`pki-common.sh`의 `common_use_engine_drbg`, `/usr/share/ovirt-engine/conf/openssl-drbg.cnf`). 운영체제가 FIPS 모드이면 FIPS 공급자의 승인 DRBG 사용 |
| 반복 횟수 | 웹(Apache) 개인키 `apache.key.nopass`: 없음(암호화하지 않은 PEM, 파일 권한으로 보호). PKCS#12 파일(`engine.p12`, `apache.p12` 등): 키 유도 PBKDF2-HMAC-SHA256 2,048회 (OpenSSL 3 `pkcs12 -export` 기본값) |
| 개인키 저장위치 | `/etc/pki/ovirt-engine/keys/` — `apache.key.nopass`·`apache.p12`(웹 HTTPS), `engine.p12`(엔진↔호스트 TLS), `websocket-proxy.key.nopass`(콘솔 프록시), 권한 `0600`. 내부 CA 개인키 `/etc/pki/ovirt-engine/private/ca.pem` |
| 공개키 저장위치 | 인증서(공개키 포함): `/etc/pki/ovirt-engine/certs/` (`apache.cer`, `engine.cer` 등), CA 인증서 `/etc/pki/ovirt-engine/ca.pem` |

### 2.2 로그인 키 (로그인 ID·비밀번호 암호화)

| 항목 | 내용 |
|---|---|
| 암호알고리즘 | RSAES-OAEP (MGF1-SHA-256, 레이블 없음). 브라우저 Web Crypto `RSA-OAEP`로 암호화, SSO `LoginEnvelopeCrypto`로 복호화 |
| 해시 알고리즘 | SHA-256 (OAEP 해시, MGF1 해시) |
| 비트 수 | 3072비트 (운영 기준, 최소 2048비트) |
| 난수발생기 | 키 생성: Hash_DRBG (SHA-256). 운영자가 `OPENSSL_CONF=/usr/share/ovirt-engine/conf/openssl-drbg.cnf openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 ...`로 생성. OAEP 암호화 시 패딩 난수: 브라우저 Web Crypto API 내부 난수발생기 |
| 반복 횟수 | 없음 (개인키를 PKCS#8 DER로 암호화하지 않고 저장, 파일 권한으로 보호) |
| 개인키 저장위치 | `/etc/ovirt-engine/encryptor/private_pkcs8.der` (PKCS#8 DER), 권한 `0600` |
| 공개키 저장위치 | `/etc/ovirt-engine/encryptor/config.json`의 `rsaPublicKey` (X.509 SPKI PEM). 공개키 다운로드 API는 `X-Client-Serial` 검증을 통과한 요청에만 제공 |

---

## 3. 근거

| 키 | 근거 소스·문서 |
|---|---|
| DEK | `packaging/encryptor/encryptor.py` (`ensure_dek`, `approved_random_bytes`, `encrypt_envelope`, `decrypt_envelope`, `dek_id`, `ENVELOPE_HEADER`, `DATA_KEY_SIZE=32`, `NONCE_SIZE=12`, `DEK_FILE`), `packaging/encryptor/encrypt_conf_files.py`, `packaging/pythonlib/ovirt_engine/csprng.py` (Hash_DRBG), `packaging/pythonlib/ovirt_engine/configfile.py` |
| KEK | `packaging/encryptor/encryptor.py` (`wrap_dek`, `unwrap_dek`, `_derive_kek`, `PBKDF2_ITERATIONS=600000`, `DEK_SALT_SIZE=32`, `DEK_HEADER`, `check_memory_passphrase`, `MEMORY_MIN_PASSPHRASE=6`), `packaging/encryptor/kek_agent.py`, `packaging/services/ovirt-engine/ovirt-engine-kek-agent.service.in`, `docs/kek-memory-pbkdf2.md` |
| TLS | `packaging/bin/pki-enroll-pkcs12.sh`, `packaging/bin/pki-create-ca.sh`, `packaging/bin/pki-common.sh.in` (`common_use_engine_drbg`), `packaging/conf/openssl-drbg.cnf`, `packaging/pki/openssl.conf`, `docs/crypto-storage-guide-for-examiners.md` §8 |
| 로그인 키 | `backend/manager/modules/enginesso/.../sso/utils/LoginEnvelopeCrypto.java` (`RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING`, `/etc/ovirt-engine/encryptor/private_pkcs8.der`), `login.jsp`, `docs/webadmin-login-credential-encryption-verification-form.md`, `docs/crypto-failure-audit-verification-form.md` §10 |

> 로그인 키는 엔진 설치 과정이 자동으로 만들지 않고 운영자가 위 명령으로 생성·등록한다. 따라서 비트 수와 난수발생기는
> 운영 절차를 따른 경우의 값이며, 설치본에서는 `openssl pkey -inform DER -in /etc/ovirt-engine/encryptor/private_pkcs8.der -text -noout | head -1`
> 로 실제 비트 수를 확인한다.
>
> Hash_DRBG는 국정원 검증대상 난수발생기 알고리즘이며, 이를 구현한 OpenSSL은 KCMVP 검증필 암호모듈이 아니다.
