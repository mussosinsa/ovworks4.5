# 중요정보 암호화 저장·암호키 관리 설명서 (보안시험 검사자용)

| 항목 | 내용 |
|---|---|
| 대상 제품 | oVirt Engine (OV-Works) 4.5.x |
| 대상 구성 | Vault Transit 모드(설정파일 봉투 `OVVLT001`), 로컬 PostgreSQL, AAA-JDBC 내부 사용자 저장소 |
| 근거 | 본 저장소 소스코드. AAA-JDBC는 외부 패키지 `ovirt-engine-extension-aaa-jdbc`(≥1.2.0) 업스트림 소스 |
| 작성일 / 작성자 | `[YYYY-MM-DD]` / `[성명·직책]` |

이 문서는 검사자가 "무엇이, 어디에, 어떤 알고리즘으로, 어떤 난수로" 저장되는지 한눈에 대조할 수
있도록 정리했다. 소스에서 확인한 사실만 적었으며, 국정원 검증대상(KCMVP)과 다르거나 약한 부분은
**§10에 따로 모아 숨기지 않고** 기재했다.

---

## 0. 한 장 요약

| 중요정보 | 저장 방식 | 알고리즘 | 난수(salt·키·논스) | 저장 위치 |
|---|---|---|---|---|
| 관리자·내부 사용자 로그인 비밀번호 | **단방향 해시** | PBKDF2-HMAC-SHA1, 반복 **2,000**회, salt **256비트**, 출력 256비트 | Java `NativePRNG` (커널 `/dev/urandom`) | Engine DB `aaa_jdbc.users.password` |
| 비밀번호 변경 이력 (재사용 금지 정책) | **단방향 해시** | PBKDF2-HMAC-SHA256, 반복 **210,000**회, salt **256비트**, 출력 256비트 | **Hash_DRBG(SHA-256, 256비트)** | Engine DB `public.user_password_history.password_hash` |
| DB 계정 비밀번호 (PostgreSQL 역할) | **단방향 해시** (SCRAM 검증값) | SCRAM-SHA-256 = PBKDF2-HMAC-SHA256, 반복 **4,096**회, salt **128비트** | PostgreSQL 서버 OpenSSL 기본 DRBG (CTR_DRBG AES-256) | PostgreSQL `pg_authid.rolpassword` |
| DB 접속 정보 설정파일 3종 | **양방향 암호화** (봉투) | 파일: AES-256-GCM(DEK) / DEK 랩핑: Vault `aes256-gcm96`(KEK) | DEK·논스: **Hash_DRBG(SHA-256, 256비트)** / KEK: Vault 내부 | `/etc/ovirt-engine/engine.conf.d/10-setup-database.conf` 외 2개 |
| Engine DB 안의 장비 비밀번호 (펜스·스토리지·외부공급자·VM 초기 root 등) | **양방향 암호화** | RSA-OAEP(SHA-256, MGF1-SHA-256), RSA 2048비트 | 패딩 난수: Java 기본 `SecureRandom` | Engine DB 각 테이블 컬럼 (값 앞 `$`) |
| SSO 클라이언트 비밀값 | **단방향 해시** (DB) | PBKDF2-HMAC-SHA1, 반복 **4,000**회, salt **256비트** | **Hash_DRBG(SHA-256)** | Engine DB `sso_clients.client_secret` |
| DEK | 평문 저장 없음, KEK로 랩핑 | — | **Hash_DRBG(SHA-256, 256비트)** | 각 암호문 파일 내부 |
| KEK | Engine 호스트 저장 없음 | AES-256-GCM (Vault Transit) | Vault 내부 Go `crypto/rand` | Vault 저장소 `/opt/vault/data` (Vault 키로 암호화) |
| TLS 개인키 | 파일 (일부 PKCS#12 암호화) | RSA 2048비트 | **Hash_DRBG(SHA-256)** (OpenSSL 설정) | `/etc/pki/ovirt-engine/keys/` |
| TLS 세션 암호화키·무결성키 | **저장하지 않음** (메모리) | 협상된 암호군 (TLS 1.2/1.3) | OpenSSL/JSSE 내부 DRBG | 프로세스 메모리, 세션 캐시(공유메모리) |

---

## 1. 암호화하여 저장하는 중요정보 식별과 저장 위치

### 1.1 양방향 암호화(복호화 가능)로 저장하는 정보

복호화해서 다시 써야 하는 정보(시스템이 접속할 때 실제 비밀번호가 필요)이므로 해시가 아닌 암호화로 저장한다.

| # | 중요정보 | 정확한 저장 위치 | 담긴 항목 | 방식 |
|:-:|---|---|---|---|
| E1 | Engine DB 접속 정보 | `/etc/ovirt-engine/engine.conf.d/10-setup-database.conf` | `ENGINE_DB_PASSWORD` 외 접속정보 9항목 | `OVVLT001` 봉투 (§3) |
| E2 | DWH DB 접속 정보 | `/etc/ovirt-engine/engine.conf.d/10-setup-dwh-database.conf` (DWH 설치 시 `/etc/ovirt-engine-dwh/ovirt-engine-dwhd.conf.d/10-setup-database.conf` 포함) | `DWH_DB_PASSWORD` 외 | `OVVLT001` 봉투 |
| E3 | AAA-JDBC 저장소 DB 접속 정보 | `/etc/ovirt-engine/aaa/internal.properties` | `config.datasource.dbpassword` 외 | `OVVLT001` 봉투 |
| E4 | 펜스 에이전트 비밀번호·옵션 | Engine DB `fence_agents.agent_password`, `options` | 전원관리 장비 계정 | RSA-OAEP (§5) |
| E5 | 스토리지 연결 비밀번호 | Engine DB `storage_server_connections.password`, `storage_server_connection_extension.password` | iSCSI CHAP 등 | RSA-OAEP |
| E6 | 외부 공급자 인증정보 | Engine DB `providers.auth_password` | OpenStack·외부 네트워크 공급자 등 | RSA-OAEP |
| E7 | VM 초기화 root 비밀번호 | Engine DB `vm_init.password` | cloud-init/sysprep 관리자 비밀번호 | RSA-OAEP |
| E8 | libvirt 비밀값 | Engine DB `libvirt_secrets.secret_value` | Ceph 등 스토리지 키 | RSA-OAEP |
| E9 | Cinder 민감 옵션 | Engine DB `cinder_storage.driver_sensitive_options` | 스토리지 드라이버 비밀값 | RSA-OAEP |
| E10 | engine-config 비밀번호형 설정 | Engine DB `vdc_options` (비밀번호 유형 키) | 예: 외부 연동 계정 | RSA-OAEP (`engine-config` 도구) |

근거: E1~E3 `packaging/encryptor/encryptor.py`(`ALLOWED_CONFIG_BASENAMES`), `encrypt_conf_files.py`.
E4~E9 `backend/manager/modules/dal/.../FenceAgentDaoImpl`, `StorageServerConnectionDaoImpl`,
`StorageServerConnectionExtensionDaoImpl`, `ProviderDaoImpl`(`DefaultPasswordCryptor`), `VmInitDaoImpl`,
`LibvirtSecretDaoImpl`, `CinderStorageDaoImpl` → `DbFacadeUtils.encryptPassword` → `EngineEncryptionUtils.encrypt`.
E10 `backend/manager/tools/.../PasswordValueHelper`.

### 1.2 단방향 해시(복호화 불가)로 저장하는 정보

원래 값으로 되돌릴 필요가 없고 "맞는지 비교"만 하면 되는 정보이다.

| # | 중요정보 | 정확한 저장 위치 | 방식 |
|:-:|---|---|---|
| H1 | 관리자(`admin@internal`)·내부 사용자 로그인 비밀번호 | Engine DB `aaa_jdbc.users.password` | PBKDF2-HMAC-SHA1 (§2.1) |
| H2 | 내부 사용자의 직전 비밀번호들 (AAA-JDBC 자체 이력) | Engine DB `aaa_jdbc.user_password_history.password` | H1과 동일 |
| H3 | 비밀번호 재사용 금지용 이력 (제품 정책) | Engine DB `public.user_password_history.password_hash` | PBKDF2-HMAC-SHA256 (§2.2) |
| H4 | PostgreSQL DB 역할 비밀번호 (`engine`, `postgres` 등) | PostgreSQL 카탈로그 `pg_authid.rolpassword` (데이터 디렉터리 `/var/lib/pgsql/data/global/`) | SCRAM-SHA-256 (§2.3) |
| H5 | SSO 클라이언트 비밀값 | Engine DB `sso_clients.client_secret` | PBKDF2-HMAC-SHA1 (§2.4) |

### 1.3 암호화하지 않고 접근통제(파일 권한)로만 보호하는 정보 — 검사자 참고

| 정보 | 위치 | 보호 |
|---|---|---|
| Vault 애플리케이션 토큰 | `/etc/ovirt-engine/encryptor/vault-token` | `ovirt:ovirt 0600` |
| 로그인 RSA 개인키 | `/etc/ovirt-engine/encryptor/private_pkcs8.der` | `0600` |
| TLS 개인키 (평문 PEM) | `/etc/pki/ovirt-engine/keys/*.key.nopass` | `0600`(go-rwx) |
| AAA 확장 설정 안의 DB 비밀번호 | `/etc/ovirt-engine/extensions.d/internal-authn.properties`, `internal-authz.properties` | `ovirt 0600` (§10 지적사항) |
| SSO 클라이언트 비밀값 원문 | `/etc/ovirt-engine/engine.conf.d/11-setup-sso.conf` (`ENGINE_SSO_CLIENT_SECRET`) | `root:ovirt 0640` (§10 지적사항) |

---

## 2. 패스워드 저장 방법 (해시 방법), 저장 위치

### 2.1 관리자·내부 사용자 로그인 비밀번호 (H1, H2)

AAA-JDBC 확장이 사용자를 저장한다. 신규 설치의 기본 인증 저장소이다.

| 항목 | 값 |
|---|---|
| 해시 방식 | **PBKDF2** (PKCS #5 v2.0 / RFC 8018, NIST SP 800-132) |
| 의사난수함수(PRF) | **HMAC-SHA1** (`PBKDF2WithHmacSHA1`) |
| 반복 횟수 | **2,000회** (AAA-JDBC 설정 `PBE_ITERATIONS`) |
| salt 크기 | **256비트(32바이트)** — 키 크기 설정 `PBE_KEY_SIZE=256`을 8로 나눈 값 |
| 출력(해시) 길이 | 256비트 |
| salt 난수발생기 | Java `SecureRandom.getInstance("NativePRNG")` → Linux 커널 `/dev/urandom` (커널 CSPRNG, ChaCha20 기반) |
| 저장 형식 | Base64( JSON{ `artifact:"EnvelopePBE"`, `version:"1"`, `algorithm`, `salt`(Base64), `iterations`, `secret`(Base64 해시) } ) |
| 저장 위치 | Engine DB(`engine`) 스키마 `aaa_jdbc`, 테이블 `users`, 컬럼 `password` (이력: `user_password_history.password`) |
| 비교 방법 | 저장된 salt·반복횟수로 입력값을 다시 PBKDF2 → 바이트 비교 |

근거: `ovirt-engine-extension-aaa-jdbc` `core/EnvelopePBE.java`(encode),
`core/Authentication.java`, `packaging/dbscripts/data/00100_insert_default_settings.sql`
(`PBE_ALGORITHM=PBKDF2WithHmacSHA1`, `PBE_ITERATIONS=2000`, `PBE_KEY_SIZE=256`).

> 설치본의 실제 값 확인(해시는 출력하지 않음):
> ```sql
> -- psql -U engine -d engine
> SELECT name, value FROM aaa_jdbc.settings
>  WHERE name IN ('PBE_ALGORITHM','PBE_ITERATIONS','PBE_KEY_SIZE');
> ```
> 값은 `ovirt-aaa-jdbc-tool settings set --name=PBE_ALGORITHM --value=PBKDF2WithHmacSHA256` 등으로
> 바꿀 수 있고, 바꾼 뒤 비밀번호를 새로 설정한 계정부터 적용된다 (§10 권고).

### 2.2 비밀번호 재사용 금지용 이력 (H3)

"직전 비밀번호 재사용 금지", "3개월 이내 재사용 금지"를 판정하기 위해 제품이 따로 보관한다.

| 항목 | 값 |
|---|---|
| 해시 방식 | **PBKDF2-HMAC-SHA256** (`PBKDF2WithHmacSHA256`) |
| 반복 횟수 | **210,000회** |
| salt 크기 | **256비트(32바이트)**, 비밀번호마다 새로 생성 |
| 출력 길이 | 256비트 |
| salt 난수발생기 | **Hash_DRBG** (NIST SP 800-90A, KCMVP 난수발생기), 해시 **SHA-256**, 보안강도 **256비트**, 재시드 지원, 개인화 문자열 `ovirt-engine csprng v1` — JDK DRBG (`ApprovedRandom`) |
| 저장 형식 | `PBKDF2WithHmacSHA256$210000$<salt Base64>$<해시 Base64>` |
| 저장 위치 | Engine DB `public.user_password_history` (`principal`, `password_hash`, `change_date`) |

근거: `backend/manager/modules/uutils/.../security/PasswordHistoryCryptor.java`
(`ALGORITHM`, `ITERATIONS=210000`, `SALT_LENGTH=32`, `KEY_LENGTH=256`, `RANDOM=ApprovedRandom.get()`),
`.../uutils/crypto/ApprovedRandom.java`.

### 2.3 PostgreSQL DB 역할 비밀번호 (H4)

| 항목 | 값 |
|---|---|
| 해시 방식 | **SCRAM-SHA-256** (RFC 5802 / RFC 7677) — 내부적으로 PBKDF2-HMAC-SHA256 |
| 반복 횟수 | **4,096회** (PostgreSQL `scram_iterations` 기본값) |
| salt 크기 | **128비트(16바이트)** |
| 저장 값 | `SCRAM-SHA-256$4096:<salt>$<StoredKey>:<ServerKey>` (StoredKey = SHA-256(HMAC(SaltedPassword,"Client Key"))) — 비밀번호 자체는 저장되지 않음 |
| 저장 위치 | PostgreSQL 카탈로그 `pg_authid.rolpassword` (`/var/lib/pgsql/data/global/` 안, `postgres 0700`) |
| salt 난수발생기 | engine-setup이 비밀번호를 서버에 보내면 **PostgreSQL 서버**가 `pg_strong_random()` → OpenSSL `RAND_bytes`(기본 CTR_DRBG AES-256)로 생성. 단 `ovirt-engine-db-local-auth`로 `postgres` 비밀번호를 설정하면 **Hash_DRBG(SHA-256)** 로 salt를 만들어 검증값을 직접 설정 |
| 설정 근거 | `password_encryption = 'scram-sha-256'` (`engine_common/postgres.py`, `docs/postgresql-scram-hardening.md`) |

DB 계정 비밀번호 원문 자체의 생성: 영숫자 62자에서 22자를 **Hash_DRBG**로 선택(약 131비트)
(`engine_common/postgres.py` `generatePassword`).

### 2.4 SSO 클라이언트 비밀값 (H5)

| 항목 | 값 |
|---|---|
| 원문 생성 | 영숫자 62자에서 32자, **Hash_DRBG** (`config/sso.py`) |
| 해시 방식 | PBKDF2-HMAC-SHA1, 반복 **4,000회**, salt **256비트**, 출력 256비트 (`ovirt-engine-crypto-tool pbe-encode` 기본값) |
| salt 난수발생기 | **Hash_DRBG(SHA-256)** (`EnvelopePBE.encode` → `ApprovedRandom`) |
| 저장 위치 | Engine DB `sso_clients.client_secret` |

---

## 3. 설정 파일 저장 방법 (암호화 방법), 저장 위치

대상은 §1.1의 E1~E3 세 파일이다. 파일마다 **봉투 암호화**를 한다: 파일 내용은 **DEK**로 암호화하고,
DEK는 **KEK**로 감싸서(랩핑) 같은 파일 안에 넣는다.

| 항목 | 값 |
|---|---|
| 파일 암호 알고리즘 | **AES-256-GCM** (NIST SP 800-38D), 키 256비트 |
| 논스(IV) | **96비트**, 파일마다 새로 생성, **Hash_DRBG(SHA-256)** |
| 무결성 | GCM 인증태그 **128비트**. 헤더와 랩핑된 DEK를 AAD(추가 인증 데이터)로 함께 인증 |
| DEK | 256비트, 파일마다 새로 생성 (§6) |
| KEK | Vault Transit `ovirt-engine-config`, `aes256-gcm96` (§7) |
| 키 유도(KDF)·반복횟수 | **사용하지 않음.** DEK는 난수 그대로이고 KEK는 Vault가 난수로 만든다 (비밀번호에서 유도하지 않으므로 salt·반복횟수 파라미터가 없다) |
| 파일 형식 | `OVVLT001`(8) ‖ 버전(1) ‖ 논스(12) ‖ 랩핑DEK길이(2) ‖ 랩핑DEK(`vault:v<N>:…`) ‖ 암호문 ‖ 태그(16) |
| 파일 권한 | E1·E2 `root:ovirt 0640`, E3 `ovirt 0600` |
| 처리 제한 | 위 3개 파일명만, `/etc/ovirt-engine`·`/etc/ovirt-engine-dwh` 아래만, 심볼릭 링크 거부 |
| 안전장치 | 암호화 직후 복호화해 원문과 같을 때만 교체(원자적 교체). 변조 시 복호화 거부·출력 없음 |

근거: `packaging/encryptor/encryptor.py` (`encrypt_vault_bytes`, `decrypt_vault_bytes`, `transform_file`).

**언제 암·복호화하나**: engine-setup 마무리 단계에 암호화 → Engine 기동 시(Java 시작 전 Python 단계)
복호화해 메모리에서만 사용 → engine-setup 재실행 시 E3만 잠시 복호화 후 재암호화.

---

## 4. DB 접속 정보 저장 방법, 저장 위치

| 저장소 | 위치 | 내용 | 보호 방법 |
|---|---|---|---|
| Engine DB 접속 설정 | `/etc/ovirt-engine/engine.conf.d/10-setup-database.conf` | 호스트·포트·계정·**비밀번호**·DB명·SSL 여부 | `OVVLT001` 봉투 암호화 (§3) |
| DWH DB 접속 설정 | `/etc/ovirt-engine/engine.conf.d/10-setup-dwh-database.conf` 등 | 같은 항목 | `OVVLT001` 봉투 암호화 |
| AAA-JDBC 접속 설정 (관리 도구용) | `/etc/ovirt-engine/aaa/internal.properties` | JDBC URL·계정·**비밀번호** | `OVVLT001` 봉투 암호화 |
| AAA-JDBC 접속 설정 (Engine 런타임용) | `/etc/ovirt-engine/extensions.d/internal-authn.properties`, `internal-authz.properties` | 같은 JDBC 접속정보 | **평문**, `ovirt 0600` (§10) |
| 기동 시 렌더링된 설정 | Engine 런타임 임시 디렉터리 `ovirt-engine.xml` | DB 비밀번호 주입된 JBoss 설정 | `0600`, 기동마다 삭제 후 재생성 |
| DB 서버 측 비밀번호 | `pg_authid.rolpassword` | SCRAM-SHA-256 검증값 | 단방향 해시 (§2.3) |
| 전송 구간 | Engine → PostgreSQL (`127.0.0.1`) | 로그인 | SCRAM-SHA-256 챌린지-응답 (비밀번호 미전송), `pg_hba.conf` scram-sha-256 |

---

## 5. Engine DB 안의 장비 비밀번호 암호화 (E4~E10)

| 항목 | 값 |
|---|---|
| 알고리즘 | **RSAES-OAEP**, OAEP 해시 SHA-256, MGF1-SHA-256, 레이블 없음 (KCMVP 검증대상 공개키 암호) |
| 키 | Engine 인증서 키쌍 RSA **2048비트** (`/etc/pki/ovirt-engine/keys/engine.p12`) |
| 저장 형식 | `$` + Base64(RSA 암호문) — `$` 없는 값은 구버전 PKCS#1 v1.5로 판독만 함 |
| 패딩 난수 | Java 기본 `SecureRandom`(NativePRNG, `/dev/urandom`) |
| 근거 | `backend/manager/modules/utils/.../crypt/EngineEncryptionUtils.java` (`encrypt`, `getInitializedCipher`) |

---

## 6. DEK — 생성·저장·파기

### 6.1 생성

| 항목 | 값 |
|---|---|
| 무엇 | 설정파일 1개를 암호화하는 **256비트 대칭키** (소스 변수 `data_key`) |
| 언제 | 파일 1개를 암호화할 때마다 새로 (재사용 없음, 3개 파일 → DEK 3개) |
| 난수발생기 | **Hash_DRBG** (NIST SP 800-90A Rev.1 §10.1.1, KCMVP 난수발생기) |
| DRBG 세부 | 해시 **SHA-256**, 보안강도 **256비트**, 엔트로피 원 OpenSSL `SEED-SRC`(Linux `getrandom(2)`), 개인화 문자열 `ovirt-engine csprng v1`, 구현 OpenSSL 3 `EVP_RAND`(전용 컨텍스트) |
| 자가시험 | 정답비교시험(KAT, 고정 입력 → 기대 출력 바이트 대조), 연속시험(연속 블록 동일·전부 0이면 사용 중지) |
| 키 유도·salt·반복횟수 | **없음** (DRBG 출력 32바이트를 그대로 DEK로 사용) |
| 근거 | `encryptor.py` `encrypt_vault_bytes` → `random_bytes(32)` → `ovirt_engine/csprng.py` `token_bytes` |

### 6.2 저장

| 항목 | 값 |
|---|---|
| 평문 DEK | **저장하지 않는다.** 암·복호화 중 프로세스 메모리에만 존재 |
| 저장 형태 | KEK로 감싼(랩핑) 상태 `vault:v<KEK버전>:<Base64>` (논스 96비트 + 랩핑 결과 256비트 + 태그 128비트) |
| 저장 위치 | **자신이 보호하는 암호문 파일 안**, 헤더 바로 뒤 (오프셋 23부터) |

### 6.3 파기

| 상황 | 방법 |
|---|---|
| 연산 종료 | 프로세스 종료로 메모리에서 소멸 |
| 재암호화 | 새 DEK로 만든 파일로 원자적 교체(`os.replace`) → 이전 랩핑 DEK 소멸 |
| KEK 버전 파기 | 그 KEK로 감싼 모든 DEK가 영구히 풀리지 않음 (암호학적 소거) |
| 제품 제거 | `engine-cleanup`이 파일을 복호화·정리하면서 함께 소멸 |
| 한계 | Python 불변 객체라 메모리 명시적 영점화(0 덮어쓰기)는 하지 않음 (§10) |

---

## 7. KEK — 생성·저장 유무·파기

### 7.1 생성

| 항목 | 값 |
|---|---|
| 무엇 | DEK를 감싸는 **256비트 대칭키**, Vault Transit 키 `ovirt-engine-config` |
| 언제·누가 | Vault 구축 시 1회, **Vault 서버 내부에서** 생성 (Engine은 요청만) |
| 생성 명령 | `vault write transit/keys/ovirt-engine-config type=aes256-gcm96 exportable=false allow_plaintext_backup=false` |
| 알고리즘 | AES-256-GCM, 논스 96비트 |
| 난수발생기 | Vault 내부 Go `crypto/rand` → Linux `getrandom(2)` |
| 키 유도·salt·반복횟수 | **없음** (난수로 직접 생성) |
| 반출 | 불가(`exportable=false`), 평문 백업 불가(`allow_plaintext_backup=false`) |

### 7.2 저장 유무·방법·위치

| 항목 | 값 |
|---|---|
| Engine 호스트 저장 | **없음** (파일·DB·로그·환경변수 어디에도 없음) |
| 저장 위치 | Vault 통합 저장소 `/opt/vault/data` (`vault:vault 0700`) |
| 저장 방법 | Vault Barrier 키(AES-256-GCM)로 암호화되어 저장. Barrier 키는 Root Key로, Root Key는 봉인해제 키로 암호화 |
| 봉인해제 키 | Shamir 비밀분산 **5조각, 임계값 3** (`vault operator init -key-shares=5 -key-threshold=3`). 5명이 나누어 보관 |
| 사용 권한 | Engine 토큰은 `transit/encrypt`, `transit/decrypt` 두 경로의 `update`만 (키 생성·삭제·반출 불가) |

### 7.3 파기

| 대상 | 방법 | 효과 |
|---|---|---|
| 특정 구버전 | `vault write transit/keys/ovirt-engine-config/config min_decryption_version=N` 후 `.../trim min_available_version=N` | N 미만 버전 키 재료 삭제 → 그 버전으로 감싼 DEK 복원 불가 |
| KEK 전체 | `deletion_allowed=true` 설정 후 `vault delete transit/keys/ovirt-engine-config` | 모든 `OVVLT001` 파일 영구 복원 불가 (암호학적 소거) |
| 봉인해제 키 조각 | `vault operator rekey`로 재발급 → 구 조각 무효, 보관 매체 물리 파기 | — |
| Engine 토큰 | `vault token revoke` 후 파일 교체 | Engine의 KEK 사용 권한 소멸 |

---

## 8. TLS 키 — 저장 방법·위치

### 8.1 TLS 개인키

| 용도 | 파일 | 형식·보호 | 생성 |
|---|---|---|---|
| 웹 HTTPS (Apache mod_ssl) | `/etc/pki/ovirt-engine/keys/apache.key.nopass` (+`apache.p12`) | PEM **평문** 개인키, `0600` | RSA 2048비트 |
| Engine ↔ 호스트(VDSM) 상호인증 TLS, DB 내 비밀번호 암호화 | `/etc/pki/ovirt-engine/keys/engine.p12` | PKCS#12 (비밀번호 보호), `0600` | RSA 2048비트 |
| 콘솔 웹소켓 프록시 | `/etc/pki/ovirt-engine/keys/websocket-proxy.key.nopass` (+`.p12`) | PEM 평문, `0600` | RSA 2048비트 |
| 내부 CA | `/etc/pki/ovirt-engine/private/ca.pem` | PEM, 기타 권한 없음 | RSA 2048비트 |
| Vault 서버 TLS | `/etc/vault.d/tls/vault.key` | PEM, `vault` 계정 전용 | 운영자 생성 |

- 생성: `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048` (`packaging/bin/pki-enroll-pkcs12.sh`, `pki-create-ca.sh`).
- 생성 난수: PKI 스크립트가 `OPENSSL_CONF=/usr/share/ovirt-engine/conf/openssl-drbg.cnf`를 지정해 OpenSSL 난수를
  **Hash_DRBG(SHA-256)** 로 바꾼다 (`pki-common.sh` `common_use_engine_drbg`; FIPS 모드면 FIPS 승인 DRBG 사용).
- PKCS#12 보호: OpenSSL 3.0 `pkcs12 -export` 기본값(설치본에서 아래 명령으로 확인) — 키 암호화 AES-256-CBC, 키 유도 PBKDF2-HMAC-SHA256 반복 2,048회, salt 64비트,
  무결성 MAC HMAC-SHA256 반복 2,048회. 확인: `openssl pkcs12 -info -noout -in engine.p12`
  (출력의 `PBES2, PBKDF2, AES-256-CBC, Iteration`, `MAC: sha256, Iteration`, `salt length`).
- PKCS#12 비밀번호: engine-setup 기본값 `mypass` (`Defaults.DEFAULT_PKI_STORE_PASS`), `/etc/ovirt-engine/engine.conf.d/10-setup-pki.conf`에 기록 (§10).

### 8.2 TLS 세션 암호화 키, 세션 무결성 검사 키

| 항목 | 내용 |
|---|---|
| 무엇 | TLS 핸드셰이크(ECDHE 키교환)마다 새로 만들어지는 세션 키. 마스터 시크릿(TLS 1.2) / 트래픽 시크릿(TLS 1.3)에서 PRF·HKDF로 유도된 **암호화 키**와, CBC 계열 암호군의 경우 **MAC(무결성) 키**. GCM 계열은 암호화 키 하나로 무결성까지 처리 |
| 생성 난수 | Apache: OpenSSL 프로세스 DRBG / Engine(Java): JSSE `SecureRandom` / Vault: Go `crypto/rand` |
| 프로토콜 | RHEL 시스템 암호정책 적용 (setup이 `SSLProtocol`을 지정하지 않음 → 기본 TLS 1.2·1.3) |
| **저장 여부** | **디스크에 저장하지 않는다.** 연결하는 동안 프로세스 메모리에만 존재 |
| 세션 재개 캐시 | Apache(RHEL 기본 `ssl.conf`) `SSLSessionCache shmcb:/run/httpd/sslcache` — 마스터 시크릿을 **공유메모리**(tmpfs `/run`)에 보관, 만료 300초. 세션 티켓 키는 httpd 기동 시 메모리에 난수 생성(파일 저장 없음) |
| Java(JSSE) | 세션 캐시 JVM 힙 메모리 |

---

## 9. 키 파기 방법 (TLS 포함 종합)

| 키 | 파기 방법 | 시점 |
|---|---|---|
| DEK | 메모리 소멸, 파일 원자적 교체, KEK 파기로 암호학적 소거 | 매 연산 종료·재암호화·제거 |
| KEK | Vault `trim`(구버전) / `delete`(전체) → 암호학적 소거 | 운영자 결정 (회전·폐기) |
| 봉인해제 키 조각 | `vault operator rekey` 후 구 조각 매체 파기 | 보관자 변경·유출 의심 시 |
| Vault 토큰 | `vault token revoke`, 파일 교체(`--install-token-stdin --overwrite`) | 회전·폐기 시 |
| 로그인 RSA 개인키 | 파일 삭제 (`engine-cleanup` 시 자동) | 제거·교체 시 |
| TLS 개인키 | 인증서 갱신 시 새 키로 교체·구 파일 삭제, 제품 제거 시 `/etc/pki/ovirt-engine` 삭제 | 갱신·제거 시 |
| TLS 세션 암호화·무결성 키 | 연결 종료 시 OpenSSL이 `OPENSSL_cleanse`로 0 덮어쓰기 후 해제. 세션 캐시는 만료(300초)·httpd 재시작 시 소멸. 세션 티켓 키는 httpd 종료 시 소멸. Java는 GC로 해제 | 연결 종료·만료·재시작 |
| 파일 삭제 일반 | `os.remove`/`os.replace` (블록 덮어쓰기 없음) → 매체 폐기 시 물리 파기 | — |

---

## 10. 검사 시 지적될 수 있는 사항 (사실 기재) 및 권고

| # | 사항 | 근거 | 권고 |
|:-:|---|---|---|
| F1 | 로그인 비밀번호 해시가 **PBKDF2-HMAC-SHA1, 반복 2,000회**, salt를 **NativePRNG**로 생성 (KCMVP DRBG 아님, 반복횟수 낮음) | AAA-JDBC 기본 설정 | `ovirt-aaa-jdbc-tool settings set`으로 `PBE_ALGORITHM=PBKDF2WithHmacSHA256`, `PBE_ITERATIONS`≥210000 설정 후 비밀번호 재설정. salt RNG 변경은 AAA-JDBC 패키지 수정 필요 |
| F2 | SSO 클라이언트 비밀값 해시가 PBKDF2-HMAC-SHA1 4,000회 | `ovirt-engine-crypto-tool pbe-encode` 기본값 | SHA-256·반복횟수 상향 |
| F3 | 설정파일·KEK의 블록암호가 **AES-256** (KCMVP 검증대상 블록암호는 ARIA·SEED·LEA·HIGHT) | `encryptor.py`, Vault Transit | 파일 암호화 ARIA-256-GCM 전환, KEK는 KCMVP 검증필 HSM 연동 |
| F4 | AAA 확장 런타임 설정에 DB 비밀번호 **평문** | `config/aaajdbc.py` (`internal-authn/authz.properties`) | 암호화 대상 확대 |
| F5 | SSO 클라이언트 비밀값 원문이 `11-setup-sso.conf`에 **평문** | `config/sso.py` | 암호화 대상 확대 |
| F6 | `engine-backup`이 설정파일 3종을 **복호화한 상태로 백업 아카이브에 포함** | `engine-backup.sh` `my_load_config` | 백업 파일 암호화·보관 통제, 코드 개선 |
| F7 | PKCS#12 키저장소 비밀번호 기본값이 `mypass`, TLS 개인키 일부가 평문 PEM(`*.key.nopass`) | `engine_common/constants.py`, `pki/ca.py` | 파일 권한(0600)으로만 보호됨을 명시, 저장소 비밀번호 변경 |
| F8 | PostgreSQL 서버가 만드는 SCRAM salt는 OpenSSL 기본 DRBG(CTR_DRBG) 사용 | PostgreSQL 동작 | `postgres` 비밀번호는 `ovirt-engine-db-local-auth`(Hash_DRBG salt)로 설정 |
| F9 | DEK·평문의 메모리 영점화 미수행, 파일 삭제 시 블록 덮어쓰기 없음 | Python `bytes`, `os.remove` | 비특권 계정·단시간 처리, core dump 비활성, 매체 물리 파기 |

---

## 11. 검사자 확인 명령 (비밀값 미출력)

```console
# 설정파일이 암호화되어 있는지 (OVVLT001)
for f in /etc/ovirt-engine/engine.conf.d/10-setup-database.conf \
         /etc/ovirt-engine/engine.conf.d/10-setup-dwh-database.conf \
         /etc/ovirt-engine/aaa/internal.properties; do printf '%s: ' "$f"; head -c 8 "$f"; echo; done

# DEK 난수발생기 (Hash_DRBG)
python3 -c 'from ovirt_engine import csprng; print(csprng.describe())'
#   기대: Hash_DRBG,SHA-256,256 (OpenSSL EVP_RAND, seeded by SEED-SRC, known-answer test passed)

# 로그인 비밀번호 해시 파라미터 (AAA-JDBC)
psql -U engine -d engine -Atc "SELECT name, value FROM aaa_jdbc.settings
  WHERE name IN ('PBE_ALGORITHM','PBE_ITERATIONS','PBE_KEY_SIZE')"

# 저장된 해시의 형식만 확인 (해시값 자체는 보지 않음)
psql -U engine -d engine -Atc "SELECT convert_from(decode(password,'base64'),'UTF8')
  FROM aaa_jdbc.users WHERE name='admin'" | python3 -c \
  'import json,sys; d=json.loads(sys.stdin.read()); print({k:d[k] for k in ("algorithm","iterations")}, "salt bits:", len(__import__("base64").b64decode(d["salt"]))*8)'

# 비밀번호 이력 해시 형식
psql -U engine -d engine -Atc "SELECT split_part(password_hash,'\$',1), split_part(password_hash,'\$',2)
  FROM user_password_history LIMIT 1"
#   기대: PBKDF2WithHmacSHA256 | 210000

# PostgreSQL 역할 비밀번호 방식 (해시 앞부분만)
psql -U engine -d engine -Atc "SHOW password_encryption"            # scram-sha-256

# KEK 속성 (관리자 토큰, 키 바이트 미출력)
vault read transit/keys/ovirt-engine-config     # type=aes256-gcm96, exportable=false
vault status                                     # Total Shares 5, Threshold 3

# TLS 개인키 권한, PKCS#12 보호 파라미터
stat -c '%n %U:%G %a' /etc/pki/ovirt-engine/keys/*
openssl pkcs12 -info -noout -in /etc/pki/ovirt-engine/keys/engine.p12   # 저장소 비밀번호 입력
```

---

## 12. 관련 문서

| 문서 | 내용 |
|---|---|
| `docs/crypto-failure-audit-verification-form.md` | Vault·OVVLT001 암호키 생성·저장·파기 명세 (상세) |
| `docs/csprng-hash-drbg.md` | Hash_DRBG 적용 범위·자가시험 |
| `docs/postgresql-scram-hardening.md`, `docs/db-local-authentication.md` | DB 비밀번호 SCRAM, 로컬 접속 인증 |
| `docs/vault-transit-rocky-linux-9.5.md` | Vault 구축·봉인해제 절차 |
| `docs/webadmin-login-credential-encryption-verification-form.md` | 로그인 RSA-OAEP 키 |
