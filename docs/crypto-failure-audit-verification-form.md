# DB 접근 설정파일 암호키 생성·저장·파기 명세서 (Vault Transit, OVVLT001)

## 1. 문서 정보

| 항목 | 내용 |
|---|---|
| 문서명 | DB 접근 설정파일 암호키 생성·저장·파기 명세서 |
| 대상 제품 | oVirt Engine (OV-Works) 4.5.x |
| 암호화 방식 | **Vault Transit 봉투 암호화, 봉투 식별자 `OVVLT001`** (본 문서는 이 방식만 다룬다) |
| 보호 대상 파일 | `10-setup-database.conf`, `10-setup-dwh-database.conf`, `internal.properties` |
| 관련 보안요구사항 | 중요정보 암호화 저장, 검증된 암호알고리즘 사용, 안전한 난수 사용, 암호키 생성·저장·접근통제·파기, 암호키 생성 실패·암호연산 실패 감사기록 |
| 대상 호스트 | `[호스트명 / IP]` |
| 문서 버전 / 작성일 | 2.0 / `[YYYY-MM-DD]` |
| 작성자 / 검증자 / 승인자 | `[성명·직책] / [성명·직책] / [성명·직책]` |

> 본 문서는 저장소 소스코드에서 확인한 사실만 기술한다. 각 항목에 근거 소스(`파일` / `함수`)를 적어
> 검사자가 같은 내용을 직접 대조할 수 있게 하였다. 실제 키 값·토큰·지문·봉인해제 키 조각은 싣지 않는다.
>
> **국정원 검증대상 암호알고리즘(KCMVP) 대응은 §3에 항목별로 표기한다.** 난수발생기(Hash_DRBG),
> 해시(SHA-256), 공개키 암호(RSAES-OAEP)는 검증대상 알고리즘이다. 반면 블록암호는 현재 **AES-256**이며
> 이는 검증대상 목록(ARIA·SEED·LEA·HIGHT)에 없다. 이 차이와 전환 방안은 §3.2와 §14에 숨기지 않고 기재한다.

---

## 2. 용어 (국내외 표준 용어 기준)

| 용어 | 정의 | 근거 표준 | 본 제품의 대응 |
|---|---|---|---|
| **DEK** (Data Encryption Key, 데이터 암호키) | 데이터를 직접 암·복호화하는 대칭키 | NIST SP 800-57 Pt.1 (Symmetric data-encryption key) | 설정파일 1건을 암호화할 때마다 새로 만드는 256비트 대칭키 |
| **KEK** (Key Encryption Key, 키 암호키) | 다른 키를 암호화(랩핑)하는 대칭키 | NIST SP 800-57 Pt.1 (Symmetric key-wrapping key) | Vault Transit 내부 키 `ovirt-engine-config` |
| **키 랩핑** (Key Wrapping) | KEK로 DEK를 암호화해 보관하는 것 | NIST SP 800-38F | Vault Transit `encrypt` API |
| **봉투 암호화** (Envelope Encryption) | DEK로 데이터를, KEK로 DEK를 암호화하는 2계층 구조 | — | `OVVLT001` 봉투 |
| **DRBG** (결정론적 난수발생기) | 엔트로피 입력으로 시드된 승인 난수발생 메커니즘 | NIST SP 800-90A Rev.1, KCMVP 난수발생기 | **Hash_DRBG (SHA-256, 보안강도 256비트)** |
| **엔트로피 원** | DRBG의 시드·재시드 입력 | NIST SP 800-90B/C | Linux 커널 `getrandom(2)` (OpenSSL `SEED-SRC`) |
| **AEAD** (인증 암호) | 기밀성과 무결성을 함께 제공하는 암호 운영모드 | NIST SP 800-38D (GCM) | GCM 모드, 인증태그 128비트 |
| **AAD** (추가 인증 데이터) | 암호화하지 않지만 무결성을 보장하는 데이터 | NIST SP 800-38D | 봉투 헤더 + 랩핑된 DEK |
| **KDF** (키 유도 함수) | 비밀값에서 키를 유도하는 함수 | NIST SP 800-132 / 800-108 | **`OVVLT001`에서는 사용하지 않는다** (§5.2) |
| **암호학적 소거** (Cryptographic Erasure) | 키를 파기해 그 키로 보호된 모든 암호문을 복원 불가로 만드는 것 | NIST SP 800-88 Rev.1 | KEK 버전 삭제 (§6.5) |
| **봉인/봉인해제** (Seal/Unseal) | Vault가 저장소 복호용 키를 메모리에 올리지 않은/올린 상태 | HashiCorp Vault | Unseal Key Share 5개 중 3개로 해제 (§7) |
| **Shamir 비밀분산** | 비밀을 n개 조각으로 나누어 k개 이상이어야 복원되게 하는 기법 | Shamir (1979) | 5개 조각 중 3개 (§7) |

> **용어 충돌 주의**: `packaging/setup/ovirt_engine_setup/engine_common/database.py`의 `DEK =
> oengcommcons.DBEnvKeysConst`는 **DB 환경변수 키 상수의 별칭**이며 데이터 암호키 DEK와 무관하다.

---

## 3. 암호 알고리즘 및 국정원 검증대상(KCMVP) 대응

### 3.1 사용 알고리즘 전체 목록

| # | 용도 | 알고리즘 / 파라미터 | 수행 위치 | KCMVP 검증대상 |
|:-:|---|---|---|:-:|
| A1 | DEK·논스 생성용 난수 | **Hash_DRBG**, SHA-256, 보안강도 256비트, 개인화 문자열 `ovirt-engine csprng v1`, 예측내성 미사용, 엔트로피 원 `SEED-SRC`(`getrandom(2)`) | Engine 호스트 (OpenSSL 3 EVP_RAND) | **적합** (난수발생기 Hash_DRBG) |
| A2 | DB 계정 비밀번호 생성용 난수 | A1과 같은 Hash_DRBG | Engine 호스트 (engine-setup) | **적합** |
| A3 | 설정파일 암호화 (DEK 사용) | AES-256-GCM, 논스 96비트, 태그 128비트 | Engine 호스트 | 운영모드 GCM은 대상, **블록암호 AES는 비대상** |
| A4 | DEK 랩핑 (KEK 사용) | Vault Transit `aes256-gcm96` (AES-256-GCM, 논스 96비트) | Vault 서버 | **블록암호 AES는 비대상** |
| A5 | KEK 생성용 난수 | Go `crypto/rand` (Linux `getrandom(2)`) | Vault 서버 | 비대상 (Vault 내부, 교체 불가) |
| A6 | Vault 저장소 보호 (Barrier) | AES-256-GCM | Vault 서버 | 비대상 (Vault 내부) |
| A7 | Vault 봉인키 분산 | Shamir 비밀분산 (5조각, 임계 3) | Vault 서버 | 해당 없음 (암호알고리즘 아님) |
| A8 | 로그인 ID/PW 보호 (로그인 키) | **RSAES-OAEP**, SHA-256, MGF1-SHA-256, 키 3072비트 권장(최소 2048) | 브라우저(암호화) / SSO(복호화) | **적합** (공개키 암호 RSAES-OAEP) |
| A9 | 해시 | **SHA-256** | DRBG·OAEP 내부 | **적합** |
| A10 | Vault 통신 | TLS 1.2 이상 (서버 인증서 검증 필수) | Engine ↔ Vault | 별도 (TLS 설정 통제) |

근거: A1·A2 `packaging/pythonlib/ovirt_engine/csprng.py`(`HashDrbg`, `token_bytes`),
`packaging/encryptor/encryptor.py`(`random_bytes`), `packaging/setup/ovirt_engine_setup/engine_common/postgres.py`
(`generatePassword`). A3·A4 `encryptor.py`(`encrypt_vault_bytes`, `VaultTransitClient.ensure_key`).
A8 `backend/manager/modules/enginesso/.../sso/utils/LoginEnvelopeCrypto.java`.

### 3.2 검증대상과 다른 부분 (사실 기재)

| 항목 | 현재 | 검증대상 알고리즘으로 맞추려면 |
|---|---|---|
| A3 파일 암호화 블록암호 | AES-256-GCM | **ARIA-256-GCM**으로 전환. Engine 호스트의 OpenSSL 3은 ARIA-GCM을 제공한다. 봉투 버전을 올려(`OVVLT002` 등) 기존 파일과 구분해야 한다 (§14) |
| A4 KEK 랩핑 블록암호 | Vault Transit `aes256-gcm96` | Vault Transit은 ARIA를 지원하지 않는다. KCMVP 검증필 HSM/KMS를 KEK 보관소로 쓰거나(Vault Enterprise Managed Keys·PKCS#11 연동 포함), KEK 계층을 검증필 모듈로 옮겨야 한다 (§14) |
| A5·A6 Vault 내부 | Go `crypto/rand`, AES-256-GCM | Vault 오픈소스 내부 구현은 변경할 수 없다. 검증필 HSM의 auto-unseal·엔트로피 증강(Enterprise)으로 보완한다 |

> 본 문서는 위 차이를 **충족한 것으로 기재하지 않는다.** 검사 제출 시 §14의 조치 계획과 함께 제출한다.

---

## 4. 보호 대상 (암호화 대상 파일)

### 4.1 파일·내용·권한

| # | 파일명 | 절대 경로 | 담긴 비밀 | 소유자:그룹 / 권한 | 런타임에 읽는 주체 |
|:-:|---|---|---|---|---|
| ① | `10-setup-database.conf` | `/etc/ovirt-engine/engine.conf.d/10-setup-database.conf` | `ENGINE_DB_PASSWORD` (Engine DB 계정 비밀번호) | `root:ovirt` / `0640` | Engine 기동 스크립트 (§9.2) |
| ② | `10-setup-dwh-database.conf` | `/etc/ovirt-engine/engine.conf.d/10-setup-dwh-database.conf` | `DWH_DB_PASSWORD` (DWH DB 계정 비밀번호) | `root:ovirt` / `0640` | Engine 기동 스크립트 (§9.2) |
| ③ | `internal.properties` | `/etc/ovirt-engine/aaa/internal.properties` | `config.datasource.dbpassword` (AAA-JDBC 저장소 DB 계정 비밀번호) | `ovirt` / `0600` | `ovirt-aaa-jdbc-tool` (engine-setup 중에만, §9.1) |

①②의 평문 형식: `*_DB_HOST / _PORT / _USER / _PASSWORD / _DATABASE / _SECURED / _SECURED_VALIDATION /
_DRIVER / _URL` 셸 형식 키=값 (`engine_common/database.py`). ③: `config.datasource.jdbcurl / dbuser /
dbpassword / jdbcdriver / schemaname` (`config/aaajdbc.py` `_getDatasourceConfigContent`).

### 4.2 대상 비밀(DB 계정 비밀번호)의 생성

| 항목 | 내용 |
|---|---|
| 생성 시점 | engine-setup이 로컬 DB를 새로 프로비저닝할 때 1회 |
| 생성 방식 | 영숫자 62자 집합에서 22자를 **Hash_DRBG**로 균등 선택 (`csprng.SystemRandom().choice`) |
| 엔트로피 | 22 × log₂62 ≈ **131비트** |
| 근거 | `engine_common/postgres.py` `Provisioning.generatePassword` |

### 4.3 대상 제한

- 암호화 도구는 위 **3개 파일명만** 처리한다. 상수로 고정되어 있으며 설정의 `allowed_files`는 이 상수의
  부분집합이어야 한다 (`encryptor.py` `ALLOWED_CONFIG_BASENAMES`, `encrypt_conf_files.py`).
- 처리 경로는 `/etc/ovirt-engine`, `/etc/ovirt-engine-dwh` 아래로 제한된다 (`ALLOWED_ROOTS`).
- 경로 어느 구간이든 심볼릭 링크면 거부하고, 그룹/기타 쓰기 가능 파일도 거부한다 (`validate_ovirt_path`).

---

## 5. DEK (데이터 암호키)

### 5.1 무엇이 DEK인가

**설정파일 내용을 직접 암호화하는 256비트 대칭키**이다. 소스의 `data_key` 변수이며 길이는
`DATA_KEY_SIZE = 32`바이트로 고정이다 (`encryptor.py`). **파일 1건마다 서로 다른 DEK**를 쓴다. 3개 파일을
암호화하면 DEK 3개가 만들어지고, 같은 파일을 다시 암호화해도 새 DEK가 만들어진다.

### 5.2 생성 — 어떻게

| 항목 | 내용 |
|---|---|
| 생성 함수 | `encryptor.encrypt_vault_bytes()` → `random_bytes(32)` |
| 난수발생기 | **Hash_DRBG** (NIST SP 800-90A Rev.1 §10.1.1), 해시 **SHA-256**, 보안강도 **256비트** |
| 구현 | OpenSSL 3 `EVP_RAND_fetch("HASH-DRBG")`, 전용 컨텍스트 (프로세스 전역 설정 변경 없음) |
| 엔트로피 입력 | OpenSSL `SEED-SRC` → Linux `getrandom(2)` (인스턴스화·재시드 시) |
| 개인화 문자열 | `ovirt-engine csprng v1` (SP 800-90A §8.7.1) |
| 자가시험 | ① 정답비교시험(KAT): 고정 엔트로피·논스·개인화 문자열로 인스턴스화해 기대 출력과 바이트 단위 대조 ② 연속시험: 연속 두 블록 동일·전부 0이면 사용 중지 (`csprng.known_answer_test`, `_health_check`) |
| 키 유도(KDF) | **사용하지 않는다.** DEK는 DRBG 출력 그대로이다. 비밀번호·패스프레이즈에서 유도하지 않으므로 반복횟수 파라미터가 없다 |
| 길이 | 256비트 |

```python
# encryptor.py  encrypt_vault_bytes()
data_key   = random_bytes(DATA_KEY_SIZE)   # DEK 256비트, Hash_DRBG(SHA-256)
data_nonce = random_bytes(NONCE_SIZE)      # 파일 암호화 논스 96비트, Hash_DRBG(SHA-256)
wrapped_key = transit_client.wrap(data_key)  # KEK로 랩핑 (Vault)
```

> **대체 경로**: libcrypto에서 Hash_DRBG를 얻을 수 없으면(OpenSSL 3 미만 등) `os.urandom()`으로 대체하고
> `csprng.describe()`가 그 사실을 보고한다. 자체 보안검증(`ov-works-security_audit.sh`의
> approved random generator 항목)이 이를 **WARN**으로 표시한다. 운영 환경에서는 PASS여야 한다.

### 5.3 저장 — 어디에

| 항목 | 내용 |
|---|---|
| 평문 DEK | **어디에도 저장하지 않는다** (디스크·DB·로그·환경변수 없음). 연산 중 프로세스 메모리에만 존재 |
| 랩핑된 DEK | **자신이 보호하는 암호문 파일 안**, 봉투 헤더 바로 뒤에 저장 (§8) |
| 랩핑 형식 | Vault 반환 문자열 `vault:v<KEK 버전>:<Base64(논스 96비트 ‖ 암호문 256비트 ‖ 태그 128비트)>` |
| 길이 | 가변(최대 65535바이트, 헤더의 uint16). KEK 버전 1이면 89바이트 |

DEK는 KEK 없이 풀 수 없다. KEK는 Vault 밖으로 나오지 않으므로(§6.3), 암호문 파일만 탈취되면 DEK도
평문도 복원할 수 없다.

### 5.4 사용 — 대상, 시점, 방법

| 항목 | 내용 |
|---|---|
| 암호화 대상 | §4.1의 파일 ①②③ 전체 바이트열 (파일 단위) |
| 알고리즘 | AES-256-GCM (NIST SP 800-38D) |
| 논스 | 96비트, **파일마다 새로** Hash_DRBG로 생성 |
| AAD | 봉투 고정 헤더(23바이트) + 랩핑된 DEK 전체 |
| 인증태그 | 128비트 (암호문 끝에 부착) |
| 무결성 효과 | 헤더·논스·랩핑 DEK·암호문 중 1비트라도 바뀌면 복호화가 인증 실패로 중단되고 **출력 파일을 만들지 않는다** |
| 자기검증 | 암호화 직후 즉시 복호화해 원문과 일치할 때만 원본을 교체 (`transform_file`, "Post-encryption self-verification") |

**사용 시점** (§9 상세):

| 시점 | 연산 | 주체 |
|---|---|---|
| engine-setup 마무리(CLOSEUP) | ①②③ 암호화 (DEK 생성 → 랩핑 → 파일 암호화) | `client_control.py` `_encrypt_configuration_files` → `encrypt_conf_files.py` |
| Engine 기동 | ①② 복호화 (랩핑 DEK 개봉 → 파일 복호) | `ovirt_engine/configfile.py` `ConfigFile._decrypt` (Java 기동 전, Python 런처) |
| engine-setup 실행 중 | ③ 복호화 → CLOSEUP에서 새 DEK로 재암호화 | `client_control.py` `_decrypt_internal_configuration` / `_closeup` |
| engine-backup | ①②③ 일시 복호화, 종료 시 원래 암호문으로 복원 | `engine-backup.sh` `decrypt_config_if_allowed` / `restore_decrypted_configs` |
| engine-cleanup | ①②③ 복호화 (제거 절차가 DB 자격증명을 읽음) | `ovirt-engine-remove/config/decrypt.py` |

### 5.5 파기

| 상황 | 처리 |
|---|---|
| 연산 종료 | 평문 DEK는 프로세스 종료와 함께 메모리에서 사라진다 |
| 파일 재암호화 | 새 DEK로 만든 파일이 원자적 교체(`os.replace`)로 이전 파일을 대체 → 이전 랩핑 DEK 접근 불가 |
| KEK 버전 파기 | 그 버전으로 랩핑된 모든 DEK가 복원 불가 (암호학적 소거, §6.5) |
| Engine 제거 | 대상 파일이 복호화·삭제되면서 랩핑 DEK도 함께 사라진다 |

> **한계(사실 기재)**: Python `bytes`는 불변 객체라 DEK의 **명시적 메모리 영점화를 수행하지 않는다.**
> 완화: 연산은 단시간이며 비특권 `ovirt` 계정 프로세스에서 수행된다 (§13).

---

## 6. KEK (키 암호키)

### 6.1 무엇이 KEK인가

**engine-setup에서 PBKDF2로 유도해 HashiCorp Vault Transit에 가져와(import) 보관하는 256비트 대칭키**이다
(상세: `docs/vault-kek-pbkdf2.md`). 키 이름은
`ovirt-engine-config`이다 (`config.json`의 `vault_transit.key_name`). 용도는 **DEK 랩핑·개봉 하나뿐**이며,
설정파일 평문은 KEK에 노출되지 않는다.

### 6.2 생성

| 항목 | 내용 |
|---|---|
| 생성 시점 | 최초 1회, engine-setup 최초 설치 시 (Vault에 키가 없을 때만). Vault 자체 회전 금지(`allow_rotation=false`) |
| 생성 주체 | **engine-setup**이 유도하고 **Vault**가 보관한다 |
| 초기 데이터 | 운영자가 engine-setup에서 직접 입력한 패스프레이즈(16자 이상, 3종 이상 문자). 화면 표시 없이 입력받아 메모리에만 두고 사용 후 덮어쓴다 |
| 키 유도 | **PBKDF2-HMAC-SHA256**, 반복 **600,000회**, 출력 256비트 (`encryptor.derive_kek`) |
| salt | 256비트, **Hash_DRBG(SHA-256)**, 설치마다 새로 생성 → 같은 패스프레이즈라도 제품마다 다른 KEK. `config.json`의 `kek_derivation`에 기록(비밀 아님) |
| 가져오기 | Vault `transit/wrapping_key`(RSA-4096) + 임시 AES-256 키: RSA-OAEP(SHA-256)·AES-KWP(RFC 5649) 랩핑 후 `transit/keys/ovirt-engine-config/import` (`VaultTransitClient.import_key`) |
| 키 유형 | `aes256-gcm96`: 256비트 키, GCM, 논스 96비트 |
| 반출 | `exportable=false`: **API로 키 바이트를 꺼낼 수 없다** |
| 평문 백업 | `allow_plaintext_backup=false`: **평문 백업 불가** |
| 일치 검증 | 가져온 직후 서비스 토큰으로 Vault가 암호화한 값을 유도 KEK로 열어 같은 키임을 확인 (`kek_matches_vault`) |
| 생성 권한 | 가져오기 전용 토큰(`transit/wrapping_key` read, `transit/keys/<키>/import` update)만. engine-setup에 직접 입력하며 파일로 저장하지 않는다. 운영(애플리케이션) 토큰에는 `transit/keys/*` 권한이 없다 |

### 6.3 저장

| 항목 | 내용 |
|---|---|
| 저장 위치 | Vault 통합 저장소(Raft) `/opt/vault/data` 안에, **Vault Barrier 키로 암호화된 상태** (§7) |
| Engine 호스트 저장 | **없음.** 봉투·설정파일·로그·환경변수 어디에도 KEK가 없다 |
| 봉인 상태 | Vault가 봉인(sealed)되면 KEK를 쓸 수 없다 → 복호화 불가 → Engine 기동 불가(fail-closed) |
| 키 버전 | 랩핑 결과에 `vault:v<N>`으로 기록되어 회전 후에도 구 버전 DEK 개봉 가능 |

### 6.4 사용

| 항목 | 내용 |
|---|---|
| 대상 | **DEK만** (32바이트) |
| 랩핑 | `POST /v1/transit/encrypt/ovirt-engine-config` → `vault:v<N>:...` (`VaultTransitClient.wrap`) |
| 개봉 | `POST /v1/transit/decrypt/ovirt-engine-config` (`VaultTransitClient.unwrap`) |
| 시점 | 파일 1건 암호화 시 1회, 복호화 시 1회 (§5.4의 시점과 같음) |
| 통신 | HTTPS(TLS 1.2+), CA 인증서 검증 필수. 평문 HTTP는 거부 (`VaultTransitClient.__init__`) |
| 인증 | 애플리케이션 토큰 (§7.4). 권한은 `encrypt`·`decrypt` 경로의 `update` **두 개뿐** |
| 사전점검 | engine-setup이 Hash_DRBG 난수 32바이트를 실제로 wrap→unwrap해 왕복 확인 (`vault_passphrase.py --check`, `client_control.py` `_preflight_vault_transit`) |

### 6.5 회전·파기

| 구분 | 방법 | 효과 |
|---|---|---|
| 회전 | `vault write -f transit/keys/ovirt-engine-config/rotate` | 이후 랩핑은 새 버전. 기존 파일은 구 버전으로 계속 개봉 |
| 기존 파일 재암호화 | 파일별 `encryptor.py --decrypt` 후 `--encrypt` (새 DEK + 최신 KEK 버전) | 구 버전 의존 제거 |
| 구 버전 사용 금지 | `vault write transit/keys/ovirt-engine-config/config min_decryption_version=<N>` | N 미만 버전으로 랩핑된 DEK 개봉 거부 |
| 구 버전 파기 | `vault write transit/keys/ovirt-engine-config/trim min_available_version=<N>` | N 미만 버전 키 재료 삭제 → **암호학적 소거** |
| KEK 전체 파기 | `deletion_allowed=true` 설정 후 `vault delete transit/keys/ovirt-engine-config` | 이 KEK로 보호된 **모든 파일 영구 복원 불가** |

> 파기·회전 명령은 관리자 토큰이 필요하다. 애플리케이션 토큰으로는 수행할 수 없다(최소권한).

---

## 7. Vault 내부 키 계층과 "Vault에서 만들어진 5개의 키"

### 7.1 5개의 키는 무엇인가

`vault operator init -key-shares=5 -key-threshold=3`를 실행하면 나오는 **5개의 키는 Unseal Key Share
(봉인해제 키 조각)** 이다. **DEK도 KEK도 아니다.** Vault의 봉인해제 키를 Shamir 비밀분산으로 5조각으로
나눈 것이며, **서로 다른 3조각**을 입력해야 Vault가 봉인해제된다.

### 7.2 Vault 키 계층

```text
Unseal Key Share ×5 (보관자 5명 분산, 임계값 3)
      │ 3조각 결합 (Shamir)
      ▼
Unseal Key (봉인해제 키)
      │ 복호화
      ▼
Root Key (루트 키, 구 명칭 Master Key)              ← 저장소에 암호화되어 보관
      │ 복호화
      ▼
Keyring = Barrier Encryption Key (AES-256-GCM)      ← 저장소 전체 암호화 키
      │ 복호화
      ▼
Vault 저장소 데이터 (/opt/vault/data)
      └─ Transit KEK  "ovirt-engine-config" (aes256-gcm96)   ← §6의 KEK
              │ 랩핑/개봉
              ▼
         DEK (파일당 1개, 256비트)                  ← §5의 DEK, 봉투 파일 안에 랩핑 상태로 저장
              │ AES-256-GCM
              ▼
         설정파일 ①②③
```

### 7.3 Vault 관련 키·자격증명 전체 목록

| # | 이름 | 개수 | 성격 | 생성 | 저장 | 용도 | 파기 |
|:-:|---|:-:|---|---|---|---|---|
| V1 | **Unseal Key Share** | **5** | 봉인해제 키의 Shamir 조각 | `vault operator init` 시 Vault 생성 | **보관자 5명이 각각 분리 보관**. Vault 데이터·oVirt 백업·암호화 설정·암호문과 같은 곳 금지 | Vault 재기동 후 봉인해제 (3조각) | `vault operator rekey`로 새 조각 발급 시 구 조각 무효. 매체 물리 파기 |
| V2 | Root Key | 1 | 저장소 보호 상위 키 | init 시 Vault 생성 | 저장소에 Unseal Key로 암호화 | Keyring 복호 | Vault 폐기 시 저장소와 함께 |
| V3 | Barrier Key (Keyring) | 1+ | 저장소 암호화 키, AES-256-GCM | init 시 Vault 생성 | 저장소에 Root Key로 암호화 | 저장소 전체(KEK 포함) 암·복호 | `vault operator rotate`로 새 키 추가 |
| V4 | **Transit KEK** | 1 (+버전) | §6의 KEK | 관리자 요청으로 Vault 생성 | 저장소 (Barrier로 암호화) | DEK 랩핑·개봉 | §6.5 |
| V5 | Initial Root Token | 1 | 최상위 관리자 토큰 (키 아님) | init 시 출력 | 부트스트랩 동안만 | Vault 초기 구성 | **구성 완료 직후 `vault token revoke`** |
| V6 | 애플리케이션 토큰 | 1 | Engine이 KEK를 호출하는 인증 자격증명 (키 아님) | `vault token create -policy=ovirt-engine-transit -no-default-policy` | `/etc/ovirt-engine/encryptor/vault-token`, `ovirt:ovirt 0600`, 디렉터리 `root:ovirt 0750` | 랩핑·개봉 API 인증 | `vault token revoke` + `--install-token-stdin --overwrite`로 교체 |
| V7 | Vault TLS 개인키 | 1 | Vault 서버 인증서 키 | 운영자 생성 | `/etc/vault.d/tls/vault.key` (vault 계정 전용) | Engine↔Vault TLS | 인증서 교체 시 삭제 |

### 7.4 애플리케이션 토큰 정책 (최소권한)

```hcl
path "transit/encrypt/ovirt-engine-config" { capabilities = ["update"] }
path "transit/decrypt/ovirt-engine-config" { capabilities = ["update"] }
```

- 키 생성·수정·삭제·반출(export)·백업·복원·설정 변경 권한이 **없다**.
- 토큰은 표준입력으로만 설치한다. 명령행 인자·환경변수·중간 파일에 남지 않는다 (`vault_passphrase.py --install-token-stdin`).

### 7.5 봉인해제 키 조각 관리 요구사항

1. 5조각을 **서로 다른 5명**(최소 3명 이상)이 분리 보관한다. 1명이 3조각 이상을 갖지 않는다.
2. 3조각 미만으로는 봉인해제가 불가능하므로 1~2명의 유출로는 KEK에 접근할 수 없다.
3. Vault 재기동 시 매번 봉인해제 의식(3인 참석)이 필요하다. 봉인 상태에서는 Engine이 기동되지 않는다.
4. 보관자 변경·유출 의심 시 `vault operator rekey`로 조각을 재발급하고 구 조각을 파기한다.

---

## 8. 봉투 형식 `OVVLT001`

```text
오프셋  길이(바이트)  필드
0       8            매직 "OVVLT001"
8       1            형식 버전 (= 1)
9       12           파일 암호화 논스 (96비트, Hash_DRBG)
21      2            랩핑된 DEK 길이 (uint16, 빅엔디안)
23      가변          랩핑된 DEK  "vault:v<N>:<Base64>"  (ASCII)
...     가변          AES-256-GCM 암호문 ‖ 인증태그(128비트)
AAD = 바이트 0~22 (고정 헤더) ‖ 랩핑된 DEK
```

정의: `encryptor.py` `VAULT_HEADER = struct.Struct(">8sB12sH")`, `encrypt_vault_bytes`,
`decrypt_vault_bytes`. 봉투에는 **KEK·Vault 토큰·평문 DEK가 들어가지 않는다.**

---

## 9. 생명주기 — 언제, 무엇이

### 9.1 설치·재설치 (`engine-setup`)

| 순서 | 단계 | 처리 | 근거 |
|:-:|---|---|---|
| 1 | CUSTOMIZATION | Vault 사전점검: 난수 32바이트 wrap→unwrap 왕복 | `client_control.py` `_preflight_vault_transit` |
| 2 | MISC | DB 계정 비밀번호 생성(Hash_DRBG) 및 ①②③ 평문 작성 | `postgres.py` `generatePassword`, `database.py`, `aaajdbc.py` |
| 3 | MISC | ③이 이미 `OVVLT001`이면 복호화 (`ovirt-aaa-jdbc-tool`이 읽어야 함) | `_decrypt_internal_configuration` |
| 4 | CLOSEUP | Vault 토큰 파일 권한 정리(`ovirt:ovirt 0600`) | `_ensure_vault_runtime_permissions` |
| 5 | CLOSEUP | **①②③ 암호화**: 파일마다 DEK 생성 → KEK 랩핑 → AES-256-GCM → 자기검증 → 원자적 교체 | `_encrypt_configuration_files` → `encrypt_conf_files.py` |
| 6 | CLOSEUP | 3개 파일이 모두 `OVVLT001`인지 재확인, 하나라도 평문이면 setup 실패 | `_encrypt_configuration_files` |
| 7 | CLOSEUP | Engine 기동 (5~6 이후로 순서 강제) | `_closeup` (`before=CORE_ENGINE_START`) |
| — | CLEANUP | setup이 중단되면 ③을 다시 암호화 | `_cleanup_internal_configuration` |

### 9.2 운영 (Engine 기동)

```text
systemd → ovirt-engine.py (Python, ovirt 계정)
  ├─ ConfigFile 로드: ①② 매직 OVVLT001 확인
  │    └─ encryptor 로드 → Vault unwrap(KEK) → DEK → AES-256-GCM 복호 → 평문은 메모리에만
  ├─ ovirt-engine.xml 렌더링(DB 비밀번호 주입), 런타임 디렉터리 0600 (기동마다 삭제 후 재생성)
  └─ Java(JBoss) 기동  ※ Java 로더는 암호문 파일을 읽지 않고 건너뜀 (ShellLikeConfd)
```

- Vault 봉인·불가·토큰 만료·TLS 오류 → 복호 실패 → **Engine 기동 중단 (fail-closed)**, 평문 대체 경로 없음.
- 성공·실패 모두 감사기록으로 남는다 (§11).

### 9.3 제거 (`engine-cleanup`)

| 처리 | 근거 |
|---|---|
| ①②③ 복호화 (제거 절차가 DB 자격증명을 읽음) | `ovirt-engine-remove/config/decrypt.py` |
| `config.json`을 배포 기본값으로 원자적 초기화 (생성된 메타데이터 미기록, `0600`) | `ovirt-engine-remove/config/misc.py` `_write_encryptor_config` |
| 로그인 개인키 `private_pkcs8.der` 삭제 | `misc.py` `_remove_encryptor_private_key` |

---

## 10. 로그인 키 (WebAdmin ID/PW 보호용 RSA 키쌍)

설정파일 암호화(DEK/KEK)와 **독립된 별도 키 체계**이다.

| 항목 | 내용 |
|---|---|
| 용도 | 로그인 화면에서 **사용자 ID와 비밀번호를 브라우저가 암호화**해 전송 (HTTPS 위의 응용계층 추가 보호) |
| 암호화 대상 | 로그인 ID 문자열, 그리고 `ovirt-login:v1:<발급시각>:<논스>:<비밀번호>` 형식의 비밀번호 봉투 (재전송 방지 논스 포함) |
| 알고리즘 | **RSAES-OAEP**, OAEP 해시 SHA-256, MGF1-SHA-256, 레이블 없음 (`LoginEnvelopeCrypto`, 브라우저 Web Crypto `RSA-OAEP`) |
| 키 길이 | 3072비트 권장, 최소 2048비트 |
| 생성 | 운영자가 Engine 서버에서 생성. **Hash_DRBG를 쓰도록 OpenSSL 설정을 지정한다:** `OPENSSL_CONF=/usr/share/ovirt-engine/conf/openssl-drbg.cnf openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -outform DER -out /etc/ovirt-engine/encryptor/private_pkcs8.der` |
| 개인키 저장 | `/etc/ovirt-engine/encryptor/private_pkcs8.der` (PKCS#8 DER), 권한 `0600` |
| 공개키 저장 | `config.json`의 `rsaPublicKey` (X.509 SPKI PEM). 비밀 아님. `X-Client-Serial` 검증을 통과한 요청에만 배포 |
| 사용 시점 | 로그인 요청마다 SSO가 `encryptedUsername`·`encryptedPassword`를 개인키로 복호화 |
| 실패 기록 | `LOGIN_CREDENTIAL_DECRYPTION_FAILED` (§11) |
| 파기 | `engine-cleanup` 시 개인키 파일 삭제. 교체 시 새 키 배포 후 구 키 삭제 |

---

## 11. 암호키 생성 실패·암호연산 실패 감사기록

### 11.1 기록 종류

| 구분 | 감사기록 | ID | 심각도 |
|---|---|:-:|---|
| KEK 생성 성공 / DEK 생성 성공 | `CRYPTO_KEY_CREATED` | 13662 | NORMAL |
| **KEK 생성 실패 / DEK 생성 실패** | `CRYPTO_KEY_CREATION_FAILED` | 13663 | ERROR |
| DEK 복호화 성공 (복호화할 때마다) | `DEK_DECRYPTION_COMPLETED` | 13729 | NORMAL |
| **DEK 복호화 실패** | `DEK_DECRYPTION_FAILED` | 13730 | ERROR |
| 설정파일 암호화 성공 | `CONFIG_FILE_ENCRYPTION_COMPLETED` | 13660 | NORMAL |
| **설정파일 암호화 실패** | `CONFIG_FILE_ENCRYPTION_FAILED` | 13661 | ERROR |
| 설정파일 복호화 성공 | `CONFIG_FILE_DECRYPTION_COMPLETED` | 13658 | NORMAL |
| **설정파일 복호화 실패** | `CONFIG_FILE_DECRYPTION_FAILED` | 13659 | ERROR |
| **로그인 자격증명 복호화 실패** | `LOGIN_CREDENTIAL_DECRYPTION_FAILED` | 13665 | ERROR |
| 기록 항목 격리 | `CRYPTO_EVENT_SPOOL_REJECTED` | 13664 | WARNING |

### 11.2 기록 경로

암·복호화는 대부분 Engine(Java)이 존재하지 않는 시점(setup, 기동 직전)에 일어난다. 결과를 스풀
`/var/lib/ovirt-engine/security/crypto-events/<uuid>.json`(파일 `0600`, 디렉터리 `0700`, 원자적 기록)에
남기고, Engine이 기동 40초 후부터 120초 주기로 감사기록(`audit_log`)으로 옮긴다
(`ovirt_engine/cryptoevents.py`, `CryptoEventAuditManager`). 검증에 실패한 항목은 삭제하지 않고
`rejected/`로 격리하며 `CRYPTO_EVENT_SPOOL_REJECTED`로 통보한다.

### 11.2.1 KEK·DEK 메시지

키 이벤트 메시지에는 어느 키인지 `KEK`/`DEK`로 표시한다(`CryptoEvent.java`). 같은 유형
(`CRYPTO_KEY_CREATED` 등) 안에서 DEK 파일(`dek.enc`, `OVDEK001`)이면 DEK, 파일이 없으면 KEK이다.

| 경우 | 메시지 예 |
|---|---|
| KEK 생성 성공 | `KEK (key encryption key) was created at 2026-10-08T10:40:38+09:00 (engine-setup, OVENC001)` |
| KEK 생성 실패 | `KEK (key encryption key) could not be created at … (engine-setup); reason: PASSPHRASE_REJECTED` |
| DEK 생성 성공 | `DEK (data encryption key) was created and stored wrapped by the KEK in dek.enc at … (encrypt-conf-files, OVDEK001)` |
| DEK 생성 실패 | `DEK (data encryption key) could not be created (dek.enc) at … (kek-agent, OVDEK001); reason: RNG_UNAVAILABLE` |
| DEK 복호화 성공 | `DEK (data encryption key) was decrypted with the KEK (dek.enc) at … (engine-start, OVDEK001)` |
| DEK 복호화 실패 | `DEK (data encryption key) could not be decrypted with the KEK (dek.enc) at … (kek-agent, OVDEK001); reason: AUTHENTICATION_FAILED` |

DEK 복호화는 `encryptor.read_dek`에서 **복호화할 때마다** 기록한다. 괄호 안의 실행 주체는
`engine-start`(엔진 기동), `kek-agent`(재부팅 후 잠금 해제·패스프레이즈 변경), `integrity-seal`(무결성
기준값 봉인·확인), `engine-setup`, 그 밖에 암호화된 설정을 읽는 서비스·도구는 실행 파일 이름
(예: `audit-storage-usage.py`, `ovirt-engine-dwhd.py`)이다. 매분 실행되는 감사 저장소 사용량 측정
(`audit-storage-usage.py`)도 DB 설정을 복호화하므로 DEK 복호화 성공 이벤트가 매분 1건씩 남는다.

### 11.2.2 재부팅 후 KEK가 메모리에 없을 때

재부팅 후 `kek_agent.py --unlock`을 하기 전에는 KEK 패스프레이즈가 메모리에 없어 KEK를 유도할 수 없고,
따라서 DEK도 복호화할 수 없다. 이때 엔진(또는 dwhd 등) 기동은 실패하며 다음이 스풀에 남는다.

| 이벤트 | 메시지 예 |
|---|---|
| `DEK_DECRYPTION_FAILED` | `DEK (data encryption key) could not be decrypted: the KEK (key encryption key) is not available, its passphrase is not held in memory (dek.enc) at … (engine-start, OVDEK001); reason: PASSPHRASE_UNAVAILABLE` |
| `CONFIG_FILE_DECRYPTION_FAILED` (엔진 기동만) | `Configuration file 10-setup-database.conf could not be decrypted at … (engine-start, OVENC002); reason: PASSPHRASE_UNAVAILABLE (KEK not available)` |

- DEK 복호화 실패는 설정을 읽는 주체가 누구든 기록한다(엔진 기동은 `engine-start`, dwhd는 `ovirt-engine-dwhd.py`).
- 엔진이 떠 있지 않은 동안에는 감사기록(DB)에 쓸 주체가 없으므로, 잠금 해제 후 엔진이 기동되면
  스풀의 기록이 **원래 발생 시각**으로 이벤트 목록에 옮겨진다. 그 전에는 다음으로 바로 확인한다.
  ```bash
  journalctl -u ovirt-engine | grep "not loaded in memory"
  ls /var/lib/ovirt-engine/security/crypto-events/
  ```

### 11.3 사유 코드 (닫힌 어휘)

예외 원문(경로·길이·토큰이 섞일 수 있음)은 기록하지 않고 아래 코드만 기록한다.

| 코드 | 의미 | 코드 | 의미 |
|---|---|---|---|
| `VAULT_UNAVAILABLE` | Vault 정지·봉인·연결 실패·권한 거부 | `PATH_REJECTED` | 미승인 경로·심볼릭 링크·쓰기 가능 파일 |
| `VAULT_RESPONSE_INVALID` | Vault 응답 이상 | `ENCRYPTOR_MISSING` | 암호화 도구 부재 |
| `AUTHENTICATION_FAILED` | GCM 인증 실패(변조·키 불일치) | `PRIVATE_KEY_UNAVAILABLE` | 로그인 개인키 판독 불가 |
| `FILE_DAMAGED` | 봉투 절단·헤더 손상 | `CIPHERTEXT_INVALID` | 제시된 로그인 봉인값 개봉 불가 |
| `CONFIGURATION_INVALID` | 암호화 설정 오류 | `ALGORITHM_UNAVAILABLE` | 알고리즘·제공자 부재 |
| `UNKNOWN` | 그 밖의 경우 | | |

### 11.4 확인 방법 (요약)

| 시험 | 유발 방법 (무중단) | 기대 기록 / 사유 |
|---|---|---|
| 암호키 생성 실패 | 최소권한 애플리케이션 토큰으로 `sudo -u ovirt vault_passphrase.py --init-key` (HTTP 403) | `CRYPTO_KEY_CREATION_FAILED` / `VAULT_UNAVAILABLE` |
| 암호화 실패 | Vault 주소만 틀린 설정 사본으로 `vault_passphrase.py --encrypt` | `CONFIG_FILE_ENCRYPTION_FAILED` / `VAULT_UNAVAILABLE` |
| 복호화 실패(변조) | ① 사본의 마지막 1바이트 변조 후 `ConfigFile(cryptoEventSource='engine-start').loadFile()` | `CONFIG_FILE_DECRYPTION_FAILED` / `AUTHENTICATION_FAILED` |
| 복호화 실패(손상) | ① 사본을 20바이트로 절단 | `CONFIG_FILE_DECRYPTION_FAILED` / `FILE_DAMAGED` |
| 로그인 복호화 실패 | `curl -k -X POST https://127.0.0.1/ovirt-engine/sso/oauth/token -d grant_type=password --data-urlencode 'encrypted_username=!!!' ...` | `LOGIN_CREDENTIAL_DECRYPTION_FAILED` / `CIPHERTEXT_INVALID` |

- 모든 시험은 `sudo -u ovirt`로 실행한다 (root로 실행하면 스풀이 root 소유가 되어 격리됨).
- 결과는 WebAdmin **이벤트** 목록(`Events: severity=error`)에서 시각·메시지·사유 코드로 확인한다.
- 감사기록에는 키·암호문·토큰·경로·예외 원문이 들어가지 않는다 (basename과 사유 코드만).

---

## 12. 접근통제 요약

| 대상 | 경로 | 소유자:그룹 | 권한 |
|---|---|---|---|
| 암호화 설정 | `/etc/ovirt-engine/encryptor/config.json` | `root:ovirt` | `0640` (Engine이 Vault 주소·CA를 바꿀 수 없음) |
| 암호화 디렉터리 | `/etc/ovirt-engine/encryptor/` | `root:ovirt` | `0750` |
| Vault 애플리케이션 토큰 | `/etc/ovirt-engine/encryptor/vault-token` | `ovirt:ovirt` | `0600` |
| 로그인 개인키 | `/etc/ovirt-engine/encryptor/private_pkcs8.der` | — | `0600` |
| 대상 파일 ①② | `/etc/ovirt-engine/engine.conf.d/` | `root:ovirt` | `0640` |
| 대상 파일 ③ | `/etc/ovirt-engine/aaa/internal.properties` | `ovirt` | `0600` |
| 암호연산 스풀 | `/var/lib/ovirt-engine/security/crypto-events/` | `ovirt` | `0700` |
| Vault 저장소 | `/opt/vault/data` | `vault:vault` | `0700` |

---

## 13. 알려진 한계 (소스 기준 사실)

| # | 한계 | 영향 | 보완 통제 |
|:-:|---|---|---|
| L1 | 블록암호가 KCMVP 검증대상(ARIA 등)이 아닌 **AES-256** (DEK·KEK 모두) | 국정원 검증대상 알고리즘 요구 미충족 | §14 조치 계획 |
| L2 | KEK 생성 난수·Vault 내부 암호는 Vault 구현(Go `crypto/rand`, AES-GCM) | Hash_DRBG 적용 범위 밖 | 검증필 HSM 연동 (§14) |
| L3 | DEK·평문의 **메모리 영점화 미수행** (Python 불변 `bytes`) | 메모리 덤프 시 잔존 가능 | 단시간 처리, 비특권 계정, core dump 비활성 권고 |
| L4 | 파일 파기가 `os.remove`/`os.replace` 기반 (블록 덮어쓰기 없음) | 저장매체 포렌식 시 잔존 가능 | 암호문으로만 기록, 매체 폐기 시 물리 파기 |
| L5 | **`engine-backup` 실행 중 ①②③을 제자리 복호화하고 그 상태로 `/etc/ovirt-engine`을 아카이브에 담는다** (종료 시 암호문 복원) | **백업 아카이브에 평문 DB 비밀번호가 포함**되고, 백업 중에는 디스크에 평문이 존재 | 백업 파일 암호화·접근통제 필수. 코드 개선 필요 (§14) |
| L6 | AAA-JDBC 런타임 설정 `/etc/ovirt-engine/extensions.d/internal-authn.properties`, `internal-authz.properties`에 같은 DB 비밀번호가 **평문으로** 들어 있다 (`ovirt 0600`). Engine의 AAA 확장은 ③이 아니라 이 파일을 읽는다 | 3개 파일 암호화 범위 밖에 평문 사본 존재 | 파일 권한 `0600` 유지, 암호화 대상 확대 필요 (§14) |
| L7 | Vault 애플리케이션 토큰이 파일에 평문 저장 (`0600`) | Engine 호스트 root 탈취 시 토큰 사용 가능 | 최소권한(encrypt/decrypt만), 토큰 TTL·폐기, Vault 감사장치로 사용 추적 |

---

## 14. 보안요구사항 대응 및 조치 계획

### 14.1 대응표

| 보안요구사항 | 충족 내용 | 상태 |
|---|---|:-:|
| 중요정보(DB 비밀번호) 암호화 저장 | ①②③을 `OVVLT001` 봉투로 암호화. 설치 종료 시 평문 잔존 시 setup 실패 | 충족 (L5·L6 예외) |
| 검증된 암호알고리즘 사용 | 난수 Hash_DRBG, 해시 SHA-256, 로그인 RSAES-OAEP는 KCMVP 검증대상 | **부분 충족** (블록암호 AES → L1) |
| 안전한 난수 사용 | DEK·논스·DB 비밀번호를 Hash_DRBG(SHA-256, 256비트)로 생성, KAT·연속시험 | 충족 (Vault 내부 제외 L2) |
| 암호키 안전 생성 | DEK 256비트 DRBG 직접 출력(KDF 없음), KEK Vault 내부 생성·반출 불가 | 충족 |
| 암호키 안전 저장 | 평문 키 파일 없음. DEK는 랩핑 상태로만, KEK는 Vault 저장소(Barrier 암호화)에만 | 충족 |
| 키와 데이터 분리 | KEK는 별도 신뢰 경계(Vault)에 존재, 봉인해제는 3인 분산 | 충족 |
| 암호키 접근통제·최소권한 | 토큰은 encrypt/decrypt만, 설정 root 소유, 파일 0600/0640 | 충족 |
| 무결성 | GCM 태그, 헤더·랩핑 DEK를 AAD로 인증, 변조 시 출력 미생성 | 충족 |
| 암호키 파기 | DEK 메모리 소멸·파일 교체, KEK 버전 trim/삭제(암호학적 소거), 봉인조각 rekey, 토큰 revoke, 로그인 개인키 삭제 | 충족 (L3·L4 한계) |
| 실패 시 안전 동작 | Vault 불가·인증 실패 시 Engine 기동 중단 | 충족 |
| 암호키 생성 실패·암호연산 실패 감사 | §11의 8종 감사기록, 비밀정보 미포함 | 충족 |

### 14.2 조치 계획 (국정원 검증대상 알고리즘 완전 적용)

| 우선 | 조치 | 내용 |
|:-:|---|---|
| 1 | DEK 블록암호 ARIA 전환 | `ARIA-256-GCM`(OpenSSL 3)으로 파일 암호화, 새 봉투 버전으로 구분, 기존 `OVVLT001` 읽기 호환 후 일괄 재암호화 |
| 2 | KEK 검증필 모듈화 | KCMVP 검증필 HSM/KMS에 KEK 보관(ARIA 키 랩핑), 또는 Vault Enterprise Managed Keys(PKCS#11)로 HSM 연동 |
| 3 | 백업 평문 제거 (L5) | `engine-backup`이 복호화 없이 암호문 그대로 아카이브하도록 수정 |
| 4 | 런타임 평문 사본 제거 (L6) | AAA 확장 설정에서 DB 비밀번호를 분리하고 기동 시 복호 주입 |

---

## 15. 검사자 확인 절차 (비밀값 미출력)

```console
# ① 대상 파일이 OVVLT001 봉투인지
for f in /etc/ovirt-engine/engine.conf.d/10-setup-database.conf \
         /etc/ovirt-engine/engine.conf.d/10-setup-dwh-database.conf \
         /etc/ovirt-engine/aaa/internal.properties; do
  printf '%s: ' "$f"; head -c 8 "$f"; echo
done                                                   # 기대: OVVLT001

# ② 평문 비밀번호 문자열 부재
grep -c 'DB_PASSWORD' /etc/ovirt-engine/engine.conf.d/10-setup-database.conf   # 기대: 0

# ③ 난수발생기 (Hash_DRBG)
python3 -c 'from ovirt_engine import csprng; print(csprng.describe())'
#   기대: Hash_DRBG,SHA-256,256 ... known-answer test passed

# ④ KEK 속성 (키 바이트는 출력되지 않음, 관리자 토큰)
vault read transit/keys/ovirt-engine-config
#   기대: type=aes256-gcm96, exportable=false, allow_plaintext_backup=false, latest_version=N

# ⑤ Vault 봉인 구성 (5조각·임계 3)
vault status        # 기대: Sealed=false, Total Shares=5, Threshold=3

# ⑥ 애플리케이션 토큰 권한
vault token capabilities "$(sudo cat /etc/ovirt-engine/encryptor/vault-token)" \
  transit/keys/ovirt-engine-config                     # 기대: deny
# (토큰 값이 화면·이력에 남지 않도록 관리자 단말에서 수행)

# ⑦ 왕복 사전점검
sudo -u ovirt /usr/share/ovirt-engine/encryptor/vault_passphrase.py --check
#   기대: Vault Transit preflight succeeded

# ⑧ 권한·소유자
stat -c '%n %U:%G %a' /etc/ovirt-engine/encryptor/config.json \
  /etc/ovirt-engine/encryptor/vault-token /etc/ovirt-engine/encryptor/private_pkcs8.der \
  /etc/ovirt-engine/engine.conf.d/10-setup-database.conf /etc/ovirt-engine/aaa/internal.properties

# ⑨ 변조 탐지 (사본으로만)
sudo -u ovirt cp /etc/ovirt-engine/engine.conf.d/10-setup-database.conf /tmp/t.conf
printf '\xff' | sudo -u ovirt dd of=/tmp/t.conf bs=1 seek=200 conv=notrunc 2>/dev/null
sudo -u ovirt /usr/share/ovirt-engine/encryptor/encryptor.py --decrypt /tmp/t.conf /tmp/t.out
#   기대: 종료코드 1, "Authentication failed", /tmp/t.out 미생성
sudo rm -f /tmp/t.conf /tmp/t.out
```

---

## 16. 관련 문서

| 문서 | 내용 |
|---|---|
| `docs/db-config-key-management-specification.md` | 설정파일 암호키 관리 명세(이전 판, 패스프레이즈 모드 포함) |
| `docs/csprng-hash-drbg.md` | Hash_DRBG 적용 범위·자가시험 |
| `docs/vault-transit-rocky-linux-9.5.md` | Vault 설치·TLS·초기화·봉인해제·정책·토큰 절차 |
| `docs/webadmin-login-credential-encryption-verification-form.md` | 로그인 RSA 키쌍 시험 절차 |
| `docs/login-credential-crypto-audit.md` | 로그인 자격증명 복호 실패 감사기록 설계 |
| `packaging/encryptor/README.md` | 암호화 도구 사용법 |
