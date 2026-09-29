# DB 접근 설정파일 암호키 관리 명세서

## 1. 문서 정보

| 항목 | 내용 |
|---|---|
| 문서명 | DB 접근 설정파일 암호키 관리 명세서 (암호 생성·저장·파기) |
| 대상 제품 | oVirt Engine (OV-Works) 4.5.x |
| 대상 파일 | `10-setup-database.conf`, `10-setup-dwh-database.conf`, `internal.properties` |
| 근거 소스 | 본 저장소 (아래 각 항목에 `파일:행` 형식으로 명시) |
| 문서 버전 / 작성일 | 1.0 / 2026-09-29 |
| 작성자 / 검증자 / 승인자 | `[성명·직책] / [성명·직책] / [성명·직책]` |

> 본 문서는 **구현된 소스코드에서 확인한 사실만** 기술한다. 각 서술에는 확인 가능한 소스 위치를
> 함께 표기하여 검사자가 동일한 내용을 직접 대조할 수 있도록 하였다. 운영 환경에서 결정되는
> 값(실제 키 값, 지문, 토큰, 일련번호)은 본 문서에 포함하지 않는다.

---

## 2. 용어 정의

본 문서는 다음 표준 용어를 사용한다. 각 용어가 본 제품의 어느 구성요소에 대응하는지 4장 이후에
구체적으로 명시한다.

| 용어 | 정의 | 본 제품에서의 대응 |
|---|---|---|
| **DEK** (Data Encryption Key, 데이터 암호키) | 평문 데이터를 직접 암·복호화하는 대칭키 | 파일 1건마다 새로 생성되는 256비트 AES 키 |
| **KEK** (Key Encryption Key, 키 암호키) | DEK를 암호화(wrapping)하는 상위 키 | ① Vault Transit 내부 AES-256 키, 또는 ② 패스프레이즈에서 PBKDF2로 유도한 256비트 키 |
| **키 랩핑** (Key Wrapping) | KEK로 DEK를 암호화하여 보관하는 방식 | AES-256-GCM (양 모드 공통) |
| **봉투 암호화** (Envelope Encryption) | DEK로 데이터를, KEK로 DEK를 암호화하는 2계층 구조 | 본 제품의 파일 암호화 전 구간 |
| **AEAD** (인증된 암호) | 기밀성과 무결성을 동시에 제공하는 암호 모드 | AES-256-GCM |
| **AAD** (Additional Authenticated Data) | 암호화하지 않되 무결성은 보장하는 부가 데이터 | 봉투 헤더 및 랩핑된 DEK |
| **CSPRNG** | 암호학적으로 안전한 의사난수 생성기 | `os.urandom()` (Linux `getrandom(2)`) |
| **KDF** | 키 유도 함수 | PBKDF2-HMAC-SHA-256 |

> ⚠ **용어 충돌 주의**: `packaging/setup/ovirt_engine_setup/engine_common/database.py:34`에는
> `DEK = oengcommcons.DBEnvKeysConst`라는 지역 별칭이 있다. 이는 **DB 환경변수 키 상수**를 가리키는
> 것으로, 본 문서의 암호키 DEK와 **무관하다**. 소스 검토 시 혼동하지 않도록 명시한다.

---

## 3. 보호 대상 파일

### 3.1 파일별 경로·내용·권한

| # | 파일명 | 절대 경로 | 보유 비밀정보 | 소유자:그룹 | 권한 |
|---|---|---|---|---|---|
| ① | `10-setup-database.conf` | `/etc/ovirt-engine/engine.conf.d/10-setup-database.conf` | Engine DB 계정 비밀번호 | `root:ovirt` | `0640` |
| ② | `10-setup-dwh-database.conf` | `/etc/ovirt-engine/engine.conf.d/10-setup-dwh-database.conf` | DWH DB 계정 비밀번호 | `root:ovirt` | `0640` |
| ③ | `internal.properties` | `/etc/ovirt-engine/aaa/internal.properties` | AAA-JDBC 인증 저장소 DB 계정 비밀번호 | `ovirt` | `0600` |

경로 근거: `packaging/setup/ovirt_engine_setup/engine/constants.py:271-280`(①②),
`:332-335`(③). 권한·소유자 근거:
`packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/config/database.py:53-56`(①),
`packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/config/aaajdbc.py:199-201`(③).

### 3.2 파일 내용(평문 상태)

①②는 다음 9개 항목의 셸 형식 키=값이며, 이 중 `*_DB_PASSWORD`가 보호 대상 비밀이다
(`packaging/setup/ovirt_engine_setup/engine_common/database.py:1570-1594`).

```
ENGINE_DB_HOST / ENGINE_DB_PORT / ENGINE_DB_USER / ENGINE_DB_PASSWORD
ENGINE_DB_DATABASE / ENGINE_DB_SECURED / ENGINE_DB_SECURED_VALIDATION
ENGINE_DB_DRIVER / ENGINE_DB_URL
```

③은 AAA-JDBC 확장의 데이터소스 설정이며 `config.datasource.dbpassword`가 보호 대상이다
(`packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/config/aaajdbc.py:174-192`).

```
config.datasource.jdbcurl / config.datasource.dbuser / config.datasource.dbpassword
config.datasource.jdbcdriver / config.datasource.schemaname
```

### 3.3 대상 제한(화이트리스트)

암호화 도구는 **위 3개 파일명 외에는 처리하지 않는다.** 코드에 고정된 상수이며 설정으로 확장할 수
없다(`packaging/encryptor/encryptor.py:39-43`, `packaging/encryptor/encrypt_conf_files.py:71-77`
— 설정의 `allowed_files`는 이 상수의 **부분집합**이어야 하며 아니면 오류로 중단된다).

디렉터리 범위도 `/etc/ovirt-engine`, `/etc/ovirt-engine-dwh` 두 곳으로 제한되고
(`encryptor.py:38`), 심볼릭 링크는 경로 전 구간에서 거부되며, 그룹/기타 쓰기 가능 파일도 거부된다
(`encryptor.py:196-231`).

---

## 4. 키 계층 구조 (Key Hierarchy)

본 제품의 설정파일 암호화는 **2계층 봉투 암호화**이며, 배포 모드에 따라 KEK의 소재만 달라진다.

```text
[모드 A] Vault Transit 모드 — 봉투 식별자 OVVLT001  (권장)

  Vault 내부                          oVirt Engine 호스트
  ┌──────────────────────┐            ┌─────────────────────────────────────┐
  │ KEK                  │            │ DEK (파일 1건당 1개, 매번 새로 생성)│
  │ aes256-gcm96         │            │ os.urandom(32) = 256비트            │
  │ exportable=false     │◀─ wrap ────│                                     │
  │ (Vault 밖으로 반출 X)│── unwrap ─▶│  AES-256-GCM으로 파일 평문 암호화   │
  └──────────────────────┘            └─────────────────────────────────────┘
                                       저장: 암호문 파일 안에 랩핑된 형태로만

[모드 B] 패스프레이즈 모드 — 봉투 식별자 OVENC001  (Vault 미구성 시)

  패스프레이즈 파일                    oVirt Engine 호스트
  ┌──────────────────────┐            ┌─────────────────────────────────────┐
  │ 384비트 난수 문자열  │            │ DEK (파일 1건당 1개, 매번 새로 생성)│
  │ base64url(48바이트)  │            │ os.urandom(32) = 256비트            │
  │        │             │            │                                     │
  │        ▼ PBKDF2      │            │                                     │
  │ KEK 256비트 ─────────┼─ wrap ────▶│  AES-256-GCM으로 파일 평문 암호화   │
  └──────────────────────┘            └─────────────────────────────────────┘
   (KEK는 메모리에만 존재, 파일로 저장되지 않음)
```

두 모드 모두 **DEK는 동일한 방식으로 생성·사용**되며, **KEK만 다르다.**

---

## 5. DEK (데이터 암호키) 상세

### 5.1 무엇이 DEK인가

**파일 내용을 실제로 암호화하는 256비트 AES 키**이다. 소스에서는 `data_key` 변수이며
`DATA_KEY_SIZE = 32`(바이트) 상수로 길이가 고정된다(`packaging/encryptor/encryptor.py:31`).

### 5.2 생성 — 언제, 어떻게

| 항목 | 내용 |
|---|---|
| 생성 시점 | 파일 1건을 암호화할 때마다 (재사용 없음) |
| 생성 주체 | `encryptor.py`의 `encrypt_bytes()` 또는 `encrypt_vault_bytes()` |
| 난수원 | `os.urandom(32)` — Linux `getrandom(2)` 시스템콜, 커널 CSPRNG(ChaCha20 기반 DRBG) |
| 길이 | 256비트 (32바이트) |
| 유도 여부 | **유도하지 않음.** KDF를 거치지 않은 순수 난수 |

근거: `packaging/encryptor/encryptor.py:292`(모드 B), `:314`(모드 A).

```python
# encryptor.py:314 (Vault 모드)
data_key = os.urandom(DATA_KEY_SIZE)      # 256비트 CSPRNG 난수
```

**중요**: 파일마다 서로 다른 DEK가 사용된다. 3개 파일을 암호화하면 3개의 서로 다른 DEK가
생성된다(`encrypt_conf_files.py:109` 주석: "Each file is encrypted under a data key generated
for it here"). 동일 파일을 재암호화해도 새 DEK가 생성된다.

### 5.3 저장 — 어디에

| 항목 | 내용 |
|---|---|
| 평문 저장 | **없음.** 디스크·DB·로그 어디에도 평문 DEK를 기록하지 않는다 |
| 암호문 저장 | 해당 암호문 파일의 헤더 직후 영역에 **KEK로 랩핑된 상태로만** 저장 |
| 저장 형식(모드 A) | Vault가 반환한 `vault:v1:<base64>` 문자열 (가변 길이, 최대 65535바이트) |
| 저장 형식(모드 B) | AES-256-GCM 암호문 48바이트 (`WRAPPED_KEY_SIZE = 32 + 16`) |
| 메모리 존속 | 암호화·복호화 처리 중에만 Python 프로세스 메모리에 존재 |

즉 **DEK는 자신이 보호하는 파일과 같은 파일 안에, 랩핑된 형태로 함께 보관된다.** 이는 봉투
암호화의 표준 형태이며, DEK 단독으로는 KEK 없이 복원할 수 없다.

### 5.4 사용 — 무엇을, 언제, 어떻게

| 항목 | 내용 |
|---|---|
| 암호화 대상 | 3.1의 파일 3종 전체 바이트열 |
| 알고리즘 | AES-256-GCM (AEAD) |
| 논스(IV) | `os.urandom(12)` — 96비트, 파일마다 새로 생성 (`encryptor.py:291`, `:315`) |
| AAD | 고정 헤더 + 랩핑된 DEK 전체 (`encryptor.py:303-308`, `:321-324`) |
| 인증 태그 | 128비트, GCM이 암호문 말미에 부착 |
| 사용 시점 | ① engine-setup 종료 단계(암호화) ② Engine 기동 시(복호화) ③ engine-setup 재실행 시(③ 파일 복호화→재암호화) ④ engine-cleanup 시(복호화) |

AAD에 헤더와 랩핑된 DEK를 포함시키므로, 반복 횟수·솔트·논스·랩핑 키를 1비트라도 변조하면
복호화가 인증 실패로 중단되고 **출력 파일을 만들지 않는다**(`encryptor.py:365-377`).

### 5.5 파기

| 상황 | 처리 |
|---|---|
| 정상 종료 | 프로세스 종료와 함께 메모리에서 소멸 |
| 파일 재암호화 | 이전 DEK를 담고 있던 암호문 파일이 원자적 교체(`os.replace`)로 대체되어 접근 불가 |
| Engine 제거 | 대상 파일 자체가 복호화·삭제되므로 랩핑된 DEK도 함께 소멸 |

> **한계 명시**: 본 구현은 Python의 `bytes` 객체를 사용하므로 DEK에 대한 **명시적 메모리
> 영점화(zeroization)는 수행하지 않는다.** Python `bytes`는 불변 객체로 in-place 소거가
> 불가능하다. 이는 소스코드에서 확인되는 사실이며, 완화책은 13장에 기술한다.

---

## 6. KEK (키 암호키) 상세 — 모드 A: Vault Transit

### 6.1 무엇이 KEK인가

**HashiCorp Vault의 Transit 시크릿 엔진 내부에 생성·보관되는 AES-256 키**이며, 이름은
기본값 `ovirt-engine-config`이다(`packaging/encryptor/config.vault.example.json`).

### 6.2 생성

| 항목 | 내용 |
|---|---|
| 생성 시점 | 최초 1회, 운영자가 Vault 구성 시 |
| 생성 주체 | **Vault 서버 내부.** oVirt는 생성을 *요청*만 한다 |
| 생성 명령 | `vault write transit/keys/ovirt-engine-config type=aes256-gcm96 exportable=false allow_plaintext_backup=false` 또는 `vault_passphrase.py --init-key` |
| 알고리즘 | `aes256-gcm96` — AES-256-GCM, 96비트 논스 |
| 난수원 | Vault 내부 CSPRNG (Go `crypto/rand` → 커널 `getrandom(2)`) |
| 반출 가능 여부 | `exportable=false` — **키 바이트를 API로 추출 불가** |
| 평문 백업 가능 여부 | `allow_plaintext_backup=false` — **평문 백업 불가** |

근거: `packaging/encryptor/encryptor.py:134-140`(oVirt가 보내는 생성 요청 파라미터),
`docs/vault-transit-rocky-linux-9.5.md:169-192`(운영 절차).

```python
# encryptor.py:134-140
def ensure_key(self):
    """Ask Vault to generate and retain a non-exportable AES-256 KEK."""
    self._request("keys", {
        "type": "aes256-gcm96",
        "exportable": False,
        "allow_plaintext_backup": False,
    })
```

### 6.3 저장

| 항목 | 내용 |
|---|---|
| 저장 위치 | **Vault 서버의 스토리지 백엔드 내부** (`/opt/vault/data` 등) |
| oVirt 호스트 저장 여부 | **저장하지 않음.** 봉투·설정파일·로그 어디에도 KEK가 없다 |
| Vault 저장 시 보호 | Vault 자체 마스터키로 봉인(seal). Vault가 sealed 상태면 복호화 불가 |
| 접근 경로 | HTTPS + Vault 토큰. TLS 인증서 검증 필수 (`encryptor.py:64-74`에서 평문 HTTP 거부) |

### 6.4 사용

| 항목 | 내용 |
|---|---|
| 사용 대상 | **DEK만.** 파일 평문은 KEK에 노출되지 않는다 |
| 랩핑 | `POST /v1/transit/encrypt/ovirt-engine-config`, 응답 `vault:v1:...` (`encryptor.py:142-149`) |
| 언랩핑 | `POST /v1/transit/decrypt/ovirt-engine-config` (`encryptor.py:151-156`) |
| 사용 시점 | 파일 암호화 시 1회, 파일 복호화 시 1회 (파일당) |
| 권한 | 런타임 토큰은 `encrypt`/`decrypt` **update 권한만** 보유. 키 생성·수정·삭제·export·backup 권한 없음 (`packaging/encryptor/README.md`, `docs/vault-transit-rocky-linux-9.5.md:193-195`) |

### 6.5 파기 / 회전

| 항목 | 내용 |
|---|---|
| 회전 | Vault의 키 회전 기능 사용. 봉투에 `vault:v<N>` 키 버전이 기록되어 구 버전 복호화 유지 |
| 파기 | Vault 측에서 키 삭제 시 **해당 KEK로 보호된 모든 파일은 영구 복호화 불가**(암호학적 소거) |
| 주의 | 암호문 백업만으로는 복원 불가. Vault 스토리지·복구키를 **별도 통제 하에** 백업해야 함 (`packaging/encryptor/README.md` "Back up Vault's storage and recovery/unseal material under separate operational control") |

---

## 7. KEK 상세 — 모드 B: 패스프레이즈 유도

Vault를 구성하지 않은 경우 사용되는 대체 모드이다(봉투 식별자 `OVENC001`).

### 7.1 KEK 생성(유도)

| 항목 | 내용 |
|---|---|
| 유도 알고리즘 | **PBKDF2-HMAC-SHA-256** |
| 반복 횟수 | **600,000회** (`PBKDF2_ITERATIONS = 600_000`, `encryptor.py:28`) |
| 솔트 | 128비트(16바이트) `os.urandom(16)`, 파일마다 새로 생성 (`encryptor.py:29`, `:289`) |
| 출력 길이 | 256비트(32바이트) |
| 입력 | 패스프레이즈(8장) |
| 저장 | **저장하지 않음.** 복호화 시마다 재유도 |

근거: `packaging/encryptor/encryptor.py:277-285`.

```python
# encryptor.py:277-285
def _derive_kek(passphrase, salt, iterations=PBKDF2_ITERATIONS):
    if iterations < PBKDF2_ITERATIONS:
        raise EncryptorError("PBKDF2 iteration count is below the security minimum")
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                      salt=salt, iterations=iterations).derive(passphrase)
```

**하한 강제**: 600,000회 미만의 반복 횟수는 유도 함수 진입 시점에 거부된다. 복호화 시에도
헤더에 기록된 반복 횟수가 상수와 일치하지 않으면 거부된다(`encryptor.py:355-359`). 즉 공격자가
암호문 헤더의 반복 횟수를 낮춰 계산량을 줄이는 공격이 차단된다.

> 600,000회는 OWASP Password Storage Cheat Sheet의 PBKDF2-HMAC-SHA-256 권고치(600,000)와
> 동일하다. NIST SP 800-132는 PBKDF2와 최소 128비트 솔트를 승인하고 있으며 본 구현은 이를 충족한다.

### 7.2 사용

DEK를 AES-256-GCM으로 랩핑하는 데에만 사용된다. 랩핑 논스는 파일 암호화 논스와 **독립적으로**
생성된 별도의 96비트 난수이다(`encryptor.py:290`, `:304`).

### 7.3 파기

프로세스 종료와 함께 소멸한다. 디스크에 기록되지 않으므로 별도 파기 절차가 없다.

---

## 8. 패스프레이즈 (모드 B의 KEK 입력)

### 8.1 생성

| 항목 | 내용 |
|---|---|
| 생성 시점 | `engine-setup` 종료 단계에서 파일이 없을 때 1회 |
| 생성 방식 | `base64.urlsafe_b64encode(os.urandom(48))` — **384비트 CSPRNG 난수**를 base64url 인코딩(64문자) |
| 생성 주체 | `client_control.py:376` |
| 사용자 입력 여부 | **없음.** 사람이 정하는 비밀번호가 아니므로 사전공격 대상이 아니다 |

```python
# client_control.py:369-377
descriptor = os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
secret = base64.urlsafe_b64encode(os.urandom(48))   # 384비트 난수
os.write(descriptor, secret + b'\n')
```

`O_EXCL` 플래그로 기존 파일을 덮어쓰지 않으며, 생성 즉시 `0600` 권한으로 만들어진다.

### 8.2 저장

| 항목 | 내용 |
|---|---|
| 경로 | `/etc/ovirt-engine/encryptor/passphrase` (설정 `secret_file`로 변경 가능) |
| 권한 | `0600` (`client_control.py:380`) — 그룹/기타 권한이 하나라도 있으면 읽기 자체가 거부됨(`encryptor.py:238-240`) |
| 소유자 | Engine 서비스 계정(`ovirt`) (`client_control.py:381-385`) |
| Vault 모드 시 | **자체가 `OVVLT001` 봉투로 재암호화된다**(`client_control.py:387-435`). 즉 패스프레이즈 파일도 Vault KEK로 보호되며, `cat`으로 읽어도 평문이 보이지 않는다 |
| 순수 Vault 모드 | `secret_file`을 설정하지 않으면 패스프레이즈 자체를 생성하지 않는다(`client_control.py:360-364`) |

### 8.3 공급 경로(우선순위)

`encryptor.py:254-275`에 정의된 순서대로 탐색한다.

| 순위 | 경로 | 비고 |
|---|---|---|
| 1 | `${CREDENTIALS_DIRECTORY}/ovirt-encryptor-passphrase` | systemd 암호화 자격증명. **권장** |
| 2 | 환경변수 `OVIRT_ENCRYPTOR_PASSPHRASE` | 호환용. 권한 있는 프로세스가 조회 가능하므로 비권장 |
| 3 | `secret_file` (0600 파일) | 기본 경로 |
| 4 | TTY 대화식 입력 | `--prompt` 지정 및 표준입력이 TTY일 때만 |

**하드웨어 식별자(MAC 주소 등)를 키 재료로 사용하지 않는다.** 명령행 인자로 비밀을 전달하는
경로도 제공하지 않는다(프로세스 목록 노출 방지).

### 8.4 파기

`engine-cleanup` 시 `config.json`은 초기화되지만 패스프레이즈 파일 자체의 자동 삭제는
수행하지 않는다. 운영 절차상 파기가 필요하다(13장 참조).

---

## 9. Vault에서 생성되는 5개의 키 — 정확한 성격

검사 과정에서 자주 혼동되는 부분이므로 명확히 구분한다.

`vault operator init -key-shares=5 -key-threshold=3`
(`docs/vault-transit-rocky-linux-9.5.md:154`) 실행 시 출력되는 **5개의 키는 Unseal Key
Share(봉인 해제 키 조각)이며, DEK도 KEK도 아니다.**

| 구분 | 개수 | 성격 | 본 제품 관련성 |
|---|---|---|---|
| **Unseal Key Share** | **5개** | Vault **마스터키**를 Shamir 비밀분산으로 나눈 조각. 3개(threshold)를 모아야 Vault 봉인 해제 | Vault 재기동 시 봉인 해제용. oVirt는 직접 사용하지 않음 |
| Initial Root Token | 1개 | Vault 초기 관리 토큰 | 부트스트랩 후 **폐기**(`docs/vault-transit-rocky-linux-9.5.md:163`) |
| **Transit KEK** | 1개 | 6장의 KEK (`ovirt-engine-config`) | **DEK 랩핑에 사용** |
| 애플리케이션 토큰 | 1개 | Engine 런타임이 KEK를 호출하기 위한 최소권한 토큰 | `/etc/ovirt-engine/encryptor/vault-token`, `0600`, `ovirt:ovirt` |

### 9.1 5개 조각의 관리 요구사항

- **3인 이상의 서로 다른 보관자**가 각각 조각을 분리 보관한다(`docs/vault-transit-rocky-linux-9.5.md:159`).
- Vault 데이터 디렉터리, oVirt 백업, 암호화 설정, 암호문과 **같은 장소에 보관 금지**(`:160-162`).
- 3개 미만으로는 봉인 해제 불가 → 단일 보관자 유출만으로는 KEK에 접근할 수 없다.
- Vault가 봉인 상태면 **DB 설정 복호화가 불가능하여 Engine이 기동하지 않는다**(fail-closed).

### 9.2 키 3종의 관계 요약

```text
Unseal Key Share 5개 중 3개 ──▶ Vault 마스터키 복원 ──▶ Vault 봉인 해제
                                                            │
                                                            ▼
                                              Transit KEK (반출 불가) 사용 가능
                                                            │
                          애플리케이션 토큰으로 인증 ────────┤
                                                            ▼
                                        DEK 랩핑/언랩핑 ──▶ 설정파일 복호화
```

---

## 10. 로그인 키 (WebAdmin ID/PW 보호용 RSA 키쌍)

설정파일 암호화와 **별개의 독립 키 체계**이다. 검사자가 `config.json`에서 `rsaPublicKey`
필드를 발견하고 KEK로 오인하는 사례가 있어 여기에 함께 기술한다.

| 항목 | 내용 |
|---|---|
| 용도 | WebAdmin 로그인 화면에서 **사용자 ID와 비밀번호를 브라우저가 암호화**하여 전송 (HTTPS 위의 응용계층 추가 보호) |
| 키 종류 | RSA 키쌍 (**비대칭**). DEK/KEK 체계와 무관 |
| 알고리즘 | RSA-OAEP, 해시 SHA-256, MGF1-SHA-256 (`LoginEnvelopeCrypto.java:120-126`) |
| 키 길이 | 운영 기준 3072비트 이상 권장, 최소 2048비트 (`docs/webadmin-login-credential-encryption-verification-form.md:74`) |
| 생성 주체 | 운영자가 승인된 Engine 서버 또는 HSM/KMS에서 `openssl genpkey`로 생성(같은 문서 `:101-110`) |
| 공개키 저장 | `/etc/ovirt-engine/encryptor/config.json`의 `rsaPublicKey` (X.509 SPKI PEM). **비밀이 아님** |
| 개인키 저장 | `/etc/ovirt-engine/encryptor/private_pkcs8.der` (PKCS#8 DER), 권한 `0600` (`LoginEnvelopeCrypto.java:30-31`) |
| 사용 시점 | 로그인 요청마다. 서버가 `encryptedUsername`/`encryptedPassword`를 개인키로 복호화 |
| 암호화 대상 | **로그인 ID와 비밀번호 문자열만.** 설정파일·DEK와 무관 |
| 파기 | `engine-cleanup` 시 개인키 파일을 **삭제**한다 (`packaging/setup/plugins/ovirt-engine-remove/ovirt-engine/config/misc.py:86-88`, `:185`) |

> 공개키는 비밀이 아니나 **변조되면 공격자 키로 자격증명이 암호화**되므로 반드시 인증된 HTTPS로
> 전달해야 한다. 공개키 배포 API는 `X-Client-Serial` 검증을 통과한 요청에만 응답한다.

---

## 11. 암호문 형식 (검사자 대조용)

### 11.1 `OVVLT001` (모드 A, Vault)

```
오프셋  길이      내용
0       8         매직 "OVVLT001"
8       1         포맷 버전 (=1)
9       12        데이터 암호화 논스 (96비트 난수)
21      2         랩핑된 DEK 길이 (빅엔디안 uint16)
23      가변      Vault 랩핑 DEK ("vault:v1:..." ASCII)
...     가변      AES-256-GCM 암호문 + 128비트 인증태그
```
구조 정의: `encryptor.py:34`(`VAULT_HEADER = struct.Struct(">8sB12sH")`), `:316-325`.
AAD = 고정헤더(23바이트) + 랩핑된 DEK.

### 11.2 `OVENC001` (모드 B, 패스프레이즈)

```
오프셋  길이      내용
0       8         매직 "OVENC001"
8       1         포맷 버전 (=1)
9       4         PBKDF2 반복 횟수 (=600000, 빅엔디안 uint32)
13      16        PBKDF2 솔트 (128비트 난수)
29      12        DEK 랩핑 논스 (96비트 난수)
41      12        데이터 암호화 논스 (96비트 난수)
53      2         랩핑된 DEK 길이 (=48)
55      48        AES-256-GCM으로 랩핑된 DEK (32바이트 + 16바이트 태그)
103     가변      AES-256-GCM 암호문 + 128비트 인증태그
```
구조 정의: `encryptor.py:33`(`HEADER = struct.Struct(">8sBI16s12s12sH")`), `:293-309`.
AAD = 고정헤더(55바이트) + 랩핑된 DEK(48바이트).

### 11.3 레거시 AES-CBC (읽기 전용)

과거 형식 마이그레이션 목적의 **복호화 전용** 경로가 존재한다(`encryptor.py:392-436`).

- **신규 기록은 불가능**하다. 어떤 경로로도 CBC 암호문을 생성하지 않는다.
- 설정에 `legacy_cbc.enabled=true`와 구 키를 명시해야만 동작한다(기본값 `false`).
- `--deny-legacy-cbc` 옵션으로 완전 차단할 수 있으며, 엔진 기동 경로와 setup 경로는 이를 사용한다
  (`client_control.py:128`).
- 마이그레이션 결과물은 반드시 `OVENC001` 또는 `OVVLT001`로 기록된다.

---

## 12. 생명주기 — 언제 무엇이 일어나는가

### 12.1 설치 (`engine-setup`)

| 순서 | 단계 | 처리 | 근거 |
|---|---|---|---|
| 1 | CUSTOMIZATION | Vault 사전점검: 난수 32바이트를 실제로 wrap→unwrap 하여 왕복 검증 | `client_control.py:238-266`, `vault_passphrase.py:133-137` |
| 2 | MISC | 대상 파일 ①②③ 평문 생성 (DB 자격증명 기록) | `database.py:46-68`, `aaajdbc.py:194-208` |
| 3 | MISC | ③이 이미 암호화되어 있으면 **복호화** (AAA-JDBC 도구가 읽어야 하므로) | `client_control.py:115-146` |
| 4 | CLOSEUP | 패스프레이즈 생성(없을 때), `config.json` 원자적 기록 | `client_control.py:571-575` |
| 5 | CLOSEUP | Vault 토큰 권한 조정(`0600`, `ovirt:ovirt`) | `client_control.py:437-466` |
| 6 | CLOSEUP | 패스프레이즈를 `OVVLT001`로 재보호 | `client_control.py:577` |
| 7 | CLOSEUP | **파일 ①②③ 암호화** 후 실제 암호화 여부 재확인 | `client_control.py:578`, `:468-514` |
| 8 | CLOSEUP | Engine 기동 (**7단계 이후**에 수행되도록 순서 강제) | `client_control.py:557` (`before=CORE_ENGINE_START`) |

암호화 직후 **복호화 자기검증**을 수행하여 원본과 일치하지 않으면 파일을 교체하지 않는다
(`encryptor.py:493-497`). 또한 대상 파일이 하나라도 암호화되지 않은 상태로 남으면 setup이
오류로 중단된다(`client_control.py:503-511`).

setup이 중간에 중단되면 CLEANUP 단계가 ③의 암호화를 복구한다(`client_control.py:148-186`).

### 12.2 운영 (Engine 기동)

```text
systemd → ovirt-engine.py (Python, ovirt 계정)
   │
   ├─ configfile.ConfigFile(...)  ← 10-setup-database.conf 등 로드
   │     └─ 매직 확인 → encryptor 모듈 동적 로드 → DEK 언랩 → 평문 복원 (메모리)
   │
   ├─ ovirt-engine.xml 렌더링 (DB 비밀번호 주입), 권한 0600
   │     위치: JBOSS_RUNTIME 임시 디렉터리 (프로세스 종료 시 삭제)
   │
   └─ Java(JBoss) 기동
```

- 복호화는 **Java 기동 전, Python 런처 단계**에서 수행된다(`packaging/pythonlib/ovirt_engine/configfile.py:72-101`).
- Java 측 로더는 암호문 파일을 만나면 **읽지 않고 건너뛴다**. 즉 Java 프로세스는 암호문을 해석하지
  않으며 복호화 키도 보유하지 않는다(`ShellLikeConfd.java:141-174`).
- 렌더링된 `ovirt-engine.xml`은 `0600`으로 생성되고(`ovirt-engine.py:497-504`) 런타임 디렉터리는
  서비스 시작 시 삭제 후 재생성된다(`service.py:115-118`).
- **Vault 봉인/불가 시 복호화 실패 → Engine 기동 실패(fail-closed).**

### 12.3 제거 (`engine-cleanup`)

| 순서 | 처리 | 근거 |
|---|---|---|
| 1 | 대상 파일 ①②③ 복호화 (제거 절차가 DB 자격증명을 읽어야 함) | `ovirt-engine-remove/config/decrypt.py:30-35` |
| 2 | `config.json`을 배포 기본값으로 원자적 초기화 (`encrypt_flag: NO`, 생성된 솔트·논스·키 메타데이터 미기록, `0600`) | `ovirt-engine-remove/config/misc.py:65-84`, `:184` |
| 3 | **로그인 개인키 `private_pkcs8.der` 삭제** | `ovirt-engine-remove/config/misc.py:86-88`, `:185` |

---

## 13. 파기(Destruction) 정리 및 한계

| 대상 | 파기 방식 | 시점 | 소스 근거 |
|---|---|---|---|
| DEK | 프로세스 메모리 소멸 + 암호문 파일 대체/삭제 | 처리 종료·재암호화·제거 시 | `encryptor.py:438-472`(원자적 교체) |
| KEK(Vault) | Vault에서 키 삭제 시 암호학적 소거 | 운영자 결정 | Vault 측 기능 |
| KEK(PBKDF2) | 미저장. 프로세스 종료 시 소멸 | 매 처리 종료 | `encryptor.py:277-285` |
| 패스프레이즈 | 파일 삭제(운영 절차), Vault 모드에서는 봉투 암호화 상태 | 운영자 결정 | `client_control.py:387-435` |
| 로그인 개인키 | **파일 삭제(`os.remove`)** | `engine-cleanup` | `ovirt-engine-remove/config/misc.py:86-88` |
| 평문 설정파일 | 원자적 교체로 암호문이 대체 | setup 종료 단계 | `encryptor.py:438-472` |
| 런타임 렌더링 XML | 디렉터리 삭제(`shutil.rmtree`) | 서비스 시작·종료 | `service.py:115-118` |

### 13.1 검사자가 인지해야 할 한계 (소스 기준 사실)

1. **메모리 영점화 미수행**: Python `bytes`의 불변성으로 DEK·패스프레이즈의 명시적 소거가
   구현되어 있지 않다. 완화: 복호화는 Engine 기동 시 단기간 1회 수행되며, 해당 프로세스는
   비특권 `ovirt` 계정으로 동작한다.
2. **디스크 블록 소거(shred) 미수행**: 파일 파기는 `os.remove`/`os.replace` 기반이다. 완화:
   대상 파일은 `0600`/`0640`으로 보호되며, 저장매체 폐기 시 별도 물리적 파기 절차가 필요하다.
3. **패스프레이즈 파일 자동 삭제 없음**: `engine-cleanup`은 `config.json`만 초기화한다. 운영
   절차에서 `/etc/ovirt-engine/encryptor/passphrase` 파기를 명시해야 한다.
4. **암호문과 랩핑 DEK의 동일 파일 보관**: 봉투 암호화의 정상 형태이나, 백업 시 Vault 스토리지가
   함께 보호되지 않으면 복호화 불가 또는 과다 노출이 발생할 수 있다.

---

## 14. 감사 기록 (Audit Trail)

암·복호화 및 키 생성은 **3중으로** 기록된다.

### 14.1 OS 감사 로그 (syslog `authpriv`)

`encrypt_conf_files.py:37-55`가 호출마다 1건 기록한다. 기록 항목은
`operation / status / mode(local|vault) / files(건수) / uid` 뿐이며, **토큰·패스프레이즈·평문·
암호문·키 이름·설정 내용을 포함하지 않는다.**

### 14.2 Engine 이벤트 (WebAdmin 이벤트 목록)

복호화는 Java 데몬 기동 **전에** 일어나므로 그 시점에는 감사로그를 쓸 수 없다. 따라서 결과를
스풀 디렉터리(`/var/lib/ovirt-engine/security/crypto-events`)에 1건 1파일로 남기고, Engine이
다음 기동 시 감사로그로 전환한다(`packaging/pythonlib/ovirt_engine/cryptoevents.py`).

| 이벤트 | AuditLogType | ID | 심각도 |
|---|---|---|---|
| 설정파일 복호화 성공 | `CONFIG_FILE_DECRYPTION_COMPLETED` | 13658 | NORMAL |
| 설정파일 복호화 실패 | `CONFIG_FILE_DECRYPTION_FAILED` | 13659 | ERROR |
| 설정파일 암호화 성공 | `CONFIG_FILE_ENCRYPTION_COMPLETED` | 13660 | NORMAL |
| 설정파일 암호화 실패 | `CONFIG_FILE_ENCRYPTION_FAILED` | 13661 | ERROR |
| 암호키(KEK) 생성 | `CRYPTO_KEY_CREATED` | 13662 | NORMAL |
| 암호키(KEK) 생성 실패 | `CRYPTO_KEY_CREATION_FAILED` | 13663 | ERROR |
| 스풀 레코드 거부 | `CRYPTO_EVENT_SPOOL_REJECTED` | 13664 | WARNING |

근거: `backend/manager/modules/common/src/main/java/org/ovirt/engine/core/common/AuditLogType.java:1711-1717`.

**비밀 미포함 설계**: 이벤트는 파일의 basename과 **고정 어휘의 사유 코드**만 담는다. 원본 예외
메시지는 경로·URL·토큰을 포함할 수 있으므로 기록하지 않는다(`cryptoevents.py:16-21`, 사유 코드
목록 `:57-67`).

### 14.3 Vault 감사 장치

Transit API 호출(encrypt/decrypt)의 권위 있는 기록은 **Vault 감사 장치**이다. Transit 활성화
전에 감사 장치를 먼저 활성화·검증해야 한다(`packaging/encryptor/README.md`).

---

## 15. 보안요구사항 대응표

| 요구사항 항목 | 본 제품의 충족 근거 |
|---|---|
| 중요정보(DB 접속 비밀번호)의 암호화 저장 | 파일 3종을 AES-256-GCM으로 암호화하여 저장. 평문 상주 없음 (§3, §5) |
| 검증된 암호 알고리즘 사용 | AES-256-GCM(기밀성·무결성), PBKDF2-HMAC-SHA-256(KDF), RSA-OAEP-SHA256(로그인). 자체 개발 알고리즘 없음 |
| 안전한 난수 사용 | 모든 키·솔트·논스가 `os.urandom()`(커널 CSPRNG) 또는 Vault 내부 CSPRNG 기반 (§5.2, §7.1) |
| 암호키의 안전한 생성 | DEK 256비트 난수, KEK는 Vault 내부 생성(반출 불가) 또는 PBKDF2 600,000회 유도 (§6.2, §7.1) |
| 암호키의 안전한 저장 | KEK는 Vault 내부 또는 미저장. DEK는 KEK로 랩핑된 상태로만 저장. 평문 키 파일 없음 (§5.3, §6.3) |
| 키와 데이터의 분리 | KEK가 Vault라는 별도 신뢰 경계에 존재. Engine 호스트 침해만으로 과거 암호문 복호화 불가(토큰 유효기간·권한 범위 내에서) |
| 암호키 접근 통제 | 패스프레이즈 `0600`, Vault 토큰 `0600 ovirt:ovirt`, `config.json` `0640 root:ovirt`(서비스가 신뢰 엔드포인트를 변조할 수 없도록 root 소유) (§8.2, §12.1) |
| 최소 권한 | 런타임 Vault 토큰은 `encrypt`/`decrypt`만 보유. 키 생성·반출·백업 권한 없음 (§6.4) |
| 무결성 검증 | AEAD 인증태그 + 헤더·랩핑키를 AAD로 포함. 변조 시 복호화 거부 및 출력 미생성 (§5.4) |
| 암호키 파기 | 프로세스 종료 시 소멸, 파일 원자적 교체, 로그인 개인키 삭제, Vault 키 삭제 시 암호학적 소거 (§13) |
| 취약 암호 사용 금지 | 레거시 AES-CBC는 **복호화 전용**이며 기본 비활성. 신규 기록 불가, `--deny-legacy-cbc`로 완전 차단 (§11.3) |
| 하드코딩된 키 금지 | 소스에 키·비밀번호 상수 없음. 하드웨어 식별자(MAC 등)를 키 재료로 사용하지 않음 (§8.3) |
| 명령행 비밀 노출 방지 | 패스프레이즈·토큰을 명령행 인자로 받지 않음. 토큰 설치는 표준입력 사용 (`vault_passphrase.py --install-token-stdin`) |
| 감사 기록 | OS `authpriv` + Engine 감사로그 7종 + Vault 감사장치 3중 기록. 비밀정보 미포함 (§14) |
| 실패 시 안전 동작 (fail-closed) | Vault 봉인/불가 또는 인증 실패 시 Engine 기동 중단. 평문 대체 경로 없음 (§12.2) |
| 경로 조작 방지 | 처리 대상 파일명 3종 화이트리스트, 디렉터리 2곳 제한, 심볼릭 링크 전 구간 거부 (§3.3) |

---

## 16. 검사자 확인 절차

아래 명령은 **비밀값을 출력하지 않는다.**

```console
# ① 대상 파일이 실제로 암호문인지 (매직 확인)
head -c 8 /etc/ovirt-engine/engine.conf.d/10-setup-database.conf; echo
head -c 8 /etc/ovirt-engine/engine.conf.d/10-setup-dwh-database.conf; echo
head -c 8 /etc/ovirt-engine/aaa/internal.properties; echo
#   기대: OVVLT001 (Vault 모드) 또는 OVENC001 (패스프레이즈 모드)

# ② 평문 비밀번호가 남아있지 않은지
grep -c 'DB_PASSWORD' /etc/ovirt-engine/engine.conf.d/10-setup-database.conf
#   기대: 0 (암호문이므로 문자열이 존재하지 않음)

# ③ 권한·소유자
stat -c '%n %U:%G %a' \
  /etc/ovirt-engine/engine.conf.d/10-setup-database.conf \
  /etc/ovirt-engine/aaa/internal.properties \
  /etc/ovirt-engine/encryptor/config.json \
  /etc/ovirt-engine/encryptor/vault-token \
  /etc/ovirt-engine/encryptor/passphrase \
  /etc/ovirt-engine/encryptor/private_pkcs8.der
#   기대: conf=root:ovirt 640, internal.properties=ovirt:* 600,
#         config.json=root:ovirt 640, vault-token=ovirt:ovirt 600,
#         passphrase=ovirt:ovirt 600, private_pkcs8.der=*:* 600

# ④ 암호화 파라미터 (설정 메타데이터, 비밀 아님)
python3 -c "import json;d=json.load(open('/etc/ovirt-engine/encryptor/config.json'));\
print({k:d.get(k) for k in ('encrypt_flag','active_format','format_version','pbkdf2_iterations')})"
#   기대: encrypt_flag=YES, active_format=OVVLT001|OVENC001,
#         format_version=1, pbkdf2_iterations=600000

# ⑤ KEK 속성 (Vault 모드) — 키 바이트는 출력되지 않음
vault read transit/keys/ovirt-engine-config
#   기대: type=aes256-gcm96, exportable=false, allow_plaintext_backup=false

# ⑥ Vault 왕복 검증 (난수 32바이트 wrap→unwrap)
/usr/share/ovirt-engine/encryptor/vault_passphrase.py --check
#   기대: "Vault Transit preflight succeeded"

# ⑦ 레거시 CBC 비활성 확인
python3 -c "import json;print(json.load(open('/etc/ovirt-engine/encryptor/config.json')).get('legacy_cbc'))"
#   기대: {'enabled': False}

# ⑧ 감사 기록
journalctl -t ovirt-encrypt-conf --no-pager | tail -20
#   기대: operation=encrypt-config status=success mode=... files=N uid=0
#   WebAdmin > 이벤트에서 CONFIG_FILE_* / CRYPTO_KEY_* 이벤트 확인

# ⑨ 변조 탐지 시험 (사본으로만 수행)
cp /etc/ovirt-engine/engine.conf.d/10-setup-database.conf /tmp/t.conf
printf '\xff' | dd of=/tmp/t.conf bs=1 seek=200 conv=notrunc 2>/dev/null
/usr/share/ovirt-engine/encryptor/encryptor.py --decrypt /tmp/t.conf /tmp/t.out
#   기대: 0이 아닌 종료코드, "Authentication failed" 메시지, /tmp/t.out 미생성
```

---

## 17. 관련 문서

| 문서 | 내용 |
|---|---|
| `docs/setup-database-config-encryption-verification-form.md` | DB 설정 암호화 보안기능 확인서(시험 항목·판정) |
| `docs/vault-transit-rocky-linux-9.5.md` | Vault Transit 구축 절차(설치·TLS·초기화·정책·토큰·부팅 순서) |
| `docs/config-file-crypto-engine-event-design.md` | 암·복호화 결과의 Engine 이벤트 전달 설계 |
| `docs/webadmin-login-credential-encryption-verification-form.md` | 로그인 RSA 키쌍 상세 및 시험 절차 |
| `docs/source-code-cryptography-security-verification.md` | 소스코드 암호기능 검증 |
| `packaging/encryptor/README.md` | 암호화 도구 사용법(운영자용) |
