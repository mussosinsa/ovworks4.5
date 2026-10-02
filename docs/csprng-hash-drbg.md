# 난수 발생기 표준화: Hash_DRBG (SHA-256, 256비트)

엔진이 만드는 모든 비밀값(키·논스·솔트·세션 토큰·생성 비밀번호)은 **Hash_DRBG(SHA-256, 보안강도 256비트)**
에서 나온다. NIST SP 800-90A의 Hash_DRBG이며, 국내 검증대상 난수발생기 목록의 Hash_DRBG(SHA-2 계열)와
같은 메커니즘이다. 운영체제 난수(getrandom(2), `/dev/urandom`)는 대체되지 않고 DRBG의 **엔트로피 입력**
(인스턴스화·재시드)으로 쓰인다 — 표준이 정한 위치다.

> 범위: 이 변경은 알고리즘(메커니즘)을 표준 DRBG로 통일한다. **KCMVP 검증필 암호모듈 탑재**가 요구되면,
> 아래 공통 생성기 내부만 검증필 모듈 호출로 교체하면 된다(사용처는 이미 한곳으로 모여 있음).

## 구성

| 영역 | 공통 생성기 | 구현 | 대체 경로(실패 시) |
|---|---|---|---|
| Java 엔진·SSO·REST·웹관리자 | `org.ovirt.engine.core.uutils.crypto.ApprovedRandom` | JDK DRBG `SecureRandom.getInstance("DRBG", instantiation(256, RESEED_ONLY, 개인화문자열))` | 기존 `new SecureRandom()`(NativePRNG) |
| Python setup·encryptor·라이브러리 | `ovirt_engine.csprng` | OpenSSL 3 EVP_RAND `HASH-DRBG`(digest SHA256), 부모 `SEED-SRC`(OS 엔트로피), 프로세스 전역 설정 변경 없음 | 기존 `os.urandom()` |
| PKI 스크립트(`pki-*.sh`의 openssl) | `/usr/share/ovirt-engine/conf/openssl-drbg.cnf` (`OPENSSL_CONF`) | OpenSSL primary/public/private DRBG를 기본 CTR-DRBG(AES-256) → HASH-DRBG(SHA2-256) | 설정 미적용(기존 동작). **FIPS 모드에서는 적용하지 않음**(FIPS 제공자의 승인 DRBG 유지) |

대체 경로는 "기능이 멈추지 않게" 하기 위한 것이며, 사용 중인 생성기는 항상 기록·점검된다(아래).

### 교체된 사용처

- Java: `SsoService`, `LoginFormNonce`, `FiltersHelper`, `SessionDataContainer`, `LoginOnBehalfCommand`,
  `TicketEncoder`, `Ticketing`(콘솔 OTP), `EnvelopeEncryptDecrypt`, `EnvelopePBE`(솔트, 기본 경로),
  `PasswordHistoryCryptor`, `CryptMD5`, `XsrfTokenGeneratorHttpSessionListener`, `SsoRegistrationToolExecutor`
- Python: `encryptor.py`·`vault_passphrase.py`(데이터 키·논스·솔트), `config/client_control.py`(단말 제어 비밀),
  `config/sso.py`·`config/aaa.py`·`engine_common/postgres.py`·`network/ovirtproviderovn.py`(생성 비밀번호),
  `pythonlib/ovirt_engine/ticket.py`(티켓 솔트)
- 비보안 용도(CA 이름 접미사, MAC 범위, UUID 식별자)는 대상이 아니다.

## 자가시험

- **정답 비교 시험(KAT, Python):** 기동 시 고정 엔트로피(`00..1f`)·논스(`20..2f`)·개인화 문자열로
  OpenSSL HASH-DRBG를 인스턴스화해 두 번째 64바이트 출력이 기대값과 일치하는지 확인한다. 기대값은 SP 800-90A
  10.1.1을 독립적으로 구현한 참조 코드(`packaging/pythonlib/tests/ovirt_engine/test_csprng.py`)로 산출했고,
  시험은 다른 입력·요청 크기에서도 두 구현이 바이트 단위로 일치함을 확인한다.
- **연속 시험(Java·Python):** 연속 두 블록이 같거나 0으로만 채워지면 해당 DRBG를 쓰지 않고 대체 경로로 전환한다.
- Java DRBG는 JDK 내장 구현이며 고정 엔트로피 주입 API가 없어 KAT 대신 메커니즘 문자열
  (`Hash_DRBG,SHA-256,256,reseed_only`)을 읽어 확인한다.

## 점검 (자체 보안 검증)

`ov-works-security_audit.sh`의 **approved random generator** 항목:

| 대상 | PASS 조건 | 아니면 |
|---|---|---|
| Python | `csprng.describe()`가 `Hash_DRBG,SHA-256,256`으로 시작 | WARN (대체 경로 사용 중) |
| 엔진(Java) | engine.log의 마지막 `Approved random generator:` 줄이 `Hash_DRBG,SHA-256,256`(또는 `HMAC_DRBG,SHA-256,256`) | WARN / 기동 후 첫 사용 전이면 INFO |
| PKI | FIPS 모드이거나, `openssl-drbg.cnf` 적용 시 `openssl list -random-instances`에 `HASH-DRBG` | WARN |

대체 경로는 **경고(WARN)** 로만 표시한다. 실패(FAIL)로 두면 동작 중인 생성기 때문에 엔진 기동이 차단되기 때문이다.

수동 확인:

```bash
python3 -c 'from ovirt_engine import csprng; print(csprng.describe())'
grep 'Approved random generator:' /var/log/ovirt-engine/engine.log | tail -1
OPENSSL_CONF=/usr/share/ovirt-engine/conf/openssl-drbg.cnf openssl list -random-instances
```

## 영향이 없는 부분 (이 변경의 범위 밖)

- TLS 내부 난수(Apache mod_ssl, JBoss JSSE), PostgreSQL SCRAM 솔트, 커널 getrandom 자체
- 브라우저의 로그인 암호화(Web Crypto RSA-OAEP) 난수
- 기존에 만들어진 키·비밀번호·인증서는 그대로 유효하다(형식·길이 변경 없음).
