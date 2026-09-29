# 로그인 자격증명 암호연산 실패 감사기록

관련 보안요구사항: **서버공통 7.1.1 — 암호연산 실패 감사기록**

## 1. 개요

**엔진 내부 암호연산(로그인 자격증명 복호) 실패가 감사기록에 표출됩니다.**

관리화면과 REST API의 자격증명은 엔진 공개키로 봉인(RSA-OAEP-SHA256)되어 전송되고, 단일 인증
서비스(`ovirt-engine-sso.war`)가 개인키로 개봉합니다. 이 **암호연산이 실패하는 것은 비밀번호가 틀린
것과 다른 사실**입니다 — 비교할 값을 읽지도 못한 상태입니다. 그러나 그 실패는 `engine.log`까지만
기록되어, 다음 두 상황에서 감사기록이 아무 말도 하지 않았습니다.

- 엔진의 로그인 개인키가 없어지거나 손상된 경우 (해당 호스트에서 아무도 로그인할 수 없음)
- 클라이언트가 이 엔진이 개봉할 수 없는 봉인값을 제시하는 경우

기존에 설정파일 암·복호화 실패(`CONFIG_FILE_*`)와 암호키 생성 실패(`CRYPTO_KEY_CREATION_FAILED`)는
감사기록으로 표출되고 있었으며, 본 변경은 **엔진 내부 암호연산**을 그 체계에 추가합니다.

| 구성요소 | 위치 |
| --- | --- |
| 암호연산 | `backend/manager/modules/enginesso/.../sso/utils/LoginEnvelopeCrypto.java` |
| 스풀 기록 | `backend/manager/modules/enginesso/.../sso/utils/CryptoEventSpool.java` |
| 스풀 판독·감사기록 | `backend/manager/modules/bll/.../CryptoEventAuditManager.java` |
| 항목 검증·문안 | `backend/manager/modules/bll/.../CryptoEvent.java` |
| 감사기록 종류 | `backend/manager/modules/common/.../AuditLogType.java` (`LOGIN_CREDENTIAL_DECRYPTION_FAILED`, 13665) |
| 공통 어휘 | `packaging/pythonlib/ovirt_engine/cryptoevents.py` |
| 시험 | `backend/.../enginesso/src/test/.../CryptoEventSpoolTest.java`, `packaging/tests/test_login_crypto_events.py` |

## 2. 왜 스풀을 경유하는가

`ovirt-engine-sso.war`는 **감사기록 작성기를 갖지 않습니다.** 별도 배포 단위이고, `common`·`dal`
모듈에 의존하지 않으며(`backend/manager/modules/enginesso/pom.xml` 참조), 감사기록 한 건이 어떻게
구성되는지 아는 코드가 없습니다. JDBC 연결(`java:/ENGINEDataSource`)은 있으나, `audit_log` 삽입은
34개 인자를 갖는 저장 프로시저(`InsertAuditLog`)이며 이를 SSO에서 직접 호출하면 스키마 결합이
두 곳으로 늘어납니다.

설정파일 암호화 도구들은 **엔진이 존재하지 않는 시점**(engine-setup, 기동 전 DB 설정 복호)의 결과를
남기기 위해 이미 스풀을 사용합니다. 같은 스풀을 재사용하면 판독자 하나, 어휘 하나,
"이벤트 이름 → 감사기록 종류" 변환 지점 하나를 유지할 수 있습니다.

```
LoginEnvelopeCrypto.decrypt() / decryptUsername()  ── 실패
  ├ engine.log (WARN)  — 모든 발생 건, 예외 원문이 허용되는 유일한 곳
  └ CryptoEventSpool.recordLoginDecryptionFailure()
       └ /var/lib/ovirt-engine/security/crypto-events/<uuid>.json  (0600, 디렉터리 0700)
            └ CryptoEventAuditManager (120초 주기 배수)
                 └ CryptoEvent.parse() → 검증 → audit_log 기록 → 항목 삭제
```

지연은 최대 120초입니다. 항목이 자체 타임스탬프를 가지므로 감사기록 메시지에는 **실패가 발생한
시각**이 표기됩니다.

## 3. 기록되는 내용

| 필드 | 값 |
| --- | --- |
| `version` | `1` |
| `id` | UUID (중복 기록 방지) |
| `timestamp` | 초 단위 UTC (`2026-09-29T06:51:40Z`) |
| `event` | `LOGIN_CREDENTIAL_DECRYPTION_FAILED` |
| `source` | `sso-credential` (비밀번호 / 비밀번호 변경 양쪽) 또는 `sso-username` |
| `reason` | 아래 어휘 중 하나 |

감사기록 메시지 예:

```
A login credential could not be decrypted at 2026-09-29T15:51:40+09:00 (sso-credential); reason: CIPHERTEXT_INVALID
A login credential could not be decrypted at 2026-09-29T15:52:03+09:00 (sso-username); reason: PRIVATE_KEY_UNAVAILABLE
```

### 사유 어휘 (추가된 3종)

| 사유 | 의미 | 유발 예외 |
| --- | --- | --- |
| `PRIVATE_KEY_UNAVAILABLE` | 개인키를 읽거나 해석할 수 없음. 아무것도 복호되지 않음 | `IOException`, `InvalidKeySpecException` |
| `CIPHERTEXT_INVALID` | 제시된 값이 이 키로 개봉되지 않음 (base64 오류, 길이 불일치, 다른 키로 봉인) | `BadPaddingException`, `IllegalBlockSizeException`, `IllegalArgumentException` |
| `ALGORITHM_UNAVAILABLE` | 암호 알고리즘·패딩·제공자 부재 | `NoSuchAlgorithmException`, `NoSuchPaddingException`, `NoSuchProviderException` |
| `UNKNOWN` | 그 외 | — |

`source`를 둘로 나눈 이유: 사용자명을 개봉하지 못한 것과 비밀번호를 개봉하지 못한 것은 서로 다른
소견이며, 하나의 이름으로 보고하면 감사기록이 어느 쪽인지 말해주지 못합니다.

## 4. 비밀정보 배제

- **사유는 예외의 *형(type)* 에서만 도출합니다.** 예외 메시지를 쓰지 않습니다 — 제공자 메시지 중
  일부는 키 파일 경로를 담고, 경로는 그 설치본이 키를 어디에 두는지 알려줍니다. 일부는 복호 대상의
  길이나 오프셋을 담습니다.
- 암호문, 평문, 키, 파일 경로는 항목에 들어가지 않습니다. 항목 필드는 위 6개뿐입니다.
- `CryptoEvent.parse()`가 `event`·`reason`·`source`를 **닫힌 어휘와 정규식**으로 검증하며, 맞지
  않는 항목은 기록하지 않고 `crypto-events/rejected/`로 격리한 뒤
  `CRYPTO_EVENT_SPOOL_REJECTED`(13664, WARNING)를 남깁니다.
- 예외 원문은 `engine.log`에만 남습니다. 감사기록보다 열람자가 적습니다.

## 5. 유량 제어

이 암호연산은 **로그인 페이지에 도달할 수 있는 누구나 유발할 수 있습니다.** 이 스풀에 기록하는 다른
모든 주체(engine-setup, 기동 전 복호)와 다른 점입니다. 제어가 없으면 쓰레기 값을 반복 전송하는
클라이언트가 시도 1건당 스풀 파일 1개, 파일 1개당 감사기록 1행을 만들어 이벤트 목록을 메웁니다.

`CryptoEventSpool.THROTTLE_SECONDS = 60`, **사유별**로 60초에 1건만 스풀에 기록합니다. 사유별로
잡은 이유: 잘못된 암호문이 쏟아지는 동안에도 "개인키가 없어졌다"는 사실은 계속 보고되어야 합니다.

모든 발생 건은 `engine.log`에 남습니다. 유량 제어는 **감사기록에 얼마나 자주 알릴지**만 정합니다.
쏟아지는 상황은 감사기록에서 "분당 1건이 계속 이어짐"으로 읽히며, 그것이 기록할 가치가 있는 사실
— 아직 계속되고 있다 — 입니다.

## 6. 기존 동작 보존

- `LoginEnvelopeCrypto.decrypt(String)` / `decryptUsername(String)`은 **받은 예외 객체를 그대로
  다시 던집니다.** 기록은 부수 효과이며 호출자가 보는 결과는 달라지지 않습니다.
- `decryptCredential(String)`은 `decrypt(String)`에 위임하므로 별도로 기록하지 않습니다. 그렇지
  않으면 한 번의 실패에 두 행이 남습니다.
- 값이 null·공백인 단축 경로에서는 기록하지 않습니다(암호연산이 수행되지 않음).
- 패키지 전용 2인자 오버로드(`decrypt(String, PrivateKey)` 등)는 그대로이므로 기존 단위 시험
  (`LoginEnvelopeCryptoTest`)은 영향을 받지 않습니다.
- `CryptoEventSpool`은 **어떤 경우에도 예외를 던지지 않습니다.** 호출자는 로그인 실패 처리 중이며,
  스풀을 쓸 수 없다는 사정이 원래의 실패 사유를 대체해서는 안 됩니다. 스풀 기록 실패는 debug
  수준으로만 남깁니다.
- 반쯤 쓰인 파일을 엔진이 읽지 않도록, `.tmp-<uuid>`로 작성한 뒤 `ATOMIC_MOVE`로 개명합니다
  (판독자는 점으로 시작하는 이름을 건너뜁니다).

## 7. 감사기록 종류

| 감사기록 | 값 | 심각도 |
| --- | --- | --- |
| `LOGIN_CREDENTIAL_DECRYPTION_FAILED` | 13665 | ERROR |

`AuditLogMessages.properties`: `A login credential could not be decrypted.`
(실제 표출 문안은 `CryptoEventAuditManager`가 `auditLogDao.save()`로 기록한 메시지입니다.)

## 8. 공통 어휘 동기화

같은 스풀을 세 곳에서 다룹니다. 이름이 어긋나면 항목이 조용히 격리되므로 시험으로 고정합니다.

| 위치 | 역할 |
| --- | --- |
| `CryptoEventSpool.java` (enginesso) | 기록 |
| `CryptoEvent.java` (bll) | 검증·문안·감사기록 종류 변환 |
| `cryptoevents.py` (pythonlib) | 설정파일 도구용 기록, 어휘 기재 |

`packaging/tests/test_login_crypto_events.py` (8건):

- 기록자와 엔진이 같은 이벤트 이름을 사용하고, 감사기록 종류·메시지 항목이 존재함
- 기록자가 쓰는 모든 사유가 엔진이 허용하는 어휘에 있음
- python 어휘에도 같은 이름이 있음
- 양쪽이 같은 스풀 디렉터리를 가리킴
- 원자적 개명과 점 접두사 건너뛰기가 짝을 이룸
- 두 로그인 경로가 각각 기록하고 예외를 그대로 다시 던짐
- 유량 제어가 존재함
- 항목에 비밀정보가 들어가지 않음 (예외 메시지 미사용)

`CryptoEventSpoolTest` (7건):

- 엔진이 기록하는 항목만 쓰고, 예외 메시지·경로는 쓰지 않음
- 사유를 형으로 분류(개인키 부재 ≠ 잘못된 암호문)
- 같은 사유는 창(60초)당 1건
- 잘못된 암호문이 쏟아지는 중에도 개인키 부재는 보고됨
- 창이 사유별로 유지되고 경과 후 다시 열림
- 임시 파일을 남기지 않음
- 쓸 수 없는 스풀이 호출자에게 전파되지 않음
