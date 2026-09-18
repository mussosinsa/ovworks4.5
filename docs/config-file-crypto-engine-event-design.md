# 설정 파일 암·복호화 엔진 이벤트 연계 설계

## 1. 적용 대상과 현재 제약

엔진 이벤트 연계 대상은 다음 세 파일로 한정한다.

| 파일 | 저장 시 암호화 | 복호화 주체 |
|---|---:|---|
| `/etc/ovirt-engine/engine.conf.d/10-setup-database.conf` | 가능 | **Python 설정 로더**(`ovirt_engine/configfile.py`), 엔진 기동 시 |
| `/etc/ovirt-engine-dwh/ovirt-engine-dwhd.conf.d/10-setup-dwh-database.conf` | 가능 | 해당 소비자가 읽기 전에 메모리 내 복호화 |
| `/etc/ovirt-engine/aaa/internal.properties` | 현재 불가 | AAA JDBC 확장이 파일을 직접 읽으므로 평문 `0600` 유지 |

> **정정.** 이 표는 첫 행을 "Java 설정 로더에서 메모리 내 복호화"라고 적고 있었으나 사실이
> 아니다. `ShellLikeConfd.loadProperties`는 암호화된 파일을 **복호화하지 않고 건너뛴다**
> (`log.info("... is encrypted and is skipped by the Java local config loader.")`). 실제
> 복호화는 `ovirt-engine.py`가 쓰는 Python 로더에서만 일어나며, 따라서 이벤트를 거는 지점도
> Java가 아니라 Python 쪽이다. 이 표를 근거로 Java에 훅을 넣으면 아무것도 잡히지 않는다.

`internal.properties`를 현재 상태에서 `OVENC001` 형식으로 저장하면 AAA JDBC 확장이
DB 접속 정보를 읽지 못해 로그인과 엔진 시작이 실패한다. 따라서 이벤트 기능을 추가한다는
이유로 이 파일을 암호화 대상 allowlist에 넣어서는 안 된다. 먼저 AAA JDBC 확장에 메모리 내
복호화 지원을 구현한 뒤 암호화를 활성화해야 한다.

## 2. 이벤트 모델

파일별로 아래 네 이벤트를 사용한다. 메시지에는 basename, 작업자, 실행 경로(WebAdmin,
setup, service), 결과 코드만 포함한다. 파일 내용, 암호문, 키 경로, DB 암호와 예외 전체는
절대로 이벤트에 포함하지 않는다.

* `CONFIG_FILE_ENCRYPTION_COMPLETED` (13660, 정상)
* `CONFIG_FILE_ENCRYPTION_FAILED` (13661, 오류)
* `CONFIG_FILE_DECRYPTION_COMPLETED` (13658, 정상)
* `CONFIG_FILE_DECRYPTION_FAILED` (13659, 오류)

키 자체에 대해서는 두 가지를 더 사용한다. 파일이 아니므로 basename을 갖지 않는다.

* `CRYPTO_KEY_CREATED` (13662, 정상)
* `CRYPTO_KEY_CREATION_FAILED` (13663, 오류)

spool 항목을 읽을 수 없는 경우는 `CRYPTO_EVENT_SPOOL_REJECTED`(13664, 경고)로 기록한다.

**실패 사유는 고정된 어휘의 코드로만 기록한다.** 암호화 도구의 오류 메시지 여러 개가 파일
경로를 포함하고(`Vault CA certificate is missing: %s`, `Refusing group/other-writable file: %s`
등), 경로는 이 설치가 키를 어디에 두는지 알려준다. 메시지 자체나 예외 체인은 이벤트에 넣지
않는다. 도구에서 문구가 바뀌고 이곳이 따라가지 않으면 `UNKNOWN`이 되는데, 이는 덜 유용한
이벤트일 뿐 유출되는 이벤트는 아니다.

| 코드 | 의미 |
|---|---|
| `AUTHENTICATION_FAILED` | 인증 태그 불일치 — 훼손·변조 또는 키 불일치 |
| `FILE_DAMAGED` | 절단, 헤더 손상, 알 수 없는 버전·길이 |
| `VAULT_UNAVAILABLE` | Vault 연결·요청·토큰·CA 문제 |
| `VAULT_RESPONSE_INVALID` | Vault 응답이 키 재료로서 유효하지 않음 |
| `PASSPHRASE_UNAVAILABLE` | 패스프레이즈 파일 없음·비어 있음·권한 |
| `CONFIGURATION_INVALID` | 암호화 설정 파일 문제 |
| `PATH_REJECTED` | 경로 검증 거부 |
| `LEGACY_DENIED` | 구형 CBC 형식 거부 |
| `ENCRYPTOR_MISSING` | 암호화 도구 없음 |
| `UNKNOWN` | 위에 해당하지 않음 |

이미 암호화된 파일을 다시 암호화하거나 평문 파일을 복호화하려는 요청은 성공으로 위장하지
않고 실패 이벤트로 기록한다. 여러 파일을 일괄 처리할 때는 각 파일 이벤트와 작업 전체 요약
이벤트를 분리하여 일부 성공을 전체 성공으로 표시하지 않는다.

## 3. 엔진 가동 중 실행

WebAdmin에서 실행하는 암·복호화는 반드시 BLL 명령을 통해 수행한다.

1. 명령 시작 전에 대상의 canonical path와 basename allowlist를 검증한다.
2. 엔진 프로세스는 비밀 값을 인자로 전달하지 않고 제한된 `sudo` wrapper를 실행한다.
3. wrapper는 `encryptor.py`의 종료 코드와 구조화된 결과만 반환한다.
4. BLL 명령은 `AuditLogDirector`로 성공 또는 실패 이벤트를 `audit_log`에 저장한다.
5. UI 성공 알림과 무관하게 감사 이벤트 저장이 완료되어야 명령을 완료한다.

이 경로는 이벤트가 즉시 WebAdmin 이벤트 화면에 나타나며, REST API 인증정보나 DB 암호를
암호화 도구에 추가로 노출하지 않는다.

## 4. 엔진 중지·시작 구간 실행

설치, 복구, 엔진 사전 시작 단계에서는 `AuditLogDirector`를 사용할 수 없으므로 로컬 REST
호출이나 `audit_log` 직접 INSERT를 사용하지 않는다. 대신 다음과 같이 내구성 있는 spool을
사용한다.

1. 암호화 wrapper가 `/var/lib/ovirt-engine/crypto-event-spool/`에 이벤트 한 건당 JSON 파일
   하나를 atomic rename으로 기록한다.
2. 디렉터리는 `root:ovirt`, `0750`, 파일은 `root:ovirt`, `0640`으로 제한한다.
3. JSON schema는 버전, event type, 허용된 basename, 결과 코드, UTC 시각, source만 허용한다.
4. 엔진 시작 후 전용 `BackendService`가 파일 소유권·권한·크기·schema를 검증한다.
5. 검증된 항목을 `AuditLogDao`를 통해 저장한 뒤 같은 트랜잭션의 처리 ID를 남기고 spool을
   삭제한다. event UUID에 unique 제약을 두어 재시작 시 중복 기록을 방지한다.
6. 잘못된 spool은 이벤트 데이터로 신뢰하지 않고 격리하며 엔진 로그에 경고한다.

이 방식이면 엔진 시작을 실패시킨 암·복호화 결과도 다음 정상 기동 시 이벤트 화면에서 확인할
수 있다. 엔진 DB에 `psql`로 직접 쓰는 방식은 원격 DB, 암호화된 접속 설정, 스키마 변경 및
권한 문제 때문에 사용하지 않는다.

## 4-1. 구현된 spool

설계대로 구현되었으며, 위치만 기존 보안 상태 디렉터리 아래로 옮겼다. RPM이 소유하고, AIDE
제외 규칙과 권한 관리가 이미 적용된 곳이다.

```
/var/lib/ovirt-engine/security/crypto-events/          0700 ovirt
  <uuid>.json                                          0600
  rejected/<uuid>.json                                 읽을 수 없어 격리된 항목
```

| 구성요소 | 위치 |
|---|---|
| 기록(writer) | `packaging/pythonlib/ovirt_engine/cryptoevents.py` |
| 기동 시 복호화 훅 | `packaging/pythonlib/ovirt_engine/configfile.py` |
| 키 생성·파일 암호화 훅 | `packaging/encryptor/vault_passphrase.py`, `encrypt_conf_files.py` |
| 항목 검증(reader) | `backend/.../bll/CryptoEvent.java` |
| 감사기록 등록 | `backend/.../bll/CryptoEventAuditManager.java` |

**spool은 엔진 안에서 온 호출이 아니라 디스크의 파일이고, 그 내용이 감사 로그에 인쇄된다.**
따라서 모든 필드를 허용된 형태와 대조한다 — 파일명은 경로가 아닌 이름(`[A-Za-z0-9._-]{1,255}`),
이벤트 유형은 존재하는 것, 사유는 위 어휘, 버전은 1, 크기는 4KiB 이하. 통과하지 못한 항목은
기록하지 않고 `rejected/`로 옮긴 뒤 그 사실을 이벤트로 남긴다. **삭제하지 않는 이유**는, 그것이
이 호스트에서 일어난 암호연산에 대한 누군가의 기록이고, 지워버리면 그것이 무엇이었는지 아무도
확인할 수 없는 유일한 결과가 되기 때문이다.

기록된 항목은 삭제하여 한 번만 기록되게 한다.

## 5. 구현 순서

1. ~~공통 모듈에 네 감사 이벤트 유형과 오류 severity, DAL 메시지를 추가한다.~~ (완료)
2. `encryptor.py`가 비밀정보 없는 구조화 결과를 반환하도록 하고 파일별 성공/실패 테스트를
   추가한다.
3. WebAdmin BLL 명령과 최소 권한 sudo wrapper를 추가한다.
4. ~~오프라인 spool writer/importer를 추가한다.~~ (완료. 중복 방지는 DB migration 없이
   기록 후 항목 삭제로 처리한다 — 항목 파일이 곧 미처리 표시이므로 별도 unique 제약이 없어도
   같은 항목이 두 번 기록되지 않는다.)
5. 두 database conf 파일에 대해 성공, 잘못된 키, 훼손, 권한 오류, 재실행을 통합 시험한다.
6. AAA JDBC 메모리 내 복호화를 구현한 뒤에만 `internal.properties` 암호화를 활성화하고 같은
   시험을 적용한다.

## 6. 완료 기준

* 성공과 실패가 파일별로 WebAdmin 이벤트 화면에 표시된다.
* 엔진 중지 중 발생한 결과가 다음 시작 후 누락이나 중복 없이 표시된다.
* 이벤트와 engine.log에 평문, 암호문, 키 및 DB 암호가 남지 않는다.
* `internal.properties` 암호화 상태에서도 로그인 성공·실패 이벤트와 AAA 인증이 정상 동작한다.
* 이벤트 저장 실패를 암·복호화 성공으로 처리하지 않으며 운영자가 재처리할 수 있다.
