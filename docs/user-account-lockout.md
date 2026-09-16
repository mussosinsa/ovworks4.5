# 로그인 실패 계정 잠금 및 자동 해제

## 1. 개요

패스워드를 반복해서 틀린 계정을 일정 시간 잠그고, 그 시간이 지나면 **관리자 개입 없이 스스로
해제**합니다. 보호 관리자(`admin@internal`)와 그 밖의 모든 계정에 같은 방식으로 적용되며, 잠금
판정은 인증 확장(aaa-jdbc, LDAP 등)의 종류와 무관하게 SSO 로그인 경로 한 곳에서 이루어집니다.

| 구성요소 | 위치 |
| --- | --- |
| 잠금 판정·집계 | `backend/manager/modules/enginesso/.../service/AuthenticationService.java` |
| 잠금 저장소 계약 | `backend/manager/modules/enginesso/.../service/LoginLockout.java` |
| 관리자 잠금(메모리) | `backend/manager/modules/enginesso/.../service/AdminLoginLockoutService.java` |
| 일반 사용자 잠금(DB) | `backend/manager/modules/enginesso/.../service/UserLoginLockoutService.java` |
| 잠금 영속화 | `backend/manager/modules/enginesso/.../db/SsoDao.java` |
| 수동 잠금해제 | `backend/manager/modules/bll/.../aaa/UnlockUserCommand.java` |
| 잠금해제 DAO | `backend/manager/modules/dal/.../dao/UserLoginFailuresDao.java` |
| 설정값 검증 | `backend/manager/modules/bll/.../SetEngineConfigValueCommand.java` |
| 스키마 | `packaging/dbscripts/create_tables.sql`, `packaging/dbscripts/user_login_failures_sp.sql` |

## 2. 동작

```
 로그인 시도
     │
     ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ 1. 잠금 조회  getLockedUntil(이름@프로파일)                    │
 └───────────────┬─────────────────────────────┬───────────────┘
                 │ 잠금 시각이 지났다            │ 아직 잠금 중
                 ▼                             ▼
      잠금 해제 + 감사 기록                로그인 거부(감사 기록)
      USER_ACCOUNT_AUTO_UNLOCKED          패스워드 검사 없이 종료
                 │
                 ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ 2. 패스워드 검사 (authn 확장)                                 │
 └───────────────┬─────────────────────────────┬───────────────┘
                 │ 성공                         │ 실패
                 ▼                             ▼
        실패 기록 삭제                 계정이 실재하는가? (authz 조회)
                                              │
                                    ┌─────────┴─────────┐
                                    │ 아니오             │ 예
                                    ▼                   ▼
                              집계하지 않음        실패 횟수 +1
                                                        │
                                              횟수 ≥ 설정값이면 잠금
                                              USER_ACCOUNT_LOCKED_BY_
                                              LOGIN_FAILURES
```

보호 관리자와 그 밖의 계정은 판정 방식이 같고, **저장 위치와 안내 문구만** 다릅니다.

| 항목 | 보호 관리자 | 그 밖의 모든 계정 |
| --- | --- | --- |
| 대상 판정 | `ENGINE_SSO_PROTECTED_ADMIN_USERNAME` / `_PROFILE` (기본 `admin` / `internal`) | 그 외 전부 |
| 실패 횟수 설정 | `ENGINE_SSO_ADMIN_LOCK_MAX_FAILURES` | `ENGINE_SSO_USER_LOCK_MAX_FAILURES` |
| 잠금 시간 설정 | `ENGINE_SSO_ADMIN_LOCK_MINUTES` | `ENGINE_SSO_USER_LOCK_MINUTES` |
| 저장 위치 | 엔진 메모리 | Engine DB `user_login_failures` |
| 재시작 시 | 잠금 해제됨 | 잠금 유지 |
| 다중 노드 | 노드별 집계 | 노드 간 공유 |
| 미존재 계정 실패 | 집계함 | 집계하지 않음 |
| 잠긴 상태의 안내 | "계정이 잠겼습니다" | 패스워드 오류와 동일한 문구 |
| REST API 로그인 | 애초에 차단됨 | 허용되며 실패도 함께 집계 |

집계 키는 `이름@프로파일`을 소문자로 정규화한 값입니다. 같은 이름이라도 프로파일이 다르면 다른
계정으로 셉니다.

## 3. 설정

설정값은 **Engine DB(`vdc_options`) → SSO 로컬 설정 → 내장 기본값** 순으로 조회합니다. 범위를
벗어난 값이나 숫자가 아닌 값은 경고를 남기고 기본값으로 되돌립니다.

| 설정 | 허용 범위 | 기본값 | 설명 |
| --- | --- | --- | --- |
| `ENGINE_SSO_ADMIN_LOCK_MAX_FAILURES` | 1 ~ 5 | 5 | 관리자 잠금까지의 실패 횟수 |
| `ENGINE_SSO_ADMIN_LOCK_MINUTES` | 5 ~ 100000 | 5 | 관리자 잠금 시간(분) |
| `ENGINE_SSO_USER_LOCK_MAX_FAILURES` | 1 ~ 5 | 5 | 일반 사용자 잠금까지의 실패 횟수 |
| `ENGINE_SSO_USER_LOCK_MINUTES` | 5 ~ 100000 | 5 | 일반 사용자 잠금 시간(분) |

```
# 현재 값 확인
engine-config -g ENGINE_SSO_USER_LOCK_MAX_FAILURES
engine-config -g ENGINE_SSO_USER_LOCK_MINUTES

# 값 변경 후 engine 재시작
engine-config -s ENGINE_SSO_USER_LOCK_MAX_FAILURES=3
engine-config -s ENGINE_SSO_USER_LOCK_MINUTES=10
systemctl restart ovirt-engine
```

WebAdmin의 환경변수 편집 화면에서도 같은 키를 조회·변경할 수 있으며, 범위를 벗어나면
`일반 사용자 잠금 후 재활성화 시간(분) 값은 5에서 100000 사이여야 합니다`와 같이 거부됩니다.

잠금 시간은 인증 기준이 요구하는 **최소값만** 설정하기를 권합니다. 길게 잡을수록 공격자가 남의
계정을 고의로 잠가 업무를 막는 서비스 거부의 효과가 커집니다.

## 4. 잠금 해제

### 4.1 자동 해제

별도의 타이머가 도는 것이 아니라, **잠금 시간이 지난 뒤 첫 로그인 시도 시점**에 해제됩니다.
동작 결과는 같지만 감사 로그의 해제 시각은 만료 시각이 아니라 그 시도 시각으로 기록됩니다.
해제된 뒤의 실패는 이전 횟수에 얹히지 않고 1부터 다시 셉니다.

### 4.2 관리자 수동 해제

WebAdmin의 사용자 목록에서 **잠금해제**를 실행하면 두 가지가 함께 처리됩니다.

1. 엔진이 기록한 잠금(`user_login_failures`)을 로그인 이름 기준으로 삭제합니다.
2. 인증 확장의 잠금을 `ovirt-aaa-jdbc-tool user unlock`으로 해제합니다.

1번은 2번의 성공 여부와 무관하게 먼저 수행되며, 실패하더라도 로그만 남기고 2번을 막지 않습니다.
엔진 잠금은 시간이 지나면 어차피 스스로 풀리기 때문입니다.

### 4.3 인증 확장의 별도 잠금

**엔진의 잠금과 인증 확장(aaa-jdbc)의 잠금은 서로 다른 두 개의 잠금입니다.** 엔진이 5회 실패를
세어 잠그는 동안, aaa-jdbc도 자신의 `MAX_FAILURES_SINCE_SUCCESS` 정책으로 같은 계정을 따로
잠급니다. 엔진의 자동 해제(4.1)는 **엔진이 기록한 잠금만** 풉니다.

두 잠금 시간이 다르면 엔진 쪽 감사 로그에는 해제가 남았는데도 로그인은 계속 거부됩니다. 인증
확장이 `ACCOUNT_LOCKED`를 반환하므로 패스워드는 검사조차 되지 않습니다.

```
# 엔진 로그: 해제됨
USER_ACCOUNT_UNLOCKED user=user01@internal unlockAt=2026-09-16T09:51:38Z

# 그러나 인증 확장은 여전히 잠금 상태
$ ovirt-aaa-jdbc-tool user show user01
Account Locked: true
Account Unlocked At: 2026-09-16 10:38:59Z
```

이 상태에서 즉시 풀려면 WebAdmin의 **잠금해제**(4.2)를 쓰거나 확장의 도구를 직접 실행합니다.

```
ovirt-aaa-jdbc-tool user unlock user01
```

두 잠금이 어긋나지 않게 하려면 확장의 잠금 정책을 엔진 정책과 맞춰야 합니다. ovirt-aaa-jdbc-tool의
기본값은 **60분**이라, 손대지 않으면 엔진이 5분 뒤 해제해도 계정은 55분을 더 잠겨 있습니다.

| 항목 | 엔진 설정 | ovirt-aaa-jdbc-tool 설정 | 도구 기본값 |
| --- | --- | --- | --- |
| 잠금까지의 실패 횟수 | `ENGINE_SSO_USER_LOCK_MAX_FAILURES` | `MAX_FAILURES_SINCE_SUCCESS` | 5 |
| 잠금 시간(분) | `ENGINE_SSO_USER_LOCK_MINUTES` | `LOCK_MINUTES` | **60** |

```
# 현재 값 확인
ovirt-aaa-jdbc-tool settings show --name=LOCK_MINUTES
ovirt-aaa-jdbc-tool settings show --name=MAX_FAILURES_SINCE_SUCCESS

# 엔진 정책과 동일하게 맞춤
ovirt-aaa-jdbc-tool settings set --name=LOCK_MINUTES --value=5
```

두 값 모두 WebAdmin의 사용자 환경변수 편집 화면에서도 조회·변경할 수 있으며, 화면과 명령 모두
엔진 설정과 같은 범위(`LOCK_MINUTES`는 5~100000, `MAX_FAILURES_SINCE_SUCCESS`는 1~5)로
제한합니다.

확장에는 이 밖에도 잠금을 거는 정책이 하나 더 있습니다. `MAX_FAILURES_PER_INTERVAL`(기본 20)은
`INTERVAL_HOURS`(기본 24) 동안 누적된 실패가 그 횟수를 넘으면 잠급니다. 연속 실패가 아니라
누적이므로, 엔진 쪽 잠금이 걸리지 않았는데도 계정이 잠길 수 있습니다. 이 잠금도 `LOCK_MINUTES`를
따릅니다.

## 5. 감사 로그

| 이벤트 | 코드 | 심각도 | 발생 시점 |
| --- | --- | --- | --- |
| `USER_ACCOUNT_LOCKED_BY_LOGIN_FAILURES` | 13648 | ERROR | 실패 횟수 도달, 그리고 잠긴 상태의 로그인 시도 |
| `USER_ACCOUNT_AUTO_UNLOCKED` | 13649 | NORMAL | 잠금 시간이 지나 스스로 해제 |
| `USER_ACCOUNT_UNLOCKED` | 13630 | NORMAL | 관리자가 수동으로 해제 |
| `USER_ACCOUNT_UNLOCK_FAILED` | 13631 | ERROR | 수동 해제 실패 |

engine.log에는 같은 사건이 `USER_ACCOUNT_LOCKED user=... sourceIp=... failCount=... lockedUntil=...`
형식으로 함께 남습니다.

## 6. 데이터

```sql
CREATE TABLE user_login_failures (
    principal       character varying(510) NOT NULL,  -- '이름@프로파일', 소문자
    login_name      character varying(255) NOT NULL,  -- 이름 부분, 수동 해제의 조회 키
    failure_count   integer DEFAULT 0 NOT NULL,
    last_failure_at timestamp with time zone DEFAULT now() NOT NULL,
    locked_until    timestamp with time zone          -- NULL이면 잠금 아님
);
```

행은 로그인에 성공하거나 잠금이 해제될 때 삭제되므로 무한히 늘지 않습니다. 실재하지 않는 계정은
애초에 기록하지 않으므로, 이름을 지어내 표를 채우는 것도 불가능합니다.

## 7. 설계상의 결정

- **미존재 계정은 집계하지 않습니다.** 실패 시 authz 확장으로 계정 실재 여부를 확인한 뒤에만
  셉니다. 잠글 대상이 없는 데다, 집계하면 임의의 이름으로 표를 채울 수 있기 때문입니다.
- **잠긴 계정에게 잠겼다고 말하지 않습니다.** 잠금은 곧 그 이름의 계정이 존재한다는 뜻이므로,
  그렇게 답하면 아무 이름이나 입력해 계정 존재 여부를 확인할 수 있게 됩니다. 일반 사용자는
  패스워드 오타와 같은 문구를 받습니다. 이름이 이미 알려진 보호 관리자만 명시적으로 안내합니다.
- **관리자 잠금은 기록하지 않습니다.** 엔진 재시작으로 잠긴 관리자는 그 복구 작업에서도 잠긴
  상태가 되고, DB가 죽었을 때도 관리자는 들어올 수 있어야 하기 때문입니다.
- **DB를 잃어도 아무도 잠기지 않습니다.** 집계하지 못한 실패는 기록만 남기고 버리고, 읽지 못한
  계정은 잠기지 않은 것으로 봅니다. 패스워드 검사 자체는 어느 경우에도 그대로 수행됩니다.

## 8. 운영 중인 엔진 서버에 적용

DB 스키마와 산출물이 함께 바뀌므로 **DB → 산출물 → 재시작** 순서를 지켜야 합니다. 테이블이 없는
상태로 새 SSO 코드가 뜨면 로그인은 정상 동작하지만 잠금이 집계되지 않고 로그에 오류만 쌓입니다.

### 8.1 배포 대상

| 변경 | 운영 서버 경로 |
| --- | --- |
| SSO 로그인 경로 | `/usr/share/ovirt-engine/engine.ear/enginesso.war/WEB-INF/lib/enginesso-<버전>.jar` |
| 설정값 검증, 잠금해제 명령 | `/usr/share/ovirt-engine/engine.ear/bll.jar` |
| 잠금해제 DAO | `/usr/share/ovirt-engine/modules/common/org/ovirt/engine/core/dal/main/dal.jar` |
| 스키마·SP·기본값 | `/usr/share/ovirt-engine/dbscripts/` |
| 설정 키 노출 | `/etc/ovirt-engine/engine-config/engine-config.properties` |

WebAdmin(GWT) 변경은 없으므로 프론트엔드는 다시 만들 필요가 없습니다.

업그레이드 스크립트 번호에는 제약이 있습니다. `schema.sh`는 **DB에 설치된 마지막 버전보다 10을
초과해 앞선 번호**를 거부합니다.

```
FATAL: Illegal script version number 04050341,version should be in max 10 gap
       from last installed version: 04050328
```

이 메시지가 나오면 대상 서버의 스키마 버전을 확인하고, 그 사이에 아직 적용되지 않은 스크립트가
있는지 보십시오. 잠금 스크립트는 `04_05_0329`로, 직전 버전 `04_05_0328` 바로 다음에 놓여 있습니다.

```
select version from schema_version where current = true;
```

한 가지 주의할 점이 있습니다. 이미 `04050329`보다 높은 버전이 설치된 서버에서는 이 스크립트가
**이미 지난 번호로 판단되어 건너뛰어집니다.** 그런 서버에 적용할 때는 스크립트를 그 서버의 현재
버전 다음 번호로 다시 매기거나, 테이블과 설정값을 직접 넣어야 합니다. 테이블이 없으면 로그인은
정상 동작하지만 잠금이 조용히 집계되지 않으므로, 적용 후 9절의 확인 절차를 반드시 수행하십시오.

### 8.2 방법 A — RPM 재빌드 (권장)

무결성 검사를 운영하는 환경에서는 패키지 경로를 그대로 타는 이 방법이 정석입니다.

```
# 빌드 호스트
make dist
rpmbuild -tb ovirt-engine-<버전>.tar.gz

# 엔진 서버
systemctl stop ovirt-engine
dnf upgrade ./ovirt-engine-*.rpm ./ovirt-engine-backend-*.rpm ./ovirt-engine-dbscripts-*.rpm
engine-setup
```

`engine-setup`이 업그레이드 스크립트를 적용해 테이블·저장 프로시저·기본값을 한 번에 넣고 서비스를
기동합니다.

### 8.3 방법 B — 산출물만 교체

```
# 1) 빌드 (GWT 생략)
mvn -B -DskipTests -am -pl \
  backend/manager/modules/enginesso,backend/manager/modules/bll,backend/manager/modules/dal \
  package

# 2) 백업
systemctl stop ovirt-engine
engine-backup --scope=db --file=/var/backups/engine-db-$(date +%F).tar.gz \
              --log=/var/log/engine-backup.log
cp -a /usr/share/ovirt-engine/engine.ear/bll.jar{,.bak}
cp -a /usr/share/ovirt-engine/modules/common/org/ovirt/engine/core/dal/main/dal.jar{,.bak}
cp -a /usr/share/ovirt-engine/engine.ear/enginesso.war/WEB-INF/lib/enginesso-<버전>.jar{,.bak}

# 3) DB 먼저
cp packaging/dbscripts/user_login_failures_sp.sql /usr/share/ovirt-engine/dbscripts/
cp packaging/dbscripts/upgrade/04_05_0329_add_user_login_lockout.sql \
   /usr/share/ovirt-engine/dbscripts/upgrade/
. /etc/ovirt-engine/engine.conf.d/10-setup-database.conf
PGPASSWORD="${ENGINE_DB_PASSWORD}" /usr/share/ovirt-engine/dbscripts/schema.sh -c apply \
   -s "${ENGINE_DB_HOST}" -p "${ENGINE_DB_PORT}" \
   -u "${ENGINE_DB_USER}" -d "${ENGINE_DB_DATABASE}"

# 4) 산출물 교체 후 기동
systemctl start ovirt-engine
```

교체 전 대상 파일을 `ls -l`로 확인하고 **기존과 같은 파일명·소유자·권한**으로 덮으십시오.
버전 문자열이 붙은 `enginesso-<버전>.jar`는 특히 설치본마다 다를 수 있습니다.

### 8.4 무결성 기준선 갱신

`/usr/share/ovirt-engine/modules`와 `/etc/ovirt-engine`은 무결성 기준선의 대상입니다. `dal.jar`와
`engine-config.properties`가 바뀌었으므로 기준선을 다시 만들지 않으면 이후 검사가 실패합니다.

```
./ov-works-security_audit.sh --integrity-baseline
aide --update
```

### 8.5 롤백

```
systemctl stop ovirt-engine
for f in /usr/share/ovirt-engine/engine.ear/bll.jar \
         /usr/share/ovirt-engine/engine.ear/enginesso.war/WEB-INF/lib/enginesso-<버전>.jar \
         /usr/share/ovirt-engine/modules/common/org/ovirt/engine/core/dal/main/dal.jar; do
  mv "$f.bak" "$f"
done
systemctl start ovirt-engine
```

테이블과 설정값은 지우지 않아도 됩니다. 구버전 코드는 `user_login_failures`를 참조하지 않으므로
남아 있어도 무해하고, 다시 적용할 때 그대로 씁니다.

## 9. 적용 확인

```
# 설정값과 스키마
engine-config -g ENGINE_SSO_USER_LOCK_MAX_FAILURES
engine-config -g ENGINE_SSO_USER_LOCK_MINUTES
psql -U engine -d engine -c "\d user_login_failures"

# 동작: 시험용 계정으로 패스워드를 설정 횟수만큼 틀린 뒤
psql -U engine -d engine -c \
  "select principal, failure_count, locked_until from user_login_failures;"
tail -f /var/log/ovirt-engine/engine.log | grep -E "USER_ACCOUNT_LOCKED|USER_ACCOUNT_UNLOCKED"
```

| 확인 항목 | 기대 결과 |
| --- | --- |
| 설정 횟수 직전까지 실패 | 잠기지 않음, `failure_count`만 증가 |
| 설정 횟수째 실패 | `locked_until`이 설정 시간 뒤로 기록, 감사 이벤트 발생 |
| 잠금 중 추가 실패 | 잠금 시각이 **연장되지 않음** |
| 잠금 시간 경과 후 로그인 | 정상 로그인, `USER_ACCOUNT_AUTO_UNLOCKED` 기록 |
| 없는 계정으로 반복 실패 | `user_login_failures`에 행이 생기지 않음 |
| WebAdmin 잠금해제 | 해당 행이 삭제되고 즉시 로그인 가능 |

동작 확인은 반드시 **시험용 계정**으로 하십시오. 관리자 계정으로 시험하면 잠금 시간 동안 관리
작업이 막힙니다.

---

**문서 버전**: 1.0
**최종 수정일**: 2026-09-16
