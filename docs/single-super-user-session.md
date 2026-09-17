# 최고관리자 단일 접속 제한

## 1. 개요

**super user 역할을 가진 계정은 동시에 한 사람만 로그인할 수 있습니다.** 한 계정이 접속 중이면
다른 최고관리자 계정은 로그인할 수 없습니다. 계정을 여러 개 만들어 두더라도 실제로 시스템을
조작할 수 있는 사람은 언제나 한 명입니다.

| 구성요소 | 위치 |
| --- | --- |
| 자리 판정·선점 | `backend/manager/modules/bll/.../aaa/SessionDataContainer.java` |
| 로그인 시 적용 | `backend/manager/modules/bll/.../aaa/CreateUserSessionCommand.java` |
| 거부 사유 | `backend/manager/modules/common/.../aaa/CreateUserSessionsError.java` |
| 사용자 안내 | `backend/manager/modules/aaa/.../SsoUtils.java`, `.../servlet/SsoPostLoginServlet.java` |

## 2. 동작

```
 로그인 (인증 통과 후, 세션 생성 직전)
     │
     ▼
 이 계정이 super user 역할을 가지고 있는가?
     │
     ├─ 아니오 ──────────────────────────────▶ 평소대로 세션 생성
     │
     └─ 예
         │
         ▼
   claimSuperUserSession(세션ID, 계정)
         │
         ├─ 자리가 비어 있음 ─────────────────▶ 자리 선점 후 세션 생성
         │
         ├─ 같은 계정이 사용 중 ──────────────▶ 자리 인계 후 세션 생성
         │
         └─ 다른 계정이 사용 중 ──────────────▶ 로그인 거부
                                               SUPER_USER_SESSION_ALREADY_ACTIVE
```

**대상은 super user 역할(`00000000-0000-0000-0000-000000000001`)을 가진 계정입니다.** 클러스터
관리자 등 다른 관리 역할은 이 제한을 받지 않습니다. 엔진이 `isAdmin`을 판정할 때 이미 조회하는
역할 목록을 그대로 사용하므로 추가 조회가 없습니다.

**같은 계정의 두 번째 접속은 이 제한이 아닙니다.** 한 계정이 몇 개의 세션을 가질 수 있는지는
`ENGINE_SSO_SINGLE_SESSION_POLICY`와 세션 수 제한이 정하고, 이 제한은 **몇 개의 계정이**
접속할 수 있는지만 정합니다. 그래서 같은 계정이 다시 로그인하면 자리를 넘겨받습니다.

## 3. 자리의 수명

자리는 **세션이 쥐고 있으며, 따로 반납하지 않습니다.** 로그아웃·세션 만료·관리자 강제 종료 중
무엇으로 끝나든 세션이 목록에서 사라지는 순간 자리도 함께 비므로, 반납을 잊어 자리가 영영 잠기는
경우가 없습니다.

| 세션 종료 사유 | 자리 해제 시점 |
| --- | --- |
| 로그아웃 | 즉시 |
| 유휴 시간 초과(`UserSessionTimeOutInterval`) | 만료 세션 정리 시 |
| 관리자가 세션 종료 | 즉시 |
| 엔진 재시작 | 재시작 시 세션이 모두 사라지므로 즉시 |

## 4. 동시 로그인 처리

두 최고관리자가 **같은 순간에** 로그인해도 한 명만 통과합니다. 자리 확인과 선점이 하나의
동기화된 단계이기 때문입니다(`claimSuperUserSession`).

자리를 쥔 계정은 세션에 **직접 기록**합니다. 세션이 "유효" 표시를 받는 것은 사용자 정보가 설정된
뒤인데, 자리를 유효한 세션만 세도록 하면 그 찰나에 자리가 비어 보여 두 번째 최고관리자가 통과할
수 있습니다.

## 5. 감사 로그

| 이벤트 | 코드 | 심각도 | 발생 시점 |
| --- | --- | --- | --- |
| `SUPER_USER_SESSION_ALREADY_ACTIVE` | 13656 | ERROR | 다른 최고관리자가 접속 중이라 로그인이 거부됨 |

```
User admin2@internal-authz was refused a login from 192.168.40.117 because super user
admin@internal-authz is already logged in. Only one super user may be logged in at a time.
```

**거부된 계정과 자리를 쥔 계정이 함께 기록**되므로, 누가 막혔고 누가 사용 중이었는지 감사 로그만
으로 확인됩니다. engine.log에도 `단일 관리자 접속 제한; 거부=...; 사용중=...` 형식으로 남습니다.

계정과 패스워드는 정상적으로 검증된 뒤에 거부되는 것이므로, 이 이벤트는 **인증 실패가 아닙니다.**
로그인 실패 횟수에도 집계되지 않아 계정이 잠기지 않습니다.

## 6. 사용자에게 보이는 안내

```
Unable to login user admin2@internal-authz with profile [internal]
because another super user is already logged in;
only one super user may be logged in at a time
```

## 7. 운영 시 유의사항

**접속 중인 최고관리자가 로그아웃하지 않으면 다른 최고관리자는 기다려야 합니다.** 자리를 쥔
세션이 유휴 시간(`UserSessionTimeOutInterval`, 1~10분)을 넘기면 자동으로 정리되므로, 브라우저를
닫고 간 경우에도 최대 그 시간 안에 자리가 비웁니다.

세션을 강제로 종료하려면 관리자 접속이 필요하므로, **자리를 쥔 세션을 화면에서 끊을 수는
없습니다.** 즉시 비워야 한다면 엔진 호스트에서 서비스를 재시작하십시오.

```bash
systemctl restart ovirt-engine
```

이 제한은 설정으로 끌 수 없습니다. 인증 기준이 요구하는 통제이므로 항상 적용됩니다.

## 8. 확인 절차

시험용 최고관리자 계정 두 개(`admin`, `admin2`)로 확인합니다.

| 절차 | 기대 결과 |
| --- | --- |
| `admin`으로 로그인 | 정상 로그인 |
| 이어서 `admin2`로 로그인 | 거부, `SUPER_USER_SESSION_ALREADY_ACTIVE` 기록 |
| `admin` 로그아웃 후 `admin2` 로그인 | 정상 로그인 |
| `admin`이 다른 브라우저에서 다시 로그인 | 이 제한에는 걸리지 않음(세션 정책이 판단) |
| 최고관리자가 아닌 계정으로 로그인 | 제한 없음 |

```bash
# 거부 기록 확인
psql -U engine -d engine -c \
  "select log_time, message from audit_log where log_type = 13656 order by log_time desc limit 5;"
```

---

**문서 버전**: 1.0
**최종 수정일**: 2026-09-17
