# 로컬 그룹 구성원 관리와 그룹 가상머신 할당

내부 인증(`internal-authz`, aaa-jdbc)에 만든 그룹에 대해 관리 포털에서 다음을 할 수 있다.

1. 그룹에 사용자를 골라 **추가·제외**한다 (구성원 관리 팝업).
2. 사용자 그룹에 **가상머신을 할당**하고, 그 **역할을 수정**하거나 **삭제**한다 (권한 하위 탭).

## 1. 그룹 구성원 관리

### 화면

관리 → 사용자 → 상단 [그룹] → 그룹 하나 선택 → **[구성원 관리]**

- 왼쪽 목록은 그룹에 없는 로컬 사용자, 오른쪽 목록은 그룹 구성원이다.
- 이름을 고른 뒤 [추가 >] / [< 제외]를 누르거나, 이름을 두 번 눌러 옮긴다. 여러 명을 함께 고를 수 있다.
- [확인]을 누르면 바뀐 사용자만 반영된다. 바뀐 것이 없으면 그대로 닫힌다.
- 버튼은 `internal-authz` 그룹 하나를 골랐을 때만 활성화된다. 외부 디렉터리(LDAP 등)의 그룹 구성원은 그 디렉터리에서 관리한다.

### 동작

| 항목 | 내용 |
|---|---|
| 구성원 조회 | `GetLocalGroupMembers` 조회가 `ovirt-aaa-jdbc-tool group-manage show <그룹>`의 결과에서 `User:` 줄을 읽는다. 아직 한 번도 로그인하지 않은 사용자도 구성원으로 보인다 |
| 왼쪽 목록 | 엔진 사용자 목록(`GetAllDbUsers`) 중 도메인이 `internal-authz`인 사용자. 엔진에 아직 등록되지 않은 사용자(한 번도 로그인하지 않았고 화면에서 만들지도 않은 사용자)는 나오지 않는다 |
| 변경 | `UpdateLocalGroupMembers` 명령이 사용자마다 `group-manage useradd/userdel <그룹> --user=<사용자>`를 실행한다 |
| 권한 | 시스템 수준 `MANIPULATE_USERS` (사용자 관리 권한) |
| 입력 검사 | 그룹·사용자 이름은 `[A-Za-z0-9._-]+`만 허용한다. 화면과 엔진에서 모두 검사한다 |
| 일부 실패 | 성공한 변경은 유지된다. 실패한 사용자와 그 이유는 팝업에 표시되고, 감사 로그에도 남는다 |

### 세션 종료

엔진은 사용자가 **로그인할 때** 그룹 소속을 읽는다. 그래서 구성원을 바꾼 뒤에도 이미 로그인한 사용자에게는 이전 그룹 권한이 남아 있다. 이를 막기 위해 **추가되거나 제외된 사용자의 열린 세션을 모두 종료**한다. 관리자가 세션을 종료할 때와 같은 방식이며(`TerminateSession`과 동일, 종료 사유 `TERMINATED_BY_ADMIN`), 다음 로그인부터 바뀐 그룹 권한이 적용된다. 변경에 실패한 사용자의 세션은 종료하지 않는다.

### 감사 로그(이벤트)

| 이벤트 | 코드 | 심각도 | 기록 시점 |
|---|---|---|---|
| `LOCAL_GROUP_MEMBER_ADDED` | 13722 | 정상 | 사용자 1명 추가 성공 |
| `LOCAL_GROUP_MEMBER_ADD_FAILED` | 13723 | 오류 | 사용자 1명 추가 실패 |
| `LOCAL_GROUP_MEMBER_REMOVED` | 13724 | 정상 | 사용자 1명 제외 성공 |
| `LOCAL_GROUP_MEMBER_REMOVE_FAILED` | 13725 | 오류 | 사용자 1명 제외 실패 |
| `LOCAL_GROUP_MEMBER_SESSIONS_TERMINATED` | 13726 | 정상 | 바뀐 사용자의 세션 종료(종료한 세션 수 포함) |

각 기록에는 대상 그룹, 대상 사용자, 작업한 관리자가 남는다. 엔진 로그(`engine.log`)에는 실패 시 도구 출력까지 남는다.

## 2. 그룹 가상머신 할당·역할 수정·삭제

### 화면

관리 → 사용자 → 그룹(또는 사용자) 선택 → 하위 탭 **[권한]**

| 버튼 | 동작 |
|---|---|
| **가상머신 할당** | 가상머신과 역할을 골라 권한을 준다 (`AddPermission`, 대상 종류 VM) |
| **역할 수정** | 고른 가상머신 권한의 역할을 바꾼다 (`ChangePermissionRole`). 가상머신은 바꿀 수 없다 |
| **삭제** | 기존 기능 그대로 권한을 삭제한다 (`RemovePermission`) |

- 역할 목록은 시스템에 있는 **기존 역할 전체**이다. 관리자 역할에는 "(관리자 역할)"이 붙는다.
- 가상머신 목록에서 **가상머신 풀에 속한 가상머신은 빠진다**. 풀 가상머신은 풀에서 할당한다(엔진도 거부한다).
- [역할 수정]은 **그 그룹(사용자)이 직접 가진 가상머신 권한 하나**를 골랐을 때만 활성화된다. 상위 그룹에서 물려받은 권한, 가상머신이 아닌 대상의 권한, 여러 개 선택은 제외된다.

### 역할 수정이 한 번에 처리되는 이유

이전에는 역할을 바꾸려면 권한을 삭제하고 다시 추가해야 했다. 그 사이에는 접근 권한이 없고, 추가가 실패하면 권한이 없는 상태로 남았다. `ChangePermissionRole`은 기존 권한 삭제와 새 권한 저장을 **하나의 트랜잭션**에서 처리하므로 결과는 "이전 역할" 또는 "새 역할" 둘 중 하나뿐이다. 감사 로그에도 한 건으로 남는다.

### 엔진 검사 (ChangePermissionRole)

| 검사 | 거부 메시지 |
|---|---|
| 권한이 저장되어 있는가 | `ACTION_TYPE_FAILED_PERMISSION_NOT_FOUND` |
| 가상머신 권한인가 | `ACTION_TYPE_FAILED_PERMISSION_ROLE_CHANGE_VM_ONLY` |
| 새 역할이 있는가 | `PERMISSION_ADD_FAILED_INVALID_ROLE_ID` |
| 역할이 바뀌는가 | `ACTION_TYPE_FAILED_PERMISSION_ROLE_UNCHANGED` |
| 관리자 역할은 최고 관리자만 줄 수 있음 | `PERMISSION_ADD_FAILED_ONLY_SYSTEM_SUPER_USER_CAN_GIVE_ADMIN_ROLES` |
| 풀 가상머신이 아닌가 | `PERMISSION_ADD_FAILED_VM_IN_POOL` |

권한 검사는 그 가상머신에 대한 `MANIPULATE_PERMISSIONS`이다(권한 추가·삭제와 같다).

### 감사 로그(이벤트)

| 이벤트 | 코드 | 심각도 |
|---|---|---|
| `USER_ADD_PERMISSION` / `USER_ADD_PERMISSION_FAILED` | 기존 | 가상머신 할당 |
| `PERMISSION_ROLE_CHANGED` | 13727 | 정상 (이전 역할 → 새 역할) |
| `PERMISSION_ROLE_CHANGE_FAILED` | 13728 | 오류 |
| `USER_REMOVE_PERMISSION` / `USER_REMOVE_PERMISSION_FAILED` | 기존 | 삭제 |

## 확인 방법

1. 로컬 사용자 `u1`, `u2`와 그룹 `g1`을 만든다.
2. `u1`으로 VM 포털에 로그인해 둔다.
3. 관리 포털에서 `g1`의 [구성원 관리]로 `u1`, `u2`를 추가한다.
   - 이벤트: `LOCAL_GROUP_MEMBER_ADDED` 2건, `u1`의 `LOCAL_GROUP_MEMBER_SESSIONS_TERMINATED` 1건
   - `u1`의 VM 포털 세션이 끊긴다
   - 셸 확인: `ovirt-aaa-jdbc-tool group-manage show g1`
4. `g1`의 [권한] 탭에서 [가상머신 할당]으로 VM `vm1`에 `UserRole`을 준다. `u1`이 다시 로그인하면 `vm1`이 보인다.
5. [역할 수정]으로 `UserVmManager`로 바꾼다. 이벤트 `PERMISSION_ROLE_CHANGED` 1건이 남는다.
6. [구성원 관리]에서 `u1`을 제외한다. `u1`의 세션이 끊기고, 다시 로그인하면 `vm1`이 보이지 않는다.
