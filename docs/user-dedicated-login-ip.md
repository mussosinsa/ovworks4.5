# 사용자 전용 접속 IP

내부(local) 사용자에게 **로그인 가능한 단일 IPv4 주소**를 지정하고, 로그인 시 실제 출발지 IP가 그 주소와 같을 때만 허용하는 기능이다. 등록/수정/삭제는 사용자 관리 화면에서 하며, 같은 주소가 **단말기 IP 인증 목록**(`z-ovirt-engine-proxy.conf`의 `Require ip`)에도 자동 반영되고 웹 서버 재시작 없이(`httpd -k graceful`) 바로 적용된다. 집행과 감사는 엔진이 수행한다.

## 1. 동작 개요

| 단계 | 위치 | 동작 |
|---|---|---|
| 등록/수정/삭제 | webadmin 사용자 추가·수정 다이얼로그 "전용 접속 IP" | `SetUserDedicatedIp` 명령 |
| ① 단말기 IP 인증 반영 | `/etc/httpd/conf.d/z-ovirt-engine-proxy.conf`의 모든 `<RequireAny>` | 단말기 IP 인증 화면과 **같은 경로**(`TerminalIpConfigUtils`)로 `Require ip` 추가/제거 |
| ② 저장 | Engine DB `user_profiles.property_content`(jsonb) | 프로필 속성 `DEDICATED_LOGIN_IP`에 JSON 문자열로 저장(예: `"192.168.0.5"`), 빈 값=삭제 |
| ③ 즉시 적용 | 웹 서버 | 목록이 바뀐 경우에만 `sudo -n /usr/sbin/httpd -k graceful` (재시작 없음) |
| 집행 | `CreateUserSessionCommand`(모든 로그인 경로의 세션 생성 지점) | internal-authz 사용자에 한해 검사 |
| 감사 | 엔진 이벤트 | 설정 `USER_DEDICATED_IP_UPDATED`/`_FAILED`, 로그인 거부 `USER_LOGIN_IP_DENIED` |

순서: **웹 서버 목록을 먼저 쓰고**(실패하면 DB도 바꾸지 않고 명령 실패) → DB 저장 → graceful 적용. graceful이 실패해도 목록은 이미 기록되어 있으므로 다음 reload/재시작 때 적용되며, 엔진 로그에 오류가 남는다.

### 주소 규칙 (단말기 IP 인증과 동일)
- **단일 IPv4 주소만** — 대역(CIDR)·IPv6·호스트명 불가
- 모든 주소를 허용하거나 단말기가 가질 수 없는 주소(`0.0.0.0`, 멀티캐스트, `255.255.255.255` 등) 불가
- `127.0.0.1`은 단말기 목록에 **항상 유지**

### 단말기 IP 인증 목록 반영 규칙
| 동작 | 목록 변화 |
|---|---|
| 등록 (새 IP) | 새 IP를 추가(이미 있으면 그대로) |
| 수정 (A → B) | B 추가, A는 **다른 사용자의 전용 IP가 A가 아닐 때만** 제거 |
| 삭제 (A → 빈 값) | A는 **다른 사용자의 전용 IP가 A가 아닐 때만** 제거 |
| 사용자 계정 삭제 | 그 사용자의 전용 IP를 먼저 해제(위 삭제 규칙 적용) 후 계정 삭제 |

> ⚠️ 주의: "다른 사용자가 쓰지 않으면 제거" 규칙은 **사용자 전용 IP끼리만** 비교한다. 같은 주소를 단말기 IP 인증 화면에서 **별도로(수동) 등록**해 두었더라도, 그 주소를 쓰던 마지막 사용자의 전용 IP를 지우면 목록에서 함께 제거된다. 그 주소를 단말기로 계속 허용해야 하면 단말기 IP 인증 화면에서 다시 등록한다.

### 집행 규칙 (internal 사용자만)
- 등록된 전용 IP == 실제 출발지 IP → **허용**
- 불일치 → **거부** + `USER_LOGIN_IP_DENIED`
- 비관리자 내부 사용자가 **미등록** → **거부**
- 수퍼유저가 **미등록** → **허용**(관리자 전체 잠금 방지 안전장치; 수퍼유저도 전용 IP를 등록하면 그 뒤로는 일치해야 함)
- 외부(LDAP 등) 사용자 → 적용 제외

## 2. 2계층 구조

| | 단말기 IP 인증 (Apache) | 전용 접속 IP (엔진) |
|---|---|---|
| 계층 | Apache httpd (인증 **전**) | 엔진 (인증 **후**) |
| 범위 | 전역 — 포털 접근 자체 | 사용자별 1:1 |
| 위치 | `z-ovirt-engine-proxy.conf`의 `Require ip` | Engine DB `user_profiles` |
| 관리 | 단말기 IP 인증 화면 + **전용 IP 등록 시 자동** (+ engine-setup `allowedIps`) | 사용자 관리 화면 |

전용 IP가 단말기 목록에 자동으로 들어가므로, 그 사용자는 Apache를 통과해 엔진의 사용자별 검사까지 도달한다. 다만 `Require ip`는 전역이라 **웹 계층에서는 1:1 바인딩이 보존되지 않는다**(B의 IP가 목록에 있으면 A도 그 IP에서 로그인 화면까지는 닿는다). 사용자별 1:1은 엔진 검사가 보장한다.

### 웹 서버 즉시 적용(graceful)
- 엔진(비특권 `ovirt` 계정)은 engine-setup이 쓰는 sudo 규칙 `/etc/sudoers.d/ovirt-httpd`로 정확히 `/usr/sbin/httpd -k graceful` 한 가지만 실행할 수 있다.
- `httpd -k graceful`은 설정을 먼저 검사하고, 읽을 수 없으면 신호를 보내지 않아 기존 서버가 그대로 동작한다. 열린 연결은 끊지 않는다.
- 단말기 IP 인증 화면(`SetTerminalIpAuthCommand`)도 같은 방식으로 즉시 적용된다.
- `z-ovirt-engine-proxy.conf`는 AIDE에서 **권한만** 측정되므로 내용 변경이 무결성 봉인을 깨지 않는다. `/etc/sudoers.d/ovirt-httpd`는 내용까지 측정된다.

### engine-setup과의 관계
engine-setup은 실행할 때마다 `allowedIps` 답변으로 `z-ovirt-engine-proxy.conf`를 다시 만들지만, 그 답변의 **기본값은 현재 파일의 `Require ip` 목록**이다(`client_control.py` `_read_allowed_ips`). 따라서 화면에서 등록한 단말기·전용 IP는 기본값 그대로 진행하면 **보존**된다. 답변을 직접 바꾸어 주소를 빼면 그 주소는 목록에서 빠지므로, 그 경우 사용자 전용 IP를 다시 저장하거나 단말기 IP 인증 화면에서 다시 등록한다.

## 3. 증빙 / 검증

```bash
# 단말기 IP 인증 목록 (두 <RequireAny> 블록 모두 같은 목록이어야 함)
grep -n "Require ip" /etc/httpd/conf.d/z-ovirt-engine-proxy.conf
# graceful 권한
sudo -l -U ovirt | grep "httpd -k graceful"
```
```sql
-- 전용 IP 저장 확인 (JSON 문자열 형태)
SELECT user_id, property_name, property_content
  FROM user_profiles WHERE property_name = 'DEDICATED_LOGIN_IP';
```

시나리오:
- 전용 IP 등록 → `Require ip`에 추가, 재시작 없이 그 IP에서 로그인 화면 접근 가능
- 등록 IP와 **같은 IP**에서 로그인 → 성공 / **다른 IP** → 거부 + `USER_LOGIN_IP_DENIED`
- 두 사용자가 같은 IP를 쓰다 한 명만 삭제 → `Require ip`에 그 IP 유지, 둘 다 삭제 → 제거
- 비관리자 내부 사용자 **미등록** → 거부, 관리자 **미등록** → 가능

## 4. 관련 소스

| 기능 | 파일 |
|---|---|
| 저장·단말기 목록 반영 명령 | `backend/.../bll/SetUserDedicatedIpCommand.java` |
| `Require ip` 추가/제거·graceful | `backend/.../bll/TerminalIpConfigUtils.java` (`addAddress`, `removeAddress`, `reloadWebServerGracefully`) |
| 단말기 IP 인증 화면 명령 | `backend/.../bll/SetTerminalIpAuthCommand.java` |
| 사용자 계정 삭제 시 해제 | `backend/.../bll/aaa/RemoveUserCommand.java` |
| 로그인 집행·감사 | `backend/.../bll/aaa/CreateUserSessionCommand.java` |
| 다른 사용자 사용 여부 조회 | `UserProfileDao.getAllByName` / SP `GetUserProfilePropertiesByName` |
| sudo 규칙 | `packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system/acl.py` (`/etc/sudoers.d/ovirt-httpd`) |
| UI(등록/수정/삭제) | `frontend/.../users/LocalUserAddModel.java`, `UserListModel.java`, `LocalUserAddPopupView.*` |
