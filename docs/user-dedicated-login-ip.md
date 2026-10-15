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
| 감사 | 엔진 이벤트 | 설정 `USER_DEDICATED_IP_UPDATED`/`_FAILED`, 로그인 거부 `USER_LOGIN_IP_DENIED`, 미등록 수퍼유저 예외 허용 `USER_LOGIN_WITHOUT_DEDICATED_IP_ALLOWED` |

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

### 단말기 IP 인증 화면 표시
사용자 전용 IP는 웹 서버 설정(`Require ip`)에는 들어가지만 **단말기 IP 인증 화면 목록에는 표시하지 않는다**(사용자 관리 화면에서 관리).
- 조회(`GetTerminalIpAuthQuery`): 설정의 목록에서 현재 사용자 전용 IP를 빼고 보여 준다. `127.0.0.1`은 항상 표시.
- 저장(`SetTerminalIpAuthCommand`): 화면이 보낸 목록에 **설정에 있던 사용자 전용 IP를 다시 합쳐** 쓴다. 화면에서 추가·수정·삭제해도 전용 IP는 유지된다.
- 이벤트(단말기 IP 등록·수정·삭제)는 화면에 보인 목록 기준으로 기록된다.
- 단말기 IP 인증 화면에서 사용자 전용 IP와 같은 주소를 추가하면 설정에는 이미 있으므로 변화가 없고, 목록에도 표시되지 않는다.

> ⚠️ 주의: "다른 사용자가 쓰지 않으면 제거" 규칙은 **사용자 전용 IP끼리만** 비교한다. 같은 주소를 단말기 IP 인증 화면에서 **별도로(수동) 등록**해 두었더라도, 그 주소를 쓰던 마지막 사용자의 전용 IP를 지우면 목록에서 함께 제거된다. 그 주소를 단말기로 계속 허용해야 하면 단말기 IP 인증 화면에서 다시 등록한다.

### 집행 규칙 (internal 사용자만)
- 등록된 전용 IP == 실제 출발지 IP → **허용**
- 불일치 → **거부** + `USER_LOGIN_IP_DENIED`
- 비관리자 내부 사용자가 **미등록** → **거부**
- 수퍼유저가 **미등록** → **허용**(관리자 전체 잠금 방지 안전장치; 수퍼유저도 전용 IP를 등록하면 그 뒤로는 일치해야 함) + 경고 이벤트 `USER_LOGIN_WITHOUT_DEDICATED_IP_ALLOWED`
- 외부(LDAP 등) 사용자 → 적용 제외

### 감사(이벤트) 기록
| 상황 | 결과 | 이벤트(심각도) | 메시지 예 |
|---|---|---|---|
| 전용 IP 불일치 | 거부 | `USER_LOGIN_IP_DENIED` (13687, ERROR) | 사용자 user1@internal의 로그인이 거부되었습니다(전용 접속 IP 불일치): 실제 접속 IP '192.168.40.20', 전용 접속 IP '192.168.40.10'. |
| 비관리자 미등록 | 거부 | `USER_LOGIN_IP_DENIED` (13687, ERROR) | 사용자 user2@internal의 로그인이 거부되었습니다(전용 접속 IP 미등록): 실제 접속 IP '192.168.40.20', 전용 접속 IP '없음'. |
| 수퍼유저 미등록 | 허용 | `USER_LOGIN_WITHOUT_DEDICATED_IP_ALLOWED` (13688, WARNING) + 로그인 이벤트 | 수퍼유저 admin@internal이(가) 전용 접속 IP 미등록 상태로 로그인했습니다(관리자 잠금 방지 예외 허용): 실제 접속 IP '…'. 전용 접속 IP를 등록하십시오. |
| 전용 IP 일치 | 허용 | `USER_VDC_LOGIN` | — |

- 거부 이벤트는 **중복 억제 없이 시도마다** 기록된다(같은 사용자가 연속으로 시도해도 각각 남음). 이 단계는 SSO 비밀번호 인증을 통과한 뒤이므로 유효한 계정 없이는 이벤트를 쌓을 수 없다.
- engine.log에도 `로그인 거부(전용 접속 IP); 사용자=…; 출발지=…; 전용 접속 IP=…; 사유=…`가 남는다.
- 출발지 IP는 Apache가 AJP로 넘긴 실제 단말기 주소(`request.getRemoteAddr()`)다.

### ⚠️ Apache 단계(인증 전)에서 막힌 접속은 엔진 이벤트가 없다
출발지 IP가 단말기 IP 인증 목록(`Require ip`)에 **없으면** Apache가 로그인 화면 전에 **403**으로 차단하므로 요청이 엔진에 오지 않는다. 이 경우의 증빙은 httpd 로그다.

```bash
# Apache 단계 차단(인증 전): 403
grep '" 403 ' /var/log/httpd/ssl_access_log | grep '/ovirt-engine/'
grep 'AH01630' /var/log/httpd/ssl_error_log   # client denied by server configuration
```

따라서 `USER_LOGIN_IP_DENIED`는 **목록에 있는 다른 주소**(다른 사용자의 전용 IP, 단말기 IP 인증 화면에서 등록한 주소, `127.0.0.1`)에서 접속해 비밀번호 인증까지 통과한 경우에 남는다.

| 접속 출발지 | 차단 단계 | 증빙 |
|---|---|---|
| 단말기 목록에 없는 주소 | Apache (인증 전) | `ssl_access_log` 403 / `ssl_error_log` AH01630 |
| 목록에 있으나 본인 전용 IP가 아닌 주소 | 엔진 (인증 후) | 이벤트 `USER_LOGIN_IP_DENIED` + engine.log |

### 전용 IP의 웹 포털 차단
전용 접속 IP는 **클라이언트 프로그램(REST API) 로그인용**이다. 단말기 목록에 들어가 웹 서버를 통과하더라도
웹 포털에는 접속할 수 없다.

| 접속 | 일반 사용자 전용 IP | 관리자 전용 IP | 그 밖의 단말기 IP |
|---|---|---|---|
| 첫 화면 `/ovirt-engine/` | **차단 (Forbidden)** | 허용 | 허용 |
| 관리 포털 `/ovirt-engine/webadmin` | **차단 (Forbidden)** | 허용 | 허용 |
| SSO 로그인 화면 (`login.html`, `oauth/authorize`, `openid/authorize`, `interactive-*`) | **차단 (Forbidden)** | 허용 | 허용 |
| REST API `/ovirt-engine/api`, 토큰 발급 `/sso/oauth/token` | 허용 (전용 IP 일치 검사) | 허용 | 허용 |

- 판정(엔진 쿼리 `IsWebPortalDeniedForAddress`): 출발지 IP를 전용 IP로 쓰는 사용자가 있고, 그 사용자 중 **관리자가 한 명도 없으면** 차단.
  관리자 전용 IP는 관리 포털을 허용한다(관리자 잠금 방지).
- 관리자 판정은 **사용자에게 직접 부여된 관리자 역할** 기준이다. 디렉터리 그룹으로만 관리자 역할을 받은 계정은 일반 사용자로 판정되므로,
  그 계정에 전용 IP를 줄 때는 관리자 역할을 직접 부여한다.
- 차단 화면은 웹 서버와 같은 403 Forbidden 페이지(`ForbiddenPage`)이며 이유를 표시하지 않는다.
- 감사: `WEB_PORTAL_DENIED_FOR_DEDICATED_IP`(13691, 경고) — 주소별 1분에 1건, 전용 IP 사용자 이름 포함. engine.log에는 요청마다 기록된다.
- 반영 시간: 필터가 주소별 판정을 30초 보관하므로 전용 IP를 등록·삭제한 뒤 최대 30초 안에 반영된다.
- 엔진 서버 자신(루프백·엔진 IP)은 차단하지 않는다. 엔진에 판정을 묻지 못하면 통과시킨다(로그인 시 전용 IP 검사는 그대로 적용).
- 구현: `aaa/filters/DedicatedIpWebPortalFilter`(첫 화면·관리 포털·SSO 로그인 화면 web.xml에서 가장 먼저 실행),
  `bll/aaa/IsWebPortalDeniedForAddressQuery`.
- VM 포털(ovirt-web-ui) 등 이 저장소 밖의 웹 애플리케이션은 SSO 로그인 화면 차단으로 로그인 단계에서 막힌다.

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
- 등록 IP와 **같은 IP**에서 로그인 → 성공 / 목록에 있는 **다른 IP** → 거부 + `USER_LOGIN_IP_DENIED`(실제·전용 IP 표시) / 목록에 **없는 IP** → Apache 403
- 같은 사용자가 연속 2회 거부 → 이벤트 2건
- 전용 IP 미등록 수퍼유저 로그인 → 허용 + `USER_LOGIN_WITHOUT_DEDICATED_IP_ALLOWED`
- 두 사용자가 같은 IP를 쓰다 한 명만 삭제 → `Require ip`에 그 IP 유지, 둘 다 삭제 → 제거
- 비관리자 내부 사용자 **미등록** → 거부(사유 "전용 접속 IP 미등록")
- 일반 사용자 전용 IP에서 브라우저로 `/ovirt-engine/`·`/ovirt-engine/webadmin` 접속 → Forbidden + `WEB_PORTAL_DENIED_FOR_DEDICATED_IP`, 같은 IP의 REST API 로그인은 정상
- 관리자 전용 IP에서 관리 포털 접속 → 정상

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
| 전용 IP 웹 포털 차단 | `aaa/filters/DedicatedIpWebPortalFilter.java`, `bll/aaa/IsWebPortalDeniedForAddressQuery.java` |
| UI(등록/수정/삭제) | `frontend/.../users/LocalUserAddModel.java`, `UserListModel.java`, `LocalUserAddPopupView.*` |
