# 사용자 전용 접속 IP

내부(local) 사용자에게 **로그인 가능한 단일 IP**를 지정하고, 로그인 시 실제 출발지 IP가 그 IP와 같을 때만 허용하는 기능이다. 등록/수정/삭제는 사용자 관리 화면에서 하며, 집행과 감사는 엔진이 수행한다.

## 1. 동작 개요

| 단계 | 위치 | 동작 |
|---|---|---|
| 등록/수정/삭제 | webadmin 사용자 추가·수정 다이얼로그 "전용 접속 IP" | `SetUserDedicatedIp` 명령 → 프로필 속성 `DEDICATED_LOGIN_IP` 저장(빈 값=삭제) |
| 저장 형식 | Engine DB `user_profiles.property_content`(jsonb) | IP를 JSON 문자열로 저장(예: `"192.168.0.5"`) |
| 집행 | `CreateUserSessionCommand`(모든 로그인 경로의 세션 생성 지점) | internal-authz 사용자에 한해 검사 |
| 감사 | 엔진 이벤트 | 거부 시 `USER_LOGIN_IP_DENIED` |

### 집행 규칙 (internal 사용자만)
- 등록된 전용 IP == 실제 출발지 IP → **허용**
- 불일치 → **거부** + 감사
- 비관리자 내부 사용자가 **미등록** → **거부**
- 수퍼유저가 **미등록** → **허용**(관리자 전체 잠금 방지 안전장치; 수퍼유저도 전용 IP를 등록하면 그 뒤로는 일치해야 함)
- 외부(LDAP 등) 사용자 → 적용 제외

## 2. 중요 — 2계층 구조와 전역 "단말기 인증 IP" 의존성

접속 IP 제어는 **서로 다른 두 계층**에서 이루어진다. 이 기능은 **엔진 계층(인증 후, 사용자별)** 만 담당한다.

| | 전역 단말기 인증 IP (Apache) | 전용 접속 IP (엔진, 본 기능) |
|---|---|---|
| 계층 | Apache httpd (인증 **전**) | 엔진 (인증 **후**) |
| 범위 | 전역 — 포털 접근 자체 | 사용자별 1:1 |
| 위치 | `/etc/httpd/conf.d/z-ovirt-engine-proxy.conf`의 `<RequireAny> Require ip … </RequireAny>` (`/ovirt-engine` 전체 가드) | Engine DB `user_profiles` |
| 관리 | **engine-setup** 시 `allowedIps`에서 생성 | 사용자 관리 화면 |

### ⚠️ 운영 전제 (반드시 지킬 것)

Apache의 `Require ip` 블록은 **로그인 페이지에 닿기 전에** IP를 차단하는 하드 게이트다. 따라서:

> **사용자의 전용 접속 IP는 전역 `Require ip` 허용목록에도 포함되어 있어야 한다.**
> 포함되지 않으면 그 사용자는 엔진의 사용자별 검사에 도달하기 전에 **Apache에서 403으로 차단**되어, 전용 IP 기능이 동작하지 않는다.

즉 전역 허용목록은 **모든 사용자 전용 IP의 상위집합**이어야 한다. 전역은 "이 IP가 포털에 접근할 수 있는가"(거친 사전 필터), 전용 IP는 "이 사용자가 자신의 IP에서 접속하는가"(정밀 1:1)로 역할이 나뉜다.

### 전역 허용목록 확인·갱신

현재 허용목록 확인:
```bash
grep -A2 RequireAny /etc/httpd/conf.d/z-ovirt-engine-proxy.conf
```

전역 허용목록은 **engine-setup 시점에만** `z-ovirt-engine-proxy.conf`로 생성된다(런타임 자동 갱신 경로 없음). 사용자 전용 IP(또는 그 대역)를 전역 허용목록에 반영하려면:

- **지원 경로**: engine-setup의 `allowedIps`(단말기 인증 허용 IP) 답변에 해당 IP/대역을 포함하고 `engine-setup`을 다시 실행 → `z-ovirt-engine-proxy.conf` 재생성 → httpd 재시작.
- **임시 운영**: `z-ovirt-engine-proxy.conf`의 두 `<RequireAny>` 블록에 `Require ip <주소>`를 추가하고 `systemctl reload httpd`. 단, **다음 engine-setup 실행 시 덮어써지므로** 반드시 `allowedIps`에도 반영해 둔다. (이 파일은 AIDE 무결성에서 **권한만** 측정되므로 내용 변경이 봉인을 깨지 않는다.)

> 자동 동기화(전용 IP 추가 시 `Require ip`를 자동 갱신)는 채택하지 않았다: `Require ip`는 전역이라 사용자별 바인딩을 웹 계층에서 보존하지 못하고(진짜 1:1은 엔진이 복원), 런타임 root 권한·httpd reload가 필요하며, engine-setup이 매 실행 시 이 파일을 재생성해 충돌하기 때문이다. 계층을 분리하고 전역 허용목록을 상위집합으로 유지하는 것이 올바른 구조다.

## 3. 증빙 / 검증

```sql
-- 전용 IP 저장 확인 (JSON 문자열 형태)
SELECT user_id, property_name, property_content
  FROM user_profiles WHERE property_name = 'DEDICATED_LOGIN_IP';
```

로그인 시나리오:
- 등록 IP와 **같은 IP**에서 로그인 → 성공
- **다른 IP**에서 로그인 → 거부 + `USER_LOGIN_IP_DENIED` 이벤트
- 비관리자 내부 사용자 **미등록** → 거부, 관리자 **미등록** → 가능
- 전역 `Require ip`에 없는 IP → Apache 403(엔진 검사 이전). `z-ovirt-engine-proxy.conf` 허용목록 확인

## 4. 관련 소스

| 기능 | 파일 |
|---|---|
| 저장 명령 | `backend/.../bll/SetUserDedicatedIpCommand.java` |
| 로그인 집행·감사 | `backend/.../bll/aaa/CreateUserSessionCommand.java` |
| 감사 유형 | `AuditLogType.USER_LOGIN_IP_DENIED` / `USER_DEDICATED_IP_UPDATED` / `_FAILED` |
| UI(등록/수정/삭제) | `frontend/.../users/LocalUserAddModel.java`, `UserListModel.java`, `LocalUserAddPopupView.*` |
| 전역 단말기 인증 IP(Apache) | `packaging/conf/ovirt-engine-proxy.conf.v2.in`, `packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/apache/engine.py` |
