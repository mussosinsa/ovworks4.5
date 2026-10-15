# 접속 단말기(X-Client-Serial) 미등록 접속 감사 기록

등록된 단말기만 엔진에 접속할 수 있도록 요청 헤더 `X-Client-Serial` 값을
`/etc/ovirt-engine/encryptor/config.json`의 `serialNum`과 비교한다. 헤더가 없거나 값이 다른 접속은
거부하고, **거부 사실을 엔진 이벤트(`audit_log`)에 기록**한다.

## 관리자 시리얼과 사용자 전용 시리얼

| 구분 | 접속 시 제시할 `X-Client-Serial` | 등록 위치 |
|---|---|---|
| 관리자(관리자 역할 보유) | `config.json`의 `serialNum` | `/etc/ovirt-engine/encryptor/config.json` |
| 내부 사용자(관리자 아님) | **사용자 전용 시리얼** | 사용자 추가·수정 화면 "단말기 시리얼" (`SetUserClientSerial`) |
| 외부(LDAP 등) 사용자 | 등록된 시리얼 중 하나 (로그인 단계 바인딩 없음) | — |

검사는 두 단계로 이루어진다.
1. **로그인 전 관문**(첫 화면, SSO 로그인 시작·토큰 발급, REST API Basic, 공개키): 누가 접속하는지 아직 모르므로
   `config.json`의 serialNum **또는 등록된 사용자 시리얼 중 하나**면 통과한다(`ClientSerialCheck.check`).
2. **로그인(세션 생성) 시 바인딩**(`CreateUserSessionCommand`): 사용자가 확정되면
   관리자는 `config.json`의 serialNum, 일반 내부 사용자는 **본인에게 등록된 시리얼**과 일치해야 한다.
   불일치·미등록·헤더 없음이면 거부하고 `USER_LOGIN_SERIAL_DENIED`(13692, 오류)를 기록한다.
   - 사유: `단말기 시리얼 없음`, `관리자 시리얼 불일치`, `관리자 시리얼 확인 불가`, `사용자 시리얼 불일치`, `사용자 시리얼 미등록`
   - 엔진 서버 자신(루프백·엔진 IP, 요청 없는 내부 로그인)은 제외

### 사용자 시리얼 저장
- **SHA-256 해시로만 저장**한다: Engine DB `user_profiles`의 `CLIENT_SERIAL_SHA256`(JSON 문자열). 원문 시리얼은 어디에도 저장·기록되지 않으며 화면에도 다시 표시되지 않는다.
- 로그인 전 관문용 목록: `/var/lib/ovirt-engine/client-serials` (해시 한 줄씩, 권한 0600, 원자적 교체).
  시리얼 등록·변경·해제 때와 **엔진 기동 때마다** DB에서 다시 만든다. 이 디렉터리는 AIDE 감시 대상이 아니다.
- 형식: 영문·숫자와 `. _ : -`, 128자 이내.
- 감사: `USER_CLIENT_SERIAL_UPDATED`(13693) / `USER_CLIENT_SERIAL_UPDATE_FAILED`(13694) — "등록/해제"만 기록, 시리얼 값은 기록하지 않음.
- 사용자 계정 삭제 시 시리얼도 해제된다.

### 사용자 추가·수정 화면
| 항목 | 추가 | 수정 |
|---|---|---|
| 단말기 시리얼 | 입력하면 등록 | 입력하면 교체, 비우면 유지 |
| 단말기 시리얼 등록 상태 | — | 등록됨 / 미등록 (읽기 전용) |
| 등록된 단말기 시리얼 해제 | — | 체크 시 해제(이후 그 사용자는 로그인 불가) |

### 확인
```bash
# 사용자 시리얼로 REST API 로그인 → 성공 / 관리자 시리얼로 같은 사용자 로그인 → 거부 + USER_LOGIN_SERIAL_DENIED
curl -k -u 'user01@internal:PASSWORD' -H 'X-Client-Serial: USER-0092' https://ENGINE_FQDN/ovirt-engine/api
curl -k -u 'user01@internal:PASSWORD' -H "X-Client-Serial: $(jq -r .serialNum /etc/ovirt-engine/encryptor/config.json)" https://ENGINE_FQDN/ovirt-engine/api
# 등록 목록(해시)
cat /var/lib/ovirt-engine/client-serials
```
```sql
SELECT u.username, p.property_name FROM user_profiles p JOIN users u ON u.user_id = p.user_id
 WHERE p.property_name = 'CLIENT_SERIAL_SHA256';
```

## 검사 지점

| 접속 경로 | 헤더 없음 | 값 불일치 | 감사 기록 |
|---|---|---|---|
| 포털 첫 화면 `/ovirt-engine/` | 403 Forbidden 페이지 | 403 Forbidden 페이지 | ✅ |
| SSO 로그인 시작 `/ovirt-engine/sso/oauth/authorize` (관리 포털·VM 포털·OpenID) | 403 Forbidden 페이지 | 403 Forbidden 페이지 | ✅ |
| SSO 토큰 발급 — 비밀번호 로그인, 비밀번호 변경 (`/sso/oauth/token`) | **거부 (신규)** | 거부 | ✅ |
| REST API Basic 인증 로그인 (`/ovirt-engine/api`) | **401 거부 (신규)** | 401 거부 | ✅ |
| SSO 공개키 다운로드 | 403 Forbidden 페이지 | 403 Forbidden 페이지 | ✅ |

브라우저에 보이는 거부 화면은 웹 서버(Apache)의 403 페이지와 **같은 형식**이다(아래 "사용자에게 보이는 화면").
REST API는 API 응답 형식(401)을 그대로 유지한다.

이전에는 SSO 로그인 경로가 헤더가 **있을 때만** 값을 확인했다. 헤더를 빼면 검사 자체를
건너뛰었으므로, 헤더 없는 접속을 거부하도록 바꿨다.

### 검사하지 않는 요청 (엔진 내부 통신)

다음 요청은 사용자의 단말기가 아니라 엔진이 자신의 SSO와 주고받는 것이어서 단말기 헤더가 없다.
검사하면 엔진 자신이 막히므로 대상에서 제외한다.

- 인증 코드 교환(`grant_type=authorization_code`) — 브라우저 로그인 후 엔진이 코드를 토큰으로 바꿀 때
- 대리 로그인(`scope`에 `ovirt-ext=token:login-on-behalf`) — 이미 인증한 사용자를 대신한 로그인
- 토큰 확인·폐기, 사용자 조회
- REST API Bearer 토큰 — 토큰은 SSO가 등록 단말기에만 발급하므로 다시 검사하지 않는다.
- **엔진 서버 자신에서 온 요청** — 출발지가 루프백(127.0.0.1, ::1)이거나 엔진 서버의 네트워크
  인터페이스에 붙은 주소(예: 엔진 IP 192.168.50.213)인 요청. 엔진 서버에서 동작하는 프로그램
  (엔진의 JBoss 관리 인증 플러그인, 외부 네트워크 제공자, API를 쓰는 도구)은 단말기가 아니어서
  일련번호가 없다. 이전에는 엔진 IP를 단말 IP 목록에 등록해도 이런 요청이 "등록되지 않은 단말기"로
  거부·기록되었다. 판단 기준과 동작은 다음과 같다.
  - 주소는 IP 문자열로만 판단하고 호스트 이름은 조회하지 않는다(`ClientSerialCheck.isThisHost`).
  - SSO는 접속 주소를 쓰되, 엔진이 대신 넘긴 REST API 로그인은 엔진이 클라이언트 비밀값과 함께
    알려준 **실제 클라이언트 주소**로 판단한다. 원격 단말기의 로그인이 엔진을 거쳤다는 이유로 면제되지 않는다.
  - 면제된 요청은 감사 이벤트를 남기지 않고, engine.log에
    `X-Client-Serial not required: request from the engine host itself; sourceIp=… path=…`로 남는다.
  - 엔진 JBoss 관리 인증 플러그인(`OvirtAuthPlugIn`)의 비밀번호 로그인은 엔진 자신의 클라이언트 비밀값과
    함께 출발지를 127.0.0.1로 알려, SSO 주소 설정과 관계없이 엔진 자신의 요청으로 처리된다.
  - 엔진 서버에 로그인할 수 있는 사람은 단말기 일련번호 없이 이 서버에서 API·SSO에 접속할 수 있다.
    엔진 서버 계정은 관리자만 가지도록 관리해야 한다.

REST API Basic 로그인은 엔진이 사용자의 요청 헤더를 그대로 SSO에 넘긴다. 이 경우 SSO에는 엔진의
주소가 보이므로, 실제 접속 주소를 아는 REST API 필터에서 먼저 검사·기록한다.

## 이벤트

| 항목 | 내용 |
|---|---|
| 유형 | `CLIENT_SERIAL_REJECTED` (13718, ERROR) |
| 메시지 | `Access from ${SourceIP} was refused: not a registered terminal. ${ClientSerialRefusal}` |
| `${SourceIP}` | 접속한 단말기 주소 |
| `${ClientSerialRefusal}` | 접속 경로와 사유 — `no X-Client-Serial header` / `... does not match` / `... could not be checked` |

예: `Access from 10.10.1.23 was refused: not a registered terminal. /ovirt-engine/sso/oauth/authorize presented no X-Client-Serial header`

- **제출된 시리얼 값은 어디에도 기록하지 않는다.** 정상 단말기가 실수로 틀린 값을 보낸 경우
  등록 시리얼과 거의 같은 값이 로그에 남을 수 있기 때문이다. 이전 첫 화면 코드가 engine.log에
  제출 값을 그대로 남기던 부분도 제거했다.
- 등록 시리얼(`config.json`)을 읽을 수 없으면 아무 접속도 허용하지 않는다(`could not be checked`).
- 비교는 상수 시간 비교(`MessageDigest.isEqual`)로 한다.

### 이벤트 폭주 방지

거부는 로그인 전에 일어나므로 누구나 반복해서 일으킬 수 있다. 그대로 기록하면 이벤트 테이블이
차서 다른 감사 기록을 밀어낸다(`docs/audit-log-storage-capacity.md`). 그래서 두 단계로 제한한다.

1. 기록 측: **같은 주소·경로·사유는 1분에 1건만** 엔진으로 보낸다(주소 최대 10,000개 기억).
2. 엔진 측: `CLIENT_SERIAL_REJECTED`는 1분 중복 억제 유형이며, 억제 키에 주소와 사유를 넣어 다른
   주소의 거부는 즉시 기록된다.

engine.log에는 매 거부마다 `CLIENT_SERIAL_REJECTED sourceIp=... <경로> presented ...` 한 줄이 남는다.

## 적용 시 확인 사항

- **REST API·SDK 연동 프로그램**도 매 로그인 요청에 `X-Client-Serial` 헤더를 보내야 한다. 헤더가
  없으면 Basic 로그인과 SSO 토큰 발급이 거부된다.
- 단말기 브라우저는 첫 화면뿐 아니라 `/ovirt-engine/sso/` 요청에도 헤더를 보내야 한다.
- 첫 화면과 REST API의 기록은 엔진이 `ENGINE_SSO_SERVICE_URL` 옆의 `/ovirt-engine/services/sso-callback`
  으로 보내며, SSO가 로그인 실패를 기록할 때와 같은 경로·인증(엔진 클라이언트 비밀)을 쓴다.

## 사용자에게 보이는 화면

브라우저로 접속한 사용자가 보는 거부·오류 화면은 모두 웹 서버의 Forbidden 페이지와 같다.

```
Forbidden
You don't have permission to access this resource.
```

| 이전 화면 | 원인 | 현재 |
|---|---|---|
| `Invalid client serial.` (첫 화면) | 미등록 단말기, 401 + 애플리케이션 서버 기본 오류 페이지 | 403 Forbidden 페이지 |
| `Internal Server Error` (`/sso/oauth/authorize`) | 미등록 단말기 401이 SSO의 401 오류 페이지(로그인 다음 단계)로 넘어가 실패 | 403 Forbidden 페이지 |
| 애플리케이션 서버 기본 오류 페이지 | 처리 중 예외(500 등) | Forbidden 페이지 (상태 코드 유지) |

- 구현: `uutils/servlet/ForbiddenPage` — Apache httpd 2.4의 403 페이지와 바이트 단위로 같은 본문
  (`text/html; charset=iso-8859-1`). 무엇을 검사했는지, 뒤에 애플리케이션 서버가 있다는 사실이 화면에 드러나지 않는다.
- 단말기 거부는 **403**으로 응답한다. 401은 SSO에서 로그인 다음 단계로 이어지는 오류 페이지에 연결되어 있어
  거부 요청이 500으로 끝났던 것이 원인이다.
- 그 밖의 오류는 각 웹앱의 오류 페이지로 Forbidden 페이지를 지정했다. 이때 **상태 코드는 원래 값을 유지**하고
  본문만 바꾼다(클라이언트가 상태 코드로 판단하는 동작을 깨지 않기 위해).

| 웹앱 | Forbidden 페이지로 바꾸는 오류 | 그대로 두는 것 |
|---|---|---|
| 첫 화면 `/ovirt-engine/` | 400, 401, 403, 500, 501, 502, 503, 모든 예외 | 404·405 안내 페이지 |
| 관리 포털 `/ovirt-engine/webadmin` | 400, 401, 403, 500, 501, 502, 503, 모든 예외 | 404·405 안내 페이지 |
| 문서 `/ovirt-engine/docs` | 400, 401, 403, 500, 501, 502, 503, 모든 예외 | 404·405 안내 페이지 |
| SSO `/ovirt-engine/sso` | 403, 404, 405, 500, 501, 502, 503, 모든 예외 | 400(OAuth 오류 안내), 401(로그인 다음 단계) |

- REST API(`/ovirt-engine/api`)와 서비스(`/ovirt-engine/services`)는 프로그램이 읽는 응답 형식이 있어 대상에서 제외했다.
- 엔진이 내려가 있을 때 Apache가 직접 내는 502/503 페이지는 웹 서버 설정 영역이라 이 변경에 포함되지 않는다.

## 점검 항목

```bash
# 헤더 없이 접속 → 403(Forbidden 페이지), 이벤트 탭에 CLIENT_SERIAL_REJECTED
curl -k -o /dev/null -w '%{http_code}\n' https://ENGINE_FQDN/ovirt-engine/
curl -k -o /dev/null -w '%{http_code}\n' \
  'https://ENGINE_FQDN/ovirt-engine/sso/oauth/authorize?response_type=code&client_id=ovirt-engine-core'

# 틀린 값 → 403(Forbidden 페이지), 사유가 "does not match"
curl -k -s -H 'X-Client-Serial: WRONG' https://ENGINE_FQDN/ovirt-engine/ | grep -c 'You don.t have permission'   # 1
curl -k -o /dev/null -w '%{http_code}\n' -H 'X-Client-Serial: WRONG' https://ENGINE_FQDN/ovirt-engine/

# 1분 안에 반복해도 이벤트는 주소·경로·사유별 1건
for i in $(seq 20); do curl -k -s -o /dev/null https://ENGINE_FQDN/ovirt-engine/; done
```

- 등록 단말기에서 관리 포털 로그인, REST API 로그인이 정상인지 확인
- 이벤트와 engine.log 어디에도 제출된 시리얼 값이 없는지 확인
