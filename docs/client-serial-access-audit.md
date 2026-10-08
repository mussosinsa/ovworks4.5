# 접속 단말기(X-Client-Serial) 미등록 접속 감사 기록

등록된 단말기만 엔진에 접속할 수 있도록 요청 헤더 `X-Client-Serial` 값을
`/etc/ovirt-engine/encryptor/config.json`의 `serialNum`과 비교한다. 헤더가 없거나 값이 다른 접속은
거부하고, **거부 사실을 엔진 이벤트(`audit_log`)에 기록**한다.

## 검사 지점

| 접속 경로 | 헤더 없음 | 값 불일치 | 감사 기록 |
|---|---|---|---|
| 포털 첫 화면 `/ovirt-engine/` | 401 거부 | 401 거부 | ✅ |
| SSO 로그인 시작 `/ovirt-engine/sso/oauth/authorize` (관리 포털·VM 포털·OpenID) | **401 거부 (신규)** | 401 거부 | ✅ |
| SSO 토큰 발급 — 비밀번호 로그인, 비밀번호 변경 (`/sso/oauth/token`) | **거부 (신규)** | 거부 | ✅ |
| REST API Basic 인증 로그인 (`/ovirt-engine/api`) | **401 거부 (신규)** | 401 거부 | ✅ |
| SSO 공개키 다운로드 | 401 거부 | 401 거부 | ✅ |

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

## 점검 항목

```bash
# 헤더 없이 접속 → 401, 이벤트 탭에 CLIENT_SERIAL_REJECTED
curl -k -o /dev/null -w '%{http_code}\n' https://ENGINE_FQDN/ovirt-engine/
curl -k -o /dev/null -w '%{http_code}\n' \
  'https://ENGINE_FQDN/ovirt-engine/sso/oauth/authorize?response_type=code&client_id=ovirt-engine-core'

# 틀린 값 → 401, 사유가 "does not match"
curl -k -o /dev/null -w '%{http_code}\n' -H 'X-Client-Serial: WRONG' https://ENGINE_FQDN/ovirt-engine/

# 1분 안에 반복해도 이벤트는 주소·경로·사유별 1건
for i in $(seq 20); do curl -k -s -o /dev/null https://ENGINE_FQDN/ovirt-engine/; done
```

- 등록 단말기에서 관리 포털 로그인, REST API 로그인이 정상인지 확인
- 이벤트와 engine.log 어디에도 제출된 시리얼 값이 없는지 확인
