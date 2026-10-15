# 사용자 접속 IP·단말기 시리얼 운영 구현 명세서

## 1. 문서 정보

| 항목 | 내용 |
|---|---|
| 문서명 | 사용자 접속 IP·단말기 시리얼 운영 구현 명세서 |
| 제품 | OV-Works Engine (oVirt Engine 4.5 기반) |
| 대상 기능 | 단말기 IP 인증, 사용자 전용 접속 IP, 관리자 시리얼, 사용자 전용 단말기 시리얼(DEK 암호화), 전용 IP 웹 포털 차단 |
| 관련 문서 | `user-dedicated-login-ip.md`, `client-serial-access-audit.md`, `key-encryption-and-destruction-verification-form.md`, `terminal-authentication-management.md` |

---

## 2. 개요

엔진 접속은 **어디서(IP)** 와 **어떤 단말기로(시리얼)** 두 가지로 통제한다. 두 통제는 각각 "관리자 공통"과 "사용자별"로 나뉜다.

| 구분 | IP | 단말기 시리얼 (`X-Client-Serial` 헤더) |
|---|---|---|
| 관리자 공통 | 단말기 IP 인증 목록 (`Require ip`) | `config.json`의 `serialNum` |
| 사용자별 | 사용자 전용 접속 IP (1인 1주소) | 사용자 전용 시리얼 (1인 1시리얼, DEK 암호화 저장) |

### 2.1 용어

| 용어 | 뜻 |
|---|---|
| 단말기 IP 인증 목록 | `/etc/httpd/conf.d/z-ovirt-engine-proxy.conf`의 모든 `<RequireAny>` 블록 안 `Require ip` 목록. 목록에 없는 주소는 웹 서버가 403으로 차단 |
| 관리자 | 관리자 역할(Admin role)을 가진 사용자 |
| 내부 사용자 | `internal-authz`(로컬 계정) 사용자. 외부(LDAP 등) 사용자는 사용자별 IP·시리얼 대상이 아님 |
| 엔진 서버 자신 | 루프백(127.0.0.1, ::1) 또는 엔진 서버 인터페이스 주소에서 온 요청. 시리얼 검사를 하지 않음 |
| DEK / KEK | 데이터 암호화 키 / 키 암호화 키. DEK는 KEK로 감싼 상태(`/etc/ovirt-engine/encryptor/dek.enc`)로만 저장 |

---

## 3. 전체 구조

```
 단말기(브라우저·클라이언트 프로그램)  ── X-Client-Serial 헤더
        │
        ▼
 ① Apache httpd ── Require ip (단말기 IP 인증 목록) ─ 목록 밖 → 403 Forbidden
        │                         (127.0.0.1 + 단말기 IP + 사용자 전용 IP)
        ▼
 ② 웹 포털 필터 (DedicatedIpWebPortalFilter)
        │  첫 화면·관리 포털·SSO 로그인 화면: 일반 사용자 전용 IP → Forbidden
        ▼
 ③ 로그인 전 시리얼 관문 (ClientSerialCheck.check)
        │  관리자 serialNum 또는 등록된 사용자 시리얼 중 하나 → 통과, 아니면 Forbidden + CLIENT_SERIAL_REJECTED
        ▼
 ④ SSO 인증 (ID/PW)
        ▼
 ⑤ 엔진 세션 생성 (CreateUserSessionCommand)
        │  관리자 필요 → LOGIN 권한 → 동시 세션 수 → 전용 IP 일치 → 시리얼 바인딩 → 수퍼유저 단일 접속
        ▼
 로그인 성공 (USER_VDC_LOGIN)
```

- ①은 인증 **전**, 전역(모든 사용자 공통) 통제다.
- ②·③은 인증 전, 엔진 웹앱에서 하는 통제다.
- ⑤는 인증 **후**, 사용자별 1:1 통제다.

---

## 4. 관리자 접속 관리 화면

경로: 관리 → 보안 설정 → **관리자 접속 관리** (이전 명칭: 클라이언트 관리)

| 영역 | 기능 | 명령 / 저장 위치 |
|---|---|---|
| 단말기 인증 | 관리자 시리얼 적용 | `SetTerminalAuthCommand` → `config.json`의 `serialNum` |
| 단말기 IP 인증 | 단말기 IPv4 주소 추가·수정·삭제 | `SetTerminalIpAuthCommand` → `z-ovirt-engine-proxy.conf`의 `Require ip` |

### 4.1 단말기 IP 인증 규칙
- 항목마다 **단일 IPv4 주소** 하나만 받는다. 대역(CIDR), IPv6, 호스트명, `0.0.0.0`, 브로드캐스트·멀티캐스트 주소는 거부한다.
- `127.0.0.1`은 항상 유지한다. 빈 목록은 저장하지 않는다.
- **engine-setup 실행 시 `127.0.0.1`과 설치 서버 IP를 무조건 목록 맨 앞에 넣는다**(`ovirt_engine_setup/client_addresses.py`, Apache 플러그인 `_misc`).
  - 설치 서버 IP: FQDN이 가리키는 IPv4 중 이 서버가 가진 주소 + 기본 경로(default route)의 출발지 주소. 루프백·미지정 주소는 제외한다.
  - 응답 파일이나 질문에서 이 주소를 빼도 다시 들어간다. 서버 IP를 찾지 못하면 경고를 남기고 `127.0.0.1`만 필수로 유지한다.
- 파일의 모든 `<RequireAny>` 블록을 같은 목록으로 다시 쓴다. 목록이 바뀌었을 때만 `sudo -n /usr/sbin/httpd -k graceful`로 웹 서버를 재시작 없이 다시 읽힌다.
- **일반 사용자(관리자가 아닌 사용자)의 전용 IP는 이 화면 목록에 표시하지 않는다.** 관리자의 전용 IP는 표시한다.
  - 판정: 그 IP를 전용 IP로 쓰는 사용자 중 관리자(직접 부여된 관리자 역할)가 한 명도 없으면 숨김. 일반 사용자와 관리자가 같은 IP를 쓰면 표시.
  - 조회할 때마다 판정하므로, 사용자를 관리자로 바꾸면 다음 조회부터 그 사용자의 전용 IP가 목록에 나타나고, 관리자 역할을 빼면 다시 숨겨진다.
  - 조회(`GetTerminalIpAuthQuery`): 설정 파일의 목록에서 숨김 대상 IP를 빼고 보여 준다.
  - 저장(`SetTerminalIpAuthCommand`): 화면이 보낸 목록에, 설정 파일에 있던 숨김 대상 IP를 다시 합쳐 쓴다(`TerminalIpConfigUtils.updateVisibleRequireIp`). 화면에서 추가·수정·삭제해도 숨겨진 전용 IP는 지워지지 않는다. 표시되는 관리자 전용 IP는 다른 단말기 IP처럼 화면에서 수정·삭제할 수 있다.
  - 등록·수정·삭제 이벤트는 화면에 보인 목록을 기준으로 기록한다.

---

## 5. 사용자 전용 접속 IP

### 5.1 등록 (사용자 추가·수정 화면 "전용 접속 IP")

| 항목 | 명세 |
|---|---|
| 형식 | 단일 IPv4 (단말기 IP 인증과 같은 규칙) |
| 명령 | `SetUserDedicatedIpCommand` (`SetUserDedicatedIpParameters(userId, ip)`). 빈 값이면 해제 |
| 저장 | Engine DB `user_profiles`, `property_name = 'DEDICATED_LOGIN_IP'`, `property_content` = JSON 문자열(예: `"192.168.40.92"`) |
| 처리 순서 | ① 웹 서버 목록 반영 → ② DB 저장 → ③ graceful 재적용. ①이 실패하면 DB를 바꾸지 않고 실패로 끝낸다 |
| 감사 | `USER_DEDICATED_IP_UPDATED`(13685) / `USER_DEDICATED_IP_UPDATE_FAILED`(13686) |

### 5.2 단말기 IP 인증 목록 반영

| 동작 | 목록 변화 |
|---|---|
| 등록 | 새 IP 추가 (이미 있으면 그대로) |
| 수정 (A → B) | B 추가. A는 다른 사용자가 같은 IP를 쓰지 않을 때만 제거 |
| 삭제 | 다른 사용자가 같은 IP를 쓰지 않을 때만 제거 |
| 사용자 계정 삭제 | `RemoveUserCommand`가 전용 IP를 먼저 해제한 뒤 계정 삭제 |

- 목록 변경은 `TerminalIpConfigUtils.addAddress/removeAddress`가 한 번의 잠금 안에서 읽기·수정·쓰기로 처리한다. 단말기 IP 인증 화면과 동시에 바꿔도 서로 덮어쓰지 않는다.
- graceful 재적용은 sudo 규칙 `/etc/sudoers.d/ovirt-httpd`(engine-setup이 생성, 0440)에 따라 `ovirt` 계정이 `/usr/sbin/httpd -k graceful` 한 가지만 실행할 수 있다.

### 5.3 로그인 집행 (`CreateUserSessionCommand`)

| 상황 | 결과 | 이벤트 |
|---|---|---|
| 전용 IP = 실제 접속 IP | 통과 | — |
| 불일치 | 거부 | `USER_LOGIN_IP_DENIED`(13687, 오류, 시도마다 기록) — 사유 "전용 접속 IP 불일치", 실제·전용 IP 표시 |
| 비관리자 내부 사용자, 미등록 | 거부 | 같은 이벤트 — 사유 "전용 접속 IP 미등록" |
| 수퍼유저, 미등록 | 허용 (관리자 잠금 방지) | `USER_LOGIN_WITHOUT_DEDICATED_IP_ALLOWED`(13688, 경고) |
| 외부(LDAP) 사용자 | 검사 제외 | — |

### 5.4 전용 IP의 웹 포털 차단
- 전용 IP는 클라이언트 프로그램(REST API) 로그인용이다. 그래서 일반 사용자 전용 IP에서 웹 포털에 접속하면 차단한다.
- 필터 `DedicatedIpWebPortalFilter`: 첫 화면(`/ovirt-engine/*`), 관리 포털(`/webadmin/*`), SSO 로그인 화면(`login.html`, `oauth/authorize`, `openid/authorize`, `interactive-*` 등)의 필터 중 **가장 먼저** 실행한다.
- 판정 쿼리 `IsWebPortalDeniedForAddress`(공개 쿼리): 접속 IP를 전용 IP로 쓰는 사용자가 있고 **그중 관리자가 한 명도 없으면** 차단한다.
  - 관리자 판정은 사용자에게 직접 부여된 관리자 역할 기준이다. 그룹을 통해서만 받은 관리자 역할은 보지 않는다.
- 판정 결과는 주소별로 30초 보관한다. 엔진 서버 자신은 차단하지 않는다. 엔진에 판정을 묻지 못하면 통과시킨다(로그인 시 검사는 그대로 적용).
- 감사: `WEB_PORTAL_DENIED_FOR_DEDICATED_IP`(13691, 경고, 주소별 1분에 1건). engine.log에는 요청마다 기록한다.
- REST API(`/ovirt-engine/api`)와 토큰 발급(`/sso/oauth/token`)은 차단 대상이 아니다.

---

## 6. 단말기 시리얼

### 6.1 관리자 시리얼
- `config.json`의 `serialNum`을 쓴다. 관리자 접속 관리 화면의 "단말기 인증"에서 적용한다.
- 관리자 역할을 가진 사용자는 로그인할 때 이 값을 제시해야 한다.

### 6.2 사용자 전용 시리얼 — 규칙

| 항목 | 명세 |
|---|---|
| 생성 규칙 | `ovworks` + 일련번호(숫자) — 정규식 `^ovworks[0-9]{5,9}$` |
| 길이 | 최소 12자, 최대 16자 (예: `ovworks00001` ~ `ovworks123456789`) |
| 유일성 | 다른 사용자에게 이미 등록된 시리얼은 등록할 수 없음 |
| 검사 위치 | 화면(`LocalUserAddModel`, 입력 최대 16자)과 엔진(`ClientSerialCheck.isAcceptableSerial`) 모두 |
| 명령 | `SetUserClientSerialCommand` (`SetUserClientSerialParameters(userId, serial)`). 빈 값이면 해제 |
| 화면 | 사용자 추가: "단말기 시리얼" 입력 / 수정: "등록 상태"(등록됨·미등록) 표시, 새 값을 입력하면 교체, 비우면 유지, "등록된 단말기 시리얼 해제" 체크 시 해제 |
| 감사 | `USER_CLIENT_SERIAL_UPDATED`(13693) / `USER_CLIENT_SERIAL_UPDATE_FAILED`(13694, 실패 사유 포함). 시리얼 값은 기록하지 않음 |

### 6.3 사용자 시리얼 저장 — DEK 암호화

| 항목 | 명세 |
|---|---|
| 알고리즘 | AES-256-GCM, 설치 DEK 사용 (설정 파일·로그인 개인키와 같은 키) |
| 형식 | `OVENC002` 봉투: `"OVENC002"(8) ‖ 버전 1(1) ‖ DEK id(8) ‖ nonce(12) ‖ 암호문 ‖ 태그(16)`. 헤더 전체를 AAD로 사용 |
| DEK id | `HMAC-SHA256(DEK, "ovirt-engine dek id")` 앞 8바이트 |
| 난수 | nonce는 승인 난수발생기(`ApprovedRandom`, Hash_DRBG SHA-256)로 생성 |
| DB | `user_profiles`, `property_name = 'CLIENT_SERIAL_ENC'`, `property_content` = 봉투의 base64(JSON 문자열) |
| 관문 목록 | `/var/lib/ovirt-engine/client-serials` — 같은 봉투(암호문) 한 줄에 하나, 권한 0600, 원자적 교체. 시리얼 등록·변경·해제 때와 엔진 기동 때마다 DB에서 다시 만듦. AIDE 감시 대상 아님 |
| 구현 | Java `DekEnvelope`(uutils)는 Python `encryptor.encrypt_envelope/decrypt_envelope`와 같은 형식이라 서로 열 수 있음 |
| 이전 형식 | 이전 버전의 SHA-256 해시(`CLIENT_SERIAL_SHA256`)는 시리얼로 되돌릴 수 없어 이전하지 않음. 다시 등록하면 이전 행은 삭제됨 |

### 6.4 런타임 DEK 전달과 파기

엔진(Java)은 KEK로 감싼 DEK를 직접 풀 수 없다. 그래서 로그인 개인키와 같은 방식으로 엔진 런처가 DEK를 넘긴다.

| 단계 | 위치 | 내용 |
|---|---|---|
| 기동 | `ovirt-engine.py` `_writeRuntimeDek()` → `runtime_dek.py --write` (ovirt 계정) | KEK 에이전트의 패스프레이즈로 DEK를 열어 `<ENGINE_TMP>/dek/dek`(0600, 0700 디렉터리)에 32바이트로 기록. 도구 안의 DEK·패스프레이즈 사본은 즉시 지움. `DEK_DECRYPTION_COMPLETED`(출처 `engine-runtime-dek`) 기록 |
| 전달 | JVM 옵션 `-Dovirt.engine.dek.path=<경로>` | `DekEnvelope`가 처음 쓸 때 한 번 읽어 메모리에 보관 |
| DEK 미구성 | `runtime_dek.py` 종료 코드 3 | 경고를 남기고 DEK 없이 기동. 사용자 시리얼 등록·검사 불가 |
| DEK 열기 실패 | 종료 코드 1 | 엔진 기동 중단 (로그인 개인키와 같음) |
| 정지 | `daemonCleanup()` → `_destroyKeyFile()` | 런타임 DEK 파일을 **0으로 3회 덮어쓰기(fsync) 후 삭제**하고, 그다음 런타임 디렉터리를 삭제 |

### 6.5 시리얼 검사

**① 로그인 전 관문** (`ClientSerialCheck.check`)
- 검사 위치: 첫 화면, SSO 로그인 시작(`oauth/authorize`, `openid/authorize`), SSO 토큰 발급(비밀번호 로그인·비밀번호 변경), REST API Basic 인증, SSO 공개키.
- 통과 조건: 관리자 serialNum과 같거나, 등록된 사용자 시리얼(관문 목록을 DEK로 복호화한 값) 중 하나와 같음. 비교는 상수 시간으로 한다.
- 거부: 웹 서버와 같은 형식의 **403 Forbidden 페이지**를 보내고 `CLIENT_SERIAL_REJECTED`(13718, 주소·경로·사유별 1분에 1건)를 기록한다.
- 관문 목록은 파일이 바뀔 때만 다시 복호화한다. DEK가 없으면 사용자 시리얼은 통과시키지 않고 관리자 시리얼만 통과한다.

**② 로그인 시 바인딩** (`CreateUserSessionCommand`)
- 로그인 요청의 `X-Client-Serial` 헤더를 세션 생성 파라미터로 넘겨 검사한다. 넘기는 곳은 `SsoUtils.createUserSession`(REST API)과 `SsoPostLoginServlet`(관리 포털)이다.

| 사용자 | 요구 시리얼 | 거부 사유 |
|---|---|---|
| 관리자 | `config.json` serialNum | 관리자 시리얼 불일치 / 관리자 시리얼 확인 불가 |
| 내부 일반 사용자 | 본인 시리얼 (DB의 봉투를 DEK로 복호화) | 사용자 시리얼 불일치 / 사용자 시리얼 미등록 / 사용자 시리얼 확인 불가(DEK) |
| 공통 | — | 단말기 시리얼 없음 |
| 외부(LDAP) 사용자, 엔진 서버 자신 | 검사 제외 | — |

- 거부되면 `USER_LOGIN_SERIAL_DENIED`(13692, 오류)를 사유와 함께 기록한다.

---

## 7. 로그인 판정 순서

`CreateUserSessionCommand.executeCommand()` 기준이다. 앞 단계에서 거부되면 뒤 단계는 실행하지 않는다.

| 순서 | 검사 | 거부 시 오류 | 이벤트 |
|---|---|---|---|
| 1 | 관리자 필요(관리 포털) & 관리자 아님 | `USER_NOT_AUTHORIZED` | `USER_VDC_LOGIN_FAILED`(114) |
| 2 | LOGIN 권한(1300) 보유 역할 없음 | `USER_NOT_AUTHORIZED` | `USER_VDC_LOGIN_FAILED`(114) |
| 3 | 동시 세션 수 초과 | `NUM_OF_SESSIONS_EXCEEDED` | `USER_MAX_SESSIONS_EXCEEDED` |
| 4 | 전용 접속 IP | `LOGIN_IP_NOT_ALLOWED` | `USER_LOGIN_IP_DENIED`(13687) |
| 5 | 단말기 시리얼 바인딩 | `CLIENT_SERIAL_NOT_ALLOWED` | `USER_LOGIN_SERIAL_DENIED`(13692) |
| 6 | 수퍼유저 단일 접속 | `SUPER_USER_SESSION_ACTIVE` | `SUPER_USER_SESSION_ALREADY_ACTIVE` |
| — | 통과 | — | `USER_VDC_LOGIN` (+ 미등록 수퍼유저면 13688) |

> 로컬 사용자를 만들 때 자동 부여되는 기본 역할(`ENGINE_LOCAL_USER_DEFAULT_ROLES`)의 기본값은 `ExternalEventsCreator`이고, 이 역할에는 LOGIN 권한이 없다. REST API 로그인이 필요한 사용자에게는 LOGIN 권한이 있는 사용자 역할(예: `UserRole`)을 VM·풀 단위로 부여해야 한다.

---

## 8. 감사 이벤트

| 코드 | 이벤트 | 심각도 | 발생 |
|---|---|---|---|
| 13622/13623 | `TERMINAL_IP_AUTH_CONFIG_UPDATED` / `_FAILED` | 정상/오류 | 단말기 IP 목록 저장(구분 불가 시) |
| 13677~13682 | `TERMINAL_IP_AUTH_ADDED/CHANGED/REMOVED` (+`_FAILED`) | 정상/오류 | 단말기 IP 등록·수정·삭제 |
| 13685/13686 | `USER_DEDICATED_IP_UPDATED` / `_FAILED` | 정상/오류 | 사용자 전용 IP 설정 |
| 13687 | `USER_LOGIN_IP_DENIED` | 오류 | 전용 IP 불일치·미등록 로그인 거부 (시도마다) |
| 13688 | `USER_LOGIN_WITHOUT_DEDICATED_IP_ALLOWED` | 경고 | 전용 IP 미등록 수퍼유저 로그인 허용 |
| 13691 | `WEB_PORTAL_DENIED_FOR_DEDICATED_IP` | 경고 | 전용 IP에서 웹 포털 접속 차단 (주소별 1분 1건) |
| 13692 | `USER_LOGIN_SERIAL_DENIED` | 오류 | 로그인 시 시리얼 바인딩 거부 |
| 13693/13694 | `USER_CLIENT_SERIAL_UPDATED` / `_FAILED` | 정상/오류 | 사용자 시리얼 등록·해제 (실패 사유 포함) |
| 13718 | `CLIENT_SERIAL_REJECTED` | 오류 | 로그인 전 관문 시리얼 거부 (1분 1건) |
| 13729/13730 | `DEK_DECRYPTION_COMPLETED` / `_FAILED` | 정상/오류 | 런타임 DEK 전달 등 DEK 열람 |

시리얼 원문, DEK, 해시 값은 어떤 이벤트·로그에도 기록하지 않는다.

---

## 9. 저장 데이터·파일

| 대상 | 위치 | 보호 |
|---|---|---|
| 단말기 IP 목록 | `/etc/httpd/conf.d/z-ovirt-engine-proxy.conf` (`Require ip`) | 엔진 계정 rw ACL, AIDE는 권한만 측정 |
| graceful sudo 규칙 | `/etc/sudoers.d/ovirt-httpd` | 0440, AIDE 내용 측정 |
| 관리자 시리얼 | `/etc/ovirt-engine/encryptor/config.json` `serialNum` | 파일 권한 |
| 사용자 전용 IP | DB `user_profiles` `DEDICATED_LOGIN_IP` | DB 접근 통제 |
| 사용자 시리얼 | DB `user_profiles` `CLIENT_SERIAL_ENC` | **DEK 암호문** |
| 관문 목록 | `/var/lib/ovirt-engine/client-serials` | DEK 암호문, 0600 |
| DEK (보관) | `/etc/ovirt-engine/encryptor/dek.enc` | KEK로 감싼 상태 |
| DEK (런타임) | `<ENGINE_TMP>/dek/dek` | 0600, 엔진 구동 중에만 존재, 정지 시 0으로 3회 덮어쓰기 후 삭제 |

---

## 10. 거부·오류 화면

- 브라우저에 보이는 거부·오류 화면은 **웹 서버(Apache)의 403 Forbidden 페이지와 같은 형식**(`ForbiddenPage`)으로 통일했다.
  - 단말기 거부는 403으로 응답한다. 그 밖의 오류(첫 화면·관리 포털·문서·SSO의 4xx/5xx·예외)는 원래 상태 코드를 유지하고 본문만 Forbidden 페이지로 바꾼다.
- 화면에는 무엇을 검사했는지, 애플리케이션 서버 정보가 드러나지 않는다.
- REST API는 프로그램이 읽는 응답 형식(401 등)을 유지한다.

---

## 11. 배포·운영 절차

### 11.1 함께 배포해야 하는 산출물
uutils·aaa·common 등은 `engine.ear`과 **따로** 설치되는 JBoss 공용 모듈이다. 일부만 바꾸면 클래스 누락(`NoClassDefFoundError`)으로 엔진 기동이 실패한다.

| 구분 | 파일 |
|---|---|
| JBoss 모듈 | `/usr/share/ovirt-engine/modules/common/org/ovirt/engine/core/{uutils,aaa,common,dal,utils}/main/*.jar` |
| EAR | `engine.ear` (bll.jar, enginesso.war, welcome.war, webadmin.war 등) |
| 암호화 도구 | `/usr/share/ovirt-engine/encryptor/runtime_dek.py` (644) |
| 엔진 런처 | `/usr/share/ovirt-engine/services/ovirt-engine/ovirt-engine.py` (755, 첫 줄 `#!/usr/bin/python3`) |
| DB 프로시저 | `user_profiles_sp.sql`의 `GetUserProfilePropertiesByName` (engine-setup이 반영) |

**RPM 일괄 설치를 원칙으로 한다.** 파일을 직접 교체할 때는 소유자 root:root, 권한, `restorecon -v`(SELinux 레이블)를 반드시 맞춘다.

### 11.2 설치 후
1. `engine-setup`을 실행한다. sudo 규칙, DB 프로시저, AIDE 기준값 재생성·봉인이 이 단계에서 반영된다.
2. 엔진을 기동하고 런타임 DEK가 전달됐는지 확인한다: `ps -eo args | grep -o 'ovirt.engine.dek.path=[^ ]*'`
3. 사용자별로 전용 IP와 시리얼을 등록한다. 이전 SHA-256 형식으로 등록한 사용자는 시리얼을 다시 등록한다.
4. REST API 로그인이 필요한 사용자에게 LOGIN 권한이 있는 역할을 부여한다.

### 11.3 일상 운영

| 작업 | 방법 | 확인 |
|---|---|---|
| 사용자 전용 IP 등록·변경 | 사용자 수정 → 전용 접속 IP | `grep "Require ip" z-ovirt-engine-proxy.conf`, 이벤트 13685 |
| 사용자 시리얼 발급 | 사용자 수정 → 단말기 시리얼 (`ovworks` + 일련번호) | 등록 상태 "등록됨", 이벤트 13693 |
| 시리얼 분실·교체 | 새 시리얼 입력(교체) 또는 "해제" 체크 | 이벤트 13693 |
| 관리자 시리얼 변경 | 관리자 접속 관리 → 단말기 인증 | `config.json` |
| 퇴사자 처리 | 사용자 삭제 → 전용 IP·시리얼 자동 해제 | 단말기 IP 목록에서 제거(다른 사용자가 같은 IP를 쓰지 않으면) |

---

## 12. 장애 대응

| 증상 | 원인 | 조치 |
|---|---|---|
| 엔진 기동 실패 `NoClassDefFoundError: ...uutils.crypto.DekEnvelope` | 모듈 jar(uutils)가 예전 버전 (bll만 교체) | 11.1의 산출물 일괄 배포, `unzip -l uutils.jar \| grep DekEnvelope`로 확인 |
| `ovirt-engine.service: Failed at step EXEC ... Permission denied` | 런처 실행 권한·SELinux 레이블 불일치 | `chmod 755`, `chown root:root`, `restorecon -v`, 첫 줄의 `@PY_VERSION@` 치환 확인 |
| 시리얼 등록 실패 "The engine was not handed a DEK for this run" | 런처가 DEK를 전달하지 않음 (예전 런처, `runtime_dek.py` 누락, DEK 미구성) | 런처·도구 배포 확인, `sudo -u ovirt python3 runtime_dek.py --write /dev/shm/x; echo $?` (0 정상 / 3 DEK 미구성), 확인 후 `shred -u` |
| `USER_VDC_LOGIN_FAILED ... not authorized to perform login` | LOGIN 권한이 있는 역할 없음 (기본 역할 ExternalEventsCreator) | 사용자 역할 부여 (7절 참고) |
| `USER_LOGIN_IP_DENIED` | 전용 IP 불일치·미등록 | 사용자 전용 IP 확인·수정 |
| `USER_LOGIN_SERIAL_DENIED` | 시리얼 불일치·미등록·DEK 불가 | 사유에 따라 시리얼 재발급 또는 DEK 전달 확인 |
| 브라우저에 Forbidden | 단말기 IP 목록 밖, 시리얼 거부, 또는 일반 사용자 전용 IP의 웹 포털 접속 | httpd `ssl_access_log`(403), 이벤트 13718 / 13691 확인 |
| 무결성 검증 실패로 엔진 정지 | 파일 교체 후 AIDE 기준값 미갱신 | `engine-setup` 재실행 또는 기준값 재생성·봉인 |

---

## 13. 시험·증빙

```bash
# 단말기 IP 목록 (사용자 전용 IP 포함), 화면에는 전용 IP 미표시
grep -n "Require ip" /etc/httpd/conf.d/z-ovirt-engine-proxy.conf

# 사용자 전용 IP·시리얼 저장값 (시리얼은 암호문만)
sudo -u postgres psql engine -c "SELECT u.username, p.property_name, p.property_content
  FROM user_profiles p JOIN users u ON u.user_id = p.user_id
  WHERE p.property_name IN ('DEDICATED_LOGIN_IP','CLIENT_SERIAL_ENC');"
sudo cat /var/lib/ovirt-engine/client-serials          # "T1ZFTkMwMDI"(OVENC002)로 시작

# 런타임 DEK — 구동 중에만 존재, 정지 후 소거
sudo find /var/lib/ovirt-engine -path '*/dek/dek' -ls

# 로그인 시나리오 (REST API)
curl -k -u 'user01@internal:PW' -H 'X-Client-Serial: ovworks00092' https://ENGINE/ovirt-engine/api        # 성공
curl -k -u 'user01@internal:PW' -H 'X-Client-Serial: <관리자 serialNum>' https://ENGINE/ovirt-engine/api   # 거부 + 13692
curl -k -s -o /dev/null -w '%{http_code}\n' https://ENGINE/ovirt-engine/                                   # 헤더 없음 → 403
```

| 시나리오 | 기대 결과 |
|---|---|
| 전용 IP 등록 | `Require ip`에 추가, 재시작 없이 적용, 단말기 IP 화면에는 미표시 |
| 다른 IP에서 같은 사용자 로그인 | 거부 + 13687 |
| 일반 사용자 전용 IP에서 웹 포털 접속 | Forbidden + 13691, 같은 IP의 REST API 로그인은 정상 |
| 사용자 시리얼로 로그인 / 관리자 시리얼로 사용자 로그인 | 성공 / 거부 + 13692 |
| 형식 위반 시리얼(`ovworks0001`, 17자 등) 또는 중복 시리얼 | 화면에서 거부 / 실패 이벤트 13694 |
| 엔진 정지 | 런타임 DEK 파일 소거 |

---

## 14. 관련 소스

| 기능 | 파일 |
|---|---|
| 단말기 IP 목록 처리·graceful | `backend/.../bll/TerminalIpConfigUtils.java`, `SetTerminalIpAuthCommand.java`, `GetTerminalIpAuthQuery.java` |
| 관리자 시리얼 | `backend/.../bll/SetTerminalAuthCommand.java`, `TerminalAuthConfigUtils.java` |
| 사용자 전용 IP | `backend/.../bll/SetUserDedicatedIpCommand.java`, `aaa/RemoveUserCommand.java` |
| 전용 IP 웹 포털 차단 | `backend/.../aaa/filters/DedicatedIpWebPortalFilter.java`, `bll/aaa/IsWebPortalDeniedForAddressQuery.java` |
| 사용자 시리얼 | `backend/.../bll/SetUserClientSerialCommand.java`, `UserClientSerials.java` |
| 시리얼 검사 | `backend/.../uutils/security/ClientSerialCheck.java`, `aaa/TerminalAccessAudit.java`, `sso/service/ClientSerialAudit.java` |
| DEK 암호화 (Java) | `backend/.../uutils/crypto/DekEnvelope.java` |
| 로그인 집행 | `backend/.../bll/aaa/CreateUserSessionCommand.java`, `aaa/SsoUtils.java`, `aaa/servlet/SsoPostLoginServlet.java` |
| 거부 화면 | `backend/.../uutils/servlet/ForbiddenPage.java` |
| 런타임 DEK | `packaging/encryptor/runtime_dek.py`, `packaging/services/ovirt-engine/ovirt-engine.py.in` |
| 화면 | `frontend/.../users/LocalUserAddModel.java`, `UserListModel.java`, `LocalUserAddPopupView.*`, `MainSecuritySettingsView.java` |
| sudo 규칙 | `packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system/acl.py` |

---

## 15. 제약·알려진 한계

- 단말기 IP 인증 목록(`Require ip`)은 전역 통제라, 웹 서버 단계에서는 사용자별 1:1 연결이 없다. 사용자별 연결은 엔진 단계(5.3·6.5)에서 보장한다.
- "다른 사용자가 쓰지 않으면 제거" 규칙은 사용자 전용 IP끼리만 비교한다. 같은 주소를 단말기 IP 화면에서 따로 등록했더라도, 그 주소를 쓰던 마지막 사용자의 전용 IP를 지우면 목록에서 함께 빠진다.
- 웹 포털 차단의 관리자 판정은 직접 부여된 관리자 역할만 본다. 그룹으로만 관리자 권한을 받은 계정의 전용 IP는 일반 사용자 IP로 판정된다.
- 관리 포털 로그인까지 시리얼을 확인하려면, 단말기가 모든 요청(로그인 콜백 포함)에 `X-Client-Serial` 헤더를 붙여야 한다.
- Java 메모리 안의 DEK 사본은 JVM 특성상 0으로 덮어쓴다는 보장을 할 수 없다. 보상통제: 엔진 프로세스(ovirt 계정) 안에만 존재하고, 프로세스 종료 시 소멸한다.
- DEK를 열 수 없는 동안에는 일반 사용자 시리얼 로그인이 불가하다. 관리자 로그인은 영향이 없다.
