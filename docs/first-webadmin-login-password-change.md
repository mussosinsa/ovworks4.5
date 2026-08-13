# engine-setup 후 WebAdmin 최초 로그인 암호 변경

## 1. 검토 결론

신규 Engine DB의 `admin@internal` 암호는 AAA-JDBC가 정상 인증할 수 있는 bootstrap credential로
생성하고 Engine DB에 최초 변경 필요 상태를 함께 기록한다. SSO는 credential 인증 성공 후에도 이 상태가
남아 있으면 session/token 발급을 중단하고 필수 패스워드 변경 흐름을 표시한다. 변경 성공 시 상태를
해제하므로 AAA-JDBC에 인위적인 만료 record를 만들지 않고도 최초 로그인 변경을 강제한다.

이전 구현에서 이미 만료된 bootstrap credential은 code 변경만으로 복구되지 않는다. AAA가
`AUTHENTICATE_CREDENTIALS`와 `CREDENTIALS_CHANGE`를 모두 내부 오류로 종료하므로 SSO가 인증을 우회해
변경화면만 제공해서는 복구할 수 없고, 오히려 동작하지 않는 절차를 표시하게 된다. 해당 credential은
console에서 정상 유효기간을 가진 새 bootstrap 암호로 reset한 뒤 WebAdmin 변경 절차를 다시 수행한다.

이 통제의 적용범위는 다음과 같다.

| 계정/상황 | 적용 여부 | 이유 |
|---|---|---|
| 신규 DB로 설치한 `admin@internal` | 적용 | Engine DB의 최초 변경 필요 상태로 session/token 발급 전 변경을 강제 |
| 기존 Engine upgrade/reconfiguration | 미적용 | setup 재실행이 기존 관리자 암호를 예고 없이 만료시키지 않도록 함 |
| 외부 LDAP/Kerberos/Keycloak 계정 | 본 구현 범위 밖 | 최초 변경 정책은 외부 identity provider에서 강제해야 함 |
| backup/restore로 복구한 기존 DB | 신규설치 통제로 간주하지 않음 | 기존 credential 상태와 조직의 복구절차를 유지 |
| built-in `InternalAuthn` static verifier | 미적용 | 해당 구현은 `CREDENTIALS_CHANGE` capability를 제공하지 않음 |

### 1.1 요청된 패스워드 보안 정책 적용 여부

최초 로그인에서 수행되는 **새 패스워드 변경** 경로를 기준으로 검토한 결과는 다음과 같다.

| 요구사항 | 판정 | 현재 구현 |
|---|---|---|
| 최소 12자리 | 적용 | 최초 변경 기본값은 12이며 `ENGINE_SSO_PASSWORD_MIN_LENGTH`로 강화 가능 |
| 대문자·소문자·숫자·특수문자 | 적용 | 최초 변경에서 기본적으로 모두 검사하며 문자 유형별 설정 제공 |
| 사용자 ID와 동일한 패스워드 금지(대소문자 무시) | 적용 | 최초 변경에서 ID 전체와의 동일 여부만 대소문자 없이 검사 |
| 특수문자 포함 선택 설정 | 적용 | `ENGINE_SSO_PASSWORD_REQUIRE_SPECIAL`, 기본값 `true` |
| 동일 문자·패턴 반복 금지 선택 설정 | 적용 | `ENGINE_SSO_PASSWORD_REJECT_REPEATED`, 기본값 `true` |
| 연속된 4자리 입력 금지 선택 설정 | 적용 | `ENGINE_SSO_PASSWORD_REJECT_SEQUENTIAL`, 기본값 `true`; 알파벳·숫자 및 qwerty 키보드 행 검사 |
| 직전 패스워드 재사용 금지 선택 설정 | 적용 | `ENGINE_SSO_PASSWORD_REJECT_PREVIOUS`, 기본값 `true` |
| 3개월 내 패스워드 재사용 금지 선택 설정 | 미구현 | 엔진은 timestamp가 있는 패스워드 이력을 저장하거나 3개월 범위를 계산하지 않음 |

대문자, 소문자 및 숫자 검사는 각각 `ENGINE_SSO_PASSWORD_REQUIRE_UPPERCASE`,
`ENGINE_SSO_PASSWORD_REQUIRE_LOWERCASE`, `ENGINE_SSO_PASSWORD_REQUIRE_DIGIT`로 조정한다. boolean 설정은
명시하지 않으면 안전한 기본값인 `true`가 적용된다. 배포 기본값은
`packaging/services/ovirt-engine/ovirt-engine.conf.in`에도 명시되어 있으므로 운영자는 engine 설정 drop-in에서
각 항목을 독립적으로 덮어쓴 뒤 서비스를 재시작할 수 있다. 최소 길이는 12 미만으로 낮출 수 없다.
upgrade 직후처럼 새 설정 key가 아직 배포 설정 파일에 없더라도 SSO는 missing property를 허용하여
정책 코드의 안전한 기본값(최소 12자리, boolean `true`)을 사용하며 변경 요청을 설정 오류로 중단하지 않는다.
3개월 이력 정책은 AAA 공급자 또는 별도 timestamp
기반 이력 구현이 필요하므로 요청된 정책 전체를 **적용 완료**로 판정해서는 안 된다.

## 2. 소스 처리 흐름

```mermaid
sequenceDiagram
    actor I as 설치 담당자
    participant E as engine-setup
    participant J as AAA-JDBC tool/DB
    actor U as 최초 WebAdmin 사용자
    participant S as Engine SSO

    I->>E: 신규 Engine DB 설치 및 초기 admin 암호 입력
    E->>E: 암호 정책 검사
    E->>J: password-reset --force, 정상 유효기간
    E->>E: 최초 변경 필요 상태=true
    U->>S: admin@internal + bootstrap 암호
    S->>J: AUTHENTICATE_CREDENTIALS
    J-->>S: SUCCESS
    S->>E: 최초 변경 필요 상태 확인
    S-->>U: session/token 없이 필수 변경 popup
    U->>S: 정책을 충족하는 새 암호
    S->>J: CREDENTIALS_CHANGE
    J-->>S: SUCCESS
    S->>E: 최초 변경 필요 상태=false
```

### 2.1 setup 단계

`aaa.py`는 신규 DB 설치에서만 초기 관리자 암호를 입력받고 최소 길이, 문자조합, 계정명 포함,
취약단어, 알파벳·숫자 3자리 연속 및 동일 문자 3회 반복을 고정 규칙으로 검사한다. 이 규칙들은 현재
개별 설정으로 활성화하거나 비활성화할 수 없다. `aaajdbc.py`는 AAA-JDBC credential에는 정상 유효기간을
부여하고 신규 DB에서만 `ENGINE_SSO_FORCE_INITIAL_ADMIN_PASSWORD_CHANGE=true`를 기록한다. SSO는 정상
credential을 확인한 뒤 이 상태를 검사하므로 AAA 공급자의 만료 검증 오류를 우회하지 않고 제거한다.
upgrade/reconfiguration에는 이 상태를 새로 설정하지 않는다.

### 2.2 로그인 및 변경 단계

AAA-JDBC가 `CREDENTIALS_EXPIRED`를 반환하면 `AuthnMessageMapper`는 해당 profile이 암호 변경 URL 또는
`CREDENTIALS_CHANGE` capability를 제공하는지 확인한다. 지원하면 `login.jsp`는 별도 link를 클릭하게
하지 않고 닫기 button이 없는 modal popup을 즉시 표시한다. popup은 이전 암호, 새 암호와 새 암호 확인을
받아 기존 `/interactive-change-passwd` endpoint로 제출한다. 변경 요청은
`AuthenticationService.changePassword()`가 새 패스워드 정책을 먼저 검사하고, 통과한 이전 credential과
새 credential을 AAA extension의 `CREDENTIALS_CHANGE` command로 전달한다. 공급자는 엔진 검사에 더해
자체 정책을 추가로 적용할 수 있다.

암호 변경이 성공하기 전에는 WebAdmin의 일반 관리 session을 발급한 것으로 판정해서는 안 된다. 성공 후 bootstrap 암호 재사용이 거부되고 새 암호로만 로그인되는지 현장시험으로 확인한다.

## 3. 구현 방식 선택 검토

| 방식 | 판정 | 설명 |
|---|---|---|
| 정상 AAA credential + Engine 최초 변경 상태 | **채택** | AAA 검증 예외 없이 session/token 발급 전에 변경을 강제 |
| 인증 성공 후 WebAdmin 내부 popup으로 변경 권고 | 부적합 | WebAdmin session이 이미 발급되어 popup 우회·닫기 가능 |
| setup에서 임의 암호 생성 후 운영자가 CLI로 변경 | 보완수단 | 사람의 후속조치 누락 가능; 대화형 최초 로그인 요구를 직접 강제하지 않음 |
| 모든 engine-setup 실행 후 암호 만료 | 부적합 | upgrade/reconfiguration이 기존 운영계정을 예고 없이 중단시킴 |
| WebAdmin UI에서만 변경 상태 검사 | 부적합 | REST/OAuth 경로에서 session/token 발급을 우회할 수 있음 |

## 4. 설치 및 운영 절차

1. 신규 설치 전 NTP/chrony가 정상인지 확인한다.
2. `engine-setup`에서 정책을 충족하는 bootstrap 관리자 암호를 입력한다.
3. Engine DB에 최초 관리자 암호 변경 필요 상태가 설정되었는지 확인한다.
4. `admin@internal` 최초 로그인 시 dashboard가 아닌 필수 패스워드 변경 popup이 표시되는지 확인한다.
5. 정책을 충족하는 새 패스워드로 변경한 뒤 새 암호 로그인 성공과 bootstrap 암호 로그인 실패를 확인한다.
6. upgrade/reconfiguration에서 기존 관리자 암호가 임의로 만료되지 않는지 확인한다.

## 5. 정상·부정 시험표

| ID | 시험 | 기대결과 |
|---|---|---|
| FLPC-01 | 신규 DB setup 직후 `admin@internal` 로그인 | AAA 인증 성공 후 session/token 없이 변경 popup |
| FLPC-02 | 변경 전 OAuth/REST token 요청 | token 미발급 및 변경 필요 응답 |
| FLPC-03 | 정책 미충족 새 암호로 변경 | SSO 정책 오류, 변경 실패 |
| FLPC-04 | 정책 설정을 개별 비활성화 후 해당 문자 유형 없이 변경 | 비활성화한 검사만 생략됨 |
| FLPC-05 | 정상 새 암호로 변경 | 변경 성공, 새 암호 로그인 성공 |
| FLPC-06 | 직전 암호와 같은 새 암호 | 기본 정책에서 변경 실패 |
| FLPC-07 | upgrade/reconfiguration | 기존 암호가 임의로 만료되지 않음 |

## 6. 장애 및 비상복구

* 변경화면이 제공되지 않으면 profile이 AAA-JDBC인지, `CREDENTIALS_CHANGE` capability가 로드됐는지, SSO log의 `CREDENTIALS_EXPIRED` mapping을 확인한다.
* `Unexpected Exception invoking: AAA_AUTHN_AUTHENTICATE_CREDENTIALS`가 발생하면 SSO의 최초 변경 상태를
  임의로 해제하거나 인증을 성공으로 간주하지 않는다. `ovirt-aaa-jdbc-tool user show admin`에서
  `Password Valid To`가 현재 UTC보다 과거이고 `CREDENTIALS_CHANGE`도 `Invoke failed`이면 손상된 bootstrap
  credential 상태이므로 console password reset이 필요하다. SSO는 이 provider 예외를 HTTP 500
  `server_error`로 노출하지 않고 일반 인증 실패로 종료하며, server log에는 password-reset 조치가 필요함을
  기록한다. 이 처리는 credential을 복구하거나 인증을 우회하지 않는다.
* 최초 암호를 분실했거나 변경이 실패한 경우 WebAdmin session 우회를 허용하지 않는다. console에서 승인된 `ovirt-aaa-jdbc-tool user password-reset` 절차로 provider 호환 유효기간의 새 암호를 발급한다.

  ```bash
  read -r -s -p 'Temporary admin password: ' pass; echo
  export pass
  ovirt-aaa-jdbc-tool user password-reset admin \
      --password=env:pass \
      --password-valid-to="$(date -u -d '+10 years' '+%Y-%m-%d %H:%M:%SZ')" \
      --force
  unset pass
  ```

  reset 후 `user show admin`의 `Password Valid To`가 현재 UTC보다 미래인지 확인하고 Engine을 재시작한다.
  최초 변경 flag는 유지하므로 WebAdmin 로그인은 정상 AAA 인증 후 다시 필수 변경화면으로 진행한다.
* 비상 reset에는 요청자, 승인자, 대상 계정, 수행 Host, UTC 시각과 reset 사유를 남기고 secret 값은 기록하지 않는다.
* 외부 identity provider 장애를 내부 계정 정책 변경으로 임시 우회하지 않는다. break-glass 계정은 별도 승인·봉인·정기시험 정책을 적용한다.

## 7. 제한사항과 후속 보완

1. 현재 setup의 최초 로그인 강제 변경은 신규 AAA-JDBC 관리자에만 적용된다. Keycloak/LDAP 계정은 provider 측 “다음 로그인 시 암호 변경” 기능을 별도로 구성해야 한다.
2. 저장소에는 AAA-JDBC extension 구현 자체가 포함되어 있지 않으므로 만료 판정과 새 암호 유효기간 부여는 설치된 extension version과 통합시험해야 한다.
3. SSO의 암호 변경 성공 log만으로 변경 주체·원본 IP·정책결과가 완전한 감사 event로 남는다고 가정하지 않는다. 실제 audit DB/SIEM 기록을 확인한다.
4. system clock이 크게 어긋나면 만료·token 판정이 달라질 수 있으므로 시간동기화를 설치 선행조건과 증적에 포함한다.
5. setup answer file이나 automation에서 bootstrap 암호를 제공하는 경우 process argument, environment dump, CI log에 노출되지 않도록 secret injection 방식을 검토한다.
6. Engine upgrade/redeploy 후 WebAdmin host page는 GWT RPC serialization contract가 바뀔 수 있으므로
   저장하거나 ETag 304로 재사용하지 않는다. root host page와 permutation selector는 매 요청 재검증하며,
   RPC endpoint는 `no-store`로 유지한다. 기존 browser에 이미 남은 이전 permutation은 한 번 hard refresh한다.

## 8. 소스 추적성

| 기능 | 소스 |
|---|---|
| 신규 DB 관리자 암호 입력·복잡도 검사 | `packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/config/aaa.py` |
| AAA-JDBC 사용자 생성·초기 암호 만료 설정 | `packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/config/aaajdbc.py` |
| 만료 결과와 암호 변경 URL/message mapping | `backend/manager/modules/enginesso/src/main/java/org/ovirt/engine/core/sso/service/AuthnMessageMapper.java` |
| credential 변경 command 전달 | `backend/manager/modules/enginesso/src/main/java/org/ovirt/engine/core/sso/service/AuthenticationService.java` |
| 로그인 화면의 필수 암호 변경 modal popup | `backend/manager/modules/enginesso/src/main/webapp/WEB-INF/login.jsp` |
| 암호 변경 화면 | `backend/manager/modules/enginesso/src/main/webapp/WEB-INF/credentialsChange.jsp` |
| 암호 변경 servlet | `backend/manager/modules/enginesso/src/main/java/org/ovirt/engine/core/sso/servlets/InteractiveChangePasswdServlet.java` |
