# 로그인 ID·패스워드 입력 제한

포털(SSO) 로그인 화면의 **아이디**와 **패스워드** 입력란, 그리고 같은 자격증명을 받는 REST API 토큰 발급
(`/ovirt-engine/sso/oauth/token`)에 같은 규칙을 적용한다. 규칙은 한 곳
(`org.ovirt.engine.core.uutils.security.LoginInputPolicy`)에만 정의되어 있고, 로그인 화면은 서버가 내려준
규칙(JSON)으로 검사하므로 화면과 서버의 판정이 어긋나지 않는다.

## 규칙

| 항목 | 아이디 | 패스워드 |
|---|---|---|
| 최대 길이 | 20자 | 20자 |
| 금지 문자 | `\|` `;` `:` `` ` `` 공백(전각·NBSP·탭 포함)·제어문자 | 동일 |
| 추가 금지 문자 | `'` `"` `=` `<` `>` `(` `)` `,` `*` | — |
| SQL 인젝션 구문 | 거부 | 거부 |

SQL 인젝션 구문(대소문자 무시):

- 따옴표·괄호 뒤의 `OR`/`AND`/`XOR` — `'or'1'='1`, `')or('1`
- 항상 참인 조건 — `or1=1`, `or'a'='a`
- 따옴표 비교 — `'='`, `'<>'`
- 주석 — `--`, `/*`, `*/`
- 구문 — `UNION … SELECT`, `SELECT … FROM`, `INSERT … INTO`, `DELETE … FROM`, `UPDATE … SET`,
  `DROP/TRUNCATE/ALTER … TABLE/DATABASE/SCHEMA/USER`
- 함수·객체 — `sleep(`, `pg_sleep(`, `benchmark(`, `exec(`, `WAITFOR … DELAY`, `xp_cmdshell`,
  `information_schema`, `pg_catalog`

`' or 1=1`은 공백 때문에 이미 금지 문자로 거부되고, 공백을 뺀 `'or1=1`은 SQL 인젝션 구문으로 거부된다.

> 참고: 로그인 자격증명은 원래 SQL 문장으로 조립되지 않는다(인증 확장에 값으로 전달). 이 제한은
> 입력 단계에서 비정상 입력을 차단하는 추가 방어선이며, 점검 기준(입력값 검증)을 충족하기 위한 것이다.

## 동작

### 로그인 화면 (`login.jsp`)

- 입력란에 `maxlength="20"` — 20자를 넘게 입력할 수 없다(붙여넣기도 20자에서 잘림).
- 금지 문자는 **입력되는 즉시 제거**되고 입력란 아래에 안내가 표시된다.
  - 아이디: `아이디에 사용 불가능한 특수문자가 포함되어 있습니다. (| ; : ` ' " = < > ( ) , * 공백)`
  - 패스워드: `패스워드에 사용 불가능한 특수문자가 포함되어 있습니다. (| ; : ` 공백)`
  - 길이 초과: `아이디는 최대 20자까지 입력할 수 있습니다.`
- 로그인 버튼을 누르면 암호화 전에 SQL 인젝션 구문을 검사하고, 해당하면 전송하지 않는다.
  - `패스워드에 허용되지 않는 입력(SQL 구문)이 포함되어 있습니다.`
- 패스워드는 nonce로 감싸 암호화되기 **전**의 입력값 그대로 검사한다.

### 서버 (화면을 거치지 않은 요청 포함)

- `InteractiveAuthServlet`(로그인 화면 제출)과 `OAuthTokenServlet`(REST 비밀번호 발급)에서 복호화 직후,
  인증 확장 호출 **전**에 같은 규칙으로 검사한다.
- 거부 시 화면에는 `아이디 또는 패스워드에 사용 불가능한 특수문자 또는 허용되지 않는 입력이 포함되어
  있습니다.`가 표시되고, REST는 인증 실패로 응답한다.
- 인증을 시도하지 않으므로 **계정 잠금 실패 횟수에 포함되지 않는다**(제3자가 고의로 잠그는 것 방지).

### 감사 이벤트

| 항목 | 값 |
|---|---|
| 유형 | `USER_VDC_LOGIN_INPUT_REJECTED` (13719, ERROR, 동일 이벤트 5초 억제) |
| 내용 | `LOGIN_INPUT_REJECTED user=<아이디> sourceIp=<IP> channel=LOGIN_PAGE\|API field=USER_NAME\|PASSWORD reason=TOO_LONG\|FORBIDDEN_CHARACTER\|SQL_INJECTION` |

입력값 자체는 기록하지 않는다. 패스워드는 물론, 거부된 것이 아이디이면 아이디도 `N/A`로 기록한다
(공격자가 보낸 문자열을 감사 로그에 남기지 않기 위함).

### 새 패스워드·계정 생성

로그인할 수 없는 패스워드·아이디가 만들어지지 않도록 같은 규칙을 적용한다.

- `PasswordPolicyValidator` — SSO 패스워드 변경, 웹관리자 사용자 추가(`AddLocalUserCommand`)·패스워드
  초기화(`ResetUserPasswordCommand`)에서 위반 규칙 `MAX_LENGTH`/`FORBIDDEN_CHARACTERS`/`SQL_INJECTION` 표시
- `AddLocalUserCommand` — 20자 초과 등 로그인 ID 규칙 위반 아이디는 생성 거부
- 패스워드 변경 화면(`credentialsChange.jsp`) 입력란 `maxlength="20"`
- `engine-setup` admin 패스워드 — 20자 초과·금지 문자·SQL 구문 입력 시 재입력 요구, 자동 생성 길이 22→20자

## 적용 전 확인 (기존 계정 영향)

다음 계정은 적용 후 **로그인할 수 없으므로** 업그레이드 전에 패스워드를 바꿔야 한다.

- 패스워드가 **20자를 넘는** 계정
- 패스워드에 `|` `;` `:` `` ` `` 또는 공백이 들어 있는 계정
- 아이디가 20자를 넘거나 `'` `"` `=` `<` `>` `(` `)` `,` `*` 를 포함하는 계정(예: 긴 UPN 형식의 LDAP 아이디)
- REST API·자동화 스크립트(Ansible 등)에서 위 조건의 계정으로 비밀번호 인증하는 경우

조치: 해당 계정은 적용 전 웹관리자 또는 `ovirt-aaa-jdbc-tool user password-reset`으로 규칙에 맞는
패스워드로 바꾼다. 적용 후 로그인이 거부되면 이벤트 `USER_VDC_LOGIN_INPUT_REJECTED`의 `field`/`reason`으로
원인을 확인할 수 있다.

패스워드 최소 길이 정책(`PasswordPolicyMinLength`, 기본 12)은 20 이하로 유지해야 한다.

## 검증

- `LoginInputPolicyTest`, `PasswordPolicyValidatorTest`(uutils), `LoginInputAuditTest`,
  `InteractiveAuthServletTest`(enginesso)
- `packaging/setup/tests/test_login_input_restriction.py` — Java·`engine-setup` 패턴 동일성, 화면·서버·감사 연결
- 화면 스크립트와 Java의 판정이 같은 입력 집합에서 일치함을 Node로 대조 확인
