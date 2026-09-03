# 패스워드 정책 및 최초 로그인 변경 절차

## 1. 개요

패스워드가 설정되는 모든 경로에 동일한 정책을 적용하고, 관리자나 `engine-setup`이 설정한
패스워드는 **최초 로그인 시 반드시 변경**하도록 합니다.

정책 판정 로직은 `org.ovirt.engine.core.uutils.security` 패키지 한 곳에 있으며, Engine(BLL)과
SSO가 같은 클래스를 호출합니다. `engine-setup`은 Python으로 동일한 규칙을 구현합니다.

| 구성요소 | 위치 |
| --- | --- |
| 정책 정의 | `backend/manager/modules/uutils/.../security/PasswordPolicy.java` |
| 정책 판정 | `backend/manager/modules/uutils/.../security/PasswordPolicyValidator.java` |
| 이력 해싱 | `backend/manager/modules/uutils/.../security/PasswordHistoryCryptor.java` |
| Engine 설정 조회 | `backend/manager/modules/bll/.../aaa/PasswordPolicyResolver.java` |
| SSO 설정 조회·검증 | `backend/manager/modules/enginesso/.../service/PasswordPolicyService.java` |
| setup 검증 | `packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/config/aaa.py` |

## 2. 적용 경로

```
 ┌──────────────────────────┐   ┌───────────────────────────┐   ┌──────────────────────────┐
 │ A. engine-setup          │   │ B. 관리자 패스워드 리셋    │   │ C. 사용자 셀프 변경       │
 │    최초 관리자 비밀번호   │   │    (WebAdmin)             │   │    (SSO 변경 화면)        │
 ├──────────────────────────┤   ├───────────────────────────┤   ├──────────────────────────┤
 │ aaa.py                   │   │ ResetUserPasswordCommand  │   │ InteractiveChangePasswd  │
 │ _validateAdminPassword   │   │ .validate()               │   │ Servlet + PasswordPolicy │
 │ Policy()                 │   │                           │   │ Service.validate()       │
 └───────────┬──────────────┘   └────────────┬──────────────┘   └───────────┬──────────────┘
             │                               │                              │
             ▼                               ▼                              ▼
      만료된 상태로 저장                만료된 상태로 저장                 정상 만료일로 저장
             │                               │                              ▲
             └───────────────┬───────────────┘                              │
                             ▼                                              │
                   최초 로그인 → CREDENTIALS_EXPIRED                        │
                             │                                              │
                             └──────────────────────────────────────────────┘
```

C 경로는 A·B가 만든 만료 상태를 해소하는 경로이므로, **최초 로그인 강제 변경 절차 그 자체**입니다.

## 3. 최초 로그인 변경 절차

1. `engine-setup` 또는 관리자가 패스워드를 설정하면 `--password-valid-to`가 **현재 시각 이전**으로
   기록되어 패스워드가 만료 상태가 됩니다.
2. 사용자가 로그인하면 authn 확장이 `CREDENTIALS_EXPIRED`를 반환합니다.
3. `AuthnMessageMapper`가 이를 감지하여 SSO가 패스워드 변경 화면(`credentialsChange.jsp`)으로
   유도합니다.
4. 사용자가 새 패스워드를 입력하면 `InteractiveChangePasswdServlet`이 정책을 검증한 뒤
   authn 확장에 변경을 위임하고, 성공 시 이력을 기록합니다.
5. 변경이 끝나면 로그인 화면으로 돌아가 새 패스워드로 로그인합니다.

일반 사용자의 관리 패스워드 재설정 동작은 다음 설정으로 선택할 수 있습니다.

- Engine: `PasswordPolicyForceChangeOnFirstLogin` (기본 `true`)

bootstrap `admin@internal` 초기 패스워드는 이 설정과 관계없이 항상 만료 상태로 저장됩니다.
설치 자동화가 이 계정을 사용하는 환경에서는 첫 REST 로그인에서 변경 grant를 수행해야 합니다.

## 4. 정책 항목

### 4.1 필수 정책

| 항목 | 기본값 | Engine 설정 키 | setup 설정 키 |
| --- | --- | --- | --- |
| 최소 길이 | 12자 | `PasswordPolicyMinLength` | `adminPasswordMinLength` |
| 영문 대문자 포함 | 사용 | `PasswordPolicyRequireUppercase` | `adminPasswordRequireUppercase` |
| 영문 소문자 포함 | 사용 | `PasswordPolicyRequireLowercase` | `adminPasswordRequireLowercase` |
| 숫자 포함 | 사용 | `PasswordPolicyRequireDigit` | `adminPasswordRequireDigit` |
| 특수문자 포함 | 사용 | `PasswordPolicyRequireSpecial` | `adminPasswordRequireSpecial` |
| 사용자 ID와 동일 금지 | 사용 | `PasswordPolicyForbidSameAsUserId` | `adminPasswordForbidSameAsUserId` |

각 문자 유형 검사는 개별적으로 끌 수 있습니다.

사용자 ID 검사는 **동일 여부만** 판정하며 대소문자를 구분하지 않습니다. `name@profile` 형식으로
입력된 경우 `@` 앞의 로컬 부분과도 비교합니다. 이전의 "ID 포함 금지"는 강한 패스워드까지
거부했기 때문에 제거했습니다.

### 4.2 선택 정책

| 항목 | 기본값 | Engine 설정 키 | setup 설정 키 |
| --- | --- | --- | --- |
| 동일 문자·패턴 반복 금지 | 사용 | `PasswordPolicyForbidRepeatedCharacters` | `adminPasswordForbidRepeated` |
| 반복 판정 횟수 | 3회 | `PasswordPolicyRepeatLimit` | `adminPasswordRepeatLimit` |
| 연속 문자 금지 | 사용 | `PasswordPolicyForbidSequentialCharacters` | `adminPasswordForbidSequential` |
| 연속 판정 길이 | 4자리 | `PasswordPolicySequenceLength` | `adminPasswordSequenceLength` |
| 직전 패스워드 재사용 금지 | 사용 | `PasswordPolicyForbidPreviousPassword` | 해당 없음 |
| 기간 내 재사용 금지 | 사용 | `PasswordPolicyForbidReuseWithinPeriod` | 해당 없음 |
| 재사용 금지 기간 | 3개월 | `PasswordPolicyReuseHistoryMonths` | 해당 없음 |
| 사전 단어 금지 | 사용 | 해당 없음(setup 전용) | `adminPasswordForbidCommonWords` |

**반복 검사**는 두 가지를 봅니다.

- 동일 문자가 설정 횟수만큼 연속되는 경우 (`aaa`)
- 2~4자 블록이 연속으로 반복되는 경우 (`abab`, `123123`)

**연속 검사**는 정방향·역방향 모두를 대상으로 다음 배열에서 설정 길이만큼의 연속을 찾습니다.

- 숫자: `0123456789`
- 알파벳: `abcdefghijklmnopqrstuvwxyz`
- 키보드 배열(US): `` `1234567890-= ``, `qwertyuiop[]\`, `asdfghjkl;'`, `zxcvbnm,./`,
  `~!@#$%^&*()_+`

따라서 `1234`, `dcba`, `asdf`, `4321` 이 모두 거부됩니다. 반복·연속 검사는 대소문자를 구분하지
않습니다.

### 4.3 재사용 금지

재사용 판정에는 Engine DB의 `user_password_history` 테이블을 사용합니다.

- 저장 값은 평문이 아니라 PBKDF2-HMAC-SHA256(210,000회, 32바이트 솔트) 해시입니다.
- 키는 `PasswordHistoryCryptor.principalKey()`가 만드는 `이름@영역` 문자열입니다. Engine의
  authz 이름(`internal-authz`)과 SSO의 프로파일 이름(`internal`)이 같은 키로 정규화되므로,
  관리자 리셋으로 설정한 패스워드를 셀프 변경에서도 인식합니다.
- `직전 패스워드 재사용 금지`는 가장 최근 1건, `기간 내 재사용 금지`는 설정 기간 내 전체 이력과
  대조합니다.
- 이력은 기간이 지나고 최근 32건에서도 밀려난 항목부터 정리됩니다.

`engine-setup`(A 경로)은 Engine DB 스키마가 준비되기 전에 동작하므로 이력 검사를 수행하지
않습니다.

## 5. 설정 변경 방법

```
# 현재 값 확인
engine-config -g PasswordPolicyMinLength

# 값 변경 후 engine 재시작
engine-config -s PasswordPolicyMinLength=14
engine-config -s PasswordPolicyForbidSequentialCharacters=false
systemctl restart ovirt-engine
```

`engine-setup`의 일반 패스워드 규칙은 답변 파일에 다음과 같이 지정합니다.

```
OVESETUP_CONFIG/adminPasswordMinLength=int:14
OVESETUP_CONFIG/adminPasswordForbidCommonWords=bool:False
```

## 6. 검증 예시

기본 정책 기준입니다. 실제 운영에서 아래 값을 사용하지 마십시오.

| 입력 예시 | 결과 | 사유 |
| --- | --- | --- |
| `Vm!Xk7pLq2Zt` | 허용 | 12자, 네 가지 문자 종류, 금지 요소 없음 |
| `Vm!Xk7pL` | 거부 | 12자 미만 |
| `kxmpvtwnbjhr` | 거부 | 대문자·숫자·특수문자 누락 |
| `admin` (ID가 `admin`) | 거부 | 사용자 ID와 동일 |
| `Vm!Xkadmin7pLq2Zt` | 허용 | ID를 포함할 뿐 동일하지 않음 |
| `Vm!Xkaaa7pLq2Zt` | 거부 | 동일 문자 3회 반복 |
| `Vm!Xkpqpq7Lq2Zt` | 거부 | `pqpq` 패턴 반복 |
| `Vm!Xk1234pLqZt` | 거부 | 숫자 4자리 연속 |
| `Vm!X7asdfpLqZt` | 거부 | 키보드 4자리 연속 |
| `Vm!X7asdpLqZt` | 허용 | 연속 3자리는 기본 설정에서 허용 |

## 7. 저장 및 전달 보안

- 관리자 리셋(B)은 새 패스워드를 `ovirt-aaa-jdbc-tool`에 **환경변수**로 전달합니다. 명령행 인수로
  전달하면 같은 호스트의 임의 사용자가 `/proc/<pid>/cmdline`에서 평문을 읽을 수 있습니다.
- Engine은 패스워드 원본을 저장하지 않으며, 이력 테이블에도 해시만 남습니다.
- 실제 자격 증명의 저장·해싱은 authn 확장(`ovirt-engine-extension-aaa-jdbc`)이 담당합니다.

## 8. 감사 로그

| 이벤트 | 코드 | 시점 |
| --- | --- | --- |
| `USER_PASSWORD_CHANGED` | 346 | 관리자 리셋 성공 |
| `USER_PASSWORD_CHANGE_FAILED` | 347 | 관리자 리셋 실패(정책 위반 포함) |

SSO 셀프 변경의 실패 사유는 SSO 로그와 변경 화면의 오류 메시지로 확인합니다.

## 9. 관련 스키마

```sql
CREATE TABLE user_password_history (
    id BIGSERIAL,
    principal VARCHAR(510) NOT NULL,
    password_hash TEXT NOT NULL,
    change_date TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_user_password_history PRIMARY KEY (id)
);
```

저장 프로시저는 `packaging/dbscripts/user_password_history_sp.sql`,
업그레이드 스크립트는 `packaging/dbscripts/upgrade/04_05_0321_add_password_policy.sql`입니다.
