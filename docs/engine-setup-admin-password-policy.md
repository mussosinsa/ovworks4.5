# `engine-setup` 관리자 비밀번호 정책

## 적용 대상과 시점

이 문서는 `engine-setup`이 새 Engine 데이터베이스를 구성할 때 생성하는 내부 관리자 계정의 비밀번호 정책을 설명합니다. 기본 관리자는 `admin@internal`이며, 내부 AAA JDBC 권한 제공자를 사용하는 경우에만 setup이 비밀번호를 설정합니다.

비밀번호 대화상자는 Engine이 활성화되어 있고 새 데이터베이스를 생성하며, `ADMIN_PASSWORD` 환경값이 아직 제공되지 않은 경우에 표시됩니다. 따라서 자동화 설치에서 해당 환경값을 전달하는 경우에는 대화형 입력 검사가 실행되지 않으므로, 자동화 도구가 아래의 동일한 정책을 사전에 검증해야 합니다.

## 필수 정책

`engine-setup`은 아래 모든 조건을 만족하는 비밀번호만 허용합니다.

| 구분 | 요구사항 | 답변 파일 키(`OVESETUP_CONFIG/`) |
| --- | --- | --- |
| 길이 | 최소 12자 | `adminPasswordMinLength` |
| 문자 종류 | 영문 소문자 1자 이상 | `adminPasswordRequireLowercase` |
|  | 영문 대문자 1자 이상 | `adminPasswordRequireUppercase` |
|  | 숫자 1자 이상 | `adminPasswordRequireDigit` |
|  | 특수문자 1자 이상(영문/숫자가 아닌 문자) | `adminPasswordRequireSpecial` |
| 계정명 | 로그인 계정의 로컬 부분과 **동일할 수 없음**. 예: `admin@internal`이면 `admin` 불가 | `adminPasswordForbidSameAsUserId` |

## 선택 정책

아래 검사는 개별적으로 끌 수 있습니다. 기본값은 모두 사용입니다.

| 구분 | 요구사항 | 답변 파일 키(`OVESETUP_CONFIG/`) |
| --- | --- | --- |
| 공통 단어 | `password`, `admin`, `ovirt`, `engine`, `welcome`, `qwerty` 포함 불가 | `adminPasswordForbidCommonWords` |
| 연속 문자열 | 숫자·알파벳·키보드 배열의 4자리 순방향/역방향 연속 불가. 예: `1234`, `dcba`, `asdf` | `adminPasswordForbidSequential`, `adminPasswordSequenceLength` |
| 반복 문자열 | 같은 문자가 3회 연속되거나 2~4자 패턴이 반복될 수 없음. 예: `aaa`, `abab` | `adminPasswordForbidRepeated`, `adminPasswordRepeatLimit` |

정책은 대소문자를 구분하지 않고 계정명·공통 단어·연속 문자열·반복 문자열을 검사합니다. 즉, `AdMiN`, `QwErTy`, `CBA`도 거부됩니다.

계정명 검사는 **동일 여부만** 판정합니다. 이전 버전은 계정명이 비밀번호 안에 포함되기만 해도 거부했으나, 그 규칙은 충분히 강한 비밀번호까지 거부했기 때문에 제거했습니다.

## 최초 로그인 시 비밀번호 변경

`adminPasswordForceChangeOnFirstLogin`(기본 `True`)이 켜져 있으면 setup은 관리자 비밀번호를 **만료된 상태로** 저장합니다. 최초 로그인 시 SSO가 비밀번호 변경 화면으로 유도하며, 새 비밀번호를 설정해야 시스템을 사용할 수 있습니다.

무인 설치 파이프라인이 setup 직후 `admin@internal`로 API 로그인을 시도한다면 이 값을 `False`로 두어야 합니다. 자세한 내용은 [패스워드 정책 및 최초 로그인 변경 절차](password-policy-and-first-login-change.md)를 참고하십시오.

## 추가 시스템 정책(`pwquality`)

호스트에 Python `pwquality` 모듈이 설치되어 있으면, 위의 애플리케이션 정책을 통과한 뒤에도 시스템 `pwquality` 설정을 읽어 추가 검사를 수행합니다. 이 모듈은 선택 사항이므로 설치되어 있지 않아도 `engine-setup`은 진행되며, 이 경우에는 본 문서의 필수 정책만 적용됩니다.

운영 환경에서는 `pwquality`를 설치하고 해당 시스템 정책을 별도로 관리하는 것을 권장합니다. 다만 시스템 정책은 배포판 설정에 따라 달라질 수 있으므로, 이 문서의 최소 정책을 대체하는 것으로 간주해서는 안 됩니다.

## 입력 및 실패 처리

1. `engine-setup`은 관리자 비밀번호와 확인 값을 숨김 입력으로 요청합니다.
2. 두 값이 다르면 다시 입력하도록 경고합니다.
3. 값이 일치하면 내장 정책을 검사하고, 사용 가능한 경우 `pwquality` 검사를 추가로 수행합니다.
4. 검사 실패 시 실패 이유를 기록하고 더 강한 비밀번호를 다시 요청합니다.
5. 검사에 성공한 값은 setup 환경에만 유지되며, 이후 내부 AAA JDBC 도구의 `password-reset` 호출에 환경변수로 전달되어 내부 관리자 계정에 설정됩니다.

설정 과정에서 내부 AAA JDBC 도구에는 장기 만료일이 함께 전달됩니다. 이 만료일 설정은 비밀번호 복잡도와 별개의 계정 만료 동작입니다.

## 자동화 설치 지침

비대화형 설치에서 `ADMIN_PASSWORD`를 주입할 때는 다음을 준수합니다.

- 비밀번호를 명령행 인수나 저장소의 평문 구성 파일에 넣지 않습니다.
- 배포 자동화의 secret store 또는 안전한 환경변수 주입 기능을 사용합니다.
- 입력값에 대해 위 표의 정책과 `pwquality` 정책(설치된 경우)을 사전 검증합니다.
- 설치 로그, CI 출력, 지원 티켓에 비밀번호가 남지 않도록 마스킹을 활성화합니다.
- 설치 후에는 관리 계정으로 로그인 가능한지 확인하고, 비밀번호 원본은 즉시 폐기합니다.

## 검증 예시

다음은 정책 검증 시나리오입니다. 실제 비밀번호 값은 운영 환경에서 재사용하지 마십시오.

| 입력 예시 | 기대 결과 | 사유 |
| --- | --- | --- |
| `Vm!Xk7pLq2Zt` | 허용 가능 | 길이와 네 가지 문자 종류 충족, 금지 요소 없음 |
| `Short1!a` | 거부 | 12자 미만 |
| `password1!A` | 거부 | 공통 단어 포함 |
| `admin` | 거부 | 기본 계정명과 동일 |
| `Vm!Xk1234pLqZt` | 거부 | `1234` 연속 문자열 포함 |
| `Vm!X7asdfpLqZt` | 거부 | 키보드 `asdf` 연속 문자열 포함 |
| `Vm!Xkaaa7pLq2Zt` | 거부 | `aaa` 반복 문자 포함 |
| `Vm!Xkpqpq7Lq2Zt` | 거부 | `pqpq` 패턴 반복 포함 |

## 운영상 유의사항

- 이 정책은 **새 데이터베이스 설치의 대화형 관리자 비밀번호 입력**에 적용됩니다. 관리자 리셋과 사용자 셀프 변경은 Engine 설정(`PasswordPolicy*`)으로 제어되는 동일한 정책을 따르며, 자세한 내용은 [패스워드 정책 및 최초 로그인 변경 절차](password-policy-and-first-login-change.md)에 있습니다.
- 내부 AAA JDBC 관리자 계정 설정 시 `--force`가 사용되므로, setup 전 단계에서 정책을 엄격하게 검증하는 것이 중요합니다.
- setup은 Engine DB 스키마가 준비되기 전에 동작하므로 **비밀번호 재사용 이력 검사는 수행하지 않습니다**. 재사용 금지는 이후의 관리자 리셋과 셀프 변경 경로에서 적용됩니다.
- 비밀번호 변경 주기와 계정 잠금은 배포된 AAA/pwquality 구성 및 조직의 보안 정책에 따라 추가로 운영해야 합니다.
