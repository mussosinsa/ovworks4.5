# AAA JDBC 계정 잠금 및 자동 해제 검토

## 일반 `internal-authz` 사용자

`MAX_FAILURES_SINCE_SUCCESS`는 마지막 로그인 성공 이후 허용할 인증 실패 횟수다. 이 값을 초과하면 AAA JDBC의
사용자 계정 자체가 잠긴다. 현재 코드에서 일반 사용자의 잠금을 해제하는 경로는 다음 관리자 작업이다.

```console
ovirt-aaa-jdbc-tool user unlock USERNAME
```

WebAdmin의 **사용자 → 잠금해제** 버튼도 동일한 명령을 실행한다. 일반 AAA JDBC 사용자를 일정 시간이 지난 뒤
자동으로 해제하는 환경 변수는 현재 제공되지 않는다.

`MINIMUM_RESPONSE_SECONDS`는 인증 실패 응답을 반환하기 전의 최소 지연 시간이다. brute-force 공격 속도를
낮추기 위한 값이며, 계정 잠금 유지 시간이나 자동 재접속 시간이 아니다.

## 보호된 `admin@internal` 로그인

SSO에는 보호된 관리자 로그인에 한정된 별도 메모리 기반 잠금 정책이 있다.

| Engine 설정 | 기본값 | 의미 |
|---|---:|---|
| `ENGINE_SSO_ADMIN_LOCK_MAX_FAILURES` | 5 | 보호된 관리자 로그인을 잠글 연속 실패 횟수 |
| `ENGINE_SSO_ADMIN_LOCK_HOURS` | 24 | 보호된 관리자 로그인 잠금 유지 시간(시간) |

이 잠금은 `AdminLoginLockoutService`에서 만료 시간을 관리하며, 설정 시간이 지나면 다음 로그인 시도에서
자동으로 해제된다. 이 설정은 일반 `internal-authz` 사용자에게 적용되지 않는다.

```console
engine-config -s ENGINE_SSO_ADMIN_LOCK_MAX_FAILURES=5
engine-config -s ENGINE_SSO_ADMIN_LOCK_HOURS=24
```

## 결론

일반 사용자의 자동 잠금 해제가 필요하면 AAA JDBC가 지원하지 않는 별도 정책을 추가해야 한다. SSO의 관리자
잠금 시간을 일반 사용자에게 그대로 재사용하면 안 된다. 두 잠금은 저장 위치, 적용 대상 및 해제 방식이 서로
다르기 때문이다. 구현 시에는 잠금 시각을 신뢰할 수 있는 저장소에 기록하고, 인증 요청 시 만료 여부를 원자적으로
검사한 뒤 AAA JDBC `user unlock`을 호출하는 별도 설계가 필요하다.
