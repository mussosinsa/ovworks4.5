# 가상머신 보안 제어 조작의 감사 기록

`가상 VM 보안 제어` 대화상자에서 수행하는 모든 조작을 엔진 이벤트(`audit_log`)로 기록한다.
누가, 어느 VM에, 무엇을 요청했고, 게스트가 뭐라고 답했는지가 남는다.

## 기록되는 조작

| 대화상자 항목 | 성공 | 실패 |
|---|---|---|
| 네트워크 설정 | `VM_GUEST_NETWORK_SETTINGS_APPLIED` | `VM_GUEST_NETWORK_SETTINGS_FAILED` (ERROR) |
| 파일 공유 설정 | `VM_GUEST_FILE_SHARING_POLICY_APPLIED` | `VM_GUEST_FILE_SHARING_POLICY_FAILED` (ERROR) |
| 화이트 명령어 (명령 프롬프트 / 관리 명령 차단) | `VM_GUEST_COMMAND_POLICY_APPLIED` | `VM_GUEST_COMMAND_POLICY_FAILED` (ERROR) |
| 정보 (이벤트 조회) | `VM_GUEST_EVENTS_VIEWED` | `VM_GUEST_EVENTS_VIEW_FAILED` (ERROR) |
| 배치 파일 실행 (API 전용) | `VM_GUEST_SCRIPT_EXECUTED` | `VM_GUEST_SCRIPT_EXECUTION_FAILED` (ERROR) |

이벤트는 `ExecuteVmGuestCommandCommand`가 기록하므로 **관리 포털뿐 아니라 REST API·SDK로 같은
작업을 해도 동일하게 남는다.**

## 이벤트에 담기는 내용

| 항목 | 내용 |
|---|---|
| `${VmName}` | 대상 VM |
| `${UserName}` | 요청한 사용자 |
| `${GuestSetting}` | 요청한 상태 — `disabled` / `enabled, on a lease` / `enabled, with 192.168.1.50` / `blocked` / `allowed` |
| `${GuestAdapter}` | 네트워크 설정의 대상 어댑터 MAC |
| `${GuestPolicy}` | 화이트 명령어에서 어느 정책인지 — `The command prompt` / `The network and file sharing commands` |
| `${GuestResult}` | 게스트가 답한 한 줄 (최대 300자) |
| `${GuestEventCount}` | 이벤트 조회로 읽어온 건수 |

요청 내용(`GuestSetting`, `GuestAdapter`, `GuestPolicy`)은 커맨드 생성 시점에 기록한다. 게스트에
닿지 못해 실패한 요청도 **무엇을 시도했는지**는 남아야 하기 때문이다.

이벤트 조회는 결과를 이벤트에 담지 않는다. 돌려받는 것이 게스트 이벤트 로그 자체이므로, 이를
그대로 넣으면 엔진 이벤트 하나가 게스트 로그 수십 줄이 되어 이벤트 목록을 덮어버린다. 대신
**읽은 건수**를 기록한다 — 감사 관점에서 읽기 행위에 필요한 정보가 그것이다.

## 기록되지 않는 것

- **게스트 이벤트 수집기의 주기 조회.** 같은 커맨드를 쓰지만 `criticalEventsRequested`로 실행되며
  `AuditLogType.UNASSIGNED`를 반환해 기록하지 않는다. 몇 분마다 모든 윈도우 VM을 도는 동작이라
  폴링마다 이벤트를 남기면 정작 수집한 이벤트가 묻힌다. 수집기는 발견한 것과 읽지 못한 것을
  스스로 기록한다(`docs/guest-event-monitoring.md`).
- **검증 단계에서 거부된 요청.** VM이 꺼져 있는 등 `validate()`에서 막힌 요청은 실행 단계에
  들어가지 않으므로 엔진 이벤트가 남지 않는다. 요청은 클라이언트에 오류로 반환된다.

## 점검 항목

- 네트워크/파일 공유/화이트 명령어를 각각 적용한 뒤 `이벤트` 탭에서 해당 이벤트와 요청 내용이
  보이는지 확인
- 게스트 에이전트를 끈 상태에서 적용 → `..._FAILED` 이벤트와 실패 사유가 남는지 확인
- `정보` 탭의 이벤트 조회 후 `VM_GUEST_EVENTS_VIEWED`에 읽은 건수가 남는지 확인
- 수집기 주기가 지나도 폴링 이벤트는 쌓이지 않는지 확인
