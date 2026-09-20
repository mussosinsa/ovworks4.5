# 게스트 이벤트 주기 모니터링

실행 중인 윈도우 가상머신의 이벤트 로그를 Engine이 주기적으로 읽어, 심각한 항목을 엔진
이벤트(`audit_log`)로 기록한다. 게스트 내부에서 일어난 일이 게스트 밖에서 일어난 일과 같은
감사기록에 남는다.

## 동작 방식

```text
GuestCriticalEventAuditManager (EngineScheduledThreadPool, 기본 15분 간격)
  -> 실행 중인 윈도우 VM 목록 (VMStatus.Up, 호스트 지정됨, VM ID 순)
  -> 지난 패스가 멈춘 자리부터 정해진 대수만큼만 (기본 25대)
  -> ExecuteVmGuestCommand (내부 실행) -> 호스트 SSH -> QEMU guest agent -> powershell.exe
  -> Get-WinEvent 결과를 한 줄에 한 건씩 반환
  -> vm_guest_event_mark 보다 뒤인 항목만 AuditLogDirector.log()
  -> vm_guest_event_mark 전진
```

한 대에게 묻는 일은 비싸다. 호스트로의 SSH 연결과 게스트 내부 명령 실행이 필요하므로, 한
패스는 정해진 대수만 묻고 나머지는 다음 패스가 이어받는다. 순서는 고정이고 지난 패스가 멈춘
자리에서 다시 시작하므로, 앞쪽 몇 대만 반복해서 묻고 뒤쪽은 영영 묻지 않는 일이 없다.

## 수집 대상 — "심각한 이벤트"의 정의

로그마다 심각도의 의미가 다르므로 질의를 세 개로 나눈다.

| 대상 로그 | 조건 | 근거 |
|---|---|---|
| System, Application | `Level = 1, 2` (Critical, Error) | 해당 로그는 스스로 심각도를 표시한다 |
| Security | `Keywords = 0x10000000000000` (감사 실패) | 로그온 실패·접근 거부도 Level은 0(정보)이다 |
| Security | `Id = 1102, 4719, 4720, 4722, 4724, 4725, 4726, 4728, 4732, 4740` | 감사 추적·계정·그룹 변경은 "성공"으로 기록된다 |

보안 로그는 `VmGuestSecurityEventsEnabled`로 따로 켜고 끈다. 그 내용은 장애 보고가 아니라
감사 추적이므로, 한쪽만 받고 싶을 수 있다.

레벨과 이벤트 ID는 **숫자로** 수집한다. `LevelDisplayName`은 게스트의 언어로 번역되므로
Engine 쪽 판정 근거가 될 수 없다. 시각도 `ToUniversalTime().ToString("o")`(UTC 왕복 형식)로
받는다. 게스트의 로캘·달력·타임존과 무관하게 읽히고, 엔진 이벤트와 나란히 놓을 수 있다.
레벨 이름("Critical", "Error")은 숫자를 받은 뒤 Engine 쪽에서 붙인다.

## 엔진 이벤트 매핑

| 조건 | AuditLogType | 심각도 |
|---|---|---|
| Security 로그의 `1102`(보안 로그 삭제), `4719`(감사 정책 변경) | `VM_GUEST_AUDIT_TRAIL_EVENT` | ALERT |
| 그 밖의 Security 로그 항목 | `VM_GUEST_SECURITY_EVENT` | ERROR |
| System, Application의 Critical·Error | `VM_GUEST_CRITICAL_EVENT` | ERROR |
| 전에는 응답하던 VM을 읽지 못함 | `VM_GUEST_EVENT_COLLECTION_FAILED` | ERROR (VM당 시간당 1회) |

읽기 실패는 **한 번이라도 응답한 적이 있는 VM에 대해서만** 기록한다. guest agent가 없는 VM,
꺼진 VM, 닿지 않는 호스트는 흔한 일이고 매 패스마다 같은 말을 남길 이유가 없다. 반면 응답하던
VM이 응답을 멈춘 것은 그 VM의 감사 추적이 조용해졌다는 뜻이므로 드러나야 한다.

## 중복과 누락 방지 — 마크

`vm_guest_event_mark(vm_id, log_name, last_record_id)`.

윈도우는 레코드 번호(`RecordId`)를 **머신이 아니라 로그마다** 매기므로, 마크도 (VM, 로그)
쌍으로 유지한다. 마크 이하의 번호는 이미 기록한 것으로 보고 건너뛴다.

보안 로그가 삭제되면 번호가 1부터 다시 시작한다. 이를 "이미 본 것"으로 읽으면 그 뒤에 기록되는
모든 항목을 번호가 원래 자리까지 올라올 때까지 놓친다. 그래서 마크보다 **1000 이상 낮은** 번호는
새 로그가 시작된 것으로 보고 마크를 되돌린다. 마크는 올리기만 하는 값이 아니라 *설정하는* 값이다.

마크는 데이터베이스에 있다. 메모리에만 두면 Engine이 재시작할 때마다 lookback 범위 안의 항목이
전부 다시 기록된다. VM이 삭제되면 마크도 함께 지워진다(`ON DELETE CASCADE`).

한 VM이 한 패스에 기록하는 건수는 20건으로 제한된다. 몇 초마다 실패하는 드라이버 하나가 이벤트
목록을 채우지 못하게 하기 위함이고, 남은 것은 다음 패스가 이어받는다.

## 설정

`engine-config`로 변경하며, 모두 **엔진 재시작 후** 적용된다.

| 키 | 기본값 | 설명 |
|---|---|---|
| `VmGuestCriticalEventsEnabled` | `true` | 전체 수집 on/off |
| `VmGuestCriticalEventsIntervalMinutes` | `15` | 패스 간격(분) |
| `VmGuestCriticalEventsVmsPerPass` | `25` | 한 패스가 묻는 VM 대수 |
| `VmGuestCriticalEventsLookbackHours` | `2` | 한 패스가 거슬러 보는 범위(시간) |
| `VmGuestSecurityEventsEnabled` | `true` | 보안 로그 수집 on/off |

```console
# engine-config -s VmGuestSecurityEventsEnabled=false
# systemctl restart ovirt-engine
```

## 전제 조건

* 게스트에 QEMU guest agent가 설치되어 동작 중이어야 한다.
* guest agent는 SYSTEM 계정으로 실행되므로 보안 로그를 읽을 수 있다.
* `관리 명령 차단`(AppLocker)을 켜면 `powershell.exe`가 일반 사용자에게 차단되지만,
  SYSTEM SID(`S-1-5-18`)는 명시적으로 허용되어 있어 수집 경로는 유지된다.

## 실패를 침묵으로 처리하지 않는다

`Get-WinEvent`는 일치하는 항목이 없으면 빈 결과가 아니라 오류를 낸다. 그 오류 하나만
`FullyQualifiedErrorId`(`NoMatchingEventsFound*`)로 식별해 넘어간다. 오류 메시지 문자열이 아니라
식별자로 판정하므로 게스트의 언어와 무관하다. 보안 로그 접근 거부처럼 그 밖의 오류는 명령을
실패시킨다. "읽을 것이 없음"과 "읽지 못함"이 구분된다.
