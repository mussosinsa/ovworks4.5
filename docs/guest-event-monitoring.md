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

읽기에 실패한 VM(재부팅 직후 agent 미응답 등)은 다음 주기를 기다리지 않고 **1분 간격으로 최대
15번** 조용히 다시 시도한다. agent가 응답하면 마크 이후의 밀린 이벤트를 한꺼번에 기록한다. VM이
다시 Down 되거나 대상이 아니게 되면 재시도를 멈춘다(다음 실패 때 다시 시작).

## 수집 대상 — "심각한 이벤트"의 정의

로그마다 심각도의 의미가 다르므로 질의를 세 개로 나눈다.

| 대상 로그 | 조건 | 근거 |
|---|---|---|
| System, Application | `Level = 1, 2` (Critical, Error) | 해당 로그는 스스로 심각도를 표시한다 |
| System | `Id = 41, 1001, 1003, 6008, 7031, 7034` | 블루스크린·비정상 종료·서비스 강제 종료. 1001은 수준이 정보(4)라 Level 조건에 안 걸려 ID로 받는다 |
| Application | `Id = 1000` (Application Error) | 응용프로그램 충돌 |
| Security | `Keywords = 0x10000000000000` (감사 실패) | 로그온 실패·접근 거부도 Level은 0(정보)이다 |
| Security | `Id = 1102, 4719, 4720, 4722, 4724, 4725, 4726, 4728, 4732, 4740` | 감사 추적·계정·그룹 변경은 "성공"으로 기록된다 |
| Security | `Id = 4689` (감시 프로세스만) | 중요 프로세스(explorer.exe) 종료. 강제 종료(taskkill /f)는 이것만 남긴다. 게스트에서 **프로세스 종료 감사**가 켜져 있어야 하고, 이름순 EventData로 걸러 감시 목록만 수집한다 |

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
| System 로그의 `1001`·`1003`(블루스크린), `41`(Kernel-Power), `6008`(비정상 종료), `7031`·`7034`(서비스 비정상 종료) | `VM_GUEST_CRASHED` | ERROR |
| Application 로그의 `1000`(응용프로그램 충돌) | `VM_GUEST_CRASHED` | ERROR |
| Security 로그의 `4689`(감시 프로세스 종료, explorer.exe) | `VM_GUEST_PROCESS_TERMINATED` | WARNING |
| System, Application의 Critical·Error | `VM_GUEST_CRITICAL_EVENT` | ERROR |
| 응답하던 VM에 닿지 못하거나, 응답한 VM의 특정 로그를 읽지 못함 | `VM_GUEST_EVENT_COLLECTION_FAILED` | ERROR (VM당 시간당 1회) |

VM 전체에 닿지 못한 실패는 **한 번이라도 응답한 적이 있는 VM에 대해서만** 기록한다. guest agent가 없는 VM,
꺼진 VM, 닿지 않는 호스트는 흔한 일이고 매 패스마다 같은 말을 남길 이유가 없다. 반면 응답하던
VM이 응답을 멈춘 것은 그 VM의 감사 추적이 조용해졌다는 뜻이므로 드러나야 한다.

응답은 했으나 **특정 로그만** 읽지 못한 경우는 조건 없이 기록한다. 응답했다는 것은 에이전트도
호스트도 정상이라는 뜻이므로, 내주지 않는 로그가 있다면 그것은 고장이다.

## 중요 프로세스 강제 종료 (예: explorer.exe)

`taskkill /f /im explorer.exe`는 **블루스크린도, 서비스/앱 충돌 기록(7031/7034/1000)도 남기지 않는다.**
explorer는 강제 종료돼도 바로 다시 뜨기 때문이다. 유일한 흔적은 Security 로그의 **프로세스 종료 감사
(이벤트 4689)** 다. 이를 `VM_GUEST_PROCESS_TERMINATED`(13739, 경고)로 기록한다.

- **전제: 게스트에 "프로세스 종료 감사"가 켜져 있어야 한다.** 기본값은 꺼짐이다.
  - `auditpol /set /subcategory:"Process Termination" /success:enable` (또는 그룹 정책:
    컴퓨터 구성 → Windows 설정 → 보안 설정 → 고급 감사 정책 → 상세 추적 → 프로세스 종료 감사: 성공)
  - 켜져 있지 않으면 4689가 아예 안 생겨 이 이벤트도 남지 않는다.
- **감시 대상은 셸(explorer.exe)뿐이다.** `svchost` 등 수시로 뜨고 지는 프로세스를 넣으면 재부팅·정상
  동작마다 4689가 쏟아지므로 넣지 않는다. explorer는 세션 중에는 종료되지 않으므로, 떠 있는 VM에서
  explorer 4689는 강제 종료(또는 충돌)를 뜻한다. 다만 로그오프·종료 때도 한 번 남을 수 있다.
- 프로세스 이름은 **번역되는 메시지가 아니라 EventData(ProcessName)** 에서 읽어 로캘과 무관하게
  감시 목록과 대조한다. 감시 목록(`WATCHED_PROCESS_NAMES`)에 없는 4689는 게스트 쪽에서 버린다.
- 보안 로그 수집(`VmGuestSecurityEventsEnabled`)이 켜져 있어야 한다(4689는 Security 로그).

## 블루스크린(크래시) 감지

Windows 게스트가 블루스크린(stop error, bugcheck)으로 멈추면, 재시작한 뒤 System 로그에
**BugCheck 기록(이벤트 1001, 원본 `Microsoft-Windows-WER-SystemErrorReporting`)** 을 남긴다.
이 기록에는 stop code(예: `0x000000ef`)가 들어 있다. 이 기록을 `VM_GUEST_CRASHED`로 남긴다.

- BugCheck 1001의 **수준은 "정보"(4)** 이므로 Critical·Error(1·2) 조건으로는 잡히지 않는다. 그래서
  System 로그에서 크래시 관련 이벤트 ID(`41`, `1001`, `1003`, `6008`)를 수준과 무관하게 따로 가져온다.
- 강제 종료가 **반드시 블루스크린은 아니다.** `svchost.exe` 같은 서비스 프로세스를 강제 종료하면
  서비스 비정상 종료(System `7031`·`7034`)가, 응용프로그램이 죽으면 Application `1000`이 남는다.
  이들은 블루스크린(bugcheck 1001)이 없어도 남으므로 함께 크래시로 잡는다. `explorer.exe` 강제
  종료는 보통 다시 떠서 블루스크린은 아니지만, 충돌로 이어지면 Application `1000`이 남는다.
- 1001(stop code)이 agent 설정 등으로 수집되지 않더라도, 크래시 뒤 따라오는 비정상 종료 기록
  (`41` Kernel-Power는 수준이 "위험"이라 기존 Level 조건으로도 수집된다, `6008`)이 함께 잡히므로
  크래시가 누락될 가능성을 줄였다. 다만 호스트에서 강제 전원 차단을 해도 다음 부팅에 `41`·`6008`이
  남으므로, 이 이벤트는 "게스트의 비정상 종료"로 넓게 본다.
- `taskkill`을 실행한 사실 자체(Security `4688`/`4689` 프로세스 생성·종료 감사)는 너무 잦아
  수집하지 않는다. 명령 실행 감사는 별도 기능(명령어 정책)에서 다룬다.
- 이 기록들은 **크래시 다음 재시작 뒤에** 쓰인다. 따라서 VM이 다시 올라와(Up) guest agent가
  응답할 때 다음 수집 패스에서 기록된다. VM이 끝내 올라오지 못하면 이 경로로는 남지 않는다.
- **이벤트가 안 보일 때 확인**:
  - 이벤트 화면 검색어에 주의. `VM_GUEST_CRASHED` 메시지에는 "guest"라는 낱말이 없다("VM X stopped
    unexpectedly ..."). VM 이름이나 "crash"로 찾거나 검색을 비운다.
  - 엔진을 새 코드로 다시 빌드·배포하고 재시작했는지 확인한다.
  - guest agent가 PowerShell `Get-WinEvent`를 실행할 수 있어야 한다(QEMU guest agent의 guest-exec).
    수집이 한 번도 성공하지 못한 Up 상태의 Windows VM은 이제 `VM_GUEST_EVENT_COLLECTION_FAILED`로
    **엔진 구동당 1회** 알리므로, 이 이벤트가 있으면 agent·guest-exec 쪽을 점검한다.
- **"됐다가 안 될 때"**: 수집은 주기 폴링이라 크래시 직후 한 번에 다 안 나올 수 있다.
  - VM이 재시작 중(Down/부팅)이라 **읽기에 실패하면, 다음 주기까지 기다리지 않고 1분 간격으로
    최대 15번 성공할 때까지 다시 시도한다.** 재부팅 직후 guest agent가 준비되는 대로 밀린
    이벤트가 수집된다. (주기 자체를 줄이려면 `VmGuestCriticalEventsIntervalMinutes`를 낮춘다.)
  - 이 재시도는 조용히 수행되어 실패 이벤트를 매번 남기지 않는다(주기 패스가 1시간에 1회만 남긴다).
  - 같은 크래시는 **한 번만** 기록된다(RecordId 마크). 새로고침해도 다시 안 나오는 건 정상이다.
    다음 크래시는 번호가 올라가므로 또 기록된다.
  - guest agent의 guest-exec가 간헐적으로 실패(에이전트 바쁨·타임아웃)하면 그 패스만 비고 다음
    패스가 이어받는다. 부팅 직후 바쁜 구간이 지나면 안정적으로 수집된다.
- 시험 방법: 윈도우 게스트에서 중요한 시스템 프로세스를 강제 종료하면 블루스크린이 발생한다.
  예) 관리자 명령 프롬프트에서 `taskkill /f /im svchost.exe` (특정 중요 svchost는 bugcheck
  `0xEF CRITICAL_PROCESS_DIED`). 재시작 뒤 수집 패스에서 `VM_GUEST_CRASHED`가 이벤트에 남는다.
  `taskkill /f /im explorer.exe`는 explorer가 다시 뜰 뿐 블루스크린은 아니다.
- 실시간(재시작 전) 감지가 필요하면 게스트에 **pvpanic 장치**를 붙여 호스트 수준에서 패닉을
  감지하는 방법이 있으나, 이는 VDSM·libvirt 설정이 필요한 별도 작업이다.


## 중복과 누락 방지 — 마크

`vm_guest_event_mark(vm_id, log_name, last_record_id)`.

윈도우는 레코드 번호(`RecordId`)를 **머신이 아니라 로그마다** 매기므로, 마크도 (VM, 로그)
쌍으로 유지한다. 마크 이하의 번호는 이미 기록한 것으로 보고 건너뛴다.

보안 로그가 삭제되면 번호가 1부터 다시 시작한다. 이를 "이미 본 것"으로 읽으면 그 뒤에 기록되는
모든 항목을 번호가 원래 자리까지 올라올 때까지 놓친다. 그래서 마크보다 **1000 이상 낮은** 번호는
새 로그가 시작된 것으로 보고 마크를 되돌린다. 마크는 올리기만 하는 값이 아니라 *설정하는* 값이다.

마크는 데이터베이스에 있다. 메모리에만 두면 Engine이 재시작할 때마다 lookback 범위 안의 항목이
전부 다시 기록된다. VM이 삭제되면 마크도 함께 지워진다(`ON DELETE CASCADE`).

한 패스에 기록하는 건수는 **로그별로 20건**으로 제한된다. 몇 초마다 실패하는 드라이버 하나가 이벤트
목록을 채우지 못하게 하기 위함이고, 남은 것은 다음 패스가 이어받는다. **VM당이 아니라 로그별**인
이유: 게스트는 로그를 이름순(Application → Security → System)으로 돌려주므로, VM당 한도였다면
Application·Security 잡음이 한도를 먼저 써버려 **System 로그의 크래시 기록(블루스크린·Kernel-Power·
서비스 비정상 종료)이 아예 안 잡히는** 일이 생긴다. 로그별 한도라 한 로그의 잡음이 다른 로그를
굶기지 않는다.

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
식별자로 판정하므로 게스트의 언어와 무관하다. "읽을 것이 없음"과 "읽지 못함"이 구분된다.

보안 로그 접근 거부처럼 그 밖의 오류가 나면, **읽어낸 로그까지 함께 버리지 않는다.** 실패한
로그는 `#unreadable<TAB><사유>` 한 줄로 따로 보고되고, 읽어낸 이벤트는 그대로 기록된다. 로그
하나를 읽지 못했다는 이유로 나머지 두 로그의 이벤트가 사라지면, 그것이 바로 아무도 모르게
감사 추적이 멈추는 방식이다.

## 반환 순서

이벤트는 **로그별로, 레코드 번호 오름차순**으로 반환된다. 엔진은 로그마다 마지막으로 본 레코드
번호를 기억하고 그 이하를 "이미 기록함"으로 처리하므로, 번호가 작은 이벤트가 큰 이벤트보다
뒤에 오면 누락된다. 시각순 정렬로는 이를 보장할 수 없다 — 같은 초에 기록된 두 이벤트 사이에는
순서가 없다.

보안 로그에 던지는 두 질의가 같은 항목을 모두 잡아 한 패스에 같은 이벤트가 두 번 올 수 있다.
두 번째는 이미 전진한 마크에 걸려 건너뛰므로 한 번만 기록된다.
