# 감사기록 저장소 용량 대시보드

관련 보안요구사항: **서버공통 7.4.1 — 저장소 일정 용량 초과 시 대시보드 화면 / 알람 화면**

## 1. 개요

**감사기록 저장소의 사용량이 관리화면에 상시 표출됩니다.**

엔진은 이전에도 감사기록 저장소를 1분 주기로 측정하여 잔여 용량이 부족하거나 한도를 초과하면
알람(`AuditLogSeverity.ALERT`)을 발생시켰습니다. 그러나 **알람은 이미 문제가 된 뒤에 알려주는 것**이고,
"지금 얼마나 찼는지"를 볼 수 있는 화면은 없었습니다. 즉 상태를 *확인*할 수는 없고 *기다릴* 수만
있었습니다. 본 변경은 그 측정값을 화면으로 표출합니다.

| 구성요소 | 위치 |
| --- | --- |
| 측정·상태 판정 | `backend/manager/modules/bll/.../AuditLogCapacityMonitor.java` |
| 상태 전달 객체 | `backend/manager/modules/common/.../businessentities/AuditLogCapacityStatus.java` |
| 조회 질의 | `backend/manager/modules/bll/.../GetAuditLogCapacityStatusQuery.java` |
| 질의 등록 | `backend/manager/modules/common/.../queries/QueryType.java` (`GetAuditLogCapacityStatus`) |
| GWT 직렬화 허용 | `frontend/webadmin/modules/gwt-common/.../Common.gwt.xml` |
| 대시보드 화면 | `frontend/webadmin/.../popup/security/AuditLogProtectionTabView.java` / `.ui.xml` |
| 알람 화면 | `frontend/webadmin/.../models/events/AlertListModel.java` (`Events: severity=alert`) |
| 단위 시험 | `backend/manager/modules/bll/src/test/.../AuditLogCapacityMonitorTest.java` |

## 2. 화면 위치

**관리화면 → 감사기록 → 「감사기록보호」 탭 → 최상단 "감사기록 저장소 용량"**

같은 탭의 아래쪽이 「감사기록 보호」(백업·복구)입니다. 용량 표출을 위에 둔 이유는, 저장소가 차오를 때
관리자가 취하는 조치가 바로 그 백업·보관이기 때문입니다.

표출 항목:

| 항목 | 내용 |
| --- | --- |
| 상태 | 정상 / 경고 (잔여 용량 부족) / 초과 (한도 도달) / 감시 중지 / 측정 불가 |
| 사용량 막대 | 한도 대비 사용률(0~100%), 상태에 따라 초록·주황·빨강 |
| 저장 위치 | `ENGINE_AUDIT_LOG_DIR` (기본 `/var/log/ovirt-engine`) |
| 사용량 / 한도 | MiB 단위, 사용률·잔여율 함께 표출 |
| 경고 임계값 | 잔여 5% 이하 (`AuditLogCapacityMonitor.WARNING_REMAINING_PERCENT`) |
| 측정 시각 | 측정된 시각과, 그것이 감시 주기의 값인지 이번 조회 시 측정한 값인지 |
| 새로 고침 | 「용량 새로 고침」 버튼. 화면이 열려 있는 동안 60초마다 자동 갱신 |

화면을 닫으면 자동 갱신 타이머가 해제됩니다(`onUnload`). 해제하지 않으면 관리자가 열었던 모든 탭이
브라우저가 열려 있는 동안 계속 조회를 반복합니다.

## 3. 상태 판정

`AuditLogCapacityMonitor.capacityState()`

| 상태 | 조건 |
| --- | --- |
| `EXCEEDED` (초과) | 사용량 ≥ 한도 |
| `WARNING` (경고) | 사용량 < 한도이고 잔여율 ≤ 5% |
| `NORMAL` (정상) | 그 외 |
| `DISABLED` (감시 중지) | `ENGINE_AUDIT_LOG_MAX_SIZE_MB` 또는 `ENGINE_AUDIT_LOG_CAPACITY_CHECK_INTERVAL_SECONDS` 가 0 이하 |
| `UNAVAILABLE` (측정 불가) | 감시는 켜져 있으나 디렉터리를 측정할 수 없음 |

`DISABLED`·`UNAVAILABLE`을 별도 상태로 둔 이유: 이 두 경우를 0으로 표출하면 화면에는 **"저장소가
비어 있음"** 으로 보입니다. 측정되지 않고 있다는 사실 자체가 관리자가 가장 먼저 알아야 하는 내용이며,
빈 화면으로 추측하게 두어서는 안 됩니다.

`UNAVAILABLE`일 때는 직전 측정값을 남겨두지 않습니다. 남겨두면 디렉터리를 읽을 수 없게 되기 *전*의
수치가 계속 표출되어, 더 이상 측정되지 않고 있다는 사실이 화면에서 사라집니다.

사용량 막대는 100%에서 잘립니다(`AuditLogCapacityStatus.getUsedPercent()`). 사용량은 한도를 넘을 수
있으므로(그것이 `EXCEEDED`의 의미) 막대를 100% 넘게 그리면 화면 오류로 보입니다. 실제 사용 바이트는
`getUsedBytes()`로 그대로 표출됩니다.

## 4. 측정 경로

측정 대상은 **엔진 호스트의 디렉터리**이므로 DB 조회로는 알 수 없습니다. 따라서 화면은 이미 측정을
수행하고 있는 구성요소에 묻습니다.

```
AuditLogCapacityMonitor (BackendService, @Singleton)
  @PostConstruct → configure()               설정 판독 (경로·한도·주기 보관)
                 → executor.scheduleWithFixedDelay(checkCapacity, 주기)
  checkCapacity() → calculateDirectorySize() 측정
                  → lastReading 보관          (판정 전에 보관: 보고할 것이 없는 회차도 표출)
                  → 임계값 전이 시 알람 발생   (기존 동작 그대로)
  getStatus()     → lastReading 반환
                  → 아직 없으면 1회 즉시 측정 (기동 직후 1분간 빈 화면 방지)
```

`getStatus()`는 감시가 꺼져 있어도 응답합니다. 즉시 측정한 값은 `measuredOnDemand = true`로 표시되어
화면에서 "이번 조회 시 측정"으로 구분됩니다. 감시 주기의 값과 즉시 측정값은 신선도가 다르므로 같은
것으로 읽히면 관리자가 갱신되지 않는 화면을 계속 새로 고치게 됩니다.

## 5. 알람 화면과의 관계

용량 초과·경고 시점에는 대시보드 표출과 **동시에** 알람이 발생합니다. 알람 감사기록은 기존 그대로이며
본 변경으로 바뀌지 않았습니다.

| 감사기록 | 값 | 심각도 | 중복 억제 |
| --- | --- | --- | --- |
| `AUDIT_LOG_CAPACITY_WARNING` | 13634 | ALERT | 1시간 |
| `AUDIT_LOG_CAPACITY_EXCEEDED` | 13635 | ALERT | 1시간 |
| `AUDIT_LOG_CAPACITY_MONITOR_STARTED` | 13646 | NORMAL | 1시간 |
| `AUDIT_LOG_CAPACITY_RECOVERED` | 13647 | NORMAL | — |

`ALERT` 심각도는 `AlertListModel`이 `Events: severity=alert`로 조회하므로 관리화면 상단의 **알람
드롭다운(종 모양)과 건수 배지**에 표출됩니다(`HeaderPresenterWidget.setAlertCount`). 대시보드는
"지금 얼마나 찼는가", 알람은 "임계값을 넘은 시점"을 각각 담당합니다.

## 6. 설정값

| 설정 | 기본값 | 의미 |
| --- | --- | --- |
| `ENGINE_AUDIT_LOG_DIR` | `/var/log/ovirt-engine` | 측정 대상 디렉터리 |
| `ENGINE_AUDIT_LOG_MAX_SIZE_MB` | 1024 | 한도(MiB). 0 이하면 감시 중지 |
| `ENGINE_AUDIT_LOG_CAPACITY_CHECK_INTERVAL_SECONDS` | 60 | 측정 주기(초). 0 이하면 감시 중지 |

변경 후 엔진 재시작이 필요합니다(`packaging/etc/engine-config/engine-config.properties`에
"restart required"로 명기). 관리화면의 환경변수 화면에서 변경할 수 있습니다.

## 7. 접근 권한

`QueryType.GetAuditLogCapacityStatus`는 `QueryAuthType`을 지정하지 않으므로 **관리자(Admin) 전용**입니다.
저장소 경로와 잔여 용량은 일반 사용자에게 표출되지 않습니다.

## 8. 시험

`AuditLogCapacityMonitorTest` (`MockConfigExtension` + Mockito):

- 잔여 5% 경계 판정, 한도 도달은 경고가 아니라 초과로 판정
- 상태 판정(정상/경고/초과), 한도 초과 시에도 초과 상태 유지
- 사용량 막대 100% 상한, 한도 0에서 0% 반환(0으로 나누지 않음)
- 설정 미판독 시 `DISABLED` 응답(빈 화면 아님)
- 설정이 명시한 경로·한도·주기 판독
- 최초 조회 시 즉시 측정, 두 번째 조회는 보관된 값 재사용
- 감시 주기 측정값 표출, 경고 상태 및 잔여율
- 측정 실패를 빈 저장소로 표출하지 않고 직전 수치도 남기지 않음
- 심볼릭 링크를 따르지 않는 재귀 측정
