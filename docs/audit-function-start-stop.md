# 감사기능 시작·종료 기록

엔진 서비스(`ovirt-engine`)가 구동되면 **"감사기능 시작"**, 중지되면 **"감사기능 종료"**가 감사(이벤트) 목록에 기록된다.

## 1. 기록 내용

| 이벤트 | 코드 | 심각도 | 기록 시점 | 메시지 예 |
|---|---|---|---|---|
| `AUDIT_FUNCTION_STARTED` | 13689 | 정상 | 엔진 초기화 중, DB 연결 확인과 설정 로드 직후 (다른 기동 이벤트보다 먼저) | 감사기능 시작: 엔진 서비스 시작으로 감사 기록을 시작합니다 (엔진 4.5.x). |
| `AUDIT_FUNCTION_STOPPED` | 13690 | 정상 | 엔진 종료 처리(`@PreDestroy`) | 감사기능 종료: 엔진 서비스 중지로 감사 기록을 종료합니다 (엔진 4.5.x). |
| `AUDIT_FUNCTION_STOPPED` | 13690 | 정상 | 시작 기록 후 엔진 초기화가 실패한 경우 | 감사기능 종료: 엔진 서비스 초기화 실패로 감사 기록을 종료합니다 (엔진 4.5.x). |

- 한 번 구동될 때마다 시작 1건, 종료 1건이 기록된다. 시작 기록이 없으면 종료도 기록하지 않는다.
- `systemctl stop/restart ovirt-engine`, 보안검증 실패에 따른 서비스 정지(`SECURITY_VERIFICATION_SERVICE_HALTED`) 모두 정상 종료 경로를 거치므로 "감사기능 종료"가 남는다.
- 기록에 실패해도 엔진의 시작·중지는 막지 않으며, 원인은 engine.log에 `감사기능 … 기록 실패`로 남는다.
- engine.log에도 `감사기능 시작; 엔진 버전=…` / `감사기능 종료; 엔진 버전=…; 사유=…`가 남는다.
- 화면의 이벤트 이름: 감사기능 시작 / 감사기능 종료. 이벤트 알림(Engine 분류)에서 구독할 수 있다.

## 2. 해석

- "감사기능 시작" 뒤에 "감사기능 종료"가 없고 바로 다음 "감사기능 시작"이 오면, 그 사이에 엔진이 **정상 종료 절차 없이** 멈춘 것이다(강제 종료 `kill -9`, 프로세스 비정상 종료, 호스트 전원 차단 등). 이 경우 systemd journal(`journalctl -u ovirt-engine`)과 `/var/log/ovirt-engine/server.log`로 원인을 확인한다.
- 엔진이 멈춰 있는 동안에는 엔진 감사 기록이 생성되지 않는다. 그 구간은 "감사기능 종료"와 다음 "감사기능 시작" 사이로 확인할 수 있다.

## 3. 증빙 / 검증

```bash
systemctl restart ovirt-engine
grep -E "EVENT_ID: AUDIT_FUNCTION_(STARTED|STOPPED)" /var/log/ovirt-engine/engine.log | tail -2
```
```sql
SELECT log_time, log_type, log_type_name, message
  FROM audit_log
 WHERE log_type IN (13689, 13690)
 ORDER BY log_time DESC LIMIT 10;
```

시나리오:
- 재시작 → `AUDIT_FUNCTION_STOPPED`(중지) 다음에 `AUDIT_FUNCTION_STARTED`(시작)
- 보안검증 실패로 서비스 정지 → `SECURITY_VERIFICATION_SERVICE_HALTED` 다음에 `AUDIT_FUNCTION_STOPPED`
- `kill -9`로 엔진 강제 종료 후 기동 → 종료 기록 없이 시작 기록만 남음

## 4. 관련 소스

| 기능 | 파일 |
|---|---|
| 시작·종료 기록(1회 보장, 실패 시 엔진 유지) | `backend/.../bll/AuditFunctionLifecycle.java` |
| 기동·종료 연결 | `backend/.../bll/Backend.java` (`initialize`, `create`, `shutdown`) |
| 이벤트 정의·메시지 | `AuditLogType.java`, `AuditLogMessages.properties` |
| 화면 이름·알림 | `LocalizedEnums*.properties`, `VdcEventNotificationUtils.java` |
