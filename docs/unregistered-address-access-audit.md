# 미등록 IP 접속 시도 감사기록

## 1. 개요

**등록되지 않은 IP에서 접속을 시도하면 webadmin 이벤트 창(감사기록)에 기록됩니다.**

미등록 주소의 요청은 **엔진까지 도달하지 않습니다.** 웹 서버(httpd)가 `Require ip` 단계에서
403으로 차단하므로 엔진은 그 요청을 볼 수 없고, 그래서 이벤트 창에는 아무것도 남지 않았습니다.
누군가 주소를 바꿔가며 접속을 시도해도 관리자가 확인할 수 있는 곳이 없었습니다.

웹 서버가 차단할 때 남기는 기록이 그 시도에 대한 **유일한 기록**이므로, 엔진이 그 파일을 읽어
이벤트로 올립니다.

| 구성요소 | 위치 |
| --- | --- |
| 차단 기록 생성 | `packaging/conf/ovirt-engine-proxy.conf.v2.in` (CustomLog) |
| 기록 파일 | `/var/log/httpd/ovirt-engine-admin-access-denied-audit.log` |
| 파일 읽기·이벤트 등록 | `backend/manager/modules/bll/.../ClientAccessDeniedAuditManager.java` |
| 한 줄 해석 | `backend/manager/modules/bll/.../ClientAccessDeniedLog.java` |
| 서비스 등록 | `backend/manager/modules/bll/.../InitBackendServicesOnStartupBean.java` |
| 읽기 권한 부여 | `packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system/acl.py` |

## 2. 동작

```
 미등록 주소에서 접속 시도
     │
     ▼
 httpd: <RequireAny> 에 없는 주소 → 403 거부   (엔진에 도달하지 않음)
     │
     ▼
 CustomLog → /var/log/httpd/ovirt-engine-admin-access-denied-audit.log
     │
     ▼
 ClientAccessDeniedAuditManager (엔진, 60초 주기)
     │  마지막으로 읽은 위치부터 새로 추가된 줄만 읽음
     ▼
 audit_log 저장 → webadmin 이벤트 창에 표출
```

**엔진 기동 60초 후 시작하여 60초 주기로 확인합니다.** 파일을 처음부터 다시 읽지 않고 마지막으로
읽은 위치(offset)부터 읽으므로, 같은 시도가 두 번 기록되지 않습니다.

## 3. 기록 범위

```apache
CustomLog ".../ovirt-engine-admin-access-denied-audit.log" ovirt_admin_access_denied_audit \
  "expr=(%{REQUEST_STATUS} == 403) && (%{REQUEST_URI} =~ m#^/ovirt-engine#)"
```

**`/ovirt-engine` 이하 전체가 대상입니다.** 관리 화면(`/ovirt-engine/webadmin`)뿐 아니라
REST API(`/ovirt-engine/api`)와 로그인 페이지(`/ovirt-engine/sso`) 시도도 함께 기록됩니다.
`Require ip` 블록이 `/ovirt-engine` 전체를 보호하므로 차단 범위와 기록 범위를 일치시킨 것입니다.

기록 형식(LogFormat)은 엔진 쪽 해석기의 입력입니다. **한쪽을 바꾸면 다른 쪽도 함께 바꿔야
합니다**(`packaging/setup/tests/test_client_access_denied_audit.py`가 이 일치를 확인합니다).

```
time=2026-09-17T07:31:07+0900 remote_ip=192.168.40.50 request="GET /ovirt-engine/webadmin/ HTTP/1.1" status=403 referer="-" user_agent="Mozilla/5.0 ..."
```

## 4. 감사 로그

| 이벤트 | 코드 | 심각도 |
| --- | --- | --- |
| `CLIENT_ACCESS_DENIED_UNREGISTERED_ADDRESS` | 13657 | ERROR |

```
Access to the engine was denied to 192.168.40.50 because the address is not registered
at 2026-09-17T07:31:07+0900; request: GET /ovirt-engine/webadmin/ HTTP/1.1
```

**차단된 주소와 시도한 요청이 함께 기록**되므로, 어디서 무엇을 시도했는지 이벤트 창만으로
확인됩니다. engine.log에도 `미등록 주소 접속 거부; address=...; request=...` 형식으로 남습니다.

### 과다 기록 방지

주소를 훑는 시도는 네트워크 속도만큼 빠르게 발생합니다. 그것을 모두 이벤트로 올리면 이벤트 창의
다른 기록이 전부 묻히므로, **한 주기(60초)에 최대 20건까지만 개별 기록하고 나머지는 한 줄로
요약**합니다.

```
Access to the engine was denied to unregistered addresses 137 further times;
see /var/log/httpd/ovirt-engine-admin-access-denied-audit.log
```

요약된 시도도 httpd 로그 파일에는 그대로 남아 있으므로 원본 확인이 가능합니다.

### 파일을 읽을 수 없는 경우

읽을 수 없는 상태는 **아무도 시도하지 않는 상태와 화면상 구별되지 않습니다.** 그래서 침묵하지
않고 한 번(상태가 회복될 때까지 반복 없이) 이벤트로 알립니다.

```
Attempts from unregistered addresses are not being reported:
/var/log/httpd/ovirt-engine-admin-access-denied-audit.log - it cannot be read by the engine
```

## 5. 권한 요구사항

`/var/log/httpd`는 root 전용(0700)이므로 엔진(`ovirt` 사용자)은 기본 상태로 이 파일을 읽을 수
없습니다. engine-setup이 ACL을 부여합니다.

| 대상 | 권한 | 이유 |
| --- | --- | --- |
| `/var/log/httpd` | `x` | 디렉터리를 통과만 함(목록 조회는 불가) |
| `.../ovirt-engine-admin-access-denied-audit.log` | `r` | 파일 읽기 |

**로그 순환(logrotate) 후에도 유지되는 것은 디렉터리 ACL입니다.** 이 파일은 httpd 자체
순환 규칙(`/var/log/httpd/*log`)이 처리하며, 순환 시 파일이 교체되면서 파일에 걸린 ACL은 사라지지만
디렉터리는 교체되지 않고 새 파일은 이전 파일의 모드(0644)를 물려받으므로 읽기는 계속 가능합니다.
별도의 logrotate 설정을 추가하지 않은 이유도 이것으로, 같은 경로를 두 곳에서 선언하면 logrotate가
중복 항목 오류로 한쪽을 건너뜁니다.

파일이 교체되면 엔진은 **읽던 위치가 파일 크기보다 크다는 것으로 교체를 감지**하고 처음부터 다시
읽습니다. 마지막 확인 이후 순환 직전까지 기록된 줄은 유실될 수 있습니다(감사기록 원본은 DB의
`audit_log`이며, httpd 로그는 전달 경로입니다).

## 6. 확인 절차

```bash
# 1. 차단 기록이 쌓이는지 (미등록 주소의 단말에서 접속 시도 후)
tail -f /var/log/httpd/ovirt-engine-admin-access-denied-audit.log

# 2. 엔진이 그 파일을 읽을 수 있는지  ← 반드시 확인할 것
sudo -u ovirt test -r /var/log/httpd/ovirt-engine-admin-access-denied-audit.log \
  && echo "읽기 가능" || echo "읽기 불가"
getfacl /var/log/httpd /var/log/httpd/ovirt-engine-admin-access-denied-audit.log

# 3. SELinux가 막고 있지 않은지
ausearch -m avc -ts recent | grep -i httpd_log

# 4. 이벤트 등록 확인 (최대 60초 후)
psql -U engine -d engine -c \
  "select log_time, message from audit_log where log_type = 13657 order by log_time desc limit 10;"
```

2번이 "읽기 불가"이면 ACL을 직접 부여합니다(engine-setup을 다시 실행하지 않는 경우).

```bash
setfacl -m u:ovirt:x /var/log/httpd
setfacl -m u:ovirt:r /var/log/httpd/ovirt-engine-admin-access-denied-audit.log
```

3번에서 AVC 거부가 보이면 SELinux 정책 추가가 필요합니다.

```bash
ausearch -m avc -ts recent | audit2allow -M ovirt-engine-httpd-log
semodule -i ovirt-engine-httpd-log.pp
```

## 7. 적용

```bash
systemctl restart httpd          # CustomLog 범위 변경 반영
systemctl restart ovirt-engine   # 읽기 서비스 기동
```

---

**문서 버전**: 1.0
**최종 수정일**: 2026-09-17
