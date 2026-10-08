# 보안 검증 실패 대응 — 서비스 중단 표출

관련 보안요구사항: **서버공통 4.1.2 (자체시험 실패 대응기능 '서비스 중단'을 보여주는 화면)**,
**서버공통 4.2.4 (검증 실패 대응기능 표출)**

## 1. 개요

**자체 보안 검증 실패로 서비스가 중단된 사실이 화면에 표출됩니다.**

대응기능 자체는 이전부터 동작하고 있었습니다. `ovirt-engine.py`가 Java 데몬 기동 **전에** 자체 보안
검증을 필수 게이트로 수행하고, 실패하면 데몬을 기동하지 않습니다. 그러나 **그 사실을 볼 수 있는
화면이 없었습니다.**

- 서비스가 중단된 동안에는 엔진이 뜨지 않으므로 관리화면에 접속할 수 없고, 브라우저에는 웹 서버의
  기본 "Service Unavailable"만 표시되었습니다. 보안과 무관한 네트워크 장애처럼 읽힙니다.
- 서비스를 복구한 뒤에도, 차단 사실이 `SECURITY_AUDIT_FAILED`로 기록되어 "점검 항목이 실패한
  호스트가 계속 서비스한 경우"와 감사기록에서 구분되지 않았습니다.

따라서 **두 개의 화면**을 추가했습니다. 하나로 두 시점을 모두 담을 수 없기 때문입니다.

| 시점 | 화면 | 제공 주체 |
| --- | --- | --- |
| 서비스 중단 중 | 서비스 중단 안내 페이지 (HTTP 503) | 웹 서버(httpd) — 엔진이 죽어 있으므로 |
| 서비스 복구 후 | 보안 설정 → "보안 검증 실패 대응 (서비스 중단)" | 관리화면 |

| 구성요소 | 위치 |
| --- | --- |
| 기동 게이트·차단 기록 | `packaging/services/ovirt-engine/ovirt-engine.py.in` (`_runPreStartSecurityVerification`, `_refuseStart`, `_recordBlockedStart`) |
| 차단 기록 파일 | `/var/lib/ovirt-engine/security/last-failed-start.json` (0600) |
| 차단 기록 판독·감사기록 | `backend/manager/modules/bll/.../StartupSecurityAuditManager.java` (`reportBlockedStart`) |
| 사유 문안 | `backend/manager/modules/bll/.../SecurityAuditRunner.java` (`BlockedStart.describe`) |
| 감사기록 종류 | `backend/manager/modules/common/.../AuditLogType.java` (`SECURITY_VERIFICATION_SERVICE_HALTED`, 13666) |
| 중단 안내 페이지 | `packaging/conf/service-halted/service-halted.html` |
| 웹 서버 연결 | `packaging/conf/ovirt-engine-proxy.conf.v2.in` (`ErrorDocument 503`, `Alias`) |
| 경로 치환 | `packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/apache/engine.py`, `packaging/setup/ovirt_engine_setup/engine/constants.py` |
| 복구 후 화면 | `frontend/webadmin/.../popup/security/IntegrityCheckView.java` / `.ui.xml` |
| 시험 | `packaging/setup/tests/test_service_halt_screen.py`, `backend/.../TerminalIpConfigUtilsTest.java` |

## 2. 서비스 중단 중 표출 (HTTP 503 화면)

엔진이 기동되지 않으면 `mod_proxy_ajp`가 503을 반환합니다. 그 503에 전용 안내 페이지를 연결했습니다.

```apache
Alias /ovirt-engine-service-halted.html "/usr/share/ovirt-engine/conf/service-halted/service-halted.html"

<Directory "/usr/share/ovirt-engine/conf/service-halted">
    <RequireAny>
        Require ip 127.0.0.1
        Require ip <등록된 관리 단말>
    </RequireAny>
</Directory>

<LocationMatch ^/ovirt-engine($|/)>
    ProxyPassMatch ajp://127.0.0.1:<port> ...
    ErrorDocument 503 /ovirt-engine-service-halted.html
    ...
</LocationMatch>
```

### 설계 근거

- **`/ovirt-engine` 하위 경로가 아닙니다.** 그 접두사는 엔진으로 프록시되므로, 엔진이 죽었을 때
  표출할 페이지를 엔진이 서비스할 수는 없습니다.
- **전용 디렉터리입니다.** `<engine data>/conf` 전체를 웹 서버에 허용하면 그 안의 모든 템플릿과
  기본값 파일이 함께 노출됩니다.
- **등록된 관리 단말만 조회할 수 있습니다.** 503을 받은 요청은 이미 그 주소 목록을 통과한 요청입니다.
- **외부 자원을 전혀 참조하지 않습니다.** 스타일시트·스크립트·글꼴·이미지 모두 인라인입니다.
  엔진이 서비스하는 모든 것이 바로 이 페이지가 필요한 순간에 사용 불가 상태입니다.
- **원인을 단정하지 않습니다.** 웹 서버는 엔진이 왜 죽었는지 알 수 없습니다(단순 유지보수 정지일 수도
  있음). 페이지는 ① 서비스가 중단되었다는 사실, ② 보안 검증 실패 시 서비스를 중단한다는 정책,
  ③ 조치 방법을 서술합니다. 사유를 확인할 서버 내부 위치는 보안 규정에 따라 표시하지 않습니다.

### 페이지 내용

- 상태: "관리 엔진 서비스가 중단되었습니다" (HTTP 503)
- 정책: 자체 보안 검증은 기동 전 필수이며, 실패 시 데몬을 기동하지 않고 서비스를 중단함
- 사유 확인 방법은 **화면에 표시하지 않음**(보안 규정: 화면에 사유 기록 파일·로그 경로·명령어를
  노출하지 않음, 재기동 명령 포함). 운영자는 서버에서 `systemctl status ovirt-engine`, `last-failed-start.json`,
  `audit-results.json`, `engine.log`, `journalctl -u ovirt-engine`으로 확인하고,
  실패 항목 해소 후 `systemctl start ovirt-engine`으로 재기동한다.
- 조치: 실패 항목 해소 후 재기동, 다른 검증 진행 중이면 종료 후 재기동,
  차단 사유는 다음 정상 기동 시 감사기록에 자동 표출됨

### 병행 안전장치 (기존 기능 보호)

`TerminalIpConfigUtils`는 관리화면에서 단말 IP를 등록·해제할 때 설치된
`z-ovirt-engine-proxy.conf`의 `Require ip` 줄을 다시 씁니다. 기존 구현은 **첫 번째 블록만 갱신하고
나머지 블록의 `Require ip` 줄은 모두 삭제**했습니다. 블록이 하나뿐일 때는 문제가 없었지만, 본 변경으로
블록이 둘이 되므로 그대로 두면 단말을 한 번 등록하는 순간 두 번째 블록이
`<RequireAny></RequireAny>`(= 아무도 허용하지 않음)가 되어, 중단 사유를 설명하는 페이지가 가장 필요한
순간에 차단됩니다.

따라서 `updateRequireIpInContent()`가 **연속된 `Require ip` 구간마다** 목록을 기록하도록 수정했습니다.
모든 블록이 같은 단말 목록을 원하므로 모든 블록에 같은 목록을 씁니다. 블록이 하나인 설정에 대한
결과는 이전과 바이트 단위로 동일합니다(기존 단위 시험 22건 전부 통과).

## 3. 서비스 복구 후 표출 (관리화면)

**관리화면 → 보안 설정 → "보안 검증 실패 대응 (서비스 중단)"**

- 정책 설명(항상 표출)
- 중단 이력이 있으면 **빨간 배너**: 중단 건수 + 최근 중단 시각 + 사유(한글)
- 중단 이력이 없으면 **초록 배너**: "보안 검증 실패로 서비스가 중단된 이력이 없습니다."
- 중단 이력 목록(최대 10건): `시각 | 서비스 중단 | 사유(한글) | 원문 메시지`

### 사유 표기

차단 사유는 감사기록의 **custom data**에 코드로 실려 옵니다. 영문 산문에서 사유를 추출하면 문안이
한 번 바뀌는 순간 깨지므로, 코드를 별도로 전달합니다.

| 코드 (`SecurityAuditRunner.BlockedStart`) | 화면 표기 |
| --- | --- |
| `SECURITY_CHECKS_FAILED` | 자체 보안 검증 항목 실패 |
| `VERIFICATION_BUSY` | 다른 보안 검증 실행 중으로 검증 불가 |
| `RUNNER_MISSING` | 보안 검증 실행기 없음 |
| `VERIFICATION_ERROR` | 보안 검증 수행 오류 |
| (미기록) | 사유 미기록 |

## 4. 감사기록 변경

| 변경 | 내용 |
| --- | --- |
| 추가 | `SECURITY_VERIFICATION_SERVICE_HALTED` (13666, ERROR) |
| 변경 | 차단된 기동 보고 시 `SECURITY_AUDIT_FAILED` → `SECURITY_VERIFICATION_SERVICE_HALTED` |

두 기록은 서로 다른 사실입니다. `SECURITY_AUDIT_FAILED`는 "점검 항목이 실패했다"이고,
`SECURITY_VERIFICATION_SERVICE_HALTED`는 "그에 대한 대응으로 서비스를 기동하지 않았다"입니다.
하나의 종류로 묶으면 차단된 기동이 "점검 실패를 안고 계속 서비스한 호스트"와 구분되지 않고,
대응을 표출하는 화면도 찾을 대상이 없습니다.

부수 효과로, 차단 이력이 「자체 보안 검증」 섹션의 상태를 빨갛게 만들던 동작이 사라집니다.
직전 검증이 통과한 호스트의 자체시험 상태가 과거 차단 이력 때문에 실패로 보이던 문제입니다.

메시지 문안(`BlockedStart.describe`)은 다른 자체시험 실패 기록과 같은 `자체시험 실패 : <이유>` 형식입니다:

```
자체시험 실패 : 보안 점검에서 실패 항목이 확인됨 - 엔진 기동을 차단함 (엔진 기동 전, 2026-09-29 06:51:40, 성공 41·경고 3·실패 2)
```

## 5. 전체 흐름

```
기동 시도
  └ ovirt-engine.py: _runPreStartSecurityVerification()
       ├ 통과 → Java 데몬 기동 → StartupSecurityAuditManager가 결과를 감사기록에 표출
       └ 실패 → _refuseStart()
            ├ last-failed-start.json 기록 (시각·사유·종료코드·점검 집계)
            ├ RuntimeError → 데몬 기동 중지                    ← 대응기능
            └ 관리자가 접속 → httpd 503 → 서비스 중단 안내 화면  ← 중단 중 표출

복구 후 최초 정상 기동
  └ StartupSecurityAuditManager.reportBlockedStart()
       ├ last-failed-start.json 판독
       ├ SECURITY_VERIFICATION_SERVICE_HALTED 감사기록 (message=산문, customData=사유코드)
       ├ 파일 삭제 (삭제 실패 시 SECURITY_AUDIT_WARNING)
       └ 관리화면 "보안 검증 실패 대응 (서비스 중단)" 에 이력 표출  ← 복구 후 표출
```

## 6. 설치 경로

| 파일 | 설치 위치 |
| --- | --- |
| `packaging/conf/service-halted/service-halted.html` | `/usr/share/ovirt-engine/conf/service-halted/service-halted.html` |

`Makefile`의 `install-packaging-files`가 `packaging/conf`를 재귀 복사하며,
`ovirt-engine.spec.in`에 `%{engine_data}/conf/service-halted/`로 등록되어 있습니다.
AIDE 무결성 감시는 `/usr/share/ovirt-engine/ NORMAL` 규칙으로 이미 이 파일을 포함합니다.

## 7. 시험

`packaging/setup/tests/test_service_halt_screen.py` (13건):

- 503에 중단 안내 페이지가 연결되어 있음
- 안내 페이지 경로가 엔진으로 프록시되는 접두사 아래에 있지 않음
- engine-setup이 두 경로 토큰을 모두 치환하고, spec이 파일을 설치함
- 안내 페이지가 단말 IP 목록으로 보호됨
- 단말 등록이 두 번째 블록을 비우지 않음
- 안내 페이지가 외부 자원을 참조하지 않음
- 정책과 사유 확인 위치를 서술함
- 웹 서버가 알 수 없는 원인을 단정하지 않음
- 중단이 독립된 감사기록 종류임
- 사유 코드가 메시지와 별도로 전달됨
- 화면이 게이트가 쓸 수 있는 모든 사유를 한글로 표기함
- 화면이 중단 이력과 "이력 없음"을 표출함
- 중단이 자체시험 실패로 집계되지 않음

`TerminalIpConfigUtilsTest` (신규 2건 + 기존 20건):

- 목록이 모든 블록에 기록됨
- 단말 해제 시 모든 블록에 loopback이 남음
