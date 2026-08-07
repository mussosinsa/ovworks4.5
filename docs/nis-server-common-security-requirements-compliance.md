# 국정원 서버 공통보안 요구사항 항목별 적합성 및 근거

## 1. 문서 목적 및 판정 기준

본 문서는 OV-Works(oVirt Engine)의 **서버 공통보안 요구사항 9개 검토 항목**에 대하여 현재 저장소의 소스 코드만으로 확인 가능한 적합성 및 근거를 정리한다. 검사기관이 배포한 요구사항 원문의 문서명·버전·항목번호는 제출 시 해당 원본과 대조하여 표의 `요구사항 ID`에 기입해야 한다. 본 문서는 비공개 또는 미제공된 요구사항 원문을 임의로 인용하거나 공식 항목번호를 추정하지 않는다.

사내 담당자·주기·운영절차·증적·예외를 포함한 지속 관리에는 `docs/nis-server-security-internal-management-guide.md`를 사용한다.

### 1.1 판정 등급

| 판정 | 의미 |
|---|---|
| **적합** | 요구사항의 강제 로직과 성공·실패 처리가 소스에서 확인되고, 추가 구현 없이 시험 가능한 상태 |
| **부분 적합** | 핵심 로직 일부는 구현되어 있으나 배포 설정, 외부 구성요소, 운영 증적 또는 일부 보완이 필요한 상태 |
| **부적합** | 요구사항과 상충하는 로직이 확인되거나 필수 강제 기능이 없는 상태 |
| **판정 보류** | 저장소만으로 실제 배포 환경의 동작이나 요구사항 충족 여부를 판단할 수 없는 상태 |

> **중요:** 소스 코드 검토 결과와 설치 서버의 최종 적합 판정은 구분한다. `부분 적합` 또는 `판정 보류` 항목은 현장 시험 결과 없이 `적합`으로 제출하지 않는다.

## 2. 항목별 적합성 총괄

| 요구사항 ID | 서버 공통보안 검토 항목 | 소스 판정 | 핵심 근거 | 최종 적합 전 필수 보완·증적 |
|---|---|---|---|---|
| 공식 ID 기입 | 1. 인증 실패 횟수 제한 및 계정 잠금·해제 | **부분 적합** | 보호 관리자 계정에 대해 실패 횟수를 누적하고 임계치 도달 시 잠금하며, 잠금 만료 시 성공 처리와 unlock 감사를 수행함 | 실제 `maxFailures`, 잠금시간 설정값 및 5회 실패 현장시험 |
| 공식 ID 기입 | 2. 인증정보 재사용 방지(세션 만료·재발급) | **부분 적합** | SSO 세션/token 처리 구조와 600초 정책 점검 로직은 존재하나, 저장소의 정적 검토만으로 모든 WebAdmin 경로의 10분 강제 및 재발급을 확정할 수 없음 | 600초 설정, 만료 전·후 session ID/token 비교, 로그아웃 후 재사용 거부 시험 |
| 공식 ID 기입 | 3. 보안관리자의 감사기록 조회 | **부분 적합** | WebAdmin 감사 화면과 감사 로그 조회 기반은 존재하고 보안 명령은 권한 검사를 수행함 | 조회 전용/관리자 역할별 접근시험, 기간·사용자·이벤트 필터 및 내보내기 결과 |
| 공식 ID 기입 | 4. 보안기능 자체 시험 | **부분 적합** | 보안 감사 script와 실행 runner가 PASS/FAIL/ERROR, timeout, 중복 실행 방지 및 AIDE 연계를 제공함 | 패키지 설치 경로, 실행 권한, 정기 timer, 실제 JSON 결과 및 실패 시 경보 시험 |
| 공식 ID 기입 | 5. 실행파일·보안설정 무결성 검증 | **부분 적합** | SHA-256 기준선 및 AIDE 실행 경로가 문서·runner에 정의되어 있음 | 운영 기준선의 승인·보관 위치, 변조 탐지, 복구 및 기준선 갱신 이력 |
| 공식 ID 기입 | 6. 잠긴 계정/세션의 안전한 해제·종료 및 감사 | **부분 적합** | 관리자 계정 자동 잠금 만료와 unlock 감사는 확인되나, 관리자의 개별 WebAdmin session 강제 종료 기능 전체는 소스 근거가 불충분함 | 수동 계정 해제 권한, 강제 session 종료, 해제 사유 및 수행자 감사기록 시험 |
| 공식 ID 기입 | 7. 비인가 단말 IP 차단 및 감사기록 | **부분 적합** | Apache `Require ip`로 출발지 IP를 차단하고 IP 설정 변경 성공·실패 감사 이벤트를 생성함 | 차단된 HTTP 요청 자체의 원본 IP·시각·정책 ID가 감사 저장소에 기록되는지 시험 |
| 공식 ID 기입 | 8. 감사저장소 손실 예측 및 대응 | **부분 적합** | 감사 script가 사용률 70/85/95%를 구분하고 95%에서 365일 초과 로그를 압축·정리한 뒤 관리자에게 통지함 | 임계치 경보, archive 무결성·원격 반출 및 서비스 지속/정지 정책 시험 |
| 공식 ID 기입 | 9. 감사기록 저장 실패 시 손실 방지 | **판정 보류** | 일반 감사 로그 및 runner 오류 통지는 존재하지만 DB/file 기록 실패 시 보안 이벤트를 유실 없이 별도 queue에 보존·재전송하는 완결 로직은 확인되지 않음 | rsyslog persistent queue/SIEM 이중화, DB insert·disk-full 장애 주입 및 replay 증적 |

### 2.1 총괄 결론

현재 소스 검토 결과는 **적합 0개, 부분 적합 8개, 판정 보류 1개**이다. 이는 제품이 8개 항목을 위반한다는 의미가 아니라, 국가기관 제출용 최종 `적합` 판정에 필요한 **배포 설정과 부정시험 증적이 저장소에 포함되어 있지 않음**을 의미한다. 특히 감사저장 실패 시 무손실 queue/replay는 운영 인프라 구성 또는 추가 구현을 반드시 확인해야 한다.

## 3. 항목별 상세 근거

### 3.1 인증 실패 횟수 제한 및 계정 잠금·해제

**판정: 부분 적합**

* SSO 인증 전 보호 관리자 여부를 확인하고, 잠금 만료 시 실패 상태를 초기화한 뒤 `USER_ACCOUNT_UNLOCKED` 메시지를 application log와 audit notification에 기록한다.
* 잠금 중인 계정은 인증 extension 호출 전에 거부한다.
* 인증 실패 시 `AdminLoginLockoutService.recordFailure`에 사용자·시각·최대 실패 횟수·잠금시간을 전달한다. 임계치에 도달하면 `USER_ACCOUNT_LOCKED`, 미도달이면 `USER_LOGIN_FAILED`를 기록한다.
* 성공 인증 시 실패 상태를 초기화한다.

**제한 및 보완:** 이 제어는 소스상 `protectedAdmin`에 조건부 적용된다. 모든 WebAdmin/외부 AAA 계정에 공통 적용되는 것으로 확대 해석해서는 안 된다. 실제 설정에서 최대 실패 횟수가 요구값(예: 5회)인지, 재기동 또는 다중 Engine 환경에서도 실패 상태가 일관되게 유지되는지를 시험해야 한다.

**소스 근거:**

* `backend/manager/modules/enginesso/src/main/java/org/ovirt/engine/core/sso/service/AuthenticationService.java`
* `backend/manager/modules/enginesso/src/main/java/org/ovirt/engine/core/sso/service/AdminLoginLockoutService.java`
* `ov-works-security_audit.sh`의 `check_auth_failure_controls`

### 3.2 인증정보 재사용 방지

**판정: 부분 적합**

* SSO는 인증 결과를 session/token 문맥에 보관하고, 로그인·로그아웃·만료 흐름을 담당한다.
* 자체 감사 script는 알려진 Engine/SSO/proxy 설정에서 `600`, `10m`, `10min` 형태의 session/idle timeout 정책을 확인한다.
* 다만 해당 script의 검사는 문자열 기반 구성 점검이므로 그 자체가 600초 만료를 강제하지 않는다.

**제한 및 보완:** 정상 로그인 token을 저장한 뒤 600초 무활동, 로그아웃, 재로그인 각각에 대해 이전 token 재사용이 거부되고 새 token/session ID가 발급되는지 API 수준에서 검증해야 한다. WebAdmin, REST API, websocket/console 경로를 분리해 시험한다.

**소스 근거:**

* `backend/manager/modules/enginesso/src/main/java/org/ovirt/engine/core/sso/service/AuthenticationService.java`
* `ov-works-security_audit.sh`의 `check_session_timeout_controls`

### 3.3 보안관리자의 감사기록 조회

**판정: 부분 적합**

* oVirt Engine은 `AuditLogType`과 audit message bundle을 이용해 관리 명령의 성공·실패 이벤트를 생성한다.
* 단말 IP와 일련번호 설정 command는 System object의 action group을 이용해 권한을 검사하고 각 성공·실패 audit type을 반환한다.
* WebAdmin에는 감사 및 보안 관련 화면 구현이 존재한다.

**제한 및 보완:** “감사기록 조회” 권한과 “운영 설정 변경” 권한이 분리되어 있는지, 권한 없는 사용자가 직접 Query/API를 호출해도 거부되는지를 확인해야 한다. 검색 조건, 시간대, 대량 결과 pagination 및 내보내기 기능은 실제 화면/API 증적을 제출한다.

**소스 근거:**

* `backend/manager/modules/common/src/main/java/org/ovirt/engine/core/common/AuditLogType.java`
* `backend/manager/modules/dal/src/main/resources/bundles/AuditLogMessages.properties`
* `backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll/SetTerminalAuthCommand.java`
* `backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll/SetTerminalIpAuthCommand.java`

### 3.4 보안기능 자체 시험

**판정: 부분 적합**

* `ov-works-security_audit.sh`는 파일 권한, 인증서 만료, DB SSL/password encryption, firewall, SELinux, AAA, 인증 실패 및 session timeout 등을 점검하고 결과를 JSON과 로그로 생성한다.
* runner는 `flock`으로 동시 실행을 방지하고 10분 timeout을 적용한다.
* runner는 audit 결과 `PASS`, `FAIL`, 기타 오류를 각각 성공, 보안실패, 실행오류 exit code로 구분하며 실패를 `authpriv.err`로 통지한다.
* `all` 모드는 보안 감사와 AIDE 무결성 검사를 함께 수행한다.

**제한 및 보완:** 검사 대상이 설치되지 않은 경우 다수 항목은 WARN이 될 수 있다. 제출 시 WARN을 적합으로 간주하지 말고 N/A 사유 또는 보완 결과를 남겨야 한다. 실행 script 자체의 위·변조 방지와 실행 권한도 별도로 확인한다.

**소스 근거:**

* `ov-works-security_audit.sh`
* `ovirt-engine-security-verification-runner.sh`

### 3.5 실행파일·보안설정 무결성 검증

**판정: 부분 적합**

* runner의 integrity 모드는 `sudo -n aide --check`를 timeout 내 실행한다.
* AIDE 결과 0은 성공, timeout은 실행오류, 그 밖의 변경 탐지 결과는 보안실패로 분류한다.
* security audit에도 SHA-256 기준선 경로가 정의되어 있다.

**제한 및 보완:** 저장소에는 설치 서버의 AIDE database, 감시 규칙 및 승인된 최초 기준선이 포함되지 않는다. 따라서 JAR, 실행 script, 인증/암호/감사 설정이 실제 감시 범위에 들어가는지 현장 확인해야 한다. 기준선은 검사 대상 서버와 동일한 쓰기 권한 영역에 무보호 상태로 두지 않는다.

**소스 근거:**

* `ovirt-engine-security-verification-runner.sh`의 `run_integrity_verification`
* `ov-works-security_audit.sh`의 `INTEGRITY_BASELINE` 및 무결성 점검 함수
* `docs/security-verification-integrity-check.md`

### 3.6 잠긴 계정/세션의 안전한 해제·종료 및 감사

**판정: 부분 적합**

* 보호 관리자 계정의 잠금 만료가 감지되면 실패 상태를 초기화하고 사용자, 출발지 IP, 해제시각을 포함한 unlock audit message를 생성한다.
* 잠긴 상태의 로그인 재시도도 사용자, 출발지 IP, 잠금 만료시각과 함께 기록한다.

**제한 및 보완:** 현재 확인된 근거는 자동 잠금 만료에 집중된다. 관리자가 특정 사용자의 잠금을 수동 해제하거나 활성 SSO session을 즉시 종료하면서 수행자·사유를 감사기록으로 남기는 완결된 흐름은 별도 입증이 필요하다.

**소스 근거:**

* `backend/manager/modules/enginesso/src/main/java/org/ovirt/engine/core/sso/service/AuthenticationService.java`
* `backend/manager/modules/enginesso/src/main/java/org/ovirt/engine/core/sso/service/AdminLoginLockoutService.java`

### 3.7 비인가 단말 IP 차단 및 감사기록

**판정: 부분 적합**

* setup plugin은 IP/network를 표준 라이브러리로 검증·정규화하고 loopback을 항상 보존한다.
* Apache proxy의 `Require ip` 설정으로 비허용 출발지의 요청을 Engine 도달 전에 차단한다.
* WebAdmin 변경 경로는 단일 IPv4만 허용하여 Apache 지시어 삽입을 방지한다.
* 설정 변경 command는 권한을 검사하고 성공·실패 audit type을 생성한다.

**제한 및 보완:** 설정 **변경** 감사와 차단된 개별 **접속 시도** 감사는 서로 다르다. Apache access/error log 또는 연계 SIEM에서 원본 IP, 시각, 요청대상, 차단 정책을 기록하고 Engine audit와 연계할 수 있어야 최종 적합으로 판정한다. serial number는 enforcement point가 확인되지 않았으므로 이 항목의 적합 근거로 사용하지 않는다.

**소스 근거:**

* `packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/config/client_control.py`
* `backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll/TerminalIpConfigUtils.java`
* `backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll/SetTerminalIpAuthCommand.java`

### 3.8 감사저장소 손실 예측 및 대응

**판정: 부분 적합**

* security audit는 감사 로그 보존기간과 점검 결과 파일을 관리할 수 있는 기본 구조를 가진다.
* `check_audit_storage_capacity`가 audit filesystem 사용률을 측정하여 70%는 용량 계획 경고, 85%는 압축·archive·offload 경고, 95%는 FAIL로 분류한다.
* 95%에서는 365일을 초과한 감사 파일을 tar.gz archive로 먼저 생성하고 성공한 경우에만 원본을 삭제하며, mail/mailx 또는 syslog로 관리자에게 결과를 통지한다.

**제한 및 보완:** archive가 기본적으로 동일 audit filesystem 아래 생성되므로 95% 상황에서 archive 생성 공간이 부족할 수 있고, 원격 반출 성공을 확인한 후 삭제하는 구조도 아니다. filesystem뿐 아니라 inode와 DB tablespace를 정기 측정하고, 임계치 이전 알림 및 별도 저장소 반출을 입증해야 한다. 보존기간 이내 기록을 임의 삭제해서는 안 되며 archive의 hash·복구 시험도 필요하다.

**소스 및 운영 근거:**

* `ov-works-security_audit.sh`의 `AUDIT_RETENTION_DAYS`
* `docs/security-control-action-plan.md`의 감사기록 손실 예측 시 대응행동
* `docs/self-security-processing-specification.md`의 증적 보존·마스킹 절차

### 3.9 감사기록 저장 실패 시 손실 방지

**판정: 판정 보류**

* runner는 자체 점검 실패를 syslog `authpriv.err` 채널로 통지한다.
* 애플리케이션에는 audit type/message 생성 구조가 존재한다.

**제한 및 보완:** 동일 디스크 장애 시 application log와 syslog가 함께 손실될 수 있으며, DB insert 실패 이후의 보존 queue/replay가 본 검토 범위에서 확인되지 않았다. 다음 모두를 현장 시험으로 입증해야 한다.

1. 원격 로그 서버 또는 SIEM으로의 TLS 보호 전송과 persistent queue
2. 원격지 장애 중 로컬 queue 적재 및 복구 후 순서 보존 재전송
3. audit DB insert 실패·disk full·read-only filesystem 장애 주입
4. 저장 실패 자체의 별도 경보와 운영자 인지시간
5. 복구 전·후 sequence/count 대조를 통한 누락 0건 확인

위 증적이 없으면 본 항목은 `적합`으로 판정하지 않는다.

**소스 및 운영 근거:**

* `ovirt-engine-security-verification-runner.sh`
* `backend/manager/modules/common/src/main/java/org/ovirt/engine/core/common/AuditLogType.java`
* `docs/security-control-action-plan.md`의 감사기록 손실 방지 절차

## 4. 제출용 적합성 근거표 작성 방법

검사기관 양식에는 각 항목마다 다음 6종 증적을 연결한다.

| 증적 구분 | 제출 내용 |
|---|---|
| 요구사항 원문 | 검사기관 문서명, 버전, 공식 항목번호와 원문 페이지 |
| 설계 근거 | 본 문서의 해당 절과 보안기능 ID |
| 소스 근거 | Git commit ID, 파일 경로, class/function 및 line 범위 |
| 설정 근거 | 실제 설치 서버의 적용값(비밀값 마스킹), 파일 권한 및 서비스 상태 |
| 시험 근거 | 정상·경계·부정시험 명령, 입력, 기대결과, 실제결과, exit code |
| 운영 근거 | 변경승인, 담당자, 수행시각, 경보·장애조치 및 재시험 이력 |

최종 판정자는 `소스 판정`을 그대로 복사하지 않고 요구사항 원문과 현장 증적을 대조해 `적합/부적합/N/A`를 확정한다. 요구사항과 무관한 기능의 존재, 실행하지 않은 시험의 예시 출력, 운영 예정 사항은 적합 근거로 사용하지 않는다.

## 5. 최종 제출 전 체크리스트

- [ ] 검사기관 요구사항 문서의 정확한 명칭·버전·공식 ID·원문 페이지를 기입했다.
- [ ] 각 `부분 적합` 항목에 현장 정상/부정시험 결과를 첨부했다.
- [ ] 인증 실패 임계치와 잠금시간이 실제 설정값 및 시험 결과와 일치한다.
- [ ] 600초 만료 후 이전 session/token의 재사용이 모든 관련 경로에서 거부된다.
- [ ] 감사 조회 권한과 설정 변경 권한의 분리를 시험했다.
- [ ] 자체 시험의 FAIL/ERROR/WARN을 숨기지 않고 조치 및 재시험 이력을 첨부했다.
- [ ] AIDE 감시 대상과 기준선의 승인·보호·갱신 이력을 첨부했다.
- [ ] 수동 잠금 해제와 session 강제 종료의 수행자·사유 감사기록을 확인했다.
- [ ] 비허용 IP의 개별 차단 이벤트가 원본 IP와 함께 기록된다.
- [ ] 감사저장소 임계치 경보 및 disk-full 사전 대응을 시험했다.
- [ ] 로그 수신지 장애 및 복구 후 queue replay에서 누락이 0건임을 대조했다.
- [ ] PW, passphrase, private key, session/token/cookie, DB 접속 암호를 모든 제출 증적에서 마스킹했다.
