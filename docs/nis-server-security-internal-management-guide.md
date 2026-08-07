# OV-Works 서버 공통보안 사내 관리지침

## 1. 문서 통제

| 항목 | 관리값 |
|---|---|
| 문서 소유자 | 정보보호책임자(CISO) 또는 지정 보안관리자 |
| 기술 소유자 | OV-Works 서비스 운영팀장 |
| 적용 대상 | OV-Works(oVirt Engine) 관리 서버, 연결 DB, Apache/SSO, 감사·무결성 점검 체계 |
| 검토 주기 | 분기 1회 및 제품·보안정책·검사기관 요구사항 변경 시 |
| 승인 주기 | 연 1회 및 중대한 통제 변경 시 |
| 증적 보존기간 | 조직의 감사기록 보존정책과 검사기관 요구기간 중 더 긴 기간 |
| 문서 등급 | 사내 보안정책에 따라 지정 |

> **사용 원칙:** 이 문서는 저장소에서 확인되는 통제를 회사가 지속적으로 운영하기 위한 기준이다. 국정원 또는 시험기관이 제공한 요구사항 원문의 문서명, 버전, 항목 ID와 판정기준은 회사가 보유한 최신 원본을 기준으로 별도 등록한다. 본 문서의 9개 관리항목이나 예시값을 공식 원문으로 인용하지 않는다.

### 1.1 개정 이력

| 버전 | 일자 | 변경 내용 | 작성 | 검토 | 승인 |
|---|---|---|---|---|---|
| 1.0 | 2026-08-07 | 소스 코드 기반 최초 제정 | 기입 | 기입 | 기입 |

## 2. 목적, 범위 및 판정 원칙

이 지침의 목적은 서버 공통보안 관련 통제를 담당자, 수행주기, 확인방법, 증적 및 미충족 조치와 연결해 사내에서 반복 관리하는 것이다. 제품 소스, 설치 서버의 설정, 외부 인프라와 실제 시험결과를 다음처럼 구분한다.

* **구현 확인:** 제어 흐름이 소스 또는 배포 template에 존재한다.
* **운영 확인:** 승인된 설정값이 대상 서버에 실제 적용되어 있다.
* **효과성 확인:** 정상·경계·부정시험에서 기대결과가 재현된다.
* **최종 적합:** 최신 요구사항 원문과 위 세 증적을 보안관리자가 대조하여 승인한다.

소스에 기능이 있다는 이유만으로 최종 적합으로 표시해서는 안 된다. 반대로 외부 AAA, 원격 syslog/SIEM, AIDE 기준선처럼 저장소 밖에서 완성되는 통제는 구성·시험 증적으로 판정한다.

## 3. 역할과 책임

| 역할 | 주요 책임 | 겸직 통제 |
|---|---|---|
| 정보보호책임자 | 정책·예외·잔여위험 최종 승인, 중대 사고 보고 판단 | 통제 수행자와 승인자를 가능한 한 분리 |
| 보안관리자 | 요구사항 원본 관리, 분기 점검, 감사기록 검토, 증적 봉인, 미충족 추적 | 자신의 특권작업은 다른 승인자가 검토 |
| 서비스 운영자 | 설정 적용, 백업·복구, 용량·인증서·서비스 상태 감시, 장애 초동조치 | 운영 변경은 승인 ticket와 연결 |
| 개발 담당자 | 보안기능 변경, code review, 단위·통합시험, 추적성 갱신 | 작성자 외 1인 이상 review |
| 감사자/검토자 | 증적의 완전성·무결성·재현성 확인, 예외 만료 확인 | 운영 write 권한을 부여하지 않음 |

## 4. 구성 및 자산 기준선

운영자는 환경별 자산대장에 최소한 Engine hostname/IP, 제품 version와 Git commit, OS/DB/Apache/AAA 유형, 로그·DB·archive 저장소, 원격 로그 수신지, 인증서 serial/만료일, AIDE database 위치를 등록한다. 비밀번호, private key, token, cookie, credential 원문은 대장과 증적에 기록하지 않는다.

배포 전에 다음 값을 회사 승인 기준선으로 확정한다. 아래 값 중 `600초`, `70/85/95%`, `365일`은 현재 저장소의 점검 목표 또는 기본값이며 공식 요구값을 대신하지 않는다.

| 기준선 | 저장소에서 확인되는 값/동작 | 운영 승인값 |
|---|---|---|
| 보호 관리자 로그인 실패/잠금 | SSO 설정에서 최대 실패 횟수와 잠금시간을 읽어 적용 | 환경별 값 기입 |
| session/idle timeout 점검 목표 | `600`초 또는 `10m`/`10min` 문자열을 점검 | 환경별 값 기입 |
| 감사 저장소 임계치 | 70% 경고, 85% 고경고, 95% 실패·긴급정리 시도 | 환경별 값 기입 |
| 오래된 감사파일 정리 기준 | 기본 365일 초과 파일만 archive 후 원본 삭제 | 환경별 값 기입 |
| 자체점검 timeout | 보안점검과 AIDE 각각 10분 | 환경별 값 기입 |
| 자체점검 결과 code | 0 성공, 20 통제실패, 40 실행오류, 75 중복실행 | 변경 금지/예외 기입 |

## 5. 통제 운영대장

| 관리 ID | 관리항목 | 책임자 | 최소 주기 | 필수 증적 | 현재 소스 기반 상태 |
|---|---|---|---|---|---|
| SRV-01 | 인증 실패 제한과 계정 잠금·해제 | 보안관리자 | 월 1회·변경 후 | 설정 마스킹본, 실패/잠금/해제 event, 시험표 | 부분 구현 |
| SRV-02 | session 만료 및 인증정보 재사용 방지 | 서비스 운영자 | 분기 1회·SSO 변경 후 | timeout 설정, 만료 전후 token 식별값의 hash, 재사용 거부 결과 | 부분 구현 |
| SRV-03 | 감사기록 조회와 권한분리 | 보안관리자 | 월 1회 | 역할목록, 권한 성공/거부 결과, 조회/export 결과 | 환경 확인 필요 |
| SRV-04 | 보안기능 자체시험 | 보안관리자 | 월 1회·배포 후 | JSON/log, exit code, 경보, 조치·재시험 | 구현 있음 |
| SRV-05 | 실행파일·보안설정 무결성 | 서비스 운영자 | 일 1회 권고·변경 후 | AIDE 결과, 기준선 승인·갱신 ticket, 변경목록 | 외부 기준선 필요 |
| SRV-06 | 잠금 해제와 활성 session 종료 | 보안관리자 | 분기 1회 | 승인 ticket, 수행자·사유·시각, 종료/해제 event | 일부 미확인 |
| SRV-07 | 비인가 단말 IP 차단과 기록 | 서비스 운영자 | 월 1회·allowlist 변경 후 | 설정 diff, `apachectl configtest`, 허용/차단 결과, 403 log | IP 제어 구현 |
| SRV-08 | 감사저장소 용량 예측·대응 | 서비스 운영자 | 일 1회 감시·월 추세검토 | 용량/inode/DB 추세, 임계치 경보, archive hash·복구시험 | file 용량점검 구현 |
| SRV-09 | 감사기록 저장 실패 시 손실 방지 | 보안관리자 | 분기 1회 | 장애주입, persistent queue, 재전송 count/sequence, 원격수신 결과 | 저장소 밖 보완 필요 |

## 6. 항목별 운영 절차

### 6.1 SRV-01 인증 실패 제한과 계정 잠금·해제

`AuthenticationService`는 보호 관리자에 한해 실패를 누적하고 임계치 도달 시 잠그며, 잠금 중 인증을 거부한다. 만료가 감지되면 상태를 초기화하고 `USER_ACCOUNT_UNLOCKED`를 남긴다. 성공 인증도 실패 상태를 초기화한다. 상태는 `AdminLoginLockoutService`의 process memory에 있으므로 재기동·다중 Engine 구성에서 보존/공유된다고 가정하지 않는다.

1. 운영값과 승인 ticket를 대조한다.
2. 허가된 시험계정으로 `임계치-1`, `임계치`, 잠금 중 올바른 비밀번호, 잠금 만료 후 로그인을 차례로 시험한다.
3. `USER_LOGIN_FAILED`, `USER_ACCOUNT_LOCKED`, `USER_ACCOUNT_UNLOCKED`의 사용자, 원본 IP, 횟수, 시각을 확인한다.
4. 내장 보호 관리자 외의 AAA 계정은 해당 provider의 잠금정책과 event를 별도 첨부한다.
5. 재기동/scale-out 시험 결과가 불충분하면 외부 AAA 잠금 또는 공유 상태 저장소를 보완통제로 등록한다.

### 6.2 SRV-02 session 만료 및 재사용 방지

`check_session_timeout_controls`는 알려진 세 구성파일에서 600초 상당의 문자열을 찾을 뿐 timeout을 강제하거나 실제 token 만료를 검증하지 않는다.

1. WebAdmin, REST API, websocket/console별 timeout 적용 지점을 등록한다.
2. 로그인 후 식별정보 원문 대신 session/token의 SHA-256 digest와 발급시각을 증적화한다.
3. 무활동 만료, logout, 재로그인 후 이전 credential의 재사용이 거부되고 새 값이 발급되는지 확인한다.
4. client와 server 시각을 동기화하고 경계값 직전/직후를 각각 시험한다.

### 6.3 SRV-03 감사기록 조회와 권한분리

`check_audit_query_capability`는 `audit_log` table의 존재·조회 가능 여부만 확인한다. 따라서 UI/API의 보안관리자 권한과 조회 전용 역할은 현장에서 입증한다.

1. 조회 전용, 보안관리, 무권한 계정을 각각 준비한다.
2. 기간·사용자·event 유형·원본 IP 검색, pagination, 시간대, export를 확인한다.
3. 무권한 직접 API/query가 거부되는지 확인한다.
4. 감사 조회 권한과 설정 변경 권한의 분리 여부를 월별 권한검토표에 기록한다.

### 6.4 SRV-04 보안기능 자체시험

승인된 service account가 `ovirt-engine-security-verification-runner.sh all <ticket-or-schedule-id>`를 실행한다. runner는 `flock` 중복 방지, 10분 timeout, 보안감사 JSON 판독과 AIDE 검사를 수행하며 실패를 `authpriv.err`로 통지한다.

* 결과 0만 성공으로 종결한다. 20은 보안기능 실패, 40은 실행환경 오류, 75는 중복 실행이므로 모두 ticket를 생성한다.
* audit의 `WARN`은 자동 적합으로 승격하지 않고 적용 제외 사유나 보완 결과를 승인받는다.
* script, runner 및 timer/unit 자체를 무결성 감시 대상에 포함한다.

### 6.5 SRV-05 실행파일·보안설정 무결성

runner는 `sudo -n aide --check`를 호출하지만 AIDE rule/database를 생성하지 않는다.

1. JAR, 배포 script, Apache/SSO/AAA/감사 설정, runner를 AIDE rule에 포함한다.
2. clean build/install 직후 2인이 최초 기준선 hash와 보관위치를 승인한다.
3. 예상된 변경은 변경목록과 대조 후 기준선을 갱신하고 구 기준선을 보존한다.
4. 미승인 변경은 서버를 격리하고 원본 보존, 영향분석, clean package 복구, credential 교체 여부 판단 후 재검사한다.

### 6.6 SRV-06 안전한 해제·종료

소스에서 자동 잠금 만료와 그 감사는 확인되지만, 관리자가 계정을 수동 해제하고 특정 활성 session을 즉시 종료하는 완결된 흐름은 본 지침 작성 범위에서 확인되지 않았다.

* 수동해제/강제종료는 요청자, 승인자, 대상, 사유, 수행자, 전후시각, 관련 event를 ticket에 남긴다.
* 기능이 없는 환경은 AAA에서 계정 disable/credential rotation 후 모든 token을 무효화할 수 있는 절차를 마련한다.
* 제품 기능 또는 검증된 보완통제가 없으면 `적합`으로 표시하지 않고 개선과제로 유지한다.

### 6.7 SRV-07 비인가 단말 IP 차단과 감사

Apache template의 `Require ip`가 접근을 강제하며 WebAdmin 경로의 403은 별도 `ovirt-engine-admin-access-denied-audit.log`에 시각, 원격 IP, request, status, referer, user-agent를 기록한다. 이 log는 header 값이 포함될 수 있으므로 신뢰 경계 밖의 입력으로 취급하고 중앙 수집 시 escaping/parsing을 검증한다.

1. allowlist 변경은 비상접속 IP를 확보한 뒤 2인 승인으로 수행한다.
2. 적용 전후 `apachectl configtest`와 설정 diff를 보존한다.
3. 허용·비허용 IP에서 각각 접속하고 비허용 요청의 403 및 denial log를 확인한다.
4. file owner/mode, logrotate, 원격전송, 보존기간과 시간동기화를 확인한다.
5. serial number 설정은 요청 차단 enforcement point가 확인되기 전에는 이 통제의 적합 근거로 사용하지 않는다.

### 6.8 SRV-08 감사저장소 손실 예측·대응

`check_audit_storage_capacity`는 file filesystem 사용률만 검사한다. 95%에서는 365일 초과 file을 같은 감사 directory 아래 archive한 뒤 성공 시 원본을 삭제하므로, 여유공간 부족과 동일 disk 장애 위험이 남는다.

* 일별로 filesystem 용량·inode와 DB tablespace를 감시하고 월별 증가율로 포화예상일을 계산한다.
* 70%는 증설계획, 85%는 별도 저장소 archive/offload, 95%는 incident로 처리한다.
* 삭제는 승인된 보존기간이 지난 자료에 한하고, 원격 archive의 SHA-256 검증과 표본 복구에 성공한 뒤 수행한다.
* `AUDIT_STORAGE_*_OVERRIDE`는 시험환경의 장애주입에만 사용하고 운영 service 환경에 영구 설정하지 않는다.

### 6.9 SRV-09 저장 실패 시 손실 방지

현재 자체점검은 `engine.log`의 실패 pattern을 탐지하고 runner 실패를 syslog로 통지하지만, DB/file 저장 실패 event의 무손실 queue/replay를 구현하지 않는다.

1. rsyslog 등에서 disk-assisted persistent queue와 TLS 원격수신을 구성한다.
2. 원격수신 중단, DB insert 실패, disk-full, read-only filesystem을 승인된 시험환경에서 주입한다.
3. 장애 중 local queue 증가, 별도 경보, 복구 후 replay를 확인한다.
4. 송신·수신 count와 sequence/time 범위를 대조해 누락 0건을 입증한다.
5. queue와 원격수신이 같은 장애영역에 있지 않은지 확인한다. 입증 전 최종 판정은 `판정 보류`로 둔다.

## 7. 정기점검 및 증적 관리

### 7.1 수행 일정

| 시점 | 수행사항 |
|---|---|
| 매일 | 자체점검 결과·AIDE·저장소 용량/inode·원격 로그 수신 상태 확인 |
| 매월 | SRV-01/03/04/07 점검, 권한 재검토, 용량 추세와 미해결 ticket 검토 |
| 분기 | 9개 통제 효과성 표본시험, session/queue replay/복구시험, 예외 만료 검토 |
| 변경 시 | 영향 통제 재시험, 추적성·기준선·문서 개정, rollback 확인 |
| 연간 | 요구사항 원본 최신성 확인, 위험 승인과 지침 재승인, 전 범위 모의심사 |

### 7.2 증적 파일명과 필수 metadata

파일명은 `<UTC일시>_<환경>_<관리ID>_<ticket>_<종류>` 형식을 사용한다. 각 증적에는 환경, hostname, 제품 version/commit, 수행자, 명령 또는 절차, 기대·실제 결과, exit code, UTC 시각, 연관 ticket를 기록한다. 원본을 read-only 저장소로 반출하고 manifest에 각 파일의 SHA-256을 기록한다. 화면 capture만 제출하지 말고 기계판독 가능한 log/JSON과 함께 보관한다.

다음 값은 수집 즉시 마스킹한다: password/passphrase, private key, session/token/cookie, DB 접속 비밀, Authorization header. 사용자명과 IP도 사내 개인정보·보안정책에 따라 접근권한과 반출범위를 제한한다.

### 7.3 점검결과 양식

| 관리 ID | 요구사항 원본 ID/페이지 | 대상/버전 | 운영값 | 시험결과 | 증적 URI/hash | 편차·위험 | 조치기한/담당 | 검토/승인 |
|---|---|---|---|---|---|---|---|---|
| SRV-__ | 기입 | 기입 | 비밀값 마스킹 | 적합/부적합/N/A | 기입 | 기입 | 기입 | 기입 |

## 8. 변경, 예외 및 사고 처리

1. 보안설정 변경은 요청, 영향분석, test 결과, 승인, 작업·rollback 계획을 갖춘다.
2. 긴급변경은 사후 1영업일 이내 독립 검토와 기준선 갱신을 완료한다.
3. 예외에는 적용대상, 미충족 이유, 위협·영향, 보완통제, 책임자, 만료일과 철회조건이 있어야 한다. 무기한 예외는 허용하지 않는다.
4. `FAIL`, 무결성 이상, 저장실패, 비인가 접근의 반복은 incident 절차로 전환해 증거를 보존한다. 조사 전에 log 삭제, AIDE 기준선 갱신 또는 재설치를 수행하지 않는다.
5. 조치 완료 후 동일 입력으로 재시험하고 원결과와 재시험결과를 함께 보존한다.

## 9. 소스 추적성

| 관리 ID | 구현·점검 근거 |
|---|---|
| SRV-01/06 | `backend/manager/modules/enginesso/src/main/java/org/ovirt/engine/core/sso/service/AuthenticationService.java`, `AdminLoginLockoutService.java` |
| SRV-02/03/08/09 | `ov-works-security_audit.sh`의 `check_session_timeout_controls`, `check_audit_query_capability`, `check_audit_storage_capacity`, `check_audit_write_failures` |
| SRV-04/05 | `ovirt-engine-security-verification-runner.sh`의 `run_security_audit`, `run_integrity_verification` 및 결과 code 처리 |
| SRV-07 | `packaging/conf/ovirt-engine-proxy.conf.v2.in`, `packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/apache/engine.py`, `backend/manager/modules/bll/src/main/java/org/ovirt/engine/core/bll/TerminalIpConfigUtils.java` |

상세 소스 판정과 제출 제한은 `docs/nis-server-common-security-requirements-compliance.md`, 실제 시험 설계는 `docs/security-test-evidence-plan.md`, 사고·저장소 대응은 `docs/security-control-action-plan.md`를 함께 사용한다.

DB 설정파일 암·복호화, WebAdmin ID/PW 검증 및 사설 SSL의 알고리즘·실패경로는 `docs/security-algorithm-flowcharts.md`를 사용한다.

## 10. 배포 전 승인 체크리스트

- [ ] 최신 요구사항 원본의 문서명·버전·ID·페이지를 통제대장에 연결했다.
- [ ] 자산대장과 승인 기준선에 실제 운영값을 기입했다.
- [ ] 9개 통제에 담당자, 일정, ticket와 증적 저장위치를 배정했다.
- [ ] 보호 관리자 외 AAA 계정의 잠금정책을 확인했다.
- [ ] session 만료 후 모든 관련 경로에서 이전 credential 재사용을 거부했다.
- [ ] 감사 조회와 설정 변경 권한을 분리하고 무권한 접근을 시험했다.
- [ ] 자체점검 WARN/FAIL/ERROR를 조치하거나 승인된 예외로 등록했다.
- [ ] AIDE rule/database와 기준선 보호·갱신 절차를 확인했다.
- [ ] WebAdmin 차단 403 log의 rotation·권한·원격수집을 확인했다.
- [ ] filesystem/inode/DB 용량과 archive 복구를 시험했다.
- [ ] 저장 장애 후 queue replay 누락 0건을 확인했다.
- [ ] 증적에서 모든 credential과 비밀정보를 마스킹했다.

