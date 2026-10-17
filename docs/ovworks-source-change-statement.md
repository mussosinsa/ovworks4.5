# OV-Works 소스 변경 내역서 (오픈소스 기반 및 수정 범위)

| 항목 | 내용 |
|---|---|
| 제품명 | OV-Works 2.4 (세부버전 V2.4.5.9) |
| 구성요소 | OV-Works Engine 4.5.7-1.el9 |
| 기반 오픈소스 | oVirt Engine 4.5.6 (Apache License 2.0) |
| 대상 저장소 | `mussosinsa/ovworks4.5`, 브랜치 `claude/tender-dijkstra-gs8tw1` |
| 대상 커밋 | `bc4ef823b1a7fbb119135ecf6dd52063c74de978` (2026-10-17) |
| 작성일 | 2026-10-17 |
| 관련 문서 | 부록 `docs/ovworks-change-inventory-appendix.md`(파일별 전체 목록), `docs/ovworks-sbom.md`(오픈소스 구성요소 목록) |

---

## 1. 요약

OV-Works Engine은 오픈소스 **oVirt Engine 4.5.6**(Apache License 2.0)을 기반으로, 보안기능 요구사항에 맞춘
기능을 **새로 개발**하고 일부 **upstream 파일을 수정**하여 만든 제품이다.

| 구분 | 파일 수 | 줄 수 | 설명 |
|---|---:|---:|---|
| **신규 개발**(제품 코드) | 272 | +39,512 | OV-Works에서 새로 작성한 파일. upstream에 없음 |
| **upstream 수정**(제품 코드) | 292 | +10,220 / −955 | upstream oVirt 파일을 고친 것 |
| **upstream 삭제** | 15 | −384 | upstream CI·저장소 관리 파일. 제품 기능과 무관 |
| 신규·수정 시험 코드 | 143 | +19,184 / −12 | 단위 시험(Java JUnit, Python unittest) |
| 신규·수정 문서 | 59 | +16,785 | 설계·명세·시험 문서 |
| **upstream 미변경** | 11,506 | — | upstream 전체 11,821개 파일 중 97.3% |

- upstream 파일 11,821개 중 **300개(2.5%)를 수정**했다(제품 코드 292, 시험 코드 7, 문서 1). 15개는 삭제했고, 나머지 11,506개(97.3%)는 원본 그대로다.
- 제품 코드 기준으로 새로 추가된 줄의 **79%(39,512줄)가 신규 파일**이다. upstream 파일 안의 수정은 10,220줄이다.
- 신규 개발 코드는 Java 27,044줄, Python 9,020줄, 셸 1,351줄, XML 1,307줄, SQL 369줄이다. 나머지는 설정·서비스 파일이다.
- 의존 오픈소스는 upstream 구성을 그대로 쓴다. 보안 보완을 위해 일부 라이브러리 **버전을 올리고 4종을 추가**했다(§8, SBOM 문서).

## 2. 기반 오픈소스(upstream) 정보

| 항목 | 내용 |
|---|---|
| 프로젝트 | oVirt Engine (The oVirt Project) |
| 저장소 | https://github.com/oVirt/ovirt-engine |
| 기준 태그 | `ovirt-engine-4.5.6` |
| 기준 커밋 | `eb315a9d37f3bb9da3061c658112e449cadec30b` ("build: ovirt-engine-4.5.6", 2024-02-09) |
| 라이선스 | Apache License 2.0 (`LICENSE`, `ASL2`, `NOTICE`, 패키지 `License: ASL 2.0`) |
| 저작권 표기 | Copyright oVirt Authors (upstream `NOTICE`) |
| 반입 시점 | 저장소 최초 커밋 `554a154b`(2026-08-07). 이 커밋이 이미 기준 태그에 사이트 변경을 얹은 상태이므로, 비교 기준은 최초 커밋이 아니라 upstream 태그로 잡았다 |

`LICENSE`, `ASL2`, `NOTICE` 파일은 upstream과 **동일하게 유지**한다(변경 없음).

## 3. 판정 기준과 방법

### 3.1 구분 정의

| 구분 | 정의 | 판정 |
|---|---|---|
| 신규 개발 | upstream 기준 태그에 없는 경로의 파일 | `git diff --name-status` 상태 `A` |
| 수정 | upstream 기준 태그에 있는 파일의 내용을 바꾼 것 | 상태 `M` |
| 삭제 | upstream 기준 태그에 있던 파일을 제거한 것 | 상태 `D` |
| 미변경 | upstream과 내용이 같은 파일 | diff에 나타나지 않음 |

- 이름 변경은 삭제와 신규로 따로 센다(`--no-renames`). upstream 파일을 옮겨 고친 것이 "신규"로 보이지 않게 하기 위해서다. 이번 비교에는 이름 변경이 없다.
- 줄 수는 `git diff --numstat` 기준이다. 바이너리 파일은 줄 수를 세지 않는다.

### 3.2 재현 방법

누구나 같은 결과를 얻을 수 있도록, 부록을 git으로 다시 생성하는 스크립트를 함께 제공한다.

```bash
git fetch --depth 1 https://github.com/oVirt/ovirt-engine \
    refs/tags/ovirt-engine-4.5.6:refs/upstream/ovirt-engine-4.5.6
git diff --shortstat refs/upstream/ovirt-engine-4.5.6 bc4ef823b1a7
#  781 files changed, 85701 insertions(+), 1351 deletions(-)
python3 docs/tools/change_inventory.py --head bc4ef823b1a7fbb119135ecf6dd52063c74de978
```

기능 분류는 스크립트 안의 경로 규칙(`RULES`)으로 정한다. 규칙을 위에서부터 차례로 적용해 처음 맞는 분류를 쓴다.

## 4. 변경 규모

### 4.1 기능 분류별 합계 (시험 코드·문서 포함)

| 코드 | 기능 분류 | 신규 | 수정 | 삭제 | 추가 줄 | 삭제 줄 |
|---|---|---:|---:|---:|---:|---:|
| F01 | 인증·로그인 보안 | 40 | 30 | 0 | 5,956 | 148 |
| F02 | 세션 관리 | 14 | 16 | 0 | 2,173 | 65 |
| F03 | 단말 접근 통제(단말기 IP·전용 IP·단말 시리얼) | 29 | 2 | 0 | 3,406 | 0 |
| F04 | 감사 기록·감사 저장소·알림 | 45 | 12 | 0 | 8,289 | 17 |
| F05 | 자체시험·무결성 검증 | 33 | 0 | 0 | 7,110 | 0 |
| F06 | 암호 키 관리·암호화·DB 인증 | 30 | 23 | 0 | 9,210 | 198 |
| F07 | 가상머신 보안 통제 | 17 | 26 | 0 | 4,302 | 73 |
| F08 | 사용자·그룹·권한 관리 | 39 | 16 | 0 | 4,416 | 19 |
| F09 | 보안 설정 화면·엔진 설정 | 19 | 64 | 0 | 3,896 | 98 |
| F10 | 백업·복구 | 5 | 2 | 0 | 427 | 10 |
| F11 | 제품화·한국어화·버전 표기 | 0 | 89 | 0 | 256 | 196 |
| F12 | 빌드·패키징·의존성 | 1 | 12 | 15 | 291 | 515 |
| F13 | 시험 코드 | 136 | 7 | 0 | 19,184 | 12 |
| F14 | 문서 | 58 | 1 | 0 | 16,785 | 0 |
| | **합계** | **466** | **300** | **15** | **85,701** | **1,351** |

### 4.2 모듈별 분포 (제품 코드)

| 모듈 | 역할 | 신규 | 수정 |
|---|---|---:|---:|
| `backend/manager/modules/bll` | 엔진 업무 로직(명령·조회·감사) | 69 | 30 |
| `frontend/webadmin/modules/webadmin` | 관리 포털 화면 | 53 | 31 |
| `backend/manager/modules/common` | 공용 엔티티·명령 정의 | 25 | 13 |
| `packaging/dbscripts` | DB 스키마·업그레이드 스크립트 | 25 | 4 |
| `backend/manager/modules/enginesso` | SSO(로그인) | 16 | 19 |
| `packaging/setup` | engine-setup / engine-cleanup 플러그인 | 12 | 44 |
| `backend/manager/modules/uutils` | 공용 유틸(암호·보안 검사) | 10 | 6 |
| `packaging/bin` | 운영 도구 스크립트 | 9 | 5 |
| `packaging/encryptor` | 설정 암호화·키 관리 도구 | 8 | 0 |
| `packaging/services` | 서비스 런처·systemd 단위 | 8 | 6 |
| `backend/manager/modules/dal` | DB 접근 계층 | 8 | 4 |
| `frontend/webadmin/modules/uicommonweb` | 화면 모델 | 7 | 21 |
| `backend/manager/modules/aaa` | 인증 필터 | 5 | 10 |
| `backend/manager/modules/restapi` | REST API | 0 | 10 |
| 그 외 | gwt-common, services, welcome, tools, pythonlib, conf, 각 모듈 pom 등 | — | — |

(시험 코드·문서는 뺀 수치다. 모든 파일은 부록에 있다.)

## 5. 기능별 변경 내용

각 기능은 **신규 개발**과 **upstream 수정**으로 나눠 적는다. 파일 전체 목록은 부록에 있다.

### F01 인증·로그인 보안
- **목적**: 비밀번호 정책, 로그인 실패 잠금, 로그인 정보 암호화 전송, 재전송·입력값 공격 차단.
- **신규 개발**
  - 비밀번호 정책 엔진: `uutils/security/PasswordPolicy*`, `PasswordHistory*`, `LoginInputPolicy`
  - 계정 잠금: `sso/service/LoginLockout`, `UserLoginLockoutService`, `AdminLoginLockoutService`, `bll/aaa/UserLoginLockoutExpiryManager`
  - 로그인 정보 RSA 암호화 전송: `sso/servlets/RsaPublicKeyServlet`, `sso/utils/LoginEnvelope*`, `aaa/RsaCredentialsDecryptor`
  - 재전송 차단·입력 감사: `LoginFormNonce`, `LoginReplayGuard`, `LoginReplayAudit`, `LoginInputAudit`
  - DB: `user_login_failures_sp.sql`, `user_password_history_sp.sql`, 업그레이드 `04_05_0320~0329`, `0341`
- **upstream 수정**
  - SSO 인증 흐름: `AuthenticationService`, `OAuthTokenServlet`, `InteractiveAuthServlet`, `InteractiveChangePasswdServlet`, `SsoDao`
  - 로그인·비밀번호 변경 화면: `login.jsp`, `credentialsChange.jsp`
  - setup 관리자 비밀번호 정책: `config/aaa.py`, `config/aaajdbc.py`
- 관련 문서: `password-policy-and-first-login-change.md`, `user-account-lockout.md`, `login-credential-crypto-audit.md`, `login-input-restriction.md`

### F02 세션 관리
- **목적**: 동시 세션 수 제한, 수퍼유저 단일 접속, 종료된 세션의 재사용 차단, 유휴 시간 처리.
- **신규 개발**: `aaa/filters/SessionReplayGuardFilter`, `RestApiSessionStatusFilter`, `RestApiLogoutFilter`, `bll/aaa/RegisterHttpSessionCommand`, `BlockReplayedSessionCommand`, `GetSessionStatusQuery`, `SetEngineSessionLimitCommand`, 세션 종료 사유 `SessionEndReason`
- **upstream 수정**: `SessionDataContainer`(세션 수·단일 세션 규칙), `RestApiSessionMgmtFilter`, `TerminateSessionCommand`, `ValidateSessionQuery`, `QueriesCommandBase`(세션 상태 조회가 유휴 시간을 연장하지 않게 함), 세션 화면 `MainSessionView`, `SessionListModel`
- 관련 문서: `concurrent-session-management.md`, `single-super-user-session.md`

### F03 단말 접근 통제
- **목적**: 등록 단말기 IP만 접속 허용(Apache `Require ip`), 사용자 전용 IP, 단말 시리얼(`X-Client-Serial`) 검사, 미등록 주소 접속 감사.
- **신규 개발**
  - 단말기 IP 목록 관리와 즉시 적용: `TerminalIpConfigUtils`, `SetTerminalIpAuthCommand`, `GetTerminalIpAuthQuery`, `GetTerminalIpProtectedQuery`
  - 전용 IP·시리얼: `SetUserDedicatedIpCommand`, `SetUserClientSerialCommand`, `UserClientSerials`, `uutils/security/ClientSerialCheck`
  - 웹 포털 차단·거부 페이지: `aaa/filters/DedicatedIpWebPortalFilter`, `IsWebPortalDeniedForAddressQuery`, `uutils/servlet/ForbiddenPage`
  - 미등록 주소 감사: `ClientAccessDeniedAuditManager`, `ClientAccessDeniedLog`
  - setup 필수 주소: `ovirt_engine_setup/client_addresses.py`
  - 화면: `ClientManagementView`(관리자 접속 관리)
- **upstream 수정**: `ovirt-engine-proxy.conf.v2.in`(단말기 IP 블록, 거부 로그), setup `apache/engine.py`
- 관련 문서: `terminal-authentication-management.md`, `user-dedicated-login-ip.md`, `user-ip-serial-implementation-specification.md`, `client-serial-access-audit.md`, `unregistered-address-access-audit.md`

### F04 감사 기록·감사 저장소·알림
- **목적**: 보안 감사 이벤트 추가, 감사기능 시작·종료 기록, 감사 저장소 용량 감시와 보존·정리, 감사 로그 백업·원격 전송, 게스트 중요 이벤트, 알림(ntfy).
- **신규 개발**: `AuditFunctionLifecycle`, `AuditLogCapacityMonitor`, `AuditLogPurger`, `AuditStorage*`, `GuestCriticalEventAuditManager`, `VmGuestEventMark*`, 감사 로그 백업·복원 명령, `packaging/bin/audit-log-backup.py`, `audit-storage-usage.py`, `configure-audit-log-remote.py`, `ovirt-engine-audit-storage-watch.{service,timer}`, 알림 `notifier/transport/ntfy/Ntfy`, 화면 `MainAuditLogView`, `AuditLogProtectionTabView`, `AuditLogRemoteBackupTabView`, `LogBackupManagementView`
- **upstream 수정**: `AuditLogType`(보안 이벤트 유형 추가), `AuditLogMessages.properties`(메시지), `AuditLogCleanupManager`, 알림 서비스 `Notifier`, `NotificationService`, `ovirt-engine-notifier.*`
- 관련 문서: `audit-function-start-stop.md`, `audit-log-storage-capacity.md`, `audit-log-backup-management.md`, `guest-event-monitoring.md`, `notifier-ntfy-push.md`

### F05 자체시험·무결성 검증
- **목적**: 주요 프로세스 6종에 대한 자체시험, AIDE 기반 무결성 검증, 기준값 봉인(HMAC), 검증 실패 시 대응(경보·서비스 중지).
- **신규 개발**: `SecurityAuditRunner`, `StartupSecurityAuditManager`, `IntegrityVerification*`, `IntegrityTargets`, `VerificationFailureReport`, `ScheduledVerificationFailureResponse`, `ov-works-security_audit.sh`, `ovirt-engine-security-verification-runner.sh`, `ovirt-engine-security-halt.{sh,path,service}`, `ovworks-process-files.conf`, setup `ovirt_engine_setup/aide.py`, `system/integrity_baseline.py`, `system/security_audit.py`, `system/acl.py`, 봉인 도구 `encryptor/integrity_seal.py`, 화면 `IntegrityCheckView`, `SecurityVerificationFailureAlert`
- **upstream 수정**: 없음(전부 신규 파일). 엔진 기동 연동은 F06의 런처(`ovirt-engine.py.in`)와 F09의 `Backend`에서 한다.
- 관련 문서: `security-verification-integrity-check.md`, `security-verification-service-halt.md`, `aide-monitoring-rules.md`, `self-security-processing-specification.md`

### F06 암호 키 관리·암호화·DB 인증
- **목적**: 설정 파일의 비밀값 암호화(KEK/DEK), 런타임 DEK 전달과 파기, 국내 검증 난수발생기(Hash_DRBG) 통일, PostgreSQL SCRAM-SHA-256·로컬 인증, DB 비밀번호 생성 규칙.
- **신규 개발**
  - 암호화 도구: `packaging/encryptor/`(`encryptor.py`, `kek_agent.py`, `runtime_dek.py`, `login_key.py`, `integrity_seal.py`, `vault_passphrase.py` 등)
  - 난수·암호 사건 기록: `pythonlib/ovirt_engine/csprng.py`, `cryptoevents.py`, `uutils/crypto/ApprovedRandom`, `DekEnvelope`, `CryptoEventAuditManager`, `openssl-drbg.cnf`
  - DB 인증·비밀번호: `pg_local_auth.py`, `ovirt-engine-db-local-auth.py`, `setup/.../system/dwh_scram_runtime.py`, `ovirt_engine_setup/password_policy.py`
  - 설정 암호화 setup·cleanup: `config/client_control.py`, `remove/.../config/decrypt.py`
- **upstream 수정**
  - 엔진 런처: `ovirt-engine.py.in`(DEK 전달·파기, KEK 에이전트 연동)
  - 암호화된 설정 읽기: `configfile.py`, `ShellLikeConfd`, `engine-prolog.sh.in`
  - 난수발생기 교체(`SecureRandom` → `ApprovedRandom`): `Ticketing`, `CryptMD5`, `EnvelopePBE`, `TicketEncoder`, `SsoRegistrationToolExecutor`
  - DB 설정: `engine_common/postgres.py`, `engine_common/database.py`, `provisioning/postgres.py`
  - cleanup 키 파기: `remove/.../config/misc.py`, `remove/.../config/ca.py`
- 관련 문서: `db-config-key-management-specification.md`, `csprng-hash-drbg.md`, `kek-memory-pbkdf2.md`, `postgresql-scram-hardening.md`, `crypto-storage-guide-for-examiners.md`

### F07 가상머신 보안 통제
- **목적**: VM 파일 공유 차단(네트워크 필터, SPICE 파일 전송·클립보드), 공유 디스크 차단, 게스트 명령 블랙리스트, 최소 호스트 수 미만 클러스터의 마이그레이션 제한.
- **신규 개발**: `block-file-sharing.xml`(호스트 nwfilter), `CommandBlacklist`, `ExecuteVmGuestCommandCommand`, `ClusterMigrationValidator`, VM 보안 통제 화면(`VmSecurityControlPopupView`, `SubTabVirtualMachineSecurityControl*`), DB 업그레이드 `0310`, `0330`, `0340`, `0343`, `0345`
- **upstream 수정**: `RunVmOnceCommand`(파일 전송·클립보드 강제 해제), `AddDiskCommand`·`UpdateDiskCommand`·`AttachDiskToVmCommand`(공유 디스크 차단), `AddVnicProfileCommand`·`UpdateVnicProfileCommand`(필터 강제), `MigrateVmCommand`·`MigrateMultipleVmsCommand`, `NetworkHelper`, VM·디스크·vNIC 화면 모델, 호스트 배포 `ovirt-host-deploy-vdsm/tasks/configure.yml`
- 관련 문서: `vnic-profile-network-filter.md`, `vm-security-dialog-audit.md`

### F08 사용자·그룹·권한 관리
- **목적**: 내부(aaa-jdbc) 사용자·그룹을 관리 포털에서 생성·수정·삭제, 비밀번호 초기화·잠금 해제, 그룹 구성원·VM 할당, 권한 역할 변경, 사용자 환경변수.
- **신규 개발**: `bll/aaa/AddLocalUserCommand`, `UpdateLocalUserCommand`, `AddLocalGroupCommand`, `UpdateLocalGroupMembersCommand`, `ResetUserPasswordCommand`, `UnlockUserCommand`, `AaaJdbcTool`, `ChangePermissionRoleCommand`, `UserEnvironmentVariable*`, 화면 `LocalUserAddPopupView`, `LocalGroup*PopupView`, `UserPasswordResetPopupView`, `VmPermissionPopupView`
- **upstream 수정**: `AddUserCommand`, `RemoveUserCommand`(전용 IP·시리얼 정리 포함), `UserProfileDao`, `UserListModel`, `UserPermissionListModel`, `AdElementListModel`, 권한 팝업
- 관련 문서: `local-group-members-and-vm-assignment.md`, `password-reset-management.md`

### F09 보안 설정 화면·엔진 설정
- **목적**: 관리 포털 "보안 설정" 메뉴(보안 정책·감사·가용성·외부 SSL 등), 엔진 설정값 조회·변경, 신규 설정 키 등록.
- **신규 개발**: `SecuritySettingsListModel`, `MainSecuritySettings*`, `SecuritySettingsPopup*`, `AvailabilityTabView`, `ExternalSslView`, `ApplyExternalSslCommand`, `Get/SetEngineConfigValueCommand`, `ListEngineConfigPropertiesCommand`, `RestartRequiredNotice`
- **upstream 수정**: `ConfigValues`, `engine-config.properties`, `0000_config.sql`, `create_tables.sql`, `ActionType`, `QueryType`, `EngineMessage`, `Backend`(기동 시 감사기능 시작·시리얼 목록 생성), 화면 등록(`PresenterModule`, `MenuView`, `ApplicationConstants*`), 각 웹앱 `web.xml`(필터 등록), SSO 공용(`SsoUtils`, `SsoOAuthServiceUtils`, `FiltersHelper`), OVN 공급자 비밀번호 처리
- 관련 문서: `national-security-implementation-specification.md`, `private-ca-ssl-tls-certificate-management.md`

### F10 백업·복구
- **신규 개발**: `EngineBackupCommand`, `RemoteBackupCommand`, `all-backup.sh.in`, `engine-backup-root.sh(.in)`
- **upstream 수정**: `engine-backup.sh.in`(암호화 설정 백업·복원), `engine-backup.8`

### F11 제품화·한국어화·버전 표기
- **목적**: 제품 버전 4.5.7 표기, 정보 창·첫 화면 표기, 한국어 메시지, 언어 목록을 한국어로 제한.
- **upstream 수정만 있음**: 각 모듈 `pom.xml` 버전(4.5.6 → 4.5.7), `maven-metadata/*.xml`, `version.mak`, `AboutPopup*`, `WelcomeServlet`, `languages.properties`, `*_ko_KR.properties`, engine-setup 대화 문구 한국어화(`pki/ca.py`, `firewall_manager*.py`, `distro-rpm/packages.py` 등 setup 플러그인)

### F12 빌드·패키징·의존성
- **신규 개발**: log4j-api JBoss 모듈 정의(`.../log4j/api/main/module.xml`)
- **upstream 수정**: `ovirt-engine.spec.in`(신규 파일·서비스 설치, `Requires: aide`), `Makefile`, 루트 `pom.xml`·`dependencies/common/pom.xml`(라이브러리 버전 상향·추가, §8), setup 플러그인 등록 `__init__.py`, `.gitignore`, `README.adoc`
- **upstream 삭제**: upstream CI·저장소 관리 파일 15개(§7)

## 6. 수정한 upstream 주요 파일 상세

제품 코드 중 변경이 크거나 동작에 영향을 주는 upstream 파일이다. 버전 문자열만 바꾼 `pom.xml`, 한국어 문구만 바꾼 파일은 부록에서 본다.

| 파일 | 추가/삭제 | 수정 요지 | 기능 |
|---|---:|---|---|
| `bll/aaa/SessionDataContainer.java` | +542/−23 | 사용자별 세션 수 제한, 수퍼유저 단일 세션, 종료 사유 기록 | F02 |
| `uicommonweb/.../users/UserListModel.java` | +540/−4 | 로컬 사용자 추가·수정·삭제·비밀번호 초기화·잠금 해제 화면 모델 | F08 |
| `setup/.../engine_common/postgres.py` | +367/−79 | SCRAM-SHA-256 강제, 수퍼유저 비밀번호 지연 설정, DB 비밀번호 생성 규칙 | F06 |
| `setup/.../config/aaa.py` | +339/−16 | 관리자 비밀번호 정책(길이·조합·반복·연속·흔한 단어), 첫 로그인 변경 | F01 |
| `common/.../AuditLogType.java` | +322/−1 | 보안 감사 이벤트 유형 추가(로그인·세션·단말·무결성·암호 등) | F04 |
| `services/ovirt-engine/ovirt-engine.py.in` | +321/−0 | 엔진 런처: 런타임 DEK 전달·종료 시 파기, KEK 에이전트·보안검증 연동 | F06 |
| `enginesso/.../AuthenticationService.java` | +302/−9 | 비밀번호 정책·잠금·로그인 실패 감사 | F01 |
| `enginesso/.../login.jsp` | +298/−2 | 로그인 정보 RSA 암호화, 입력 제한, 재전송 방지 nonce | F01 |
| `bll/aaa/CreateUserSessionCommand.java` | +290/−18 | 로그인 판정(관리자·LOGIN 권한·세션 수·전용 IP·시리얼·수퍼유저 단일 접속) | F02·F03 |
| `enginesso/.../SsoDao.java` | +241/−0 | 잠금·비밀번호 이력·감사 기록 DB 접근 | F01 |
| `enginesso/.../OAuthTokenServlet.java` | +236/−10 | REST 토큰 발급 시 잠금·단말 시리얼·비밀번호 정책 적용 | F01·F03 |
| `remove/.../config/misc.py` | +228/−0 | engine-cleanup 때 암호화 설정 복호화·키 파일 파기 | F06 |
| `common/.../ConfigValues.java` | +208/−0 | 신규 보안 설정 키 | F09 |
| `webadmin/.../ApplicationConstants.java` | +201/−0 | 신규 화면 문구 | F09 |
| `enginesso/.../InteractiveAuthServlet.java` | +195/−33 | 대화형 로그인: 암호화 로그인 정보 해독, 재전송·입력 검사 | F01 |
| `pythonlib/ovirt_engine/configfile.py` | +182/−5 | 암호화된 설정을 메모리에서 해독해 읽기(평문을 디스크에 쓰지 않음) | F06 |
| `enginesso/.../credentialsChange.jsp` | +166/−3 | 비밀번호 변경 화면 정책 안내·검사 | F01 |
| `setup/.../config/aaajdbc.py` | +163/−28 | aaa-jdbc 잠금 시간·정책을 엔진 설정과 일치 | F01 |
| `setup/.../engine/constants.py` | +163/−0 | 신규 setup 환경 키(비밀번호 정책, 감사, 보안검증 등) | F09 |
| `uicommonweb/.../UserPermissionListModel.java` | +134/−6 | 권한 역할 변경, 그룹 VM 할당 | F08 |
| `bin/engine-backup.sh.in` | +132/−7 | 암호화된 설정의 백업·복원 처리 | F10 |
| `AuditLogMessages.properties` | +130/−0 | 신규 감사 이벤트 메시지 | F04 |
| `RestApiSessionMgmtFilter.java` | +124/−14 | REST API 세션 수·재사용 규칙 | F02 |
| `engine-config.properties` | +120/−2 | 신규 설정 키의 engine-config 노출 | F09 |
| `provisioning/postgres.py` | +110/−8 | 수퍼유저 비밀번호 입력·정책 검사 | F06 |
| `SsoOAuthServiceUtils.java` | +108/−16 | 엔진 감사 콜백, SSO 호출 연결 제한시간 | F09 |
| `InteractiveChangePasswdServlet.java` | +108/−9 | 비밀번호 변경 정책·이력 검사 | F01 |
| `SsoService.java` | +98/−3 | 단일 세션 정책, 단말 시리얼 거부, 승인 난수 | F01·F03 |
| `engine-prolog.sh.in` | +78/−1 | 암호화된 설정을 도구에 전달 | F06 |
| `RemoveUserCommand.java` | +72/−0 | 사용자 삭제 시 전용 IP·시리얼 정리, 감사 | F08 |
| `ovirt-engine-proxy.conf.v2.in` | +52/−0 | 단말기 IP `Require ip` 블록, 거부 접속 로그 | F03 |
| `create_tables.sql` | +53/−1 | 신규 테이블(로그인 실패, 비밀번호 이력 등) | F09 |
| `MigrateVmCommand.java` | +38/−0 | 최소 호스트 수 미만 클러스터의 수동 마이그레이션 제한 | F07 |
| `WelcomeServlet.java` | +34/−8 | 단말 시리얼 검사, 거부 페이지 통일, 표시 버전 | F03·F11 |
| `UpdateVnicProfileCommand.java` | +26/−0 | 파일 공유 차단 필터 강제 | F07 |
| `RunVmOnceCommand.java` | +3/−6 | SPICE 파일 전송·클립보드를 항상 끔 | F07 |
| `AddDiskCommand.java` | +1/−3 | 공유 디스크 생성 차단 | F07 |
| `Ticketing.java`, `CryptMD5.java`, `EnvelopePBE.java`, `TicketEncoder.java` | 각 1~5줄 | 난수를 `ApprovedRandom`(Hash_DRBG)으로 교체 | F06 |
| `languages.properties` | +0/−10 | 언어 목록을 한국어로 제한 | F11 |

## 7. 삭제한 upstream 파일

모두 upstream 프로젝트의 CI·저장소 관리용 파일이다. 제품 빌드 결과물과 기능에는 영향이 없다.

`.automation/build-rpm.sh`, `.automation/build-srpm.sh`, `.automation/milestone-config.sh.in`, `.copr/Makefile`,
`.github/CODEOWNERS`, `.github/ISSUE_TEMPLATE/*`(3개), `.github/pull_request_template.md`,
`.github/workflows/build.yml`, `.github/workflows/ost.yaml`, `.gitignore.in`, `.gitreview`, `.isort.cfg`, `.travis.yml`

## 8. 오픈소스 구성요소 변경

upstream이 쓰던 오픈소스 구성을 유지한다. 보안 보완을 위해 아래만 바꿨다. 전체 목록·버전·라이선스는 `docs/ovworks-sbom.md`에 있다.

| 구성요소 | upstream 4.5.6 | OV-Works | 사유 | 라이선스 |
|---|---|---|---|---|
| org.springframework:spring-* (8종) | 5.3.27 | **5.3.39** | 5.3 계열 최종 공개 패치 버전으로 상향(커밋 `a8f29008`) | Apache-2.0 |
| org.apache.commons:commons-compress | 1.21 | **1.27.1** | CVE-2024-25710, CVE-2024-26308(조작된 압축 파일에 의한 서비스 거부) 조치(커밋 `a8f29008`) | Apache-2.0 |
| commons-io:commons-io | — | **2.16.1 (추가)** | commons-compress 1.26 이상의 실행 의존성 | Apache-2.0 |
| org.apache.commons:commons-lang3 | — | **3.16.0 (추가)** | 위와 같음 | Apache-2.0 |
| org.apache.logging.log4j:log4j-api | (애플리케이션 서버 제공) | **2.26.1 (엔진 모듈로 고정)** | 서버 제공 버전 대신 검증한 버전 사용, log4j-core는 넣지 않음(`docs/log4j-api-module-override.md`) | Apache-2.0 |
| com.ongres.scram:client, common | — | **2.1 (추가)** | PostgreSQL JDBC의 SCRAM-SHA-256 인증 | BSD-2-Clause |
| com.ongres.stringprep:saslprep, stringprep | — | **1.1 (추가)** | 위와 같음 | BSD-2-Clause |
| RPM `aide` | — | **Requires 추가** | 무결성 검증 | GPL-2.0-or-later |

**주의**: RPM 빌드에서 commons-compress와 spring-*은 빌드 산출물 jar 대신 시스템 RPM jar(`apache-commons-compress`, `ovirt-dependencies`)로 링크된다(`ovirt-engine.spec.in` "Link dependencies to system provided"). 그래서 위 상향 버전이 RPM 설치본에서 실제로 동작하는지는 설치 서버에서 확인해야 한다(SBOM §3.1).

신규 개발 Python 코드가 쓰는 외부 모듈은 upstream이 이미 요구하던 것뿐이다(`python3-cryptography`, `otopi`, `jinja2`). 난수는 OpenSSL 3 libcrypto의 Hash_DRBG를 `ctypes`로 직접 호출한다(추가 패키지 없음).

## 9. 라이선스 준수 사항

Apache License 2.0 제4조의 재배포 조건과 현황이다.

| 조건 | 내용 | 현황 |
|---|---|---|
| 4(a) 라이선스 사본 제공 | 배포물에 라이선스 사본 포함 | `LICENSE`, `ASL2` 유지, RPM `License: ASL 2.0` |
| 4(b) 수정 사실 표시 | 수정한 파일에 변경했다는 사실을 눈에 띄게 표시 | **조치 완료**. 수정 파일 300개 중 299개의 머리말에 "Modified by 새올정보기술 for OV-Works (2026). Changes against oVirt Engine 4.5.6: docs/ovworks-source-change-statement.md"를 넣었다(`docs/tools/mark_modified_files.py`). 주석 문법이 없는 `MANIFEST.MF` 1개는 이 내역서로 표시한다 |
| 4(c) 저작권·특허·상표 고지 유지 | upstream 파일의 고지 유지 | upstream 파일 머리말 고지를 지우지 않았다 |
| 4(d) NOTICE 유지 | NOTICE 파일 내용 포함 | `NOTICE` upstream과 동일하게 유지 |
| 상표 | "oVirt" 상표 사용 제한(제6조) | 제품명·화면 표기는 OV-Works로 바꿨다(F11). 내부 패키지·클래스명의 `ovirt`는 upstream 식별자 그대로다 |

**권고**
1. **수정 파일 표시(4(b))**: 조치 완료. 이후 upstream 파일을 새로 고치면 `python3 docs/tools/mark_modified_files.py`를 다시 실행한다(이미 표시된 파일은 건너뜀). `--check`로 표시가 빠진 파일을 확인할 수 있다. 표시 위치는 셔뱅·인코딩 줄·XML 선언 다음, JSP는 JSP 주석이다.
2. **신규 파일 저작권 표기**: 조치 완료. upstream 머리말("Copyright oVirt Authors")을 그대로 쓰던 신규 파일 17개의 저작권자를 "Copyright 새올정보기술 (OV-Works), 2026"으로 바꿨다(라이선스 표기 `SPDX-License-Identifier: Apache-2.0`은 유지). `packaging/services/ovirt-engine/ovirt-engine.py`는 upstream `ovirt-engine.py.in`을 복사해 고친 파일이므로 upstream 저작권을 유지하고 수정 표시만 넣었다. 처음 집계된 20개 중 나머지 2개(`test_pg_major_version.py`, `docs/cve-2024-7259-remediation-evidence.md`)는 본문에 "Red Hat"이라는 낱말이 들어 있을 뿐, 머리말이 아니다.
   대상: `ProviderPasswords.java`, `engine-backup-root.sh(.in)`, `ovirt-engine-check-deployment.sh`, `cryptoevents.py`, `ovirt_engine_setup/{aide,client_addresses,password_policy}.py`, `remove/.../config/decrypt.py`, `remove/.../system/aide.py`, `config/client_control.py`, `system/{acl,audit_storage_watch,dwh_scram_runtime,integrity_baseline,security_audit,systemd_timer}.py`. 머리말이 없는 나머지 신규 파일에 저작권 표기를 추가할지는 회사 방침으로 정한다.
3. **생성물 커밋**: `packaging/services/ovirt-engine/ovirt-engine.py`와 `packaging/bin/engine-backup-root.sh`는 각각 `.in` 템플릿에서 생성되는 파일이 함께 커밋되어 있다. 두 파일의 내용이 어긋나지 않게 관리하거나 생성물을 저장소에서 빼기를 권고한다.

## 10. 부록

- **부록 A — 파일별 전체 목록**: `docs/ovworks-change-inventory-appendix.md`. 신규 466개, 수정 300개, 삭제 15개를 기능 코드·줄 수와 함께 나열한다.
- **부록 B — 오픈소스 구성요소 목록(SBOM)**: `docs/ovworks-sbom.md`, 기계 판독용 `docs/sbom/ovworks-engine-sbom.cdx.json`(CycloneDX 1.5).
- **생성 도구**: `docs/tools/change_inventory.py`(부록 A), `docs/tools/mark_modified_files.py`(수정 파일 머리말 표시), `docs/tools/sbom.py`(부록 B), `docs/tools/sbom_installed_rpms.sh`(설치 서버의 실제 RPM 버전·라이선스 수집).
