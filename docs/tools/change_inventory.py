#!/usr/bin/python3
#
# OV-Works -- source change inventory against the upstream oVirt Engine base
#
# SPDX-License-Identifier: Apache-2.0
#

"""Writes the file-by-file appendix of the source change statement.

Every file that differs between the upstream oVirt Engine release the product
is built on and the product's tree is listed once, as new (developed for
OV-Works), modified (an upstream file changed) or deleted (an upstream file
removed), with the lines added and removed and the function it belongs to.

    git fetch --depth 1 https://github.com/oVirt/ovirt-engine \\
        refs/tags/ovirt-engine-4.5.6:refs/upstream/ovirt-engine-4.5.6
    python3 docs/tools/change_inventory.py [--base REF] [--head REF] [--out FILE]

The classification is by path, from the ordered rules below: the first rule
that matches a file decides its function.
"""

import argparse
import collections
import re
import subprocess
import sys


DEFAULT_BASE = 'refs/upstream/ovirt-engine-4.5.6'
DEFAULT_OUT = 'docs/ovworks-change-inventory-appendix.md'

STATUS = {'A': '신규', 'M': '수정', 'D': '삭제'}

# (code, title), in the order the statement presents them.
FUNCTIONS = collections.OrderedDict((
    ('F01', '인증·로그인 보안'),
    ('F02', '세션 관리'),
    ('F03', '단말 접근 통제(단말기 IP·전용 IP·단말 시리얼)'),
    ('F04', '감사 기록·감사 저장소·알림'),
    ('F05', '자체시험·무결성 검증'),
    ('F06', '암호 키 관리·암호화·DB 인증'),
    ('F07', '가상머신 보안 통제'),
    ('F08', '사용자·그룹·권한 관리'),
    ('F09', '보안 설정 화면·엔진 설정'),
    ('F10', '백업·복구'),
    ('F11', '제품화·한국어화·버전 표기'),
    ('F12', '빌드·패키징·의존성'),
    ('F13', '시험 코드'),
    ('F14', '문서'),
))

# First match wins. Tests and documents first, so that a test of a feature is
# counted as test code; build and product-identity rules last.
RULES = (
    ('F13', r'(/src/test/|^packaging/setup/tests/|^packaging/tests/)'),
    ('F14', r'^docs/|/README\.(md|adoc)$|^contrib/README'),
    # Plugin registration, and the poms that change dependencies or the build (not only the
    # version), are build changes.
    ('F12', r'/plugins/.*/__init__\.py$|^pom\.xml$|^backend/manager/dependencies/.*pom\.xml$|'
            r'^frontend/webadmin/modules/pom\.xml$'),
    ('F03', r'Terminal|ClientSerial|DedicatedIp|UserClientSerials|IsWebPortalDenied|'
            r'ClientAccessDenied|ClientAddress|client_addresses|ClientManagementView|'
            r'ForbiddenPage|Ipv4AddressUtils|ovirt-engine-proxy\.conf|'
            r'ovirt-engine-setup/ovirt-engine/apache/engine\.py'),
    ('F02', r'Session(?!sMgmt)|SessionReplayGuard|RegisterHttpSession|BlockReplayedSession|'
            r'RestApiLogout|RestApiSession|ValidateSessionQuery|TerminateSession|'
            r'SetSesssionSoftLimit|SetEngineSessionLimit|single_session|login_replay|'
            r'XsrfToken'),
    ('F05', r'Integrity|SecurityAudit|security_audit|StartupSecurityAudit|Verification|'
            r'ov-works-security_audit|security-verification|security-halt|service-halted|'
            r'ovirt_engine_setup/aide\.py|/system/aide\.py|integrity_|ovworks-process-files|'
            r'check-deployment|systemd_timer|/system/acl\.py|process-file-stat|'
            r'security_verification_failure|AuditFunctionLifecycle|security-audit'),
    ('F06', r'^packaging/encryptor/|csprng|cryptoevents|CryptoEvent|DekEnvelope|ApprovedRandom|'
            r'openssl-drbg|client_control\.py|remove/ovirt-engine/config/decrypt\.py|kek-agent|'
            r'pg_local_auth|db-local-auth|dwh_scram|password_policy\.py|ProviderPasswords|'
            r'PasswordHistoryCryptor|/uutils/crypto/|configfile\.py|Ticketing\.java|'
            r'ovirt-engine/ovirt-engine\.py|engine_common/postgres\.py|engine_common/database\.py|'
            r'provisioning/postgres\.py|org/postgresql/main/module\.xml|ShellLikeConfd|'
            r'LoginEnvelope|RsaPublicKey|RsaCredentialsDecryptor|ticket\.py|'
            r'/ovirt-engine/ovirt-engine\.(conf|systemd)\.in|ovirt-engine-remove/ovirt-engine/config/'
            r'(misc|ca)\.py|ovirt-engine-common/ovirt-engine/db/connection\.py|'
            r'SsoRegistrationToolExecutor|register-sso-client-tool|engine-config\.sh|pki-common'),
    ('F04', r'AuditLog|AuditStorage|audit-log|audit-storage|audit_storage|LogBackup|'
            r'audit_log_capacity|audit_event_tables|AuditLogMessages|AuditLogType|'
            r'GuestCriticalEvent|VmGuestEventMark|guest_event|guest_critical|notifier|'
            r'Notification|EventNotification|VdcEventNotification|audit-log-dummy|'
            r'AuditLogRemote|configure-audit-log-remote'),
    ('F01', r'enginesso/|/aaa/(?!.*(LocalUser|LocalGroup|ResetUserPassword|UnlockUser|'
            r'AaaJdbcTool|AddUserCommand|RemoveUserCommand))|Password|Login|password_|login_|'
            r'sso_admin_lock|user_login|credentials|InitialPasswordValidity|'
            r'AuthnMessage|SsoCallbackServlet|/aaa\.py$|aaajdbc\.py'),
    ('F07', r'block.file.sharing|BlockFileSharing|VnicProfile|NetworkFilter|network_filter|'
            r'SecurityControl|CommandBlacklist|ExecuteVmGuestCommand|Migrat|ClusterHostCount|'
            r'minimum_hosts|ovirt-host-deploy-vdsm|RunVm|RunOnce|/storage/disk/|AbstractDiskModel|'
            r'UnitVmModel|ImportVmsModel|VmManagementCommandBase|NetworkHelper|VmListModel|'
            r'VirtualMachineSubTabPanel|MainVnicProfile|SubTabNetworkProfile'),
    ('F08', r'LocalUser|LocalGroup|ResetUserPassword|UnlockUser|AaaJdbcTool|ChangePermissionRole|'
            r'VmPermission|EnvironmentVariable|UserListModel|UserPermission|AddUserCommand|'
            r'RemoveUserCommand|local_user|AdElementListModel|PermissionListModel|Permissions|'
            r'UserModule|UserActionPanel|UserProfileDao|user_profiles_sp|OrderedMultiSelection|'
            r'UserPasswordReset'),
    ('F10', r'backup|Backup'),
    ('F09', r'SecuritySettings|EngineConfig|ApplyExternalSsl|ExternalSsl|AvailabilityTab|'
            r'RestartRequiredNotice|engine-config|ConfigValues|0000_config\.sql|apache/ssl\.py|'
            r'/pki/|pki-common|ConfigurePopupView|Menu(Presenter|View)|PresenterModule|'
            r'UiCommonModule|ApplicationConstants|ApplicationMessages|WebAdminApplicationPlaces|'
            r'DetailTabDataIndex|PluginUiFunctions|ErrorPopup|AbstractActionTable|'
            r'ovirt_engine_setup/engine(_common)?/constants\.py|'
            r'SearchQuery|QueriesCommandBase|Backend\.java|InitBackendServicesOnStartup|'
            r'ActionType|QueryType|EngineMessage|AppErrors|LocalizedEnums|UIConstants|HelpTag|'
            r'Common\.gwt\.xml|web\.xml$|aop\.xml|BusinessEntitiesDefinitions|'
            r'GetAllProvidersQuery|GetProviderBy|TestProviderConnectivity|UpdateProviderCommand|'
            r'ProviderModel|ovirtproviderovn|create_tables\.sql|engine-prolog|sso\.py$|'
            r'FiltersHelper|EnforceAuthFilter|SsoRestApiAuthFilter|SsoUtils|SsoLogout|SsoPostLogin|'
            r'SsoOAuthServiceUtils|/upgrade/04_05_03'),
    ('F11', r'About|WelcomeServlet|languages\.properties|_ko_KR|version\.mak|maven-metadata|'
            r'MANIFEST\.MF|WebAdmin\.gwt\.xml|pom\.xml$|/setup/plugins/|/man/'),
    ('F12', r'.*'),
)

_COMPILED = [(code, re.compile(pattern)) for code, pattern in RULES]


def classify(path):
    for code, pattern in _COMPILED:
        if pattern.search(path):
            return code
    return 'F12'


def git(*args):
    return subprocess.run(
        ('git',) + args, check=True, stdout=subprocess.PIPE, universal_newlines=True,
    ).stdout


def inventory(base, head):
    lines = {}
    for line in git('diff', '--numstat', '--no-renames', base, head).splitlines():
        added, removed, path = line.split('\t', 2)
        lines[path] = (
            int(added) if added != '-' else 0,
            int(removed) if removed != '-' else 0,
            added == '-',
        )
    rows = []
    for line in git('diff', '--name-status', '--no-renames', base, head).splitlines():
        status, path = line.split('\t', 1)
        added, removed, binary = lines.get(path, (0, 0, False))
        rows.append((status[0], path, classify(path), added, removed, binary))
    return rows


def write(rows, base, head, out):
    base_commit = git('rev-parse', base).strip()
    head_commit = git('rev-parse', head).strip()
    by_status = collections.Counter(r[0] for r in rows)
    lines_by = collections.defaultdict(lambda: [0, 0])
    for status, _, _, added, removed, _ in rows:
        lines_by[status][0] += added
        lines_by[status][1] += removed

    o = []
    o.append('# OV-Works 소스 변경 내역서 — 부록: 파일별 변경 목록\n')
    o.append('> 이 부록은 `docs/tools/change_inventory.py`가 git으로 생성한다. 손으로 고치지 말고 '
             '스크립트를 다시 실행한다. 본문은 `docs/ovworks-source-change-statement.md`.\n')
    o.append('| 항목 | 값 |')
    o.append('|---|---|')
    o.append('| 기준(upstream) | `{}` (`{}`) |'.format(base, base_commit))
    o.append('| 대상(OV-Works) | `{}` (`{}`) |'.format(head, head_commit))
    o.append('| 비교 방법 | `git diff --name-status --no-renames` / `--numstat` (이름 변경도 삭제+신규로 집계) |')
    o.append('')
    o.append('## 1. 구분별 합계\n')
    o.append('| 구분 | 파일 수 | 추가 줄 | 삭제 줄 |')
    o.append('|---|---:|---:|---:|')
    for status in ('A', 'M', 'D'):
        o.append('| {} ({}) | {} | {} | {} |'.format(
            STATUS[status], status, by_status[status], lines_by[status][0], lines_by[status][1]))
    o.append('| 합계 | {} | {} | {} |'.format(
        len(rows), sum(v[0] for v in lines_by.values()), sum(v[1] for v in lines_by.values())))
    o.append('')

    o.append('## 2. 기능 분류별 합계\n')
    o.append('| 코드 | 기능 분류 | 신규 | 수정 | 삭제 | 추가 줄 | 삭제 줄 |')
    o.append('|---|---|---:|---:|---:|---:|---:|')
    for code, title in FUNCTIONS.items():
        mine = [r for r in rows if r[2] == code]
        if not mine:
            continue
        count = collections.Counter(r[0] for r in mine)
        o.append('| {} | {} | {} | {} | {} | {} | {} |'.format(
            code, title, count['A'], count['M'], count['D'],
            sum(r[3] for r in mine), sum(r[4] for r in mine)))
    o.append('')

    sections = (
        ('A', '3. 신규 개발 파일 (OV-Works에서 새로 작성)'),
        ('M', '4. 수정 파일 (upstream oVirt 파일을 변경)'),
        ('D', '5. 삭제 파일 (upstream oVirt 파일을 제거)'),
    )
    for status, title in sections:
        mine = sorted((r for r in rows if r[0] == status), key=lambda r: (r[2], r[1]))
        o.append('## {}\n'.format(title))
        o.append('| No | 기능 | 파일 경로 | 추가 줄 | 삭제 줄 |')
        o.append('|---:|---|---|---:|---:|')
        for number, (_, path, code, added, removed, binary) in enumerate(mine, 1):
            o.append('| {} | {} | `{}` | {} | {} |'.format(
                number, code, path,
                '(바이너리)' if binary else added,
                '' if binary else removed))
        o.append('')

    with open(out, 'w', encoding='utf-8') as stream:
        stream.write('\n'.join(o))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--base', default=DEFAULT_BASE)
    parser.add_argument('--head', default='HEAD')
    parser.add_argument('--out', default=DEFAULT_OUT)
    args = parser.parse_args()
    rows = inventory(args.base, args.head)
    write(rows, args.base, args.head, args.out)
    count = collections.Counter(r[0] for r in rows)
    print('{}: {} new, {} modified, {} deleted'.format(args.out, count['A'], count['M'], count['D']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
