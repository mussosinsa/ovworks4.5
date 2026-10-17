#!/usr/bin/python3
#
# OV-Works -- software bill of materials of OV-Works Engine
#
# Copyright 새올정보기술 (OV-Works), 2026
# SPDX-License-Identifier: Apache-2.0
#

"""Writes the SBOM of OV-Works Engine from the component table below.

    python3 docs/tools/sbom.py

Writes docs/sbom/ovworks-engine-sbom.cdx.json (CycloneDX 1.5) and the
component tables of docs/ovworks-sbom.md, between its BEGIN/END markers. The
table is the source-level SBOM: the versions the build declares (pom.xml,
ovirt-engine.spec.in). Where the RPM links a library to a system package, the
version that runs is that package's; docs/tools/sbom_installed_rpms.sh reads
it from an installed host.
"""

import json
import re
import uuid


JSON_OUT = 'docs/sbom/ovworks-engine-sbom.cdx.json'
MD_OUT = 'docs/ovworks-sbom.md'
BEGIN = '<!-- BEGIN GENERATED COMPONENTS: docs/tools/sbom.py -->'
END = '<!-- END GENERATED COMPONENTS -->'
TIMESTAMP = '2026-10-17T00:00:00Z'

PRODUCT = {
    'name': 'OV-Works Engine',
    'version': '4.5.7-1.el9',
    'description': 'OV-Works 2.4 (V2.4.5.9) - oVirt Engine 4.5.6 based virtualization manager',
}

# How a component reaches the running product.
PROVENANCE = {
    'base': '기반 오픈소스(소스 반입·수정)',
    'bundled': '엔진 RPM에 포함(빌드 산출물 jar)',
    'system-link': '시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전)',
    'provided': '애플리케이션 서버/ovirt-dependencies 제공(빌드 시 provided)',
    'ui-compiled': '관리 포털 JavaScript로 컴파일되어 포함',
    'python-rpm': '시스템 RPM(Python)',
    'platform-rpm': '시스템 RPM(플랫폼·서비스)',
    'ovirt-rpm': 'oVirt 동반 RPM',
}

# What OV-Works did to it, against upstream oVirt Engine 4.5.6.
CHANGE = {
    '': '변경 없음(upstream 그대로)',
    'modified': '소스 수정(변경 내역서 참조)',
    'upgraded': '버전 상향',
    'added': '신규 추가',
}

# (category, group, name, version, license (SPDX), provenance, change, note)
# version: the declared or minimum version; '' when the platform decides.
# license: SPDX expression; 'NOASSERTION' when it has to be read from the installed package.
C = []


def add(category, group, name, version, license_, provenance, change='', note=''):
    C.append(dict(category=category, group=group, name=name, version=version,
                  license=license_, provenance=provenance, change=change, note=note))


# 1. Base
add('1. 기반 오픈소스', 'org.ovirt', 'ovirt-engine', '4.5.6', 'Apache-2.0', 'base', 'modified',
    'https://github.com/oVirt/ovirt-engine 태그 ovirt-engine-4.5.6 (eb315a9)')

# 2. Java libraries in the engine's JBoss modules (backend/manager/dependencies)
J = '2. 엔진 Java 라이브러리(JBoss 모듈)'
add(J, 'org.apache.logging.log4j', 'log4j-api', '2.26.1', 'Apache-2.0', 'bundled', 'added',
    '서버 제공 log4j-api를 대체하는 엔진 모듈. log4j-core는 포함하지 않음')
add(J, 'commons-io', 'commons-io', '2.16.1', 'Apache-2.0', 'bundled', 'added',
    'commons-compress 1.26+ 실행 의존성')
add(J, 'org.apache.commons', 'commons-lang3', '3.16.0', 'Apache-2.0', 'bundled', 'added',
    'commons-compress 1.26+ 실행 의존성')
add(J, 'com.ongres.scram', 'client', '2.1', 'BSD-2-Clause', 'bundled', 'added',
    'PostgreSQL JDBC SCRAM-SHA-256 인증')
add(J, 'com.ongres.scram', 'common', '2.1', 'BSD-2-Clause', 'bundled', 'added', '위와 같음')
add(J, 'com.ongres.stringprep', 'saslprep', '1.1', 'BSD-2-Clause', 'bundled', 'added', '위와 같음')
add(J, 'com.ongres.stringprep', 'stringprep', '1.1', 'BSD-2-Clause', 'bundled', 'added', '위와 같음')
add(J, 'org.ovirt.engine.api', 'metamodel-server', '1.3.10', 'Apache-2.0', 'bundled')
add(J, 'org.apache.commons', 'commons-compress', '1.27.1', 'Apache-2.0', 'system-link', 'upgraded',
    '1.21→1.27.1(CVE-2024-25710, CVE-2024-26308). RPM은 apache-commons-compress RPM jar로 링크: '
    '설치본 버전 확인 필요')
for artifact in ('spring-aop', 'spring-beans', 'spring-context', 'spring-core',
                 'spring-expression', 'spring-instrument', 'spring-jdbc', 'spring-tx'):
    add(J, 'org.springframework', artifact, '5.3.39', 'Apache-2.0', 'system-link', 'upgraded',
        '5.3.27→5.3.39. RPM은 ovirt-dependencies jar로 링크: 설치본 버전 확인 필요')
add(J, 'org.postgresql', 'postgresql', '42.2.27', 'BSD-2-Clause', 'system-link', '',
    'postgresql-jdbc >= 42.2.27')
add(J, 'org.apache.sshd', 'sshd-core', '2.9.2', 'Apache-2.0', 'system-link', '', 'apache-sshd >= 2.9.2')
add(J, 'org.apache.sshd', 'sshd-common', '2.9.2', 'Apache-2.0', 'system-link', '', 'apache-sshd >= 2.9.2')
add(J, 'net.i2p.crypto', 'eddsa', '0.3.0', 'CC0-1.0', 'system-link', '', 'ed25519-java >= 0.3.0')
add(J, 'aopalliance', 'aopalliance', '1.0', 'LicenseRef-Public-Domain', 'system-link')
add(J, 'org.apache.ws.commons.util', 'ws-commons-util', '1.0.2', 'Apache-2.0', 'system-link')
add(J, 'org.apache.xmlrpc', 'xmlrpc-client', '3.1.3', 'Apache-2.0', 'system-link')
add(J, 'org.apache.xmlrpc', 'xmlrpc-common', '3.1.3', 'Apache-2.0', 'system-link')
add(J, 'org.ebaysf.web', 'cors-filter', '1.0.1', 'Apache-2.0', 'system-link', '', 'ebay-cors-filter')
add(J, 'org.ovirt.engine.api', 'ovirt-engine-extensions-api', '1.0.1', 'Apache-2.0', 'system-link')
add(J, 'org.ovirt.java-client-kubevirt', 'java-client-kubevirt', '0.5.0', 'Apache-2.0', 'system-link')
add(J, 'org.ovirt.vdsm-jsonrpc-java', 'vdsm-jsonrpc-java-client', '1.7.2', 'Apache-2.0', 'system-link')
add(J, 'org.snmp4j', 'snmp4j', '3.6.4', 'Apache-2.0', 'system-link')
add(J, 'com.woorea', 'openstack-java-sdk', '3.2.9', 'Apache-2.0', 'system-link', '',
    'openstack-client, keystone/glance/cinder/quantum client·model, resteasy-connector (10종)')
add(J, 'org.slf4j', 'slf4j-api', '1.7.22', 'MIT', 'system-link', '', '도구(tools) 모듈')
add(J, 'org.slf4j', 'slf4j-jdk14', '1.7.22', 'MIT', 'system-link', '', '도구(tools) 모듈')
add(J, 'org.slf4j', 'jcl-over-slf4j', '1.7.22', 'Apache-2.0', 'system-link', '', '도구(tools) 모듈')

# 3. Provided at run time by the application server or ovirt-dependencies (pom scope provided)
P = '3. 실행 환경 제공 Java 라이브러리(provided)'
for group, name, version, license_ in (
    ('com.fasterxml.jackson.core', 'jackson-databind', '2.12.7.1', 'Apache-2.0'),
    ('com.fasterxml.jackson.core', 'jackson-core', '2.12.7', 'Apache-2.0'),
    ('org.apache.httpcomponents', 'httpclient', '4.5.13', 'Apache-2.0'),
    ('org.apache.httpcomponents', 'httpcore', '4.4.14', 'Apache-2.0'),
    ('commons-codec', 'commons-codec', '1.10', 'Apache-2.0'),
    ('commons-lang', 'commons-lang', '2.6', 'Apache-2.0'),
    ('commons-collections', 'commons-collections', '3.2.2', 'Apache-2.0'),
    ('commons-beanutils', 'commons-beanutils', '1.9.4', 'Apache-2.0'),
    ('commons-configuration', 'commons-configuration', '1.6', 'Apache-2.0'),
    ('org.hibernate.validator', 'hibernate-validator', '6.0.18.Final', 'Apache-2.0'),
    ('org.infinispan', 'infinispan-core', '9.4.18.Final', 'Apache-2.0'),
    ('org.jboss.resteasy', 'resteasy', '3.9.3.Final', 'Apache-2.0'),
    ('org.javassist', 'javassist', '3.23.1-GA', 'MPL-1.1 OR LGPL-2.1-or-later OR Apache-2.0'),
    ('org.yaml', 'snakeyaml', '1.33', 'Apache-2.0'),
    ('net.sf.dozer', 'dozer', '5.2.0', 'Apache-2.0'),
    ('org.reflections', 'reflections', '0.9.9', 'WTFPL'),
    ('javax.xml.bind', 'jaxb-api', '2.3.1', 'CDDL-1.1 OR GPL-2.0-only WITH Classpath-exception-2.0'),
    ('javax.mail', 'mail', '1.4.4', 'CDDL-1.0 OR GPL-2.0-only WITH Classpath-exception-2.0'),
):
    add(P, group, name, version, license_, 'provided', '', 'pom 선언 버전. 실행 버전은 설치본에서 확인')

# 4. Compiled into the administration portal (GWT to JavaScript)
U = '4. 관리 포털 UI 라이브러리(GWT 컴파일 포함)'
add(U, 'com.google.gwt', 'gwt-user', '2.9.0', 'Apache-2.0', 'ui-compiled')
add(U, 'com.google.gwt', 'gwt-servlet', '2.9.0', 'Apache-2.0', 'system-link', '',
    'webadmin.war WEB-INF/lib → ovirt-dependencies')
add(U, 'com.gwtplatform', 'gwtp-mvp-client', '1.6', 'Apache-2.0', 'ui-compiled')
add(U, 'com.google.gwt.inject', 'gin', '3.0.0', 'Apache-2.0', 'ui-compiled')
add(U, 'com.google.inject', 'guice', '4.2.3', 'Apache-2.0', 'ui-compiled', '', 'GIN 컴파일 의존')
add(U, 'org.gwtbootstrap3', 'gwtbootstrap3', '0.9.4', 'Apache-2.0', 'ui-compiled', '',
    'Bootstrap 3·jQuery(MIT) 포함')
add(U, 'org.gwtbootstrap3', 'gwtbootstrap3-extras', '0.9.4', 'Apache-2.0', 'ui-compiled')

# 5. Python modules (system RPMs) used by engine-setup, the encryptor and the services
Y = '5. Python 모듈(시스템 RPM)'
for name, version, license_, note in (
    ('python3-otopi', '1.10.3', 'LGPL-2.1-or-later', 'engine-setup 프레임워크'),
    ('python3-ovirt-setup-lib', '1.1.1', 'Apache-2.0', ''),
    ('python3-cryptography', '', 'Apache-2.0 OR BSD-3-Clause', '신규 암호화 도구(encryptor)가 사용'),
    ('python3-psycopg2', '', 'LGPL-3.0-or-later', ''),
    ('python3-jinja2', '', 'BSD-3-Clause', ''),
    ('python3-dateutil', '', 'Apache-2.0 AND BSD-3-Clause', ''),
    ('python3-daemon', '2.1.2', 'Apache-2.0', ''),
    ('python3-paramiko', '', 'LGPL-2.1-or-later', ''),
    ('python3-pwquality', '', 'BSD-3-Clause OR GPL-2.0-or-later', ''),
    ('python3-libxml2', '', 'MIT', ''),
    ('python3-numpy', '', 'BSD-3-Clause', ''),
    ('python3-websockify', '', 'LGPL-3.0-only', ''),
    ('python3-websocket-client', '', 'Apache-2.0', ''),
    ('python3-six', '', 'MIT', ''),
    ('python3-pyOpenSSL', '', 'Apache-2.0', ''),
    ('python3-dnf', '', 'GPL-2.0-or-later', ''),
    ('python3-libselinux', '', 'LicenseRef-Public-Domain', ''),
):
    add(Y, 'rocky', name, version, license_, 'python-rpm', '', note)

# 6. Platform and services the engine runs on and requires
S = '6. 플랫폼·서비스(시스템 RPM)'
for name, version, license_, change, note in (
    ('Rocky Linux', '9', 'NOASSERTION', '', '운영체제(배포판 구성요소별 라이선스)'),
    ('java-11-openjdk-headless', '11.0.11', 'GPL-2.0-only WITH Classpath-exception-2.0', '', ''),
    ('ovirt-engine-wildfly', '24.0.1', 'NOASSERTION', '', 'WildFly Full 24.0.1.Final. 라이선스는 설치본에서 확인'),
    ('ovirt-dependencies', '4.5.2', 'NOASSERTION', '', 'spring·gwt-servlet 등 jar 묶음'),
    ('httpd', '', 'Apache-2.0', '', '웹 서버(단말기 IP 접근 통제)'),
    ('mod_ssl', '', 'Apache-2.0', '', ''),
    ('postgresql-server', '12.0', 'PostgreSQL', '', 'SCRAM-SHA-256 강제'),
    ('postgresql-contrib', '12.0', 'PostgreSQL', '', ''),
    ('postgresql-jdbc', '42.2.27', 'BSD-2-Clause', '', ''),
    ('openssl', '3', 'Apache-2.0', '', 'libcrypto Hash_DRBG 사용'),
    ('aide', '', 'GPL-2.0-or-later', 'added', '무결성 검증. OV-Works가 Requires 추가'),
    ('apache-commons-compress', '', 'Apache-2.0', '', 'commons-compress 링크 대상'),
    ('apache-sshd', '2.9.2', 'Apache-2.0', '', ''),
    ('ansible-core', '2.13.0', 'GPL-3.0-or-later', '', ''),
    ('ansible-runner', '2.1.3', 'Apache-2.0', '', ''),
    ('novnc', '1.0.0', 'MPL-2.0', '', ''),
    ('openssh', '', 'BSD-2-Clause', '', ''),
    ('fapolicyd', '1.1', 'GPL-3.0-or-later', '', ''),
    ('rsyslog', '', 'GPL-3.0-or-later AND Apache-2.0', '', ''),
    ('collectd', '5.12.0', 'MIT AND GPL-2.0-only', '', ''),
    ('scap-security-guide', '0.1.60', 'BSD-3-Clause', '', ''),
    ('logrotate', '', 'GPL-2.0-or-later', '', ''),
    ('curl', '', 'curl', '', ''),
    ('sqlite', '', 'LicenseRef-Public-Domain', '', ''),
    ('ceph-common', '', 'NOASSERTION', '', ''),
):
    add(S, 'rocky', name, version, license_, 'platform-rpm', change, note)

# 7. oVirt companion packages the engine requires
O = '7. oVirt 동반 패키지(RPM)'
for name, version, license_, note in (
    ('ovirt-engine-extension-aaa-jdbc', '1.2.0', 'Apache-2.0', '내부 사용자 인증(aaa-jdbc)'),
    ('ovirt-engine-ui-extensions', '1.0.4', 'Apache-2.0', ''),
    ('ovirt-web-ui', '', 'Apache-2.0', 'VM 포털'),
    ('ovirt-provider-ovn', '1.2.35', 'Apache-2.0', ''),
    ('ovirt-openvswitch-ovn-central', '2.17', 'Apache-2.0', ''),
    ('ovirt-imageio-daemon', '2.0.10', 'GPL-2.0-or-later', ''),
    ('ovirt-ansible-collection', '3.0.0', 'NOASSERTION', ''),
    ('ovirt-cockpit-sso', '', 'NOASSERTION', ''),
    ('ovirt-vmconsole', '1.0.7', 'NOASSERTION', ''),
    ('ovirt-log-collector', '4.3.0', 'NOASSERTION', ''),
    ('ovirt-engine-metrics', '1.3.4.1', 'NOASSERTION', ''),
    ('ovirt-engine-keycloak-setup', '', 'NOASSERTION', ''),
    ('ovirt-engine-dwh-setup', '4.4.1.2', 'NOASSERTION', '이 저장소 밖(DWH)'),
    ('python3-cinderlib', '', 'Apache-2.0', ''),
):
    add(O, 'ovirt', name, version, license_, 'ovirt-rpm', '', note)


def purl(c):
    if c['provenance'] in ('python-rpm', 'platform-rpm', 'ovirt-rpm'):
        return 'pkg:rpm/{}/{}'.format('rocky' if c['group'] == 'rocky' else 'ovirt', c['name'])
    if c['provenance'] == 'base':
        return 'pkg:github/oVirt/ovirt-engine@ovirt-engine-4.5.6'
    version = '@' + c['version'] if c['version'] else ''
    return 'pkg:maven/{}/{}{}'.format(c['group'], c['name'], version)


def licenses(expression):
    if expression == 'NOASSERTION':
        return []
    if re.fullmatch(r'[A-Za-z0-9.\-+]+', expression):
        return [{'license': {'id': expression}}] if not expression.startswith('LicenseRef-') \
            else [{'license': {'name': expression}}]
    return [{'expression': expression}]


def cyclonedx():
    components = []
    for c in C:
        component = {
            'type': 'operating-system' if c['name'] == 'Rocky Linux'
            else 'application' if c['provenance'] in ('base', 'platform-rpm', 'ovirt-rpm')
            else 'library',
            'bom-ref': purl(c),
            'name': c['name'],
            'purl': purl(c),
            'properties': [
                {'name': 'ovworks:category', 'value': c['category']},
                {'name': 'ovworks:provenance', 'value': c['provenance']},
                {'name': 'ovworks:change', 'value': c['change'] or 'none'},
            ],
        }
        if c['group'] not in ('rocky', 'ovirt'):
            component['group'] = c['group']
        if c['version']:
            component['version'] = c['version']
        if c['provenance'] in ('system-link', 'provided', 'python-rpm', 'platform-rpm', 'ovirt-rpm'):
            component['properties'].append(
                {'name': 'ovworks:version-meaning',
                 'value': 'declared or minimum version; the installed package decides'})
        lic = licenses(c['license'])
        if lic:
            component['licenses'] = lic
        if c['note']:
            component['description'] = c['note']
        components.append(component)
    serial = uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(components, sort_keys=True, ensure_ascii=False))
    return {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.5',
        'serialNumber': 'urn:uuid:{}'.format(serial),
        'version': 1,
        'metadata': {
            'timestamp': TIMESTAMP,
            'tools': [{'vendor': 'OV-Works', 'name': 'docs/tools/sbom.py'}],
            'component': {
                'type': 'application',
                'bom-ref': 'ovworks-engine',
                'name': PRODUCT['name'],
                'version': PRODUCT['version'],
                'description': PRODUCT['description'],
            },
        },
        'components': components,
        'dependencies': [
            {'ref': 'ovworks-engine', 'dependsOn': [purl(c) for c in C]},
        ],
    }


def markdown():
    o = []
    categories = []
    for c in C:
        if c['category'] not in categories:
            categories.append(c['category'])
    for category in categories:
        mine = [c for c in C if c['category'] == category]
        o.append('### {} ({}종)\n'.format(category, len(mine)))
        o.append('| No | 구성요소 | 그룹 | 버전 | 라이선스(SPDX) | 포함 방식 | OV-Works 변경 | 비고 |')
        o.append('|---:|---|---|---|---|---|---|---|')
        for number, c in enumerate(mine, 1):
            o.append('| {} | {} | {} | {} | {} | {} | {} | {} |'.format(
                number, c['name'], '' if c['group'] in ('rocky', 'ovirt') else c['group'],
                c['version'] or '(배포판)',
                '확인 필요' if c['license'] == 'NOASSERTION' else c['license'],
                PROVENANCE[c['provenance']], CHANGE[c['change']], c['note']))
        o.append('')
    total = len(C)
    o.append('합계 {}종 (신규 추가 {}, 버전 상향 {}, 소스 수정 {}, 라이선스 확인 필요 {}).\n'.format(
        total,
        sum(1 for c in C if c['change'] == 'added'),
        sum(1 for c in C if c['change'] == 'upgraded'),
        sum(1 for c in C if c['change'] == 'modified'),
        sum(1 for c in C if c['license'] == 'NOASSERTION')))
    return '\n'.join(o)


def main():
    with open(JSON_OUT, 'w', encoding='utf-8') as stream:
        json.dump(cyclonedx(), stream, indent=2, ensure_ascii=False)
        stream.write('\n')
    with open(MD_OUT, encoding='utf-8') as stream:
        document = stream.read()
    start = document.index(BEGIN) + len(BEGIN)
    end = document.index(END)
    document = document[:start] + '\n\n' + markdown() + '\n' + document[end:]
    with open(MD_OUT, 'w', encoding='utf-8') as stream:
        stream.write(document)
    print('{} components -> {}, {}'.format(len(C), JSON_OUT, MD_OUT))


if __name__ == '__main__':
    main()
