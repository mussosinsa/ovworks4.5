#!/bin/bash
#
# OV-Works -- the SBOM of an installed engine host, as it runs
#
# SPDX-License-Identifier: Apache-2.0
#
# The source-level SBOM (docs/ovworks-sbom.md) gives the versions the build declares. Where the
# engine RPM links a library to a system package, and for every RPM the engine requires, the
# version that runs is the installed one. This reads it, with the license the package declares.
#
#   sudo bash docs/tools/sbom_installed_rpms.sh > ovworks-sbom-installed.md
#
# Read-only: it changes nothing on the host.

set -u

ENGINE_USR=/usr/share/ovirt-engine

echo "# OV-Works Engine 설치본 SBOM (실측)"
echo
echo "- 호스트: $(hostname -f 2>/dev/null || hostname)"
echo "- 수집 시각: $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "- 운영체제: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
echo

echo "## 1. RPM 패키지 (엔진 패키지와 그 요구 패키지)"
echo
echo "| 패키지 | 버전-릴리스 | 라이선스 | 공급자 |"
echo "|---|---|---|---|"
{
	rpm -qa 'ovirt-engine*' 'python3-ovirt-engine*' --qf '%{NAME}\n'
	for pkg in $(rpm -qa 'ovirt-engine*' --qf '%{NAME}\n'); do
		rpm -q --requires "${pkg}" 2>/dev/null \
			| awk '{print $1}' \
			| grep -v -e '^/' -e '^rpmlib(' -e '^config(' -e '(' \
			| while read -r capability; do
				rpm -q --whatprovides "${capability}" --qf '%{NAME}\n' 2>/dev/null
			done
	done
} | grep -v 'no package provides' | sort -u | while read -r name; do
	rpm -q "${name}" --qf '| %{NAME} | %{VERSION}-%{RELEASE} | %{LICENSE} | %{VENDOR} |\n' 2>/dev/null | head -1
done
echo

echo "## 2. 엔진 Java 라이브러리 (JBoss 모듈·웹앱)"
echo
echo "링크(시스템 RPM)는 대상 jar와 그 jar를 소유한 RPM을, 번들은 jar의 MANIFEST 버전을 적는다."
echo
echo "| jar | 포함 방식 | 대상/버전 | 소유 RPM |"
echo "|---|---|---|---|"
find "${ENGINE_USR}/modules" "${ENGINE_USR}/engine.ear" -name '*.jar' 2>/dev/null | sort | while read -r jar; do
	short="${jar#${ENGINE_USR}/}"
	if [ -L "${jar}" ]; then
		target="$(readlink -f "${jar}")"
		owner="$(rpm -qf "${target}" 2>/dev/null || echo '-')"
		echo "| ${short} | 시스템 RPM 링크 | ${target} | ${owner} |"
	else
		version="$(unzip -p "${jar}" META-INF/MANIFEST.MF 2>/dev/null \
			| tr -d '\r' \
			| grep -m1 -E '^(Implementation-Version|Bundle-Version):' \
			| cut -d' ' -f2)"
		owner="$(rpm -qf "${jar}" 2>/dev/null || echo '-')"
		echo "| ${short} | 번들 | ${version:--} | ${owner} |"
	fi
done
echo

echo "## 3. 주요 구성요소 버전 확인"
echo
echo '```'
java -version 2>&1 | head -1
httpd -v 2>/dev/null | head -1
postgres --version 2>/dev/null || /usr/bin/postgres --version 2>/dev/null || true
openssl version 2>/dev/null
aide --version 2>&1 | head -1
python3 --version 2>&1
echo '```'
