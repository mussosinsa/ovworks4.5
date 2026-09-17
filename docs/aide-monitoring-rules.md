# AIDE 감시 규칙

## 1. 개요

`engine-setup`이 `/etc/aide.conf`에 **관리 블록**을 써 넣습니다. 이 블록이 무결성 검사(AIDE)가
설치 상태를 대조하는 기준입니다.

```
# BEGIN OVIRT-ENGINE MANAGED EXCLUSIONS
... 규칙 ...
# END OVIRT-ENGINE MANAGED EXCLUSIONS
```

| 구성요소 | 위치 |
| --- | --- |
| 규칙 정의 | `packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system/acl.py` (`_AIDE_RULES`) |
| 블록 교체 | 같은 파일 `_aide_config_with_exclusions()` |
| 규칙 고정 | `packaging/setup/tests/test_aide_managed_rules.py` |

**블록은 매번 통째로 교체됩니다.** engine-setup은 업그레이드마다 실행되므로, 블록이 두 개가 되면
옛 규칙이 새 규칙과 함께 살아남습니다. 블록 밖의 내용은 건드리지 않습니다.

## 2. 핵심 원칙 — 제외하지 않고 감시 수준을 낮춘다

운영 중 정당하게 다시 쓰이는 파일을 `!`로 제외하면 **그 파일은 어떤 변조도 탐지되지 않습니다.**
누군가 그 파일을 world-writable로 만들거나 소유자를 바꿔도 아무 기록이 남지 않습니다.

내용은 바뀌어도 **소유자·권한·SELinux 컨텍스트는 바뀌면 안 되는** 파일이므로, 해시 대신 권한만
감시합니다. 소음은 사라지고 통제는 남습니다.

```
OVIRT_PERMS = p+u+g+acl+selinux+xattrs
```

| | 내용 변경 | 권한·소유자 변경 |
| --- | --- | --- |
| `!` (제외) | 탐지 안 됨 | **탐지 안 됨** |
| `OVIRT_PERMS` | 탐지 안 됨 | **탐지됨** |
| `NORMAL` | 탐지됨 | 탐지됨 |

완전히 제외한 것은 `uninstall.d/` 하나뿐입니다. 실행 코드가 없는 설치 기록이고 **실행할 때마다
파일이 하나씩 추가**되어 권한 감시로도 소음이 남기 때문입니다.

## 3. 감시 대상

| 경로 | 수준 | 비고 |
| --- | --- | --- |
| `/usr/share/ovirt-engine/` | `NORMAL` | `engine.ear`, `bin/`, `services/`, `ui-plugins/` 전체 |
| `/usr/share/ovirt-engine-wildfly/` | `NORMAL` | `JBOSS_HOME` |
| `/usr/share/ovirt-engine-keycloak/` | `NORMAL` | |
| `/usr/share/ovirt-engine-dwh/` | `NORMAL` | |
| `/usr/share/ovirt-engine-extension-aaa-jdbc/` | `NORMAL` | |
| `/usr/share/ovirt-cockpit-sso/` | `NORMAL` | |
| `/etc/ovirt-engine/` | `NORMAL` | 아래 예외 제외 |
| `/etc/pki/ovirt-engine/` | `NORMAL` | 아래 예외 제외 |
| `/etc/httpd` | `CONTENT_EX` | 아래 예외 제외 |

**UI 플러그인(`ui-plugins/`)과 관리자가 만든 인증 프로파일(`extensions.d/`의 LDAP 등)은 낮추지
않았습니다.** 플러그인은 관리자 브라우저에서 실행되는 코드라 교체되면 세션 탈취로 이어지고,
인증 프로파일은 인증 자체를 좌우합니다. 둘 다 변경 빈도가 낮습니다.

## 4. 권한만 감시하는 파일과 그 근거

운영 중 정당하게 다시 쓰이는 파일들입니다. 각 항목은 이 저장소의 코드에서 확인한 것입니다.

### engine-setup이 실행될 때마다

| 파일 | 근거 |
| --- | --- |
| `engine.conf.d/[12][0-9]-setup-*.conf` | `engine/constants.py` `OVIRT_ENGINE_SERVICE_CONFIG_*` |
| `aaa/*.properties` | `engine/constants.py` `AAA_JDBC_CONFIG_DB` |
| `extensions.d/internal-auth{n,z}.properties` | `config/aaainternal.py`, `config/aaajdbc.py` |
| `uninstall.d/` (완전 제외) | `constants.py` `OVIRT_ENGINE_UNINSTALL_DIR` |

### 관리화면에서 설정을 바꿀 때 엔진이

| 파일 | 근거 |
| --- | --- |
| `encryptor/config.json` | `TerminalAuthConfigUtils.getConfigPath()` — 단말 인증 일련번호 |
| `engine.conf.d/99-limit-user-sessions.conf` | `acl.py`가 엔진에 `rw` 부여 — 세션 수 제한 |
| `/etc/httpd/conf.d/z-ovirt-engine-proxy.conf` | `TerminalIpConfigUtils.getConfigPath()` — 등록 단말 IP |

### 관리자가 교체·회전하는 값

| 파일 | 비고 |
| --- | --- |
| `encryptor/passphrase` | |
| `encryptor/vault-token` | |
| `encryptor/private_pkcs8.der` | |
| `/etc/pki/ovirt-engine/certs/apache.cer` | 만료 갱신, 외부 인증서 적용 |
| `/etc/pki/ovirt-engine/keys/apache.key.nopass` | `ApplyExternalSslCommand` |
| `/etc/pki/ovirt-engine/apache-ca.pem` | |

## 5. 감시하지 않는 경로

엔진이 돌면서 쓰는 곳입니다. 매 검사마다 보고되어 **다른 발견을 전부 묻어버립니다.**

```
!/var/lib/ovirt-engine/     # 검증 결과, jboss_runtime, timer-service-data 등
!/var/log/ovirt-engine/
!/var/cache/ovirt-engine/
!/var/tmp/ovirt-engine/
!/run/ovirt-engine/
!/var/run/ovirt-engine/
```

`/run`과 `/var/run`을 **둘 다** 적었습니다. 최신 배포판에서 `/var/run`은 `/run`의 심볼릭
링크이지만 AIDE는 규칙에 적힌 경로 문자열로 대조하므로, 한쪽만 적으면 한쪽만 제외됩니다.

## 6. 확인 절차

```bash
# 문법
aide --config-check

# 규칙 우선순위 — 구체적인 줄이 디렉터리 줄을 이기는지
aide --dry-init | grep -E 'encryptor|z-ovirt-engine-proxy'

# 경로가 실제로 있는지 (없으면 그 줄은 아무것도 감시하지 않습니다)
ls -d /usr/share/ovirt-engine-wildfly /usr/share/ovirt-engine-keycloak \
      /usr/share/ovirt-cockpit-sso /etc/ovirt-engine/encryptor
```

**AIDE는 파일 경로의 가장 긴 부분과 일치하는 규칙을 적용합니다.** 그래서 구체적인 파일 규칙이
디렉터리 규칙을 이깁니다. 배포판 기본 aide.conf가 `/etc PERMS` 뒤에 `/etc/hosts$ CONTENT_EX`를
두는 것과 같은 방식이지만, AIDE 버전에 따라 동작이 다를 수 있으므로 위 `--dry-init`으로 실제
적용 결과를 확인하십시오.

## 7. 적용

규칙을 바꾸면 **기준선을 다시 만들어야 합니다.** 그러지 않으면 이전 기준선과 대조되어 규칙 변경
자체가 변경으로 보고됩니다.

```bash
engine-setup                 # 관리 블록 갱신
aide --config-check
aide --update && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
```

승인된 설정 변경(단말 IP, 세션 제한, 인증서 교체 등) 이후에도 같은 절차로 기준선을 갱신합니다.
권한만 감시하는 파일은 내용이 바뀌어도 보고되지 않으므로, 대부분의 경우 갱신이 필요 없습니다.

---

**문서 버전**: 1.0
**최종 수정일**: 2026-09-17
