# OV-Works Engine 오픈소스 구성요소 목록 (SBOM)

| 항목 | 내용 |
|---|---|
| 제품명 | OV-Works 2.4 (세부버전 V2.4.5.9) |
| 구성요소 | OV-Works Engine 4.5.7-1.el9 |
| 기반 오픈소스 | oVirt Engine 4.5.6 (Apache License 2.0) |
| 대상 소스 | `mussosinsa/ovworks4.5` 브랜치 `claude/tender-dijkstra-gs8tw1`, 커밋 `bc4ef823b1a7` |
| 작성일 | 2026-10-17 |
| 기계 판독본 | `docs/sbom/ovworks-engine-sbom.cdx.json` (CycloneDX 1.5 JSON) |
| 생성 도구 | `docs/tools/sbom.py`(이 문서의 구성요소 표와 JSON), `docs/tools/sbom_installed_rpms.sh`(설치 서버 실측) |
| 관련 문서 | `docs/ovworks-source-change-statement.md`(소스 변경 내역서) |

---

## 1. 목적과 범위

OV-Works Engine을 이루는 오픈소스 구성요소와 버전, 라이선스, 그리고 OV-Works가 무엇을 바꿨는지 정리한다.

- **대상**: 엔진 RPM(`ovirt-engine`, `-backend`, `-webadmin-portal`, `-setup*`, `-tools` 등)과, 엔진이 실행에 요구하는 패키지.
- **기준**: 소스에 적힌 선언값을 쓴다.
  - Java 라이브러리: 루트 `pom.xml` 속성과 `backend/manager/dependencies/*/pom.xml`
  - RPM 의존성: `ovirt-engine.spec.in`의 `Requires`
- **이 문서에 없는 것**
  - 운영체제(Rocky Linux 9) 기본 패키지 전체
  - 개발·시험에만 쓰는 도구(JUnit, Mockito, Maven 플러그인 등). 배포물에 들어가지 않는다.

## 2. 포함 방식에 따른 버전의 의미

RPM으로 설치하면 Java 라이브러리가 엔진에 들어가는 방식이 두 가지다. **같은 라이브러리라도 방식에 따라 실제로 동작하는 버전이 달라질 수 있다.**

| 포함 방식 | 설명 | 표의 "버전" 의미 |
|---|---|---|
| 엔진 RPM에 포함(번들) | 빌드 산출물 jar가 엔진 모듈 디렉터리에 그대로 들어간다 | 실제 동작 버전 |
| 시스템 RPM jar로 링크 | `ovirt-engine.spec.in`의 "Link dependencies to system provided" 단계에서 빌드 jar를 지우고 `/usr/share/java/...`의 시스템 패키지 jar로 심볼릭 링크한다 | pom 선언(빌드) 버전. **실제 동작 버전은 설치된 RPM 버전** |
| 실행 환경 제공(provided) | 애플리케이션 서버(WildFly) 또는 `ovirt-dependencies`가 제공한다 | pom 선언 버전. 실제 버전은 설치본 |
| 관리 포털 컴파일 포함 | GWT가 JavaScript로 컴파일해 관리 포털에 넣는다 | 실제 포함 버전 |
| 시스템 RPM | 운영체제 저장소에서 설치한다 | spec의 최소 요구 버전. 실제 버전은 설치본 |

실제 버전은 설치 서버에서 아래 명령으로 실측한다. 결과(설치본 SBOM)를 이 문서와 함께 제출한다.

```bash
sudo bash docs/tools/sbom_installed_rpms.sh > ovworks-sbom-installed.md
```

## 3. 확인이 필요한 사항

### 3.1 버전을 올린 라이브러리 중 시스템 RPM으로 링크되는 것
OV-Works는 아래 두 라이브러리의 pom 버전을 올렸다(변경 내역서 §8). 하지만 RPM 빌드에서는 두 라이브러리 모두 시스템 패키지 jar로 링크된다.

| 라이브러리 | pom 버전 | RPM에서 링크되는 대상 |
|---|---|---|
| commons-compress | 1.27.1 | `apache-commons-compress` RPM의 `/usr/share/java/commons-compress.jar` |
| spring-* (8종) | 5.3.39 | `ovirt-dependencies` RPM의 `/usr/share/java/ovirt-dependencies/spring-*.jar` |

따라서 **RPM 설치본에서는 pom에 적은 버전이 아니라, 서버에 설치된 RPM의 버전이 동작한다.**
- `rpm -q apache-commons-compress ovirt-dependencies`로 설치 버전을 확인한다.
- 설치본에서도 1.27.1·5.3.39가 동작해야 한다면, 두 라이브러리를 spec의 링크 목록에서 빼고 빌드 산출물 jar를 넣도록(번들) 바꿔야 한다.
- CVE-2024-25710, CVE-2024-26308 조치 증빙은 설치본 실측 결과를 기준으로 작성한다.

### 3.2 라이선스 "확인 필요" 항목
배포판이나 동반 패키지에서 라이선스 표기가 여러 개이거나 버전마다 다른 항목은 "확인 필요"로 남겼다. 설치본 SBOM의 RPM `License` 값으로 확정한다.

## 4. 구성요소 목록

이 절의 표는 `docs/tools/sbom.py`가 생성한다. 구성요소를 바꿀 때는 스크립트의 표를 고치고 다시 실행한다.

<!-- BEGIN GENERATED COMPONENTS: docs/tools/sbom.py -->

### 1. 기반 오픈소스 (1종)

| No | 구성요소 | 그룹 | 버전 | 라이선스(SPDX) | 포함 방식 | OV-Works 변경 | 비고 |
|---:|---|---|---|---|---|---|---|
| 1 | ovirt-engine | org.ovirt | 4.5.6 | Apache-2.0 | 기반 오픈소스(소스 반입·수정) | 소스 수정(변경 내역서 참조) | https://github.com/oVirt/ovirt-engine 태그 ovirt-engine-4.5.6 (eb315a9) |

### 2. 엔진 Java 라이브러리(JBoss 모듈) (34종)

| No | 구성요소 | 그룹 | 버전 | 라이선스(SPDX) | 포함 방식 | OV-Works 변경 | 비고 |
|---:|---|---|---|---|---|---|---|
| 1 | log4j-api | org.apache.logging.log4j | 2.26.1 | Apache-2.0 | 엔진 RPM에 포함(빌드 산출물 jar) | 신규 추가 | 서버 제공 log4j-api를 대체하는 엔진 모듈. log4j-core는 포함하지 않음 |
| 2 | commons-io | commons-io | 2.16.1 | Apache-2.0 | 엔진 RPM에 포함(빌드 산출물 jar) | 신규 추가 | commons-compress 1.26+ 실행 의존성 |
| 3 | commons-lang3 | org.apache.commons | 3.16.0 | Apache-2.0 | 엔진 RPM에 포함(빌드 산출물 jar) | 신규 추가 | commons-compress 1.26+ 실행 의존성 |
| 4 | client | com.ongres.scram | 2.1 | BSD-2-Clause | 엔진 RPM에 포함(빌드 산출물 jar) | 신규 추가 | PostgreSQL JDBC SCRAM-SHA-256 인증 |
| 5 | common | com.ongres.scram | 2.1 | BSD-2-Clause | 엔진 RPM에 포함(빌드 산출물 jar) | 신규 추가 | 위와 같음 |
| 6 | saslprep | com.ongres.stringprep | 1.1 | BSD-2-Clause | 엔진 RPM에 포함(빌드 산출물 jar) | 신규 추가 | 위와 같음 |
| 7 | stringprep | com.ongres.stringprep | 1.1 | BSD-2-Clause | 엔진 RPM에 포함(빌드 산출물 jar) | 신규 추가 | 위와 같음 |
| 8 | metamodel-server | org.ovirt.engine.api | 1.3.10 | Apache-2.0 | 엔진 RPM에 포함(빌드 산출물 jar) | 변경 없음(upstream 그대로) |  |
| 9 | commons-compress | org.apache.commons | 1.27.1 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 버전 상향 | 1.21→1.27.1(CVE-2024-25710, CVE-2024-26308). RPM은 apache-commons-compress RPM jar로 링크: 설치본 버전 확인 필요 |
| 10 | spring-aop | org.springframework | 5.3.39 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 버전 상향 | 5.3.27→5.3.39. RPM은 ovirt-dependencies jar로 링크: 설치본 버전 확인 필요 |
| 11 | spring-beans | org.springframework | 5.3.39 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 버전 상향 | 5.3.27→5.3.39. RPM은 ovirt-dependencies jar로 링크: 설치본 버전 확인 필요 |
| 12 | spring-context | org.springframework | 5.3.39 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 버전 상향 | 5.3.27→5.3.39. RPM은 ovirt-dependencies jar로 링크: 설치본 버전 확인 필요 |
| 13 | spring-core | org.springframework | 5.3.39 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 버전 상향 | 5.3.27→5.3.39. RPM은 ovirt-dependencies jar로 링크: 설치본 버전 확인 필요 |
| 14 | spring-expression | org.springframework | 5.3.39 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 버전 상향 | 5.3.27→5.3.39. RPM은 ovirt-dependencies jar로 링크: 설치본 버전 확인 필요 |
| 15 | spring-instrument | org.springframework | 5.3.39 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 버전 상향 | 5.3.27→5.3.39. RPM은 ovirt-dependencies jar로 링크: 설치본 버전 확인 필요 |
| 16 | spring-jdbc | org.springframework | 5.3.39 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 버전 상향 | 5.3.27→5.3.39. RPM은 ovirt-dependencies jar로 링크: 설치본 버전 확인 필요 |
| 17 | spring-tx | org.springframework | 5.3.39 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 버전 상향 | 5.3.27→5.3.39. RPM은 ovirt-dependencies jar로 링크: 설치본 버전 확인 필요 |
| 18 | postgresql | org.postgresql | 42.2.27 | BSD-2-Clause | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 변경 없음(upstream 그대로) | postgresql-jdbc >= 42.2.27 |
| 19 | sshd-core | org.apache.sshd | 2.9.2 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 변경 없음(upstream 그대로) | apache-sshd >= 2.9.2 |
| 20 | sshd-common | org.apache.sshd | 2.9.2 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 변경 없음(upstream 그대로) | apache-sshd >= 2.9.2 |
| 21 | eddsa | net.i2p.crypto | 0.3.0 | CC0-1.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 변경 없음(upstream 그대로) | ed25519-java >= 0.3.0 |
| 22 | aopalliance | aopalliance | 1.0 | LicenseRef-Public-Domain | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 변경 없음(upstream 그대로) |  |
| 23 | ws-commons-util | org.apache.ws.commons.util | 1.0.2 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 변경 없음(upstream 그대로) |  |
| 24 | xmlrpc-client | org.apache.xmlrpc | 3.1.3 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 변경 없음(upstream 그대로) |  |
| 25 | xmlrpc-common | org.apache.xmlrpc | 3.1.3 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 변경 없음(upstream 그대로) |  |
| 26 | cors-filter | org.ebaysf.web | 1.0.1 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 변경 없음(upstream 그대로) | ebay-cors-filter |
| 27 | ovirt-engine-extensions-api | org.ovirt.engine.api | 1.0.1 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 변경 없음(upstream 그대로) |  |
| 28 | java-client-kubevirt | org.ovirt.java-client-kubevirt | 0.5.0 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 변경 없음(upstream 그대로) |  |
| 29 | vdsm-jsonrpc-java-client | org.ovirt.vdsm-jsonrpc-java | 1.7.2 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 변경 없음(upstream 그대로) |  |
| 30 | snmp4j | org.snmp4j | 3.6.4 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 변경 없음(upstream 그대로) |  |
| 31 | openstack-java-sdk | com.woorea | 3.2.9 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 변경 없음(upstream 그대로) | openstack-client, keystone/glance/cinder/quantum client·model, resteasy-connector (10종) |
| 32 | slf4j-api | org.slf4j | 1.7.22 | MIT | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 변경 없음(upstream 그대로) | 도구(tools) 모듈 |
| 33 | slf4j-jdk14 | org.slf4j | 1.7.22 | MIT | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 변경 없음(upstream 그대로) | 도구(tools) 모듈 |
| 34 | jcl-over-slf4j | org.slf4j | 1.7.22 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 변경 없음(upstream 그대로) | 도구(tools) 모듈 |

### 3. 실행 환경 제공 Java 라이브러리(provided) (18종)

| No | 구성요소 | 그룹 | 버전 | 라이선스(SPDX) | 포함 방식 | OV-Works 변경 | 비고 |
|---:|---|---|---|---|---|---|---|
| 1 | jackson-databind | com.fasterxml.jackson.core | 2.12.7.1 | Apache-2.0 | 애플리케이션 서버/ovirt-dependencies 제공(빌드 시 provided) | 변경 없음(upstream 그대로) | pom 선언 버전. 실행 버전은 설치본에서 확인 |
| 2 | jackson-core | com.fasterxml.jackson.core | 2.12.7 | Apache-2.0 | 애플리케이션 서버/ovirt-dependencies 제공(빌드 시 provided) | 변경 없음(upstream 그대로) | pom 선언 버전. 실행 버전은 설치본에서 확인 |
| 3 | httpclient | org.apache.httpcomponents | 4.5.13 | Apache-2.0 | 애플리케이션 서버/ovirt-dependencies 제공(빌드 시 provided) | 변경 없음(upstream 그대로) | pom 선언 버전. 실행 버전은 설치본에서 확인 |
| 4 | httpcore | org.apache.httpcomponents | 4.4.14 | Apache-2.0 | 애플리케이션 서버/ovirt-dependencies 제공(빌드 시 provided) | 변경 없음(upstream 그대로) | pom 선언 버전. 실행 버전은 설치본에서 확인 |
| 5 | commons-codec | commons-codec | 1.10 | Apache-2.0 | 애플리케이션 서버/ovirt-dependencies 제공(빌드 시 provided) | 변경 없음(upstream 그대로) | pom 선언 버전. 실행 버전은 설치본에서 확인 |
| 6 | commons-lang | commons-lang | 2.6 | Apache-2.0 | 애플리케이션 서버/ovirt-dependencies 제공(빌드 시 provided) | 변경 없음(upstream 그대로) | pom 선언 버전. 실행 버전은 설치본에서 확인 |
| 7 | commons-collections | commons-collections | 3.2.2 | Apache-2.0 | 애플리케이션 서버/ovirt-dependencies 제공(빌드 시 provided) | 변경 없음(upstream 그대로) | pom 선언 버전. 실행 버전은 설치본에서 확인 |
| 8 | commons-beanutils | commons-beanutils | 1.9.4 | Apache-2.0 | 애플리케이션 서버/ovirt-dependencies 제공(빌드 시 provided) | 변경 없음(upstream 그대로) | pom 선언 버전. 실행 버전은 설치본에서 확인 |
| 9 | commons-configuration | commons-configuration | 1.6 | Apache-2.0 | 애플리케이션 서버/ovirt-dependencies 제공(빌드 시 provided) | 변경 없음(upstream 그대로) | pom 선언 버전. 실행 버전은 설치본에서 확인 |
| 10 | hibernate-validator | org.hibernate.validator | 6.0.18.Final | Apache-2.0 | 애플리케이션 서버/ovirt-dependencies 제공(빌드 시 provided) | 변경 없음(upstream 그대로) | pom 선언 버전. 실행 버전은 설치본에서 확인 |
| 11 | infinispan-core | org.infinispan | 9.4.18.Final | Apache-2.0 | 애플리케이션 서버/ovirt-dependencies 제공(빌드 시 provided) | 변경 없음(upstream 그대로) | pom 선언 버전. 실행 버전은 설치본에서 확인 |
| 12 | resteasy | org.jboss.resteasy | 3.9.3.Final | Apache-2.0 | 애플리케이션 서버/ovirt-dependencies 제공(빌드 시 provided) | 변경 없음(upstream 그대로) | pom 선언 버전. 실행 버전은 설치본에서 확인 |
| 13 | javassist | org.javassist | 3.23.1-GA | MPL-1.1 OR LGPL-2.1-or-later OR Apache-2.0 | 애플리케이션 서버/ovirt-dependencies 제공(빌드 시 provided) | 변경 없음(upstream 그대로) | pom 선언 버전. 실행 버전은 설치본에서 확인 |
| 14 | snakeyaml | org.yaml | 1.33 | Apache-2.0 | 애플리케이션 서버/ovirt-dependencies 제공(빌드 시 provided) | 변경 없음(upstream 그대로) | pom 선언 버전. 실행 버전은 설치본에서 확인 |
| 15 | dozer | net.sf.dozer | 5.2.0 | Apache-2.0 | 애플리케이션 서버/ovirt-dependencies 제공(빌드 시 provided) | 변경 없음(upstream 그대로) | pom 선언 버전. 실행 버전은 설치본에서 확인 |
| 16 | reflections | org.reflections | 0.9.9 | WTFPL | 애플리케이션 서버/ovirt-dependencies 제공(빌드 시 provided) | 변경 없음(upstream 그대로) | pom 선언 버전. 실행 버전은 설치본에서 확인 |
| 17 | jaxb-api | javax.xml.bind | 2.3.1 | CDDL-1.1 OR GPL-2.0-only WITH Classpath-exception-2.0 | 애플리케이션 서버/ovirt-dependencies 제공(빌드 시 provided) | 변경 없음(upstream 그대로) | pom 선언 버전. 실행 버전은 설치본에서 확인 |
| 18 | mail | javax.mail | 1.4.4 | CDDL-1.0 OR GPL-2.0-only WITH Classpath-exception-2.0 | 애플리케이션 서버/ovirt-dependencies 제공(빌드 시 provided) | 변경 없음(upstream 그대로) | pom 선언 버전. 실행 버전은 설치본에서 확인 |

### 4. 관리 포털 UI 라이브러리(GWT 컴파일 포함) (7종)

| No | 구성요소 | 그룹 | 버전 | 라이선스(SPDX) | 포함 방식 | OV-Works 변경 | 비고 |
|---:|---|---|---|---|---|---|---|
| 1 | gwt-user | com.google.gwt | 2.9.0 | Apache-2.0 | 관리 포털 JavaScript로 컴파일되어 포함 | 변경 없음(upstream 그대로) |  |
| 2 | gwt-servlet | com.google.gwt | 2.9.0 | Apache-2.0 | 시스템 RPM jar로 링크(실행 버전 = 설치된 RPM 버전) | 변경 없음(upstream 그대로) | webadmin.war WEB-INF/lib → ovirt-dependencies |
| 3 | gwtp-mvp-client | com.gwtplatform | 1.6 | Apache-2.0 | 관리 포털 JavaScript로 컴파일되어 포함 | 변경 없음(upstream 그대로) |  |
| 4 | gin | com.google.gwt.inject | 3.0.0 | Apache-2.0 | 관리 포털 JavaScript로 컴파일되어 포함 | 변경 없음(upstream 그대로) |  |
| 5 | guice | com.google.inject | 4.2.3 | Apache-2.0 | 관리 포털 JavaScript로 컴파일되어 포함 | 변경 없음(upstream 그대로) | GIN 컴파일 의존 |
| 6 | gwtbootstrap3 | org.gwtbootstrap3 | 0.9.4 | Apache-2.0 | 관리 포털 JavaScript로 컴파일되어 포함 | 변경 없음(upstream 그대로) | Bootstrap 3·jQuery(MIT) 포함 |
| 7 | gwtbootstrap3-extras | org.gwtbootstrap3 | 0.9.4 | Apache-2.0 | 관리 포털 JavaScript로 컴파일되어 포함 | 변경 없음(upstream 그대로) |  |

### 5. Python 모듈(시스템 RPM) (17종)

| No | 구성요소 | 그룹 | 버전 | 라이선스(SPDX) | 포함 방식 | OV-Works 변경 | 비고 |
|---:|---|---|---|---|---|---|---|
| 1 | python3-otopi |  | 1.10.3 | LGPL-2.1-or-later | 시스템 RPM(Python) | 변경 없음(upstream 그대로) | engine-setup 프레임워크 |
| 2 | python3-ovirt-setup-lib |  | 1.1.1 | Apache-2.0 | 시스템 RPM(Python) | 변경 없음(upstream 그대로) |  |
| 3 | python3-cryptography |  | (배포판) | Apache-2.0 OR BSD-3-Clause | 시스템 RPM(Python) | 변경 없음(upstream 그대로) | 신규 암호화 도구(encryptor)가 사용 |
| 4 | python3-psycopg2 |  | (배포판) | LGPL-3.0-or-later | 시스템 RPM(Python) | 변경 없음(upstream 그대로) |  |
| 5 | python3-jinja2 |  | (배포판) | BSD-3-Clause | 시스템 RPM(Python) | 변경 없음(upstream 그대로) |  |
| 6 | python3-dateutil |  | (배포판) | Apache-2.0 AND BSD-3-Clause | 시스템 RPM(Python) | 변경 없음(upstream 그대로) |  |
| 7 | python3-daemon |  | 2.1.2 | Apache-2.0 | 시스템 RPM(Python) | 변경 없음(upstream 그대로) |  |
| 8 | python3-paramiko |  | (배포판) | LGPL-2.1-or-later | 시스템 RPM(Python) | 변경 없음(upstream 그대로) |  |
| 9 | python3-pwquality |  | (배포판) | BSD-3-Clause OR GPL-2.0-or-later | 시스템 RPM(Python) | 변경 없음(upstream 그대로) |  |
| 10 | python3-libxml2 |  | (배포판) | MIT | 시스템 RPM(Python) | 변경 없음(upstream 그대로) |  |
| 11 | python3-numpy |  | (배포판) | BSD-3-Clause | 시스템 RPM(Python) | 변경 없음(upstream 그대로) |  |
| 12 | python3-websockify |  | (배포판) | LGPL-3.0-only | 시스템 RPM(Python) | 변경 없음(upstream 그대로) |  |
| 13 | python3-websocket-client |  | (배포판) | Apache-2.0 | 시스템 RPM(Python) | 변경 없음(upstream 그대로) |  |
| 14 | python3-six |  | (배포판) | MIT | 시스템 RPM(Python) | 변경 없음(upstream 그대로) |  |
| 15 | python3-pyOpenSSL |  | (배포판) | Apache-2.0 | 시스템 RPM(Python) | 변경 없음(upstream 그대로) |  |
| 16 | python3-dnf |  | (배포판) | GPL-2.0-or-later | 시스템 RPM(Python) | 변경 없음(upstream 그대로) |  |
| 17 | python3-libselinux |  | (배포판) | LicenseRef-Public-Domain | 시스템 RPM(Python) | 변경 없음(upstream 그대로) |  |

### 6. 플랫폼·서비스(시스템 RPM) (25종)

| No | 구성요소 | 그룹 | 버전 | 라이선스(SPDX) | 포함 방식 | OV-Works 변경 | 비고 |
|---:|---|---|---|---|---|---|---|
| 1 | Rocky Linux |  | 9 | 확인 필요 | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) | 운영체제(배포판 구성요소별 라이선스) |
| 2 | java-11-openjdk-headless |  | 11.0.11 | GPL-2.0-only WITH Classpath-exception-2.0 | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) |  |
| 3 | ovirt-engine-wildfly |  | 24.0.1 | 확인 필요 | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) | WildFly Full 24.0.1.Final. 라이선스는 설치본에서 확인 |
| 4 | ovirt-dependencies |  | 4.5.2 | 확인 필요 | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) | spring·gwt-servlet 등 jar 묶음 |
| 5 | httpd |  | (배포판) | Apache-2.0 | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) | 웹 서버(단말기 IP 접근 통제) |
| 6 | mod_ssl |  | (배포판) | Apache-2.0 | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) |  |
| 7 | postgresql-server |  | 12.0 | PostgreSQL | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) | SCRAM-SHA-256 강제 |
| 8 | postgresql-contrib |  | 12.0 | PostgreSQL | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) |  |
| 9 | postgresql-jdbc |  | 42.2.27 | BSD-2-Clause | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) |  |
| 10 | openssl |  | 3 | Apache-2.0 | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) | libcrypto Hash_DRBG 사용 |
| 11 | aide |  | (배포판) | GPL-2.0-or-later | 시스템 RPM(플랫폼·서비스) | 신규 추가 | 무결성 검증. OV-Works가 Requires 추가 |
| 12 | apache-commons-compress |  | (배포판) | Apache-2.0 | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) | commons-compress 링크 대상 |
| 13 | apache-sshd |  | 2.9.2 | Apache-2.0 | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) |  |
| 14 | ansible-core |  | 2.13.0 | GPL-3.0-or-later | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) |  |
| 15 | ansible-runner |  | 2.1.3 | Apache-2.0 | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) |  |
| 16 | novnc |  | 1.0.0 | MPL-2.0 | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) |  |
| 17 | openssh |  | (배포판) | BSD-2-Clause | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) |  |
| 18 | fapolicyd |  | 1.1 | GPL-3.0-or-later | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) |  |
| 19 | rsyslog |  | (배포판) | GPL-3.0-or-later AND Apache-2.0 | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) |  |
| 20 | collectd |  | 5.12.0 | MIT AND GPL-2.0-only | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) |  |
| 21 | scap-security-guide |  | 0.1.60 | BSD-3-Clause | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) |  |
| 22 | logrotate |  | (배포판) | GPL-2.0-or-later | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) |  |
| 23 | curl |  | (배포판) | curl | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) |  |
| 24 | sqlite |  | (배포판) | LicenseRef-Public-Domain | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) |  |
| 25 | ceph-common |  | (배포판) | 확인 필요 | 시스템 RPM(플랫폼·서비스) | 변경 없음(upstream 그대로) |  |

### 7. oVirt 동반 패키지(RPM) (14종)

| No | 구성요소 | 그룹 | 버전 | 라이선스(SPDX) | 포함 방식 | OV-Works 변경 | 비고 |
|---:|---|---|---|---|---|---|---|
| 1 | ovirt-engine-extension-aaa-jdbc |  | 1.2.0 | Apache-2.0 | oVirt 동반 RPM | 변경 없음(upstream 그대로) | 내부 사용자 인증(aaa-jdbc) |
| 2 | ovirt-engine-ui-extensions |  | 1.0.4 | Apache-2.0 | oVirt 동반 RPM | 변경 없음(upstream 그대로) |  |
| 3 | ovirt-web-ui |  | (배포판) | Apache-2.0 | oVirt 동반 RPM | 변경 없음(upstream 그대로) | VM 포털 |
| 4 | ovirt-provider-ovn |  | 1.2.35 | Apache-2.0 | oVirt 동반 RPM | 변경 없음(upstream 그대로) |  |
| 5 | ovirt-openvswitch-ovn-central |  | 2.17 | Apache-2.0 | oVirt 동반 RPM | 변경 없음(upstream 그대로) |  |
| 6 | ovirt-imageio-daemon |  | 2.0.10 | GPL-2.0-or-later | oVirt 동반 RPM | 변경 없음(upstream 그대로) |  |
| 7 | ovirt-ansible-collection |  | 3.0.0 | 확인 필요 | oVirt 동반 RPM | 변경 없음(upstream 그대로) |  |
| 8 | ovirt-cockpit-sso |  | (배포판) | 확인 필요 | oVirt 동반 RPM | 변경 없음(upstream 그대로) |  |
| 9 | ovirt-vmconsole |  | 1.0.7 | 확인 필요 | oVirt 동반 RPM | 변경 없음(upstream 그대로) |  |
| 10 | ovirt-log-collector |  | 4.3.0 | 확인 필요 | oVirt 동반 RPM | 변경 없음(upstream 그대로) |  |
| 11 | ovirt-engine-metrics |  | 1.3.4.1 | 확인 필요 | oVirt 동반 RPM | 변경 없음(upstream 그대로) |  |
| 12 | ovirt-engine-keycloak-setup |  | (배포판) | 확인 필요 | oVirt 동반 RPM | 변경 없음(upstream 그대로) |  |
| 13 | ovirt-engine-dwh-setup |  | 4.4.1.2 | 확인 필요 | oVirt 동반 RPM | 변경 없음(upstream 그대로) | 이 저장소 밖(DWH) |
| 14 | python3-cinderlib |  | (배포판) | Apache-2.0 | oVirt 동반 RPM | 변경 없음(upstream 그대로) |  |

합계 116종 (신규 추가 8, 버전 상향 9, 소스 수정 1, 라이선스 확인 필요 11).

<!-- END GENERATED COMPONENTS -->

## 5. OV-Works 신규 개발분의 외부 의존

OV-Works가 새로 개발한 코드(신규 파일 272개)가 쓰는 외부 구성요소는 아래가 전부다.

| 신규 코드 | 쓰는 외부 구성요소 | 비고 |
|---|---|---|
| Java(엔진·SSO·화면) | upstream이 이미 쓰는 라이브러리(Spring, Jackson, GWT 등) | 새로 추가한 Java 라이브러리 없음 |
| Python(setup·encryptor·운영 도구) | `python3-cryptography`, `otopi`, `jinja2`, 표준 라이브러리 | upstream 요구 패키지 범위 안 |
| 난수(Hash_DRBG) | OpenSSL 3 libcrypto(`EVP_RAND`) | `ctypes`로 직접 호출. 추가 패키지 없음 |
| 무결성 검증 | AIDE | spec에 `Requires: aide` 추가 |
| PostgreSQL SCRAM | com.ongres.scram / stringprep | PostgreSQL JDBC의 실행 의존성으로 추가 |

## 6. 라이선스 의무 요약

| 라이선스 | 해당 구성요소(예) | 배포 시 의무 |
|---|---|---|
| Apache-2.0 | oVirt Engine(기반), Spring, Apache Commons, log4j-api, GWT | 라이선스 사본·NOTICE 유지, 수정 파일 표시(변경 내역서 §9) |
| BSD-2-Clause / BSD-3-Clause | PostgreSQL JDBC, ongres SCRAM, Jinja2 | 저작권·라이선스 고지 유지 |
| MIT | slf4j, Bootstrap·jQuery(gwtbootstrap3 포함) | 저작권·라이선스 고지 유지 |
| LGPL-2.1 / LGPL-3.0 | otopi, psycopg2, paramiko, websockify | 별도 패키지로 동적 사용. 수정 시 해당 소스 공개 |
| GPL-2.0 / GPL-3.0 | AIDE, ansible-core, fapolicyd | 별도 프로그램으로 실행(링크하지 않음). 수정·재배포 시 소스 제공 |
| MPL-2.0 | noVNC | 별도 패키지. 수정 파일 소스 공개 |
| PostgreSQL | PostgreSQL 서버 | 저작권 고지 유지 |
| CC0-1.0 / Public Domain | eddsa, aopalliance, sqlite | 의무 없음 |

OV-Works는 GPL·LGPL 구성요소를 **수정하지 않았고**, 엔진 코드와 정적으로 링크하지도 않는다. 모두 운영체제 RPM 그대로 쓰거나 별도 프로세스로 실행한다.

## 7. 갱신 절차

1. 의존성을 바꾸면(pom, spec) `docs/tools/sbom.py`의 구성요소 표를 고친다.
2. `python3 docs/tools/sbom.py`를 실행해 이 문서의 §4와 CycloneDX JSON을 다시 만든다.
3. 설치 서버에서 `docs/tools/sbom_installed_rpms.sh`로 실측본을 만들어 함께 보관한다.
