# log4j-api 버전 고정 (엔진 JBoss 모듈 override)

## 목적

엔진이 실행되는 애플리케이션 서버(EAP/WildFly)는 자체 `org.apache.logging.log4j.api`
모듈(배포본이 정한 버전)을 제공합니다. 보안 요구사항에 따라 **실행 중인 엔진이 반드시
특정 log4j-api 버전(현재 `2.26.1`)을 사용**하도록, 엔진 패키지가 같은 이름의 모듈을
**덮어써서(override)** 배포본 버전보다 우선 적용되게 합니다.

> 적용 대상은 **log4j-api 뿐**입니다. 이 엔진에는 `log4j-core`가 포함되지 않으므로
> (Log4Shell류 CVE의 대상인 core 미포함), core는 추가하지 않습니다.

## 동작 원리

엔진은 WildFly를 기동할 때 모듈 경로를 다음 순서로 전달합니다
(`packaging/services/ovirt-engine/ovirt-engine.py.in`):

```
-mp  <ENGINE_JAVA_MODULEPATH>:<JBOSS_HOME>/modules
     = /usr/share/ovirt-engine/modules/common : /usr/share/ovirt-engine-wildfly/modules
```

`jboss-modules`는 **같은 이름의 모듈이 여러 경로에 있으면 먼저 나오는 경로의 것**을
사용합니다. 따라서 엔진의 `modules/common`에 놓인 `org.apache.logging.log4j.api`
모듈이 EAP 기본 모듈을 이깁니다. EAP 파일은 **건드리지 않으므로**, EAP/overlay RPM을
재설치·업데이트해도 override가 유지됩니다.

## 구성 파일 (이 저장소)

| 파일 | 내용 |
|---|---|
| `pom.xml` | `log4j-api.version` 속성 + `dependencyManagement`에 `org.apache.logging.log4j:log4j-api` 관리 버전 |
| `backend/manager/dependencies/common/pom.xml` | `log4j-api` 의존성 추가 + `ovirt-jboss-modules-maven-plugin`의 `<module>` 항목(`moduleName=org.apache.logging.log4j.api`) |
| `backend/manager/dependencies/common/src/main/modules/org/apache/logging/log4j/api/main/module.xml` | override 모듈 정의(손으로 작성, jboss-logmanager 바인딩 보존) |

jar는 **Maven이 받아** 빌드 중 `modules/common/org/apache/logging/log4j/api/main/log4j-api.jar`로
설치되고, spec의 `%{engine_jboss_modules}/` 글롭으로 그대로 패키징됩니다. (다른 서드파티
모듈과 달리 **시스템 jar 심볼릭 링크로 치환하지 않습니다** — 그래야 고정 버전이 유지됨)

## 버전 변경 방법

`pom.xml`의 `<log4j-api.version>` 한 곳만 바꾸면 됩니다.

## ⚠️ 빌드 전 반드시 확인 (호환성)

이 override는 EAP의 log4j-api 모듈 **정의를 대체**하므로, log4j2 API → JBoss LogManager
라우팅(Provider: `org.jboss.logmanager.log4j2`)이 그대로 유지되는지 확인해야 합니다.

1. **모듈 의존성 대조** — 빌드/대상 호스트에서 실제 EAP 모듈과 비교해 `<dependencies>`를 맞춥니다:
   ```
   diff \
     /usr/share/ovirt-engine-wildfly/modules/system/layers/base/org/apache/logging/log4j/api/main/module.xml \
     backend/manager/dependencies/common/src/main/modules/org/apache/logging/log4j/api/main/module.xml
   ```
2. **core 존재 여부** — EAP가 `log4j-core`도 제공하면 별도 검토:
   ```
   find /usr/share/ovirt-engine-wildfly -name "log4j-core*.jar"
   ```
3. **스테이징 회귀 시험** — 재빌드·배포 후:
   - `systemctl restart ovirt-engine` 정상 기동
   - `/var/log/ovirt-engine/engine.log` 로그 정상 기록
   - WebAdmin/keycloak 로그인, 감사로그(이벤트) 기록 정상
   - 적용 버전 확인:
     ```
     ls -l /usr/share/ovirt-engine/modules/common/org/apache/logging/log4j/api/main/
     unzip -p /usr/share/ovirt-engine/modules/common/org/apache/logging/log4j/api/main/log4j-api.jar \
       META-INF/MANIFEST.MF | grep -i version
     ```

## 주의

- 이 변경은 **오프라인 빌드 검증이 불가**하며, Maven이 Central에서 `log4j-api:2.26.1`을
  받을 수 있어야 합니다(빌드 저장소/미러에 해당 아티팩트 필요).
- 라우팅 어댑터(`org.jboss.logmanager.log4j2`)가 특정 log4j-api 버전과 비호환이면,
  log4j2 API 경유 로그가 LogManager로 전달되지 않을 수 있습니다(엔진 자체 코드는 slf4j를
  쓰므로 영향이 제한적이나, keycloak 등 내장 구성요소는 스테이징에서 반드시 확인).
