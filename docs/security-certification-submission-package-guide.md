# 보안기능 확인서 시험·인증 제출 문서 패키지 가이드

## 1. 목적

본 문서는 OV-Works의 보안기능 확인서 시험·인증을 준비할 때 구현 명세서 외에 함께 준비해야 할 보안 문서, 책임자, 증적 및 제출 전 품질 기준을 정의한다. 시험기관의 최신 제출 양식과 계약상 요구사항이 본 문서보다 우선하며, 기관이 제공한 공식 문서명·번호·버전은 접수 전에 반드시 확인한다.

문서만 존재한다고 보안기능이 적합한 것은 아니다. 각 문서는 **제품 버전, Git commit, 설치 패키지, 실제 설정 및 시험 결과**와 일치해야 한다.

## 2. 제출 패키지 구성 총괄

| 번호 | 문서/증적 | 목적 | 저장소 현황 | 제출 상태 |
|---:|---|---|---|---|
| 1 | 보안기능 확인서 | 제품·신청인·보안기능과 적용 범위 선언 | `docs/security-function-verification-form.md` | 기관 양식으로 전환 필요 |
| 2 | 보안 구현 명세서 | 기능별 설계, 알고리즘, 제어 흐름 및 소스 추적 | `docs/national-security-implementation-specification.md` | 제품/버전 정보 확정 필요 |
| 3 | 서버 공통보안 적합성 근거표 | 요구사항별 적합 판정과 근거 연결 | `docs/nis-server-common-security-requirements-compliance.md` | 공식 요구사항 ID·페이지 기입 필요 |
| 4 | 자체 보안처리 명세서 | 설치·운영·점검·장애·증적 절차 | `docs/self-security-processing-specification.md` | 현장 경로·담당자 확정 필요 |
| 5 | 보안 아키텍처 및 위협 모델 | 신뢰경계, 자산, 공격경로와 대응 통제 설명 | `docs/security-architecture-threat-model.md` | 제출 대상 구성으로 검토 필요 |
| 6 | 보안 시험계획서·결과서·증적목록 | 정상/경계/부정시험의 재현성과 판정 보장 | `docs/security-test-evidence-plan.md` | 실제 결과·서명 입력 필요 |
| 7 | 암호모듈·알고리즘 목록 | 암호 사용처, 키 길이, 모드, 난수, 인증서와 예외 공개 | 본 문서 5장 및 암호 관련 기존 문서 | 실제 provider/버전 확인 필요 |
| 8 | 키·인증서 수명주기 절차 | 생성·주입·사용·교체·백업·폐기·사고 대응 | 기존 암호화/사설 CA 문서에 분산 | 운영자와 HSM/credential 방식 확정 필요 |
| 9 | 안전한 설치·운영·삭제 지침 | 보안 기본값, 최소 포트, 권한, 백업, 폐기 | 기존 운영 문서에 분산 | 릴리스별 설치 검증 필요 |
| 10 | 형상·빌드·배포 명세 | 동일 소스에서 제출 바이너리를 재현하고 식별 | `pom.xml`, spec, build scripts | 빌드 환경·서명·hash 증적 생성 필요 |
| 11 | 제3자 구성요소/SBOM·라이선스 | 공급망과 알려진 취약점 추적 | Maven/RPM metadata, `LICENSE`, `NOTICE` | CycloneDX/SPDX 산출물 생성 필요 |
| 12 | 취약점 분석 및 조치보고서 | SAST/SCA/DAST/침투시험 결과와 잔여위험 승인 | 일부 예시 문서 존재 | 실제 대상 버전으로 재수행 필요 |
| 13 | 보안결함·패치 정책 | 신고, 분류, 수정, 배포, 고객통지 및 EOL | 별도 운영 정책 필요 | 조직 승인본 작성 필요 |
| 14 | 감사·개인정보·민감정보 처리표 | 수집 항목, 목적, 보존, 접근, 마스킹, 파기 | 감사 관련 문서에 분산 | 조직 보존정책과 정합화 필요 |
| 15 | 추적성 매트릭스 | 요구사항→설계→소스→시험→증적의 누락 방지 | 본 문서 4장 양식 | 최종 제출본 작성 필요 |
| 16 | 편차·미해결사항·잔여위험 목록 | 미구현/조건부/운영의존 항목을 투명하게 관리 | 본 문서 8장 양식 | 승인자 서명 필요 |

## 3. 문서 통제 기준

모든 제출 문서의 표지 또는 문서정보 표에 다음을 기록한다.

| 통제 항목 | 필수 내용 |
|---|---|
| 문서 식별 | 문서명, 문서번호, 버전, 보안등급 |
| 제품 식별 | 제품명, edition, 제품 버전, build/RPM release, Git commit |
| 대상 구성 | Engine/Host/DB/OS/브라우저/외부 AAA의 지원 버전 |
| 책임 | 작성자, 기술검토자, 보안승인자, 승인일 |
| 변경이력 | 개정번호, 변경일, 변경 사유, 변경 절, 변경자 |
| 배포 통제 | 제출처, 배포번호, 사본번호, 회수·파기 여부 |
| 무결성 | 파일명, byte 크기, SHA-256, 전자서명 또는 승인시스템 ID |
| 비밀정보 | 마스킹 기준 및 원본 접근권한 |

문서의 제품 버전과 시험 바이너리 버전이 다르면 별도 영향분석 없이 동일 제출물로 사용하지 않는다. 예시 IP, 예시 CVE, 예상 출력은 실제 시험 결과로 표시하지 않는다.

## 4. 요구사항 추적성 매트릭스 양식

시험기관 제출본에는 다음 열을 유지한다.

| 공식 요구사항 ID/페이지 | 요구사항 요약 | 보안기능 ID | 설계 절 | 소스 commit/path/symbol | 설정값 | 시험 ID | 증적 ID | 판정 | 편차/조치 |
|---|---|---|---|---|---|---|---|---|---|
| 기관 원문 기입 | 원문의 의미를 변경하지 않고 요약 | 예: SF-DB-01 | 문서·절 | commit + class/function | 비밀값 마스킹 | T-DB-01 | EV-DB-001 | 적합/부적합/N/A | 티켓·기한 |

### 4.1 작성 규칙

1. 하나의 요구사항에 여러 구현 또는 시험이 있으면 행을 분리하거나 모든 ID를 명시한다.
2. 소스 근거는 파일명만 적지 않고 commit, symbol 및 line 범위를 기록한다.
3. 운영 절차만 있고 강제 코드가 없으면 `운영통제`로 표시하고 제품 구현으로 오인하지 않는다.
4. 실행하지 않은 시험은 `미수행`, 환경에 적용되지 않으면 근거를 갖춘 `N/A`로 표시한다.
5. FAIL을 문서에서 제거하지 않고 결함 ID, 수정 commit, 재시험 증적을 연결한다.

## 5. 암호모듈·알고리즘 제출표

### 5.1 현재 소스에서 확인되는 암호 사용

| 사용처 | 알고리즘/형식 | 키·파라미터 | 구현/provider | 소스 근거 | 제출 전 확인 |
|---|---|---|---|---|---|
| DB 접속설정 파일 | AES-256-GCM `OVENC001` | 랜덤 256-bit DEK, 96-bit nonce, 128-bit tag | Python `cryptography` AESGCM | `packaging/encryptor/encryptor.py` | cryptography/OpenSSL/RPM 버전, KCMVP 적용 여부 |
| wrapping key 유도 | PBKDF2-HMAC-SHA-256 | 600,000회, 랜덤 128-bit salt, 256-bit KEK | Python `cryptography` PBKDF2HMAC | 동일 | passphrase 생성 강도와 보관 방식 |
| 구형 설정 복호 | AES-256-CBC/PKCS#7 | 이관 설정에 명시된 key/IV | Python `cryptography` | 동일 | 신규 사용 금지, 이관 후 기능 비활성 증적 |
| built-in admin PW | EnvelopePBE verifier 검사 | 실제 형식은 uutils 구현/배포값 확인 | Java crypto abstraction | `InternalAuthn.java`, uutils crypto | provider·salt·iteration·저장 샘플(마스킹) |
| WebAdmin/API 통신 | TLS/HTTPS | 인증서·protocol·cipher는 배포 설정 | Apache/JVM/OpenSSL | Engine/Apache setup 및 SSL command | 실제 협상 protocol/cipher, 검증모듈 여부 |
| 사설 CA | X.509 chain 검증 | server key/cert/CA chain | OpenSSL 및 Java truststore | `ApplyExternalSslCommand.java` | key type/길이, signature, SAN, CRL/OCSP |
| 무결성 기준선 | SHA-256 | 파일별 digest | `sha256sum`, AIDE | audit script/runner | 기준선 보호와 승인·갱신 절차 |

### 5.2 별도 제출 증적

* 암호 라이브러리와 provider의 정확한 패키지명·버전·hash
* 검증필 암호모듈 사용이 요구될 경우 모듈 검증번호, 유효범위, 운용환경 및 approved mode 증적
* 난수원이 OS CSPRNG인지 확인한 자료와 entropy 장애 처리
* 키별 소유자, 생성위치, 저장매체, 접근주체, 교체주기, 백업, 폐기 및 유출 대응표
* 인증서 profile, key usage/EKU, SAN, 유효기간, chain, 폐기정보 배포 절차
* 평문·키·passphrase가 log, crash dump, command line, 환경변수, 임시파일에 잔존하지 않는다는 시험

“AES-256 사용”만으로 검증필 암호모듈 요구 충족을 주장하지 않는다. 알고리즘 적합성과 모듈/운용환경 적합성은 별도로 입증한다.

## 6. 안전한 설치·운영·삭제 지침에 포함할 내용

### 6.1 설치 전

* 지원 OS/RPM/DB/JVM/브라우저 버전과 보안 패치 최소수준
* 관리망, Host망, DB망의 신뢰경계와 최소 허용 port
* FQDN/DNS/NTP, 사설 CA 및 인증서 발급 준비
* 서비스 계정과 root 작업 범위, SELinux enforcing 및 firewalld 정책
* DB credential/systemd credential 생성과 전달의 이중 통제

### 6.2 설치 및 초기화

* 기본 또는 예제 password·certificate·secret을 운영에 사용하지 않음
* 설치 후 파일 owner/mode, 실행 사용자, open port, active service를 기준선과 비교
* DB 접속설정 암호화, HTTPS 적용, AAA profile, 관리자 잠금정책, session timeout 확인
* 최초 AIDE/SHA-256 기준선은 승인된 설치 완료 후 생성하고 별도 보호 저장
* backup/restore, 장애 rollback 및 비상관리자 접근을 운영 전 시험

### 6.3 정기 운영

* 일일: 인증서 만료, 저장공간, 자체보안점검, backup 성공, 중요 audit alert
* 주간: 실패 로그인/IP 차단, 관리자 작업, 변경승인 대조
* 월간: 권한 재검토, restore 표본시험, 무결성 차이 승인, 취약점/patch 현황
* 반기: 부정시험, key rotation rehearsal, 원격로그 장애 queue/replay, 침해사고 훈련

### 6.4 제거·폐기

* 서비스 중지와 token/session 폐기 후 DB, backup, log, credential, key, certificate의 보유·파기 범위를 승인
* 인증서 폐기 및 CRL/OCSP 반영, systemd credential/secret file/keystore 백업 폐기
* 저장매체 유형과 조직 정책에 맞는 삭제 또는 물리 파기
* 파기 대상, 방식, 도구, 수행자, 검토자, 시각 및 결과 hash를 파기확인서에 기록

## 7. SBOM·공급망·취약점 제출물

### 7.1 SBOM 필수 필드

CycloneDX 또는 SPDX 형식으로 최소 다음을 포함한다.

* 제품 component 이름·버전·supplier·PURL/CPE
* Maven/RPM/Python/JavaScript 및 번들 바이너리의 transitive dependency
* 파일/package SHA-256과 license expression
* dependency relationship과 build timestamp/tool version
* 알려진 수정본, fork 또는 vendor patch 식별자

SBOM은 source tree가 아니라 **실제 제출 RPM/배포 이미지**에서 재확인한다. 개발·시험 전용 dependency는 scope를 구분한다.

### 7.2 취약점 보고서

| 필드 | 내용 |
|---|---|
| 스캔 식별 | 도구·버전·DB update 시각·명령·정책 |
| 대상 식별 | 제품 build/hash, OS/image/repository snapshot |
| 발견사항 | CVE/CWE, component, installed/fixed version, severity와 산정기준 |
| 도달가능성 | 취약 code path 포함·호출·노출 여부 및 분석 근거 |
| 조치 | upgrade/backport/config mitigation/비활성화 |
| 잔여위험 | 악용조건, 보완통제, 승인자, 만료일 |
| 재시험 | 수정 build, 시험 ID, 결과 및 증적 ID |

도구가 “0건”을 출력했다는 사실만 제출하지 않고 DB freshness, scan scope, suppression 및 오탐 분석을 함께 제공한다.

## 8. 편차 및 잔여위험 관리대장

| 편차 ID | 요구사항 | 현 상태/원인 | 영향·악용조건 | 임시 보완통제 | 영구조치/기한 | 책임자 | 승인/만료 | 재시험 |
|---|---|---|---|---|---|---|---|---|
| DEV-예시 | 공식 ID 기입 | serial number enforcement 미확인 | 일련번호만으로 단말 식별 불가 | Apache IP allowlist | 인증서 기반 단말인증 검토 | 담당자 기입 | 승인자 기입 | T-TA 항목 |

현재 문서에서 최소한 다음 편차를 추적한다.

1. 외부 AAA password 저장·잠금정책은 외부 구성요소 증적에 의존한다.
2. 단말 serial number의 요청단 강제 지점이 확인되지 않았다.
3. 감사저장 실패 시 persistent queue와 무손실 replay가 제품 소스만으로 확인되지 않았다.
4. 감사 archive가 기본적으로 동일 filesystem에 생성되어 disk-full 상황의 실패 가능성이 있다.
5. 수동 계정 잠금 해제와 개별 활성 session 강제 종료의 완결된 감사 흐름은 추가 입증이 필요하다.

## 9. 제출 디렉터리 및 증적 명명 규칙

```text
submission/
  00-index/
  01-application-and-product-id/
  02-requirements-and-traceability/
  03-design-and-source/
  04-installation-and-operation/
  05-cryptography-and-key-management/
  06-test-plan-and-results/
  07-sbom-and-vulnerability/
  08-audit-and-incident-response/
  09-deviations-and-approvals/
```

증적 파일명은 `<증적ID>_<시험ID>_<대상>_<UTC시각>.<확장자>` 형식을 사용한다. 예: `EV-DB-001_T-DB-02_engine01_20260805T120000Z.txt`. 각 디렉터리에 `MANIFEST.sha256`과 담당자의 서명 또는 승인시스템 export를 둔다.

## 10. 제출 전 최종 검토

- [ ] 시험기관의 최신 양식·요구사항 버전·제출 매체·암호화 방법을 확인했다.
- [ ] 모든 문서의 제품 version/build/commit이 시험 바이너리와 일치한다.
- [ ] 공식 요구사항의 모든 행이 설계·소스·설정·시험·증적에 연결된다.
- [ ] 부분 적합, 판정 보류, FAIL, N/A 및 잔여위험을 숨기지 않았다.
- [ ] 실제 실행 결과와 예시/계획을 명확히 구분했다.
- [ ] source line은 최종 commit 기준으로 다시 생성했다.
- [ ] SBOM과 취약점 scan이 실제 제출 package/image를 대상으로 한다.
- [ ] 암호모듈 검증 상태를 알고리즘 이름만으로 과장하지 않았다.
- [ ] PW, private key, passphrase, token/cookie, DB credential과 개인정보를 마스킹했다.
- [ ] 모든 제출 파일의 SHA-256, 서명, 배포번호 및 사본 이력을 생성했다.
- [ ] 기술·보안·품질 책임자가 추적성 및 편차를 검토하고 서명했다.
