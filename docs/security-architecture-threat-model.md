# 보안 아키텍처 및 위협 모델

## 1. 문서 범위

본 위협 모델은 보안기능 확인서 제출 범위인 OV-Works Engine, WebAdmin/REST API, SSO/AAA, PostgreSQL, 관리 Host, 설정 암호화 도구 및 사설 PKI를 대상으로 한다. 실제 배포의 reverse proxy, 외부 LDAP/Kerberos, SIEM, HSM, backup 저장소는 연결 여부에 따라 범위에 추가한다.

## 2. 보호 자산

| 자산 ID | 자산 | 보안 목표 | 주요 저장·처리 위치 |
|---|---|---|---|
| AS-01 | WebAdmin ID/PW/token/session | 기밀성·무결성·재사용 방지 | 브라우저, HTTPS, SSO/AAA |
| AS-02 | DB 접속정보 | 기밀성·무결성·가용성 | setup DB conf, systemd credential |
| AS-03 | server/Host private key | 기밀성·무결성 | Engine/Host PKI 경로, keystore |
| AS-04 | 보안정책과 설정 | 무결성·인가된 변경 | Engine/Apache/AAA/encryptor 설정 |
| AS-05 | 감사기록 | 완전성·무결성·가용성·추적성 | Engine DB/log, syslog/SIEM |
| AS-06 | 관리 명령과 VM/Host 제어권 | 인증·인가·부인방지 | WebAdmin/API/BLL |
| AS-07 | 암호화 passphrase/KEK/DEK | 기밀성·수명주기 통제 | credential, process memory, ciphertext |
| AS-08 | 제출 바이너리와 기준선 | 출처·무결성 | RPM/JAR, AIDE DB, SHA-256 manifest |

## 3. 행위자 및 신뢰 가정

| 행위자 | 권한/능력 | 신뢰 가정 |
|---|---|---|
| 일반 사용자 | 허용된 VM/리소스 사용 | 다른 사용자·관리기능 접근 불가 |
| 보안/시스템 관리자 | 정책·인증서·서비스 변경 | 승인·최소권한·감사와 이중 통제 적용 |
| 외부 API client | 발급 token 범위의 API 호출 | TLS와 token 검증 필수 |
| 관리 Host | Engine과 인증서 기반 통신 | 등록된 Host 인증서만 신뢰 |
| 외부 AAA/SIEM | 인증 또는 audit 처리 | 별도 제품의 보안성과 TLS 구성 입증 필요 |
| 비인가 원격 공격자 | 네트워크 요청·credential 추측 | 내부망·OS/root 접근권한 없음 |
| 침해된 관리자 단말 | 유효 session 탈취·관리 요청 | IP allowlist만으로 완전 방어할 수 없음 |
| 로컬 권한 공격자 | file/process/log 접근 시도 | OS DAC, SELinux, service account 분리 적용 |

## 4. 데이터 흐름과 신뢰경계

```text
[관리자 브라우저]
       | HTTPS/TLS, ID/PW/token                    TB-01 외부→관리망
       v
[Apache/Private CA SSL] -- Require ip --> [WebAdmin/REST/SSO]
                                                |
                                  credential    | TB-02 Web→AAA
                                                v
                                           [AAA Provider]
                                                |
                                      auth result/session
                                                |
                audit/action                    v
          +------------------------------ [Engine BLL] -------- TLS/cert ---- [Hosts]
          |                                      |                TB-04
          v                                      | JDBC
 [Audit DB/log/SIEM]                             v
       TB-05                                [PostgreSQL]
                                                 TB-03

[systemd credential] --> [encryptor] --> [OVENC001 DB config]
           TB-06 key injection/process/file boundary
```

### 4.1 신뢰경계

* **TB-01:** 비신뢰 client network와 Apache HTTPS endpoint 사이. TLS, server identity, IP allowlist 및 rate/lockout가 필요하다.
* **TB-02:** SSO와 내장/외부 AAA 사이. credential 노출 방지, provider 신뢰 및 실패 결과의 일관된 처리가 필요하다.
* **TB-03:** Engine과 PostgreSQL 사이. DB 인증정보, TLS, DB 권한과 SQL 처리 보호가 필요하다.
* **TB-04:** Engine과 Host 사이. 상호 인증서, 재등록, 폐기 및 Host 상태 검증이 필요하다.
* **TB-05:** 애플리케이션과 audit 저장/전송 사이. 기록 실패, disk full, queue/replay 및 관리자 변조를 고려한다.
* **TB-06:** key source와 encryptor/process/config file 사이. command line·환경·임시파일·memory 노출과 잘못된 key를 고려한다.

## 5. 위협 및 통제 매트릭스

| 위협 ID | STRIDE | 위협 시나리오 | 영향 자산 | 현재 통제 | 잔여위험/필수 시험 |
|---|---|---|---|---|---|
| TH-01 | Spoofing | 공격자가 관리자 PW를 반복 추측 | AS-01/06 | 보호 admin 5회 기본 잠금, audit | 외부 AAA·다중 Engine 상태 공유, 5회 부정시험 |
| TH-02 | Spoofing | 위조 server가 WebAdmin credential 수집 | AS-01 | HTTPS, 사설 CA chain 적용 | hostname/SAN, client trust, HTTP 우회 시험 |
| TH-03 | Spoofing | serial number를 복제해 단말 위장 | AS-06 | IP allowlist | serial enforcement 미확인; 인증서/challenge-response 필요 |
| TH-04 | Tampering | DB config 암호문·header 변조 | AS-02 | AES-256-GCM과 AAD | byte 변조 시 출력 미생성 시험 |
| TH-05 | Tampering | Apache allowlist에 지시어 삽입 | AS-04/06 | 단일 IPv4 parser, 권한검사 | setup CIDR 경로 포함 config syntax 시험 |
| TH-06 | Tampering | JAR/보안설정 비인가 변경 | AS-04/08 | SHA-256 baseline, AIDE runner | 기준선 자체의 별도 보호·승인 필요 |
| TH-07 | Repudiation | 관리자가 보안정책 변경을 부인 | AS-04/05 | command audit type/message | 수행자·사유·전후값 완전성 시험 |
| TH-08 | Repudiation | 차단 IP가 접속 시도를 부인 | AS-05 | Apache/firewall log 점검 | 원본 IP·정책 ID·시간의 중앙 audit 연계 필요 |
| TH-09 | Information disclosure | DB passphrase가 환경/process/log에 노출 | AS-02/07 | systemd credential 우선, 0600 file | 환경변수 비상용 제한, crash/log/memory 절차 |
| TH-10 | Information disclosure | PW/token/private key가 제출 증적에 포함 | AS-01/03 | 마스킹 절차 | 자동 secret scan과 이중 검토 |
| TH-11 | Information disclosure | private key upload 임시내용/권한 노출 | AS-03 | 적용 후 0600/owner 설정 | 쓰기 순간 권한과 임시파일, backup 잔존 시험 |
| TH-12 | Denial of service | 로그인 brute force 또는 잠금 악용 | AS-01/06 | 계정 잠금 | 사용자명 기반 DoS, source rate limit 검토 |
| TH-13 | Denial of service | audit filesystem 고갈 | AS-05 | 70/85/95% 감시, 오래된 log archive | 동일 filesystem archive 실패, 원격 offload 필요 |
| TH-14 | Denial of service | 잘못된 key로 Engine DB 시작 실패 | AS-02/06 | GCM fail closed, 복구 절차 | key backup·offline rollback 훈련 |
| TH-15 | Elevation of privilege | 일반 사용자가 보안 설정 command 호출 | AS-04/06 | System object action-group 권한검사 | 직접 API 부정시험과 역할 분리 |
| TH-16 | Elevation of privilege | group writable/symlink config로 root file 변경 | AS-02/04 | allowed root, symlink·writable 거부 | 경로교체 경쟁조건 및 packaging 권한 시험 |
| TH-17 | Tampering/DoS | audit DB write 실패로 사건기록 유실 | AS-05 | 실패 pattern 점검/syslog 통지 | persistent queue/replay 미확인, 장애 주입 필수 |
| TH-18 | Spoofing/Tampering | 폐기·만료 Host 인증서가 계속 사용됨 | AS-03/06 | Host certificate enrollment | CRL/OCSP, 갱신/폐기 후 접속 거부 시험 |

## 6. 보안 설계 원칙

1. **Fail closed:** GCM 인증, certificate chain, 권한검사 또는 Host enrollment 실패를 성공으로 전환하지 않는다.
2. **최소 권한:** Engine은 non-root로 실행하고 보안 설정 변경은 System action group에 제한한다.
3. **비밀정보 분리:** ciphertext와 key source를 분리하고 systemd encrypted credential을 우선한다.
4. **다중 계층:** HTTPS, IP allowlist, AAA, RBAC와 audit를 상호 대체가 아닌 중첩 통제로 사용한다.
5. **추적 가능성:** 요구사항, 위협, 통제, source, test, evidence와 잔여위험을 ID로 연결한다.
6. **운영의존성 공개:** 외부 AAA, SIEM, 사설 CA 및 배포 Apache 설정에 의존하는 판정을 제품 구현으로 과장하지 않는다.

## 7. 잔여위험 승인 기준

잔여위험마다 발생가능성, 영향, 탐지가능성, 현재 보완통제, 조치기한과 승인자를 기록한다. 다음 상태는 무기한 승인하지 않는다.

* 관리자 credential 또는 private key의 평문 노출 가능성
* 인증 우회 또는 일반 사용자의 보안관리 권한 상승
* 감사기록 누락을 탐지·복구할 수 없는 상태
* 지원 종료 또는 알려진 치명적 취약 component 사용
* 검증이 요구되는 암호모듈 대신 검증범위 밖 provider를 사용하는 상태

## 8. 위협 모델 갱신 조건

외부 AAA/SIEM 추가, proxy 구조 변경, 새 API, 암호 포맷·provider 변경, session 정책 변경, Host 통신 변경, 신규 privileged command 또는 중대한 보안사고/CVE가 발생할 때 본 문서를 갱신한다. 변경된 위협 ID는 영향받는 요구사항과 회귀시험에 연결한다.
