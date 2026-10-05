# UUID 생성 방식 설명서 (보안 감사용)

이 문서는 본 제품(oVirt Engine 4.5 기반)이 **UUID(범용 고유 식별자)를 어떻게 만드는지**, 그리고 그것이
**보안에 어떤 의미가 있는지**를 감사자가 이해하고 직접 확인할 수 있도록 정리한 것이다.

---

## 1. 결론 요약

| 질문 | 답 |
|---|---|
| UUID를 무엇에 쓰는가? | 가상머신·디스크·호스트·사용자·이벤트 등 **객체를 구별하는 이름표(식별자)**로만 쓴다 |
| UUID를 비밀값으로 쓰는가? | **쓰지 않는다.** 세션 ID, 로그인 토큰, nonce, salt, 암호 키는 UUID가 아니라 검증대상 난수발생기 **Hash_DRBG(SHA-256)**로 만든다 (`docs/csprng-hash-drbg.md`) |
| 대부분의 UUID는 어떻게 만드는가? | **버전 4(난수형)**. 운영체제 커널의 암호학적 난수(`/dev/urandom`, `getrandom`)에서 122비트를 뽑는다 |
| 예외가 있는가? | ① 설치 시 DB가 만드는 초기 데이터 일부는 **버전 1(시간형)** ② 관리화면(브라우저)이 임시로 만드는 ID는 비암호 난수 ③ REST API 통계 항목 ID는 **버전 3(이름형, 고정값)**. 모두 식별자 용도이며 비밀값이 아니다 |
| UUID를 알면 객체에 접근할 수 있는가? | **없다.** 모든 요청은 로그인(인증)과 권한 검사(인가)를 거친다. UUID는 "어느 객체인지"를 가리킬 뿐 "접근해도 되는지"를 결정하지 않는다 |

---

## 2. UUID 기초 (용어 설명)

UUID는 128비트(16바이트) 값이고, 보통 다음처럼 36자로 표기한다.

```
5f0c8a2e-3b1d-4c7e-9a41-2d6b0e8f1a37
              ^    ^
              |    └ 변형(variant) 표시: 8, 9, a, b 중 하나 → RFC 4122/9562 표준 UUID
              └ 버전(version) 표시: 이 자리 숫자가 생성 방식을 나타냄
```

| 버전 | 만드는 방법 | 특징 | 본 제품 사용 |
|---|---|---|---|
| **1** | 생성 시각 + 일련번호 + 장비 MAC 주소 | 겹치지 않지만 **생성 시각과 장비 MAC을 값에서 알 수 있음** | DB 초기 데이터 일부 |
| **3** | 이름을 MD5로 해시 | 같은 이름이면 **항상 같은 값** (의도적으로 고정) | REST API 통계 항목 |
| **4** | 난수 | 122비트가 무작위. **예측 불가** (난수원이 안전한 경우) | **대부분** |

> 버전 4의 122비트 난수는 경우의 수가 약 5.3×10³⁶이다. 무작위로 맞힐 확률은 사실상 0이다.

---

## 3. 생성 위치별 상세

### 3.1 엔진 서버 (Java) — 주 생성 방식, 버전 4

| 항목 | 내용 |
|---|---|
| 생성 함수 | `Guid.newGuid()` → Java 표준 `java.util.UUID.randomUUID()` |
| 소스 위치 | `backend/manager/modules/compat/src/main/java/org/ovirt/engine/core/compat/Guid.java` (71행) |
| 난수원 | Java `SecureRandom` → Linux 기본 설정에서 **커널 난수(`/dev/urandom`)** |
| 사용 범위 | 백엔드 약 145개 소스 파일. VM, 디스크, 네트워크, 호스트, 스토리지, 사용자, 권한, 작업, 이벤트 등 **DB 기본키 대부분** |

같은 방식(`UUID.randomUUID()`)을 직접 쓰는 곳:

| 용도 | 위치 | 설명 |
|---|---|---|
| 요청 추적 ID | `restapi/.../CurrentFilter.java`, `frontend/.../GenericApiGWTServiceImpl.java` | 한 요청의 로그를 묶어 보기 위한 번호. 클라이언트가 보내지 않았을 때만 생성 |
| cloud-init 메타데이터 | `vdsbroker/.../CloudInitHandler.java` | VM 최초 부팅 설정의 인스턴스 번호 |
| Ansible 실행 ID | `common/.../AnsibleCommandParameters.java`, `bll/.../AnsibleCommandConfig.java` | 호스트 설치 작업 실행 구분 |
| 암호 이벤트 파일 이름 | `enginesso/.../CryptoEventSpool.java` | 감사 이벤트 임시 파일이 겹치지 않게 하는 이름 |

문자열로 들어온 UUID는 `Guid.createGuidFromString()`이 형식을 검사한다. 형식이 틀리면 거부하거나
빈 값(`00000000-0000-0000-0000-000000000000`)으로 처리하므로, 잘못된 값이 식별자로 쓰이지 않는다.

### 3.2 설치·운영 도구 (Python) — 버전 4

| 용도 | 위치 |
|---|---|
| 내부 인증 도메인 ID (설치 시 1회) | `packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/config/aaainternal.py` |
| OVN 네트워크 공급자 ID | `packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/network/ovirtproviderovn.py` |
| 암호 이벤트 기록 ID | `packaging/pythonlib/ovirt_engine/cryptoevents.py` |

생성 함수는 Python 표준 `uuid.uuid4()`이고, 난수원은 `os.urandom()`, 즉 **커널 `getrandom()`**이다.

### 3.3 데이터베이스 (PostgreSQL) — 버전 1

| 항목 | 내용 |
|---|---|
| 생성 함수 | `uuid_generate_v1()` (PostgreSQL `uuid-ossp` 확장) |
| 사용 위치 | `packaging/dbscripts/common_sp.sql`(초기 권한), `packaging/dbscripts/dbfunc-custom.sh`(기본 데이터센터·클러스터), 일부 업그레이드 스크립트 |
| 언제 | **설치·업그레이드 때 한 번** 만들어지는 초기 데이터. 기본 데이터센터·클러스터는 초기 데이터 스크립트의 고정 ID를 설치 때 새 버전 1 값으로 바꿔 넣는다(`dbfunc-custom.sh`). 운영 중 생기는 객체는 3.1의 버전 4를 쓴다 |
| 구성 | 생성 시각(100나노초 단위) + 일련번호 + DB 서버 네트워크 카드 MAC |
| 보안상 의미 | 값에서 **DB 서버의 MAC 주소와 설치 시각**을 알 수 있다. 둘 다 비밀 정보가 아니고, 이 값은 비밀값 용도로 쓰이지 않는다 |
| 설치 조건 | engine-setup이 `uuid-ossp` 확장을 설치한다. 없으면 업그레이드 전 점검(`upgrade/pre_upgrade/0050_check_uuid_ossp_extension_installation.sql`)이 중단시키고 설치 방법을 안내한다 |

### 3.4 관리화면 (웹 브라우저) — 버전 4 형식, 비암호 난수

| 항목 | 내용 |
|---|---|
| 생성 함수 | 브라우저용으로 다시 구현한 `UUID.randomUUID()` |
| 소스 위치 | `frontend/webadmin/modules/gwt-extension/src/main/java/org/ovirt/engine/ui/uioverrides/java/util/UUID.java` (167행) |
| 난수원 | JavaScript `Math.random()` — **암호학적으로 안전한 난수가 아님** |
| 용도 | 화면에서 새 객체를 편집하는 동안 쓰는 임시 구별값 |
| 보안상 의미 | 비밀값으로 쓰지 않는다. 저장되는 객체 ID는 서버가 만들거나 검증하고, 접근은 서버의 권한 검사로 통제된다 |

### 3.5 이름 기반 — 버전 3 (의도적 고정값)

| 항목 | 내용 |
|---|---|
| 생성 함수 | `UUID.nameUUIDFromBytes(이름)` (MD5 기반) |
| 위치 | `backend/manager/modules/restapi/types/src/main/java/org/ovirt/engine/api/restapi/utils/StatisticResourceUtils.java` |
| 용도 | REST API의 통계 항목(예: `memory.used`)에 **매번 같은 ID**를 붙이기 위함 |
| 보안상 의미 | 예측 가능한 것이 의도된 동작이다. MD5는 여기서 보안 기능(무결성·인증)이 아니라 이름을 고정 번호로 바꾸는 데만 쓰인다 |

---

## 4. UUID와 보안값(비밀값)의 구분

감사 시 "UUID가 보안값을 대신하는 곳이 없는가"가 핵심이다. 본 제품에서 보안값은 아래처럼 별도로 만든다.

| 보안값 | 생성 방식 | 위치 |
|---|---|---|
| 엔진 세션 ID | Hash_DRBG(SHA-256) | `bll/aaa/SessionDataContainer.java` |
| SSO 토큰·인가 코드 | Hash_DRBG(SHA-256) | `enginesso/service/SsoService.java` |
| 로그인 nonce | Hash_DRBG(SHA-256) | `enginesso/service/LoginFormNonce.java` |
| 콘솔 접속 티켓 | Hash_DRBG(SHA-256) | `uutils/crypto/ticket/TicketEncoder.java`, `utils/Ticketing.java` |
| 암호화 키·IV·salt | Hash_DRBG(SHA-256) | `uutils/crypto/EnvelopeEncryptDecrypt.java`, `EnvelopePBE.java`, `PasswordHistoryCryptor.java` |
| Python 쪽 키·salt | Hash_DRBG(SHA-256, OpenSSL) | `packaging/pythonlib/ovirt_engine/csprng.py`, `packaging/encryptor/encryptor.py` |

공통 생성기는 `uutils/crypto/ApprovedRandom.java`(Java)와 `csprng.py`(Python)이다.
`docs/csprng-hash-drbg.md`에 "비보안 용도(UUID 식별자)는 대상이 아니다"라고 범위를 명시했다.

---

## 5. 감사자 확인 방법

### 5.1 소스에서 확인

```bash
# 엔진 UUID 생성 함수
grep -n "randomUUID" backend/manager/modules/compat/src/main/java/org/ovirt/engine/core/compat/Guid.java

# 보안값이 UUID를 쓰지 않는지 (세션·토큰·nonce가 ApprovedRandom 사용)
grep -rn "ApprovedRandom" --include=*.java backend | grep -v /test/

# DB 버전 1 사용 위치
grep -rn "uuid_generate_v1" packaging/dbscripts/*.sql packaging/dbscripts/*.sh
```

### 5.2 운영 서버에서 확인

UUID의 15번째 글자가 버전 번호다.

```bash
# VM ID들의 UUID 버전 분포 (운영 중 만든 객체는 4가 나와야 함)
su - postgres -c "psql engine -c \"
SELECT substr(vm_guid::text, 15, 1) AS uuid_version, count(*)
FROM vm_static GROUP BY 1\""

# 초기 데이터(기본 데이터센터)는 1일 수 있음
su - postgres -c "psql engine -c \"
SELECT name, id, substr(id::text, 15, 1) AS uuid_version FROM storage_pool\""

# Java의 SecureRandom 난수원 설정
grep -E "^securerandom.source" $(dirname $(readlink -f $(which java)))/../conf/security/java.security
```

예상 결과:
- 운영 중 생성된 객체: `uuid_version = 4`
- 설치 시 만든 기본 데이터센터(`Default`)·클러스터: `1`
- 제품에 미리 정해진 고정 ID(예: Blank 템플릿 `00000000-0000-0000-0000-000000000000`, 기본 역할): 생성된 값이 아니라 제품 정의값이므로 버전 표시가 없을 수 있음
- `securerandom.source=file:/dev/urandom`

### 5.3 UUID를 알아도 접근할 수 없음을 확인

1. 일반 사용자 A로 로그인해 A에게 권한이 없는 VM의 UUID로 REST API를 호출한다.
   ```bash
   curl -k -u 'userA@internal:비밀번호' https://<엔진>/ovirt-engine/api/vms/<다른 VM UUID>
   ```
2. 응답이 **404(없음) 또는 권한 오류**인지 확인한다. 객체가 존재해도 권한이 없으면 내용이 나오지 않는다.

---

## 6. 위험 평가와 개선 선택지

| 항목 | 위험도 | 판단 | 개선 선택지 (필요 시) |
|---|---|---|---|
| 엔진·Python의 버전 4 | 낮음 | 커널 CSPRNG 기반이며 식별자 용도 | `Guid.newGuid()`를 Hash_DRBG 기반으로 통일 |
| DB 초기 데이터의 버전 1 | 낮음 | MAC·설치 시각이 노출되지만 비밀 아님. 초기 데이터 일부만 해당 | `gen_random_uuid()`(버전 4, PostgreSQL 13+ 내장)로 교체 |
| 관리화면 `Math.random()` | 낮음 | 임시 구별값이고 서버가 권한 통제 | 브라우저 `crypto.getRandomValues()` 사용 |
| REST 통계 ID 버전 3 (MD5) | 해당 없음 | 의도된 고정값. 보안 기능 아님 | 불필요 |

**종합:** UUID는 모든 곳에서 **식별자로만** 쓰인다. 인증·세션·암호화에 필요한 비밀값은 검증대상
난수발생기(Hash_DRBG)로 따로 만든다. UUID가 노출되거나 추측되더라도 인증과 권한 검사를 우회할 수 없으므로,
UUID 생성 방식이 보안 기능의 안전성에 영향을 주지 않는다.
