# WebAdmin ID/PW 공개키·개인키 암복호화 보안기능 확인서

## 1. 문서 정보

| 항목 | 내용 |
|---|---|
| 문서명 | WebAdmin ID/PW 공개키·개인키 암복호화 보안기능 확인서 |
| 대상 제품 | oVirt Engine (OV-Works) 4.5.x |
| 대상 기능 | WebAdmin 대화형 로그인 ID/PW 보호 |
| 문서 버전 / 작성일 | 1.0 / 2026-07-29 |
| 작성자 / 검증자 / 승인자 | `[성명·직책] / [성명·직책] / [성명·직책]` |
| 최종 판정 | `[적합 / 조건부 적합 / 부적합]` |

> 제출 전 대괄호(`[ ]`)를 운영 정보로 대체한다. 실제 ID/PW, 개인키, 클라이언트 일련번호, 세션 값 및 복호화 평문은 증적에 포함하지 않는다.

## 2. 목적과 보안 경계

본 확인서는 WebAdmin 로그인 화면에서 사용자가 입력한 ID와 PW를 브라우저가 RSA 공개키로 암호화하고, Engine SSO 서버가 대응 개인키로 복호화하여 인증하는 기능의 구현 방식과 자체 시험 절차를 정의한다.

이 기능은 HTTPS/TLS 위에 적용하는 **응용계층 추가 보호**이다. 다음 보안 통제를 대신하지 않는다.

- HTTPS 강제, 신뢰 가능한 서버 인증서와 TLS 1.2 이상 적용
- 서버·브라우저·리버스 프록시·WAF의 안전한 로그 및 메모리 관리
- 사용자 인증, 계정 잠금, 다중 인증, 세션 및 CSRF 보호
- 인증 저장소의 단방향 비밀번호 해시 정책

공개키는 비밀정보가 아니지만 변조되면 공격자 키로 ID/PW가 암호화될 수 있으므로 반드시 인증된 HTTPS로 전달한다. 개인키는 Engine 서버 밖으로 배포하지 않는다.

## 3. 구현 구조 및 처리 흐름

### 3.1 구성요소

| 구성요소 | 위치 또는 형식 | 역할 |
|---|---|---|
| 공개키 설정 | `/etc/ovirt-engine/encryptor/config.json`의 `rsaPublicKey` | 브라우저 암호화용 RSA 공개키 |
| 개인키 | `/etc/ovirt-engine/encryptor/private_pkcs8.der` | SSO 서버 복호화용 PKCS#8 RSA 개인키 |
| 로그인 화면 | `login.jsp` | Web Crypto API로 ID/PW를 각각 암호화 |
| 복호화 모듈 | `LoginEnvelopeCrypto` | Base64 해제, RSA-OAEP 복호화 및 UTF-8 변환 |
| 인증 처리 | `InteractiveAuthServlet` | 암호화 필드 복호화 후 기존 인증 서비스 호출 |
| 공개키 다운로드 | `/ovirt-engine/sso/oauth/public-key` | 일련번호 검증 후 X.509 SPKI PEM 공개키 제공 |

### 3.2 처리 순서

```text
브라우저                         Engine SSO                         인증 저장소
   │  ① HTTPS 로그인 화면 요청       │                                  │
   │ ◀─ ② X.509 SPKI 공개키 포함 ────│                                  │
   │  ③ ID/PW 각각 RSA-OAEP-256 암호화                                  │
   │  ④ 평문 입력란 삭제, Base64 암호문 POST                            │
   │ ────────────────────────────────▶│                                  │
   │                                  │ ⑤ PKCS#8 개인키로 각각 복호화      │
   │                                  │ ⑥ 기존 자격증명 검증 요청 ────────▶│
   │                                  │ ◀──────── 인증 결과 ──────────────│
   │ ◀──────── ⑦ 세션/오류 응답 ─────│                                  │
```

로그인 폼은 `encryptedUsername`과 `encryptedPassword`를 전송한다. 암호화 성공 전에 평문 필드를 비우며, 공개키가 없거나 Web Crypto API를 사용할 수 없거나 암호화에 실패하면 폼 제출을 중단한다. 서버는 암호문이 존재하면 이를 복호화하여 평문 폼 값보다 우선 사용한다.

공개키 다운로드 API는 `X-Client-Serial` 검증에 성공한 요청만 허용하고 `Cache-Control: no-store`, `application/x-pem-file` 및 `public_key.pem` 다운로드 형식을 사용한다. 로그인 페이지 내 공개키 제공 경로와 다운로드 API 경로는 별개이므로 각각 시험한다.

## 4. 암호 알고리즘과 키 형식

| 항목 | 구현·승인 기준 |
|---|---|
| 비대칭 알고리즘 | RSA |
| 패딩 | OAEP |
| OAEP 해시 | SHA-256 |
| MGF | MGF1 with SHA-256 |
| Label | 빈 값(`PSource.PSpecified.DEFAULT`) |
| 브라우저 API | Web Crypto `RSA-OAEP`, `hash: SHA-256` |
| 전송 인코딩 | 암호문 Base64 |
| 공개키 형식 | X.509 SubjectPublicKeyInfo, PEM `PUBLIC KEY` |
| 개인키 형식 | PKCS#8 DER |
| 키 크기 | 운영 기준 RSA 3072비트 이상 권장, 최소 2048비트 |

Java 변환 문자열의 `RSA/ECB/...`에서 `ECB`는 RSA 공급자 명명 관례이며 블록암호 ECB 모드를 사용한다는 뜻이 아니다. 브라우저와 서버는 OAEP 해시뿐 아니라 **MGF1 해시도 SHA-256**으로 일치해야 한다.

RSA-OAEP는 같은 평문도 매번 다른 암호문을 생성한다. SHA-256을 사용하는 RSA-OAEP의 최대 평문 길이는 `키 바이트 수 - 2×32 - 2`이다. 예를 들어 2048비트 RSA는 최대 190바이트이므로 ID/PW 입력 길이가 이를 넘으면 브라우저가 제출을 중단해야 한다. RSA는 대용량 데이터 암호화가 아닌 짧은 로그인 자격증명 보호에만 사용한다.

## 5. 보안기능 확인 결과표

| 번호 | 확인 기능 | 합격 기준 | 판정 | 증적 |
|:---:|---|---|:---:|---|
| WLE-01 | HTTPS 보호 | 로그인 화면·폼 제출·공개키 조회가 모두 유효한 HTTPS를 사용한다. | `[ ]` | `[EV-01]` |
| WLE-02 | 공개키 형식 | `rsaPublicKey`가 유효한 RSA X.509 SPKI이고 등록 지문과 일치한다. | `[ ]` | `[EV-02]` |
| WLE-03 | 개인키 보호 | PKCS#8 개인키가 서버에만 존재하고 최소 권한으로 보호된다. | `[ ]` | `[EV-03]` |
| WLE-04 | 알고리즘 일치 | 클라이언트와 서버 모두 RSA-OAEP/SHA-256/MGF1-SHA-256을 사용한다. | `[ ]` | `[EV-04]` |
| WLE-05 | 평문 미전송 | 요청 본문에 평문 ID/PW 필드 또는 값이 존재하지 않는다. | `[ ]` | `[EV-05]` |
| WLE-06 | Fail closed | 공개키 누락·Web Crypto 미지원·암호화 실패 시 로그인 요청을 전송하지 않는다. | `[ ]` | `[EV-06]` |
| WLE-07 | 복호화 오류 | 손상·잘못된 암호문은 인증 실패로 처리하고 평문·키를 로그에 남기지 않는다. | `[ ]` | `[EV-07]` |
| WLE-08 | 비결정성 | 같은 입력을 반복 암호화한 결과가 서로 다르며 모두 정상 복호화된다. | `[ ]` | `[EV-08]` |
| WLE-09 | API 접근통제 | 잘못되거나 누락된 `X-Client-Serial`의 공개키 다운로드는 401이다. | `[ ]` | `[EV-09]` |
| WLE-10 | 키 쌍 일치 | 공개키와 개인키에서 산출한 공개키 지문이 일치한다. | `[ ]` | `[EV-10]` |
| WLE-11 | 키 교체 | 신규 키 배포·재기동·시험·구 키 폐기·롤백 절차가 승인되어 있다. | `[ ]` | `[EV-11]` |
| WLE-12 | 로그·메모리 보호 | ID/PW, 개인키, 복호화 평문이 로그·오류 응답·core dump에 노출되지 않는다. | `[ ]` | `[EV-12]` |

## 6. 키 생성·등록 및 보호 절차

### 6.1 키 쌍 생성

승인된 Engine 서버 또는 HSM/KMS에서 생성한다. 다음은 RSA 3072비트 소프트웨어 키 예시이다.

```bash
sudo install -d -m 0700 -o root -g root /etc/ovirt-engine/encryptor
sudo openssl genpkey -algorithm RSA \
  -pkeyopt rsa_keygen_bits:3072 \
  -outform DER \
  -out /etc/ovirt-engine/encryptor/private_pkcs8.der
sudo chmod 0600 /etc/ovirt-engine/encryptor/private_pkcs8.der

sudo openssl pkey \
  -inform DER \
  -in /etc/ovirt-engine/encryptor/private_pkcs8.der \
  -pubout -out /root/login_public_key.pem
```

생성된 공개키 PEM을 `config.json`의 `rsaPublicKey`에 등록하되 JSON 개행 이스케이프를 정확히 적용하고, 개인키는 설정 파일·티켓·메일에 삽입하지 않는다. 설정 갱신은 임시파일 작성, `fsync`, 권한 설정 후 원자적 교체 방식으로 수행한다.

### 6.2 키 쌍과 형식 확인

```bash
# 실제 키 값 대신 공개키 SHA-256 지문만 증적으로 보관한다.
sudo openssl pkey -inform DER \
  -in /etc/ovirt-engine/encryptor/private_pkcs8.der \
  -pubout -outform DER | sha256sum

openssl pkey -pubin -in /root/login_public_key.pem \
  -pubout -outform DER | sha256sum

sudo stat -c '%n %U:%G %a %s bytes' \
  /etc/ovirt-engine/encryptor/private_pkcs8.der \
  /etc/ovirt-engine/encryptor/config.json
sudo restorecon -Rv /etc/ovirt-engine/encryptor
```

두 지문이 같아야 하며 개인키가 다른 사용자에게 읽기 가능하면 부적합이다. 공개키 지문은 승인 티켓과 별도 무결성 기준 저장소에 기록한다.

## 7. 자체 시험 절차

### 7.1 정적·단위 시험

1. 로그인 페이지가 Web Crypto `RSA-OAEP`와 SHA-256으로 공개키를 가져오는지 확인한다.
2. 서버 복호화가 OAEP SHA-256, MGF1 SHA-256, 빈 label을 명시하는지 확인한다.
3. 공개키 PEM 정규화, 다운로드 성공, 잘못된 일련번호 거부 및 공개키 누락 시험을 실행한다.

```bash
mvn -pl backend/manager/modules/enginesso \
  -Dtest=LoginEnvelopeCryptoTest,RsaPublicKeyServletTest test
```

### 7.2 브라우저 동적 시험

1. 전용 시험 계정으로 WebAdmin 로그인 페이지에 HTTPS 접속한다.
2. 개발자 도구의 Network 탭에서 `interactive-login` 요청을 확인한다.
3. 실제 값은 캡처하지 않고 다음 필드 존재 여부만 기록한다.
   - `encryptedUsername`: Base64 RSA 암호문
   - `encryptedPassword`: Base64 RSA 암호문
   - 평문 `username`, `password`: 빈 값 또는 미전송
4. 같은 시험 입력으로 두 번 로그인하여 암호문이 서로 다른지 확인한다.
5. 정상 로그인, 잘못된 비밀번호, 암호문 1바이트 변조, 과도하게 긴 입력을 각각 시험한다.
6. JavaScript에서 공개키를 제거하거나 `window.crypto.subtle`을 비활성화한 시험에서 요청이 전송되지 않는지 확인한다.

브라우저 화면·HAR 증적을 저장할 때 쿠키, 세션 토큰, ID/PW, 암호문 및 `X-Client-Serial`을 삭제하거나 마스킹한다. 암호문도 장기 보존이 필요한 증적은 아니며 공격자가 개인키를 나중에 획득할 가능성을 고려하여 수집을 최소화한다.

### 7.3 공개키 API 및 헤더 시험

```bash
# 실제 일련번호는 셸 이력에 직접 입력하지 않고 제한 권한 환경변수로 전달한다.
curl --fail --silent --show-error \
  --header "X-Client-Serial: ${CLIENT_SERIAL}" \
  --output /tmp/public_key.pem \
  https://engine.example.internal/ovirt-engine/sso/oauth/public-key
openssl pkey -pubin -in /tmp/public_key.pem -text -noout

# 헤더 누락 요청은 HTTP 401이어야 한다.
test "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  https://engine.example.internal/ovirt-engine/sso/oauth/public-key)" = 401
rm -f /tmp/public_key.pem
```

응답에서 `Content-Type: application/x-pem-file`, `Content-Disposition: attachment; filename="public_key.pem"`, `Cache-Control: no-store`를 확인한다. 일련번호 헤더는 공개 네트워크에서 단독 인증수단으로 간주하지 않으며 HTTPS, IP 접근통제 및 관리 절차와 함께 사용한다.

## 8. 키 교체·폐기 및 장애 대응

### 8.1 정기·수시 교체

- 키 사용기간은 최대 2년을 권장하며 조직 정책이 더 짧으면 이를 따른다.
- 개인키 유출 의심, 관리자 권한 침해, 파일 무결성 훼손, 알고리즘 취약화 또는 담당자 권한 변경 시 즉시 교체한다.
- 신규 공개키와 개인키는 한 쌍으로 배포하고 Engine 재기동 후 로그인과 다운로드 API를 시험한다.
- 로드밸런서 다중 노드에서는 키 쌍을 동시에 전환하거나 키 ID를 포함한 이중 키 복호화 전환 설계를 사용한다.

### 8.2 롤백 및 침해 대응

1. 키 불일치, 로그인 전면 실패 또는 복호화 예외 증가 시 변경을 중단한다.
2. 승인된 직전 키 쌍과 `config.json`을 원래 권한·SELinux 컨텍스트로 복원한다.
3. Engine을 재기동하고 HTTPS 로그인·인증 실패·API 접근통제를 재시험한다.
4. 개인키 침해가 의심되면 구 키로 롤백하지 않고 긴급 신규 키 전환, 세션 폐기, 로그 조사 및 사고 대응을 수행한다.
5. 구 개인키는 롤백 기간 종료 또는 침해 확인 즉시 안전하게 폐기하고 모든 복제본을 추적한다.

## 9. 알려진 제한과 보완 통제

| 제한 | 위험 | 보완 통제 |
|---|---|---|
| 서버가 제공한 공개키를 브라우저가 사용 | HTTPS가 침해되면 키 치환 가능 | 인증서 검증, HSTS, 안전한 프록시, 공개키 지문 관리 |
| 서버에서 ID/PW 평문 복호화 필요 | 서버 메모리·로그 노출 가능 | 최소 수명, 로그 금지, heap/core dump 통제, 관리자 권한 최소화 |
| 암호문 재전송 방지값 없음 | 캡처 암호문 재전송 가능성 | TLS, SSO 세션·CSRF 토큰, 로그인 시도 제한; nonce/timestamp 결합 개선 검토 |
| 정적 RSA 키 | 개인키 유출 시 과거 수집 암호문 복호화 가능 | 짧은 키 수명, 암호문 미보관, 순방향 비밀성을 제공하는 TLS 필수 |
| ID/PW를 각각 직접 RSA 암호화 | 입력 길이 제한 | 입력 길이 제한 및 필요 시 AEAD 기반 하이브리드 envelope 도입 |
| 평문 폼 파라미터 fallback 가능 | 암호문 없이 평문 경로가 사용될 위험 | WebAdmin 경로에서는 암호화 필드 필수화 및 서버 측 fail-closed 시험 |

서버 구현은 암호화 필드가 없을 때 기존 평문 필드를 사용할 수 있으므로, **WebAdmin 로그인 보안 요구사항이 공개키 암호화를 의무화한다면 서버 측에서도 암호화 필드 누락 요청을 거부하도록 별도 강화해야 한다.** 클라이언트 JavaScript 차단만으로는 직접 HTTP 요청을 막을 수 없다.

## 10. 제출용 점검표·증적·결재

### 10.1 점검표

- [ ] 로그인 화면, 폼 제출 및 공개키 API가 HTTPS만 허용한다.
- [ ] RSA 키는 2048비트 이상이며 공개키·개인키 지문이 일치한다.
- [ ] 브라우저와 서버가 OAEP SHA-256 및 MGF1 SHA-256으로 일치한다.
- [ ] 정상 요청에 평문 ID/PW가 없고 암호화 실패 시 제출되지 않는다.
- [ ] 변조·잘못된 키·과도한 길이·공개키 누락 시험이 fail closed로 끝난다.
- [ ] 개인키 권한, SELinux 컨텍스트, 백업 및 폐기 절차가 적합하다.
- [ ] 로그·HAR·오류 응답·core dump에 ID/PW와 개인키가 없다.
- [ ] 키 교체·롤백·다중 노드 전환 시험을 완료했다.
- [ ] 평문 fallback과 재전송 제한에 대한 보완 통제를 적용했다.

### 10.2 증적과 결재

| 증적 | 내용 | 위치 / 티켓 | 판정 |
|---|---|---|:---:|
| EV-01~04 | HTTPS, 키 형식·권한, 알고리즘 확인 | `[ ]` | `[ ]` |
| EV-05~08 | 평문 미전송, 실패·변조·비결정성 시험 | `[ ]` | `[ ]` |
| EV-09~10 | 공개키 API 접근통제와 키 쌍 일치 | `[ ]` | `[ ]` |
| EV-11~12 | 키 교체 및 로그·메모리 보호 확인 | `[ ]` | `[ ]` |

| 결재 구분 | 성명 / 직책 | 의견 | 서명 | 일자 |
|---|---|---|---|---|
| 운영 확인 | `[ ]` | `[ ]` | `[ ]` | `[ ]` |
| 보안 검증 | `[ ]` | `[ ]` | `[ ]` | `[ ]` |
| 최종 승인 | `[ ]` | `[ ]` | `[ ]` | `[ ]` |
