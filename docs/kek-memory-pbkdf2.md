# DB 접속 정보 설정파일 암호화: 설치당 DEK 1개(국정원 검증대상 Hash_DRBG) + PBKDF2 KEK (Vault 미사용)

DB 접속 정보(DB 계정 비밀번호) 설정파일을 **AES-256-GCM**으로 암호화한다. **데이터 암호화 키(DEK)는 설치당 1개**를
국정원 검증대상 난수발생기 **Hash_DRBG(SHA-256)**로 만들고, **키 암호화 키(KEK)로 암호화해
`/etc/ovirt-engine/encryptor/dek.enc` 파일로 저장**한다. KEK는 engine-setup에서 직접 입력해 **메모리에만** 두는
패스프레이즈로부터 PBKDF2로 유도한다. DEK·KEK 생성과 실패는 모두 감사기록(이벤트)으로 남는다.

| 요구사항 | 구현 |
|---|---|
| 데이터 암호화 | AES-256-GCM (태그 128비트, 헤더를 AAD로 인증), 형식 `OVENC002` |
| DEK | 설치당 1개, 256비트, Hash_DRBG(SHA-256, 보안강도 256비트)로 생성. 승인 난수발생기를 쓸 수 없으면 **생성하지 않고 실패**(os.urandom 등으로 대체하지 않음) |
| DEK 저장 | `/etc/ovirt-engine/encryptor/dek.enc` (`OVDEK001`), KEK로 AES-256-GCM 암호화, `root:ovirt 0640`. 평문 DEK는 어디에도 저장하지 않음 |
| KEK | PBKDF2-HMAC-SHA256(패스프레이즈, salt 256비트, 600,000회) → 256비트. 저장하지 않음 |
| 패스프레이즈 | engine-setup에서 직접 입력(6자 이상, 2회), `ovirt-engine-kek-agent.service` 메모리에만 보관 |
| 감사기록 | DEK 생성 `CRYPTO_KEY_CREATED`(file=dek.enc) / 실패 `CRYPTO_KEY_CREATION_FAILED`, 패스프레이즈(KEK) 보관·실패, 파일별 암호화·복호화 성공·실패 |

## 1. 구조

```
engine-setup (최초 설치)
 ① ovirt-engine-kek-agent.service 시작
 ② 패스프레이즈 입력 (화면 표시 없음, 2회, 6자 이상)         → 실패 시 CRYPTO_KEY_CREATION_FAILED
 ③ 에이전트 메모리에 보관                                   → CRYPTO_KEY_CREATED (engine-setup)
 ④ closeup: DEK 생성 (encrypt_conf_files.py → encryptor.ensure_dek, 설치당 1회)
     DEK(256) · salt(256) · 논스(96) ← Hash_DRBG(SHA-256)  (불가 시 실패, 사유 RNG_UNAVAILABLE)
     KEK = PBKDF2-HMAC-SHA256(패스프레이즈, salt, 600,000회, 256비트)
     dek.enc = OVDEK001 헤더 ‖ AES-256-GCM(KEK, 논스, DEK, AAD=헤더)
                                                           → CRYPTO_KEY_CREATED (file=dek.enc, OVDEK001)
 ⑤ 설정파일마다: 암호문 = OVENC002 헤더 ‖ AES-256-GCM(DEK, 새 논스, 내용, AAD=헤더)
                                                           → CONFIG_FILE_ENCRYPTION_COMPLETED (OVENC002)
엔진 기동 (ovirt 계정)
 ⑥ 에이전트에서 패스프레이즈 → KEK 유도 → dek.enc 풀기 → DEK → 설정 복호화 (메모리에서만)
                                                           → CONFIG_FILE_DECRYPTION_COMPLETED/FAILED
```

| 파일 | 형식 |
|---|---|
| `dek.enc` (`OVDEK001`, 107바이트) | `OVDEK001`(8) ‖ 버전(1) ‖ PBKDF2 반복횟수(4) ‖ salt(32) ‖ 논스(12) ‖ 랩핑 DEK 길이(2) ‖ 랩핑 DEK(32) ‖ 태그(16) |
| 설정파일 (`OVENC002`) | `OVENC002`(8) ‖ 버전(1) ‖ DEK 식별값(8) ‖ 논스(12) ‖ 암호문 ‖ 태그(16) |

- DEK 식별값 = HMAC-SHA256(DEK, "ovirt-engine dek id")의 앞 8바이트. DEK를 드러내지 않고 "이 파일은 다른 DEK로 암호화됨"을
  구분한다(사유 `DEK_UNAVAILABLE`).
- 헤더 전체가 GCM 인증 대상이라 한 바이트라도 바뀌면 복호화가 실패한다.
- 이미 `dek.enc`가 있으면 새로 만들지 않고 그것을 쓴다(설치당 1개). engine-setup을 다시 실행해도 같은 DEK를 쓴다.
- 예전 형식(`OVENC001`: 파일마다 DEK를 헤더 안에 저장)은 읽기만 지원한다. `kek_agent.py --migrate`로 옮긴다.

`config.json`에는 위치 정보만 남는다(비밀값 없음):

```json
"kek_agent": {"enabled": true, "socket": "/run/ovirt-engine-kek/agent.sock"},
"dek_file": "/etc/ovirt-engine/encryptor/dek.enc",
"active_format": "OVENC002"
```

## 2. KEK 에이전트 (`ovirt-engine-kek-agent.service`)

| 항목 | 내용 |
|---|---|
| 실행 | `/usr/share/ovirt-engine/encryptor/kek_agent.py --serve`, 계정 `ovirt` |
| 통신 | 유닉스 소켓 `/run/ovirt-engine-kek/agent.sock` (디렉터리 0700, 소켓 0600). 네트워크 사용 안 함(`PrivateNetwork`, `AF_UNIX`만 허용) |
| 접근 통제 | 커널이 알려주는 상대 UID(`SO_PEERCRED`)로 판단. 넣기·지우기: root만. 꺼내기: root와 엔진 계정만. 그 외 거부. 클라이언트도 에이전트 UID를 확인해 root·ovirt가 아니면 보내지 않음 |
| 디스크 유출 방지 | 코어 덤프 금지(`LimitCORE=0`, `PR_SET_DUMPABLE=0`), 스왑 금지(`MemorySwapMax=0`, 비밀 버퍼 `mlock`) |
| 비밀값 전달 | JSON이 아닌 원시 바이트로 bytearray에 직접 주고받음(지울 수 없는 문자열 사본을 만들지 않음) |
| 종료·지우기 | 서비스 중지·재부팅·`--lock` 시 0으로 덮어쓰고 버림 |
| 기록 | 요청마다 journal에 `uid`와 결과만 남김(비밀값 없음) |

## 3. 신규 설치

```
# engine-setup
KEK passphrase (6+ characters):
KEK passphrase again:
```

- engine-setup은 Vault를 쓰지 않는다. `config.json`에 예전 `vault_transit` 설정이 남아 있어도(예: 예전 engine-cleanup이
  써 둔 것, 예전 예제를 복사한 것) 무시하고 이 질문을 하며, closeup에서 그 설정을 지운다. 남아 있던
  `/etc/ovirt-engine/encryptor/vault-token`·`passphrase` 파일은 0으로 덮어쓴 뒤 삭제한다.
- 예외: 설정파일이 아직 패스프레이즈 파일로 암호화(`OVENC001` + 파일 존재)되어 있으면 그 방식을 유지한다(§5로 전환).
  Vault로 암호화(`OVVLT001`)되어 있으면 engine-setup이 멈추고 `--migrate`를 먼저 하라고 알린다.
- 6자 미만, 256자 초과, 제어문자 포함, 두 번 입력 불일치 → 다시 묻는다(최대 3회). 매번 `CRYPTO_KEY_CREATION_FAILED`
  (사유 `PASSPHRASE_REJECTED`)가 남는다.
- 응답 파일만 쓰는 무인 설치는 이 질문에서 멈춘다(직접 입력 요건).

## 4. 재부팅 후 (필수 절차)

패스프레이즈는 메모리에만 있으므로 **재부팅하거나 에이전트를 재시작하면 사라진다.** 그 상태에서 엔진은 설정을 복호화하지
못해 기동하지 않고 `CONFIG_FILE_DECRYPTION_FAILED`(사유 `PASSPHRASE_UNAVAILABLE`)가 남는다. 다음과 같이 다시 입력한다.

```bash
/usr/share/ovirt-engine/encryptor/kek_agent.py --unlock      # 화면 표시 없이 입력
systemctl start ovirt-engine
```

- 입력값으로 `dek.enc`를 실제로 풀어 봐서(GCM 태그 검증) 맞는 패스프레이즈일 때만 메모리에 올린다.
- 성공: `CRYPTO_KEY_CREATED`(kek-agent). 틀림: `CRYPTO_KEY_CREATION_FAILED`(사유 `AUTHENTICATION_FAILED`).
- engine-setup을 다시 실행할 때도 먼저 `--unlock` 한다(engine-setup은 시작 단계에서 이미 DB 설정을 읽음).

그 밖의 명령: `--status`(보관 여부, 미보관이면 종료코드 3), `--lock`(즉시 지우기), `--get`(패스프레이즈를 파이프로만
출력 — Java 11에서 유닉스 소켓을 못 여는 AAA JDBC 확장(`ovirt-aaa-jdbc-tool`, 엔진 내부 확장)용. 터미널로는 출력 거부,
보관 서비스가 root·ovirt 계정에만 응답).

### engine-cleanup 시 키 삭제

engine-cleanup도 먼저 `--unlock` 한다. 패스프레이즈가 메모리에 없으면 engine-cleanup은 **아무것도 바꾸기 전에** 멈추고
`--unlock`을 안내한다. 설정파일 하나라도 복호화에 실패해도 멈춘다(예전에는 경고만 하고 진행해, 끝에 DEK가 지워지면서
남은 파일을 영구히 열 수 없게 되었다).

| 키 / 비밀값 | engine-cleanup(엔진 제거) 처리 |
|---|---|
| DEK `dek.enc` | 0으로 덮어쓴 뒤 삭제 |
| KEK 패스프레이즈(메모리) | `ovirt-engine-kek-agent` `disable --now` → 메모리에서 0으로 덮어씀, 재부팅해도 다시 뜨지 않음 |
| KEK | 저장된 적 없음 |
| 예전 `passphrase`·`vault-token` | 덮어쓴 뒤 삭제 |
| 로그인 키 개인키 `private_pkcs8.der` | 덮어쓴 뒤 삭제 |
| PKI 개인키 `/etc/pki/ovirt-engine/keys/*`, `private/*`(CA·웹·엔진·콘솔/웹소켓 프록시) | 덮어쓴 뒤 삭제. **백업(tar.gz)을 만들지 않음**(예전에는 `/var/lib/ovirt-engine/backups/engine-pki-*.tar.gz`에 남김) |
| DB 비밀번호 설정파일(복호화된 상태) | 삭제 직전 0으로 덮어씀 |
| `config.json` | 비밀값 없는 초기 템플릿으로 교체 |

- **엔진을 제거하지 않거나(질문에 No) 도중에 중단되면**, 시작 시 복호화했던 파일을 끝에서 다시 암호화한다
  (평문으로 남기지 않음). 다시 암호화하지 못하면 오류로 알린다.
- **DEK가 아직 필요한 파일이 남아 있으면**(엔진만 제거하고 DWH는 남긴 경우의 DWH 설정파일 등) DEK·패스프레이즈·
  `config.json`을 남기고 그 파일 목록을 경고한다. 그 파일(또는 그 구성요소)을 제거한 뒤 `dek.enc`를 지운다.
- 키 삭제 결과는 syslog(authpriv, 식별자 `ovirt-engine-cleanup`)에 `operation=key-destroy file=... status=success|failure|kept`로
  남는다(엔진 이벤트 목록은 엔진과 함께 제거되므로).
- engine-cleanup 전에 이미 만들어진 `engine-pki-*.tar.gz` 백업은 자동으로 지우지 않는다. 필요 없으면 직접 삭제한다.
- DB 백업(`/var/lib/ovirt-engine/backups/` 의 DB 덤프)은 키가 아니므로 기존대로 남는다.
- 0 덮어쓰기는 저널링 파일시스템·SSD에서 물리적 소거를 보장하지 않는다.

다음 engine-setup은 새 패스프레이즈를 묻고 새 DEK를 만든다.

## 5. 기존 설치본 전환

패스프레이즈 파일(`/etc/ovirt-engine/encryptor/passphrase`)을 쓰던 설치본이나 Vault(`OVVLT001`) 설치본은 그대로
동작한다(자동 전환하지 않음). 전환하려면:

```bash
systemctl enable --now ovirt-engine-kek-agent
/usr/share/ovirt-engine/encryptor/kek_agent.py --migrate     # 새 패스프레이즈 2회 입력
systemctl restart ovirt-engine
```

- DEK: `dek.enc`가 있으면 그 DEK를, 없으면 Hash_DRBG로 새 DEK를 만든다. 새 패스프레이즈의 KEK로 감싸 `dek.enc`를 먼저 쓴다.
- 모든 대상 파일을 메모리에서 복호화 → 그 DEK로 `OVENC002` 재암호화 → 검증한 뒤에 쓴다. 중간에 멈추면 다시 실행하면 되고,
  이미 바뀐 파일은 건너뛴다.
- 끝나면 `config.json`에 `kek_agent`를 켜고 `secret_file`을 지우며 Vault를 끈다. 예전 패스프레이즈 파일은 0으로
  덮어쓴 뒤 삭제한다.
- 감사기록: `CRYPTO_KEY_CREATED`(패스프레이즈 보관, `dek.enc`), 파일별 `CONFIG_FILE_ENCRYPTION_COMPLETED`, 실패 시
  `CRYPTO_KEY_CREATION_FAILED`·`CONFIG_FILE_ENCRYPTION_FAILED`.

### 문제 해결: `Unable to inspect Vault token for runtime access: ... vault-token`

예전 engine-setup·engine-cleanup은 `config.json`에 `vault_transit.enabled: true`를 써 넣었고, 그 상태에서 engine-setup이
Vault 토큰을 찾다가 실패했다. 이 버전에서는 engine-setup이 Vault 설정을 무시·삭제하므로 그대로 다시 실행하면 KEK
패스프레이즈를 묻는다. 이전 실패에서 설정파일이 평문으로 남아 있어도 문제없다(closeup에서 새 패스프레이즈로 암호화).

## 6. 감사기록(이벤트)

| 상황 | 이벤트 | source | 사유(reason) |
|---|---|---|---|
| engine-setup에서 패스프레이즈 입력·메모리 보관 성공 | `CRYPTO_KEY_CREATED` | engine-setup | — |
| 6자 미만·불일치·제어문자 | `CRYPTO_KEY_CREATION_FAILED` | engine-setup / kek-agent | `PASSPHRASE_REJECTED` |
| 재입력(`--unlock`) 값이 틀림 | `CRYPTO_KEY_CREATION_FAILED` | kek-agent | `AUTHENTICATION_FAILED` |
| 에이전트 미기동·연결 불가 | `CRYPTO_KEY_CREATION_FAILED` | engine-setup / encrypt-conf-files | `PASSPHRASE_UNAVAILABLE` |
| DEK 생성·`dek.enc` 저장 (설치당 1회) | `CRYPTO_KEY_CREATED` (file=dek.enc, OVDEK001) | encrypt-conf-files | — |
| DEK 생성·열기 실패 | `CRYPTO_KEY_CREATION_FAILED` (file=dek.enc) | encrypt-conf-files | `RNG_UNAVAILABLE`(승인 난수발생기 불가), `AUTHENTICATION_FAILED`(패스프레이즈 불일치), `PASSPHRASE_UNAVAILABLE` 등 |
| `dek.enc` 없음·다른 DEK로 된 파일 | `CONFIG_FILE_DECRYPTION_FAILED` | engine-start | `DEK_UNAVAILABLE` |
| 파일 암호화 성공·실패 | `CONFIG_FILE_ENCRYPTION_COMPLETED` / `_FAILED` | encrypt-conf-files | 실패 시 사유 |
| 엔진 기동 시 복호화 성공·실패 | `CONFIG_FILE_DECRYPTION_COMPLETED` / `_FAILED` | engine-start | 실패 시 사유 |

엔진이 기동되기 전의 기록은 `/var/lib/ovirt-engine/security/crypto-events`에 남았다가, 엔진이 기동하면 이벤트 목록에
등록된다. 이벤트 문구 예: `An encryption key was created for configuration file dek.enc (encrypt-conf-files,
OVDEK001)`.

## 7. 대칭키 양식

### DEK (데이터 암호화 키)

| 항목 | 값 |
|---|---|
| 암호 알고리즘 | AES-256-GCM (인증태그 128비트, 헤더를 AAD로 인증) |
| 논스 | 96비트, 파일을 암호화할 때마다 Hash_DRBG로 새로 생성 |
| 난수발생기 | Hash_DRBG (SHA-256, 보안강도 256비트) — 국정원 검증대상 난수발생기. OpenSSL 3 `EVP_RAND`, 운영체제 엔트로피(SEED-SRC)로 시드, 기지답 시험 통과 후 사용. 불가 시 생성 거부 |
| 반복횟수 | 없음 (난수로 직접 생성) |
| 비트 수 | 256비트 |
| 생성 주기 | 설치당 1회 (최초 engine-setup 또는 `--migrate`) |
| 저장 위치 | `/etc/ovirt-engine/encryptor/dek.enc` — KEK로 AES-256-GCM 암호화된 상태, `root:ovirt 0640`. 평문 DEK는 저장하지 않음(사용 시 메모리에서만) |

### KEK (키 암호화 키)

| 항목 | 값 |
|---|---|
| 암호 알고리즘 | AES-256-GCM (DEK 암호화) |
| 생성 방식 | PBKDF2-HMAC-SHA256(engine-setup에서 입력한 패스프레이즈, `dek.enc`의 salt) |
| 해시 알고리즘 | SHA-256 (PBKDF2의 HMAC) |
| salt | 256비트, DEK를 감쌀 때 Hash_DRBG로 생성해 `dek.enc` 헤더에 기록 → 같은 패스프레이즈라도 제품마다 KEK가 다름 |
| 반복횟수 | 600,000회 |
| 비트 수 | 256비트 |
| 패스프레이즈 | 6~256자, engine-setup(또는 `--unlock`)에서 직접 입력, 에이전트 메모리에만 보관 |
| 저장 위치 | KEK는 저장하지 않음(쓸 때마다 유도, 사용 후 폐기). 패스프레이즈도 디스크에 저장하지 않음 |

## 8. 한계 (사실 기재)

- 재부팅 후 사람이 `--unlock` 하기 전에는 엔진이 기동하지 않는다. "메모리에만 보관"의 당연한 결과다.
- Python 특성상 KEK 유도 라이브러리 내부 사본과, engine-setup 대화 모듈(otopi)이 입력을 문자열로 돌려줄 때 생기는
  사본은 덮어쓸 수 없다(프로세스 종료 시 해제). 에이전트·`kek_agent.py`는 bytearray로 받아 사용 후 0으로 덮어쓴다.
- 6자 패스프레이즈는 PBKDF2 600,000회로도 무차별 대입에 약하다. 암호문 파일이 유출되면 짧은 패스프레이즈는 추측될 수
  있으므로 운영에서는 길게 정하는 것을 권장한다(최소 길이는 요구사항대로 6자).
- 패스프레이즈를 잊거나 `dek.enc`를 잃으면 암호화된 설정을 복구할 수 없다. 패스프레이즈는 오프라인으로 보관하고,
  `dek.enc`는 백업에 포함한다(무결성 감시 AIDE 대상에도 포함됨).
- Hash_DRBG는 국정원 검증대상 알고리즘이지만, 구현한 OpenSSL은 KCMVP 검증필 암호모듈이 아니다. 평가가 검증필 모듈
  사용까지 요구하면 KCMVP 인증 라이브러리로 바꿔야 한다.
