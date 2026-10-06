# KEK: engine-setup 입력 패스프레이즈(메모리 보관) → PBKDF2 → DEK 봉투 암호화 (Vault 미사용)

DB 접속 정보 설정파일을 Vault 없이 보호한다. KEK를 만드는 초기 데이터(패스프레이즈)는 **engine-setup에서 운영자가
직접 입력**하고, 그 뒤로는 **메모리에만** 둔다. 각 설정파일은 그 패스프레이즈로부터 PBKDF2로 KEK를 유도하고, 그
KEK로 파일마다 새로 만든 DEK를 감싼다(봉투 암호화, `OVENC001`). 키 생성과 실패는 모두 감사기록(이벤트)으로 남는다.

| 요구사항 | 구현 |
|---|---|
| Vault 없이 | `vault_transit` 미사용. 신규 설치 기본값 |
| engine-setup 시 입력 | 화면 표시 없이 입력(최초 설치는 2회 입력해 일치 확인) |
| 메모리에 저장 | `ovirt-engine-kek-agent.service` 프로세스 메모리에만 보관. 파일·환경변수·응답 파일·로그·`config.json`에 남기지 않음 |
| PBKDF2로 KEK 생성 | PBKDF2-HMAC-SHA256, 반복 600,000회, 파일마다 128비트 salt, 출력 256비트 |
| DEK 봉투 암호화 | 파일마다 256비트 DEK(난수)로 내용을 AES-256-GCM 암호화, DEK는 KEK로 AES-256-GCM 랩핑 |
| 암호 4자리 이상 | 4~256자. 제어문자 불가 |
| 생성·실패 감사기록 | `CRYPTO_KEY_CREATED` / `CRYPTO_KEY_CREATION_FAILED` (+ 파일별 `CONFIG_FILE_ENCRYPTION_COMPLETED/FAILED`) |

## 1. 구조

```
engine-setup (최초 설치)
 ① ovirt-engine-kek-agent.service 시작 (systemctl enable --now)
 ② 패스프레이즈 입력 (화면 표시 없음, 2회, 4자 이상)        → 실패 시 CRYPTO_KEY_CREATION_FAILED
 ③ 에이전트에 전달 → 에이전트 메모리에 보관                 → CRYPTO_KEY_CREATED (engine-setup)
    engine-setup 쪽 입력 버퍼는 0으로 덮어씀
 ④ 설정파일 암호화 (encrypt_conf_files.py, 파일마다)
     salt(128비트)·논스 2개(96비트)·DEK(256비트) ← Hash_DRBG(SHA-256)
     KEK = PBKDF2-HMAC-SHA256(패스프레이즈, salt, 600,000회, 256비트)
     랩핑 DEK = AES-256-GCM(KEK, 논스1, DEK, AAD=헤더)
     암호문   = AES-256-GCM(DEK, 논스2, 내용, AAD=헤더‖랩핑 DEK)
                                                         → 파일별 CRYPTO_KEY_CREATED,
                                                           CONFIG_FILE_ENCRYPTION_COMPLETED
엔진 기동 (ovirt 계정)
 ⑤ 에이전트에서 패스프레이즈를 받아 KEK 유도 → DEK 풀기 → 설정 복호화 (메모리에서만)
                                                         → CONFIG_FILE_DECRYPTION_COMPLETED/FAILED
```

파일 형식(`OVENC001`): `OVENC001`(8) ‖ 버전(1) ‖ 반복횟수(4) ‖ salt(16) ‖ 논스1(12) ‖ 논스2(12) ‖ 랩핑DEK 길이(2)
‖ 랩핑 DEK(48) ‖ 암호문 ‖ 태그(16). 헤더 전체가 GCM 인증 대상이라 한 바이트라도 바뀌면 복호화가 실패한다.

`config.json`에는 위치 정보만 남는다(비밀값 없음):

```json
"kek_agent": {"enabled": true, "socket": "/run/ovirt-engine-kek/agent.sock"}
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
KEK passphrase (4+ characters):
KEK passphrase again:
```

- Vault를 설정하지 않은 신규 설치에서 자동으로 이 방식을 쓴다.
- 4자 미만, 256자 초과, 제어문자 포함, 두 번 입력 불일치 → 다시 묻는다(최대 3회). 매번 `CRYPTO_KEY_CREATION_FAILED`
  (사유 `PASSPHRASE_REJECTED`)가 남는다.
- 응답 파일만 쓰는 무인 설치는 이 질문에서 멈춘다(직접 입력 요건).

## 4. 재부팅 후 (필수 절차)

패스프레이즈는 메모리에만 있으므로 **재부팅하거나 에이전트를 재시작하면 사라진다.** 그 상태에서 엔진은 설정을 복호화하지
못해 기동하지 않고 `CONFIG_FILE_DECRYPTION_FAILED`(사유 `PASSPHRASE_UNAVAILABLE`)가 남는다. 다음과 같이 다시 입력한다.

```bash
/usr/share/ovirt-engine/encryptor/kek_agent.py --unlock      # 화면 표시 없이 입력
systemctl start ovirt-engine
```

- 입력값으로 암호화된 파일 하나를 실제로 열어 봐서(GCM 태그 검증) 맞는 패스프레이즈일 때만 메모리에 올린다.
- 성공: `CRYPTO_KEY_CREATED`(kek-agent). 틀림: `CRYPTO_KEY_CREATION_FAILED`(사유 `AUTHENTICATION_FAILED`).
- engine-setup을 다시 실행할 때도 먼저 `--unlock` 한다(engine-setup은 시작 단계에서 이미 DB 설정을 읽음).

그 밖의 명령: `--status`(보관 여부, 미보관이면 종료코드 3), `--lock`(즉시 지우기).

## 5. 기존 설치본 전환

패스프레이즈 파일(`/etc/ovirt-engine/encryptor/passphrase`)을 쓰던 설치본이나 Vault(`OVVLT001`) 설치본은 그대로
동작한다(자동 전환하지 않음). 전환하려면:

```bash
systemctl enable --now ovirt-engine-kek-agent
/usr/share/ovirt-engine/encryptor/kek_agent.py --migrate     # 새 패스프레이즈 2회 입력
systemctl restart ovirt-engine
```

- 모든 대상 파일을 메모리에서 복호화 → 새 패스프레이즈로 재암호화 → 검증한 뒤에 쓴다. 중간에 멈추면 다시 실행하면 되고,
  이미 바뀐 파일은 건너뛴다.
- 끝나면 `config.json`에 `kek_agent`를 켜고 `secret_file`을 지우며 Vault를 끈다. 예전 패스프레이즈 파일은 0으로
  덮어쓴 뒤 삭제한다.
- 감사기록: `CRYPTO_KEY_CREATED`, 파일별 `CRYPTO_KEY_CREATED`·`CONFIG_FILE_ENCRYPTION_COMPLETED`, 실패 시
  `CRYPTO_KEY_CREATION_FAILED`·`CONFIG_FILE_ENCRYPTION_FAILED`.

## 6. 감사기록(이벤트)

| 상황 | 이벤트 | source | 사유(reason) |
|---|---|---|---|
| engine-setup에서 패스프레이즈 입력·메모리 보관 성공 | `CRYPTO_KEY_CREATED` | engine-setup | — |
| 4자 미만·불일치·제어문자 | `CRYPTO_KEY_CREATION_FAILED` | engine-setup / kek-agent | `PASSPHRASE_REJECTED` |
| 재입력(`--unlock`) 값이 틀림 | `CRYPTO_KEY_CREATION_FAILED` | kek-agent | `AUTHENTICATION_FAILED` |
| 에이전트 미기동·연결 불가 | `CRYPTO_KEY_CREATION_FAILED` | engine-setup / encrypt-conf-files | `PASSPHRASE_UNAVAILABLE` |
| 파일별 DEK·KEK 생성 | `CRYPTO_KEY_CREATED` (파일명 포함) | encrypt-conf-files | — |
| 파일 암호화 성공·실패 | `CONFIG_FILE_ENCRYPTION_COMPLETED` / `_FAILED` | encrypt-conf-files | 실패 시 사유 |
| 엔진 기동 시 복호화 성공·실패 | `CONFIG_FILE_DECRYPTION_COMPLETED` / `_FAILED` | engine-start | 실패 시 사유 |

엔진이 기동되기 전의 기록은 `/var/lib/ovirt-engine/security/crypto-events`에 남았다가, 엔진이 기동하면 이벤트 목록에
등록된다. 이벤트 문구 예: `An encryption key was created for configuration file 10-setup-database.conf
(encrypt-conf-files, OVENC001)`.

## 7. 대칭키 양식

### DEK

| 항목 | 값 |
|---|---|
| 암호 알고리즘 | AES-256-GCM (인증태그 128비트, 헤더를 AAD로 인증) |
| 논스 | 96비트, 암호화마다 새로 생성 |
| 난수발생기 | Hash_DRBG (SHA-256, 보안강도 256비트) |
| 반복횟수 | 없음 (난수로 직접 생성) |
| 비트 수 | 256비트 |
| 생성 주기 | 파일을 암호화할 때마다 |
| 저장 위치 | 평문 DEK는 저장하지 않음. KEK로 랩핑한 DEK만 암호문 파일 헤더 뒤에 저장 |

### KEK

| 항목 | 값 |
|---|---|
| 암호 알고리즘 | AES-256-GCM (DEK 랩핑) |
| 생성 방식 | PBKDF2-HMAC-SHA256(engine-setup에서 입력한 패스프레이즈, 파일별 salt) |
| 해시 알고리즘 | SHA-256 (PBKDF2의 HMAC) |
| salt | 128비트, 파일을 암호화할 때마다 Hash_DRBG로 새로 생성 → 같은 패스프레이즈라도 제품·파일마다 KEK가 다름 |
| 반복횟수 | 600,000회 |
| 비트 수 | 256비트 |
| 패스프레이즈 | 4~256자, engine-setup(또는 `--unlock`)에서 직접 입력, 에이전트 메모리에만 보관 |
| 저장 위치 | KEK는 저장하지 않음(쓸 때마다 유도, 사용 후 폐기). 패스프레이즈도 디스크에 저장하지 않음 |

## 8. 한계 (사실 기재)

- 재부팅 후 사람이 `--unlock` 하기 전에는 엔진이 기동하지 않는다. "메모리에만 보관"의 당연한 결과다.
- Python 특성상 KEK 유도 라이브러리 내부 사본과, engine-setup 대화 모듈(otopi)이 입력을 문자열로 돌려줄 때 생기는
  사본은 덮어쓸 수 없다(프로세스 종료 시 해제). 에이전트·`kek_agent.py`는 bytearray로 받아 사용 후 0으로 덮어쓴다.
- 4자 패스프레이즈는 PBKDF2 600,000회로도 무차별 대입에 약하다. 암호문 파일이 유출되면 짧은 패스프레이즈는 추측될 수
  있으므로 운영에서는 길게 정하는 것을 권장한다(최소 길이는 요구사항대로 4자).
- 패스프레이즈를 잊으면 암호화된 설정을 복구할 수 없다. 오프라인으로 보관한다.
