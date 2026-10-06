# DB 접근 설정파일 암호화 — 대칭키 양식 (OVVLT001)

대상 파일: `/etc/ovirt-engine/engine.conf.d/10-setup-database.conf`,
`/etc/ovirt-engine/engine.conf.d/10-setup-dwh-database.conf`(DWH 설치 시),
`/etc/ovirt-engine/aaa/internal.properties`

암호화는 2단계 대칭키(봉투 암호화) 구조이다. 파일 내용은 **DEK**로 암호화하고, DEK는 **KEK**로 암호화(랩핑)한다.
두 키 모두 대칭키이므로 각각 양식을 작성한다.

## 1. DEK (데이터 암호키, 파일 내용 암호화)

| 항목 | 값 |
|---|---|
| 암호 알고리즘 | AES-256-GCM (블록암호 AES, 운영모드 GCM — NIST SP 800-38D). 인증태그 128비트. 봉투 헤더와 랩핑된 DEK를 추가 인증 데이터(AAD)로 함께 인증 |
| 논스(IV) | 96비트(12바이트). 파일을 암호화할 때마다 새로 생성하며 재사용하지 않음. 봉투 헤더에 평문으로 기록(논스는 비밀값이 아님) |
| salt | 사용하지 않음. 키를 패스워드에서 유도하지 않고 난수로 직접 생성하므로 salt가 필요 없음 |
| 난수발생기 | Hash_DRBG (SHA-256, 보안강도 256비트, NIST SP 800-90A). OpenSSL 3 DRBG를 운영체제 엔트로피(SEED-SRC)로 시드하며, 기동 시 기지답 시험(KAT)을 통과해야 사용. DEK와 논스 모두 이 생성기에서 생성 |
| 반복횟수 | 없음 (0회). DEK는 난수로 직접 생성하고 패스워드 기반 키 유도(PBKDF2 등)를 거치지 않으므로 반복횟수 파라미터가 없음 |
| 비트 수(키 길이) | 256비트 (32바이트) |
| 생성 주기 | 파일을 암호화할 때마다 새로 생성 (파일마다, 암호화할 때마다 다른 DEK) |
| 저장 위치 | 평문 DEK는 어디에도 저장하지 않음(연산 중 프로세스 메모리에만 존재, 사용 후 폐기). KEK로 랩핑한 DEK만 해당 암호문 파일 안, 봉투 헤더 바로 뒤에 저장 |

## 2. KEK (키 암호키, DEK 랩핑)

| 항목 | 값 |
|---|---|
| 암호 알고리즘 | AES-256-GCM. HashiCorp Vault Transit 키 유형 `aes256-gcm96`(키 이름 `ovirt-engine-config`) |
| 논스(IV) | 96비트. DEK를 랩핑할 때마다 Vault가 새로 생성해 랩핑 결과(`vault:v<버전>:<Base64(논스‖암호문‖태그)>`) 안에 포함 |
| salt | 사용하지 않음. 패스워드에서 유도하지 않음 |
| 난수발생기 | Vault 서버 내부 난수발생기(Go `crypto/rand`, Linux `getrandom(2)`). KEK와 랩핑 논스 모두 Vault 내부에서 생성 |
| 반복횟수 | 없음 (0회). Vault가 난수로 직접 생성하며 키 유도를 거치지 않음 |
| 비트 수(키 길이) | 256비트 |
| 생성 주기 | Vault 구축 시 1회. 키 회전 시 새 버전 생성(이전 버전은 복호용으로만 유지) |
| 저장 위치 | Vault 서버 저장소(Raft, `/opt/vault/data`) 안에 Vault Barrier 키로 암호화된 상태로 저장. 내보내기 불가(`exportable=false`, `allow_plaintext_backup=false`)로 Vault 밖으로 나오지 않음. Engine 호스트에는 저장하지 않음 |

## 3. 참고

| 항목 | 내용 |
|---|---|
| 봉투 형식 | `OVVLT001`(8바이트) ‖ 버전(1) ‖ 논스(12) ‖ 랩핑DEK 길이(2) ‖ 랩핑DEK ‖ 암호문 ‖ 태그(16) |
| Vault 접근 | Engine은 최소 권한 토큰(`/etc/ovirt-engine/encryptor/vault-token`, `ovirt:ovirt 0600`)으로 Vault Transit의 encrypt/decrypt만 호출. 통신은 TLS(서버 인증서 검증) |
| Vault 봉인 해제 | Unseal Key 5조각 중 3조각 필요(Shamir 비밀분산) |
| 근거 소스 | `packaging/encryptor/encryptor.py`의 `encrypt_vault_bytes`(DEK·논스 생성, AES-256-GCM)·`VaultTransitClient.ensure_key`(KEK `aes256-gcm96`)와 상수 `DATA_KEY_SIZE=32`, `NONCE_SIZE=12`. `packaging/pythonlib/ovirt_engine/csprng.py`(Hash_DRBG) |

> 이전 형식 `OVENC001`(패스워드 기반 PBKDF2-HMAC-SHA256, salt 128비트, 반복 600,000회)은 복호 호환용으로만
> 남아 있다. 현재 설정파일 암호화에는 쓰지 않으므로 위 양식에는 포함하지 않았다.
