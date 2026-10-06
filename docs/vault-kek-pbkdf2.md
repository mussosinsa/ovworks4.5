# KEK 생성: PBKDF2 유도 → Vault Transit 가져오기

DB 접속 설정파일(OVVLT001)을 보호하는 키 암호키(KEK)를 Vault가 난수로 만들지 않고, **engine-setup에서 운영자가
직접 입력한 초기 데이터(패스프레이즈)로부터 PBKDF2로 유도**한 뒤 Vault Transit으로 가져와(import) 저장·관리한다.

| 요구사항 | 구현 |
|---|---|
| KEK를 패스워드 기반 키 유도로 생성 | PBKDF2-HMAC-SHA256, 반복 600,000회, 출력 256비트 |
| 최초 KEK는 제품마다 다르게 생성 | 설치마다 Hash_DRBG(SHA-256)로 만든 256비트 salt. 같은 패스프레이즈라도 제품마다 KEK가 다름 |
| 초기 데이터는 engine-setup에서 직접 입력받아 메모리에 저장 | 화면 표시 없이 입력받아 bytearray로 메모리에만 보관. 응답 파일·otopi 환경·로그·디스크에 남기지 않고, 가져오기가 끝나면 0으로 덮어씀 |

## 1. 구조

```
engine-setup (최초 설치, KEK가 아직 없을 때만)
 ① 입력(화면 표시 없음): Vault 가져오기 토큰, KEK 패스프레이즈 2회
 ② salt 256비트 ← Hash_DRBG(SHA-256), config.json에 status=pending으로 먼저 기록
 ③ KEK(256비트) = PBKDF2-HMAC-SHA256(패스프레이즈, salt, 600,000회)
 ④ Vault Transit 가져오기 (BYOK)
     - transit/wrapping_key 조회 (Vault RSA-4096 공개키)
     - 임시 AES-256 키(Hash_DRBG)로 KEK를 AES-KWP(RFC 5649) 랩핑
     - 임시키를 RSA-OAEP(SHA-256)로 랩핑
     - transit/keys/<키 이름>/import
         type=aes256-gcm96, exportable=false, allow_plaintext_backup=false, allow_rotation=false
 ⑤ 검증: 엔진 서비스 토큰으로 Vault가 암호화한 값을 유도한 KEK로 열어 봄 → 같은 키임을 확인
 ⑥ 패스프레이즈·토큰·KEK·임시키를 메모리에서 0으로 덮어씀
 ⑦ config.json의 kek_derivation을 status=active로 갱신 (비밀값 없음)
 이후: DEK 생성·랩핑, 파일 암호화(OVVLT001)는 기존과 동일
```

`config.json`의 기록 예:

```json
"kek_derivation": {
    "kdf": "PBKDF2-HMAC-SHA256",
    "iterations": 600000,
    "salt": "<Base64 32바이트>",
    "key_length_bits": 256,
    "key_name": "ovirt-engine-config",
    "salt_rng": "Hash_DRBG(SHA-256)",
    "verified": true,
    "status": "active"
}
```

`status`가 `pending`이면 가져오기 도중 중단된 것이다(salt는 이미 기록됨). engine-setup이나
`vault_passphrase.py --init-kek-from-passphrase`를 다시 실행해 **같은 패스프레이즈**를 입력하면 기록된 salt로 같은 KEK를
유도해 마무리한다. Vault에 키가 이미 들어가 있으면 다시 가져오지 않고, 유도한 KEK와 같은 키인지 확인한 뒤 채택한다.
다른 키이면(다른 패스프레이즈 등) 채택하지 않고 오류로 끝난다.

salt와 반복횟수는 비밀값이 아니다. 패스프레이즈(오프라인 보관)와 함께 있으면 Vault 데이터를 잃었을 때 **같은 KEK**를
다시 만들 수 있다(§5).

## 2. Vault 준비 (가져오기 전용 토큰)

엔진 서비스 토큰(`vault-token`)은 encrypt/decrypt만 할 수 있어 키를 가져올 수 없다. engine-setup에서 한 번만 쓰는
**가져오기 전용 토큰**을 따로 만든다. 이 토큰은 파일로 저장하지 않고 engine-setup 화면에 직접 입력한다.

`/root/ovirt-engine-kek-import.hcl`:

```hcl
path "transit/wrapping_key" {
  capabilities = ["read"]
}
path "transit/keys/ovirt-engine-config" {
  capabilities = ["read"]
}
path "transit/keys/ovirt-engine-config/import" {
  capabilities = ["update"]
}
```

```bash
vault policy write ovirt-engine-kek-import /root/ovirt-engine-kek-import.hcl
vault token create -policy=ovirt-engine-kek-import -no-default-policy -ttl=15m -use-limit=6 -field=token
# 출력된 토큰을 engine-setup의 "Vault token allowed to import the KEK" 질문에 입력 (화면 표시 없음)
```

엔진 서비스 토큰 정책(`ovirt-engine-transit`, encrypt/decrypt만)은 기존과 같다
(`docs/vault-transit-rocky-linux-9.5.md` §5). **Vault에서 `vault write transit/keys/ovirt-engine-config ...`로 키를
미리 만들지 않는다.** 키가 이미 있으면 engine-setup은 그 키를 그대로 쓰고 새로 유도하지 않는다.

## 3. 신규 설치

1. Vault 구축·봉인 해제, Transit 활성화, 서비스 토큰 설치, `config.json` 작성(`vault_transit.enabled=true`)
2. `engine-setup` 실행. 키가 없으면 다음을 묻는다(입력 내용은 화면에 표시되지 않음):
   ```
   Vault token allowed to import the KEK:
   KEK passphrase (16+ characters, 3 of: lower case, upper case, digits, other):
   KEK passphrase again:
   ```
   - 패스프레이즈: 16자 이상 256자 이하, 소문자·대문자·숫자·기타 중 3종 이상
   - 두 번 입력이 다르거나 규칙에 맞지 않으면 다시 묻는다(최대 3회)
3. 가져오기·검증이 끝나면 로그에 `Imported the PBKDF2-derived KEK into Vault Transit key ovirt-engine-config`가 남고,
   감사기록 `CRYPTO_KEY_CREATED`가 엔진 이벤트로 기록된다(실패 시 `CRYPTO_KEY_CREATION_FAILED`).
4. 가져오기 토큰 폐기: `vault token revoke <토큰>` (TTL 15분으로도 만료)

응답 파일만으로 하는 무인 설치에서는 이 질문에 답할 수 없어 설치가 멈춘다. "직접 입력" 요건에 따라 의도된 동작이다.

engine-setup 밖에서 같은 작업을 할 때:

```bash
/usr/share/ovirt-engine/encryptor/vault_passphrase.py --init-kek-from-passphrase \
  --config /etc/ovirt-engine/encryptor/config.json
```

## 4. 기존 설치본 전환 (Vault가 난수로 만든 KEK → PBKDF2 KEK)

Vault의 가져오기는 **새 키만 만들 수 있고 기존 키를 대체할 수 없다.** 그래서 새 키 이름으로 가져온 뒤 파일을 다시
암호화한다.

```bash
# 1) 가져오기 토큰 정책에 새 키 이름 추가 (§2의 hcl에서 ovirt-engine-config → ovirt-engine-config-pbkdf2)
# 2) 새 키 생성 (패스프레이즈·토큰 입력, config.json에 kek_derivation 기록)
/usr/share/ovirt-engine/encryptor/vault_passphrase.py --init-kek-from-passphrase \
  --key-name ovirt-engine-config-pbkdf2
# 3) 엔진 서비스 토큰 정책에 새 키의 encrypt/decrypt 추가 (구 키도 아직 유지)
vault policy write ovirt-engine-transit /root/ovirt-engine-transit.hcl
# 4) 암호화된 파일 전부를 새 키로 재암호화하고 config.json의 key_name 변경
/usr/share/ovirt-engine/encryptor/vault_passphrase.py --rewrap-to-key ovirt-engine-config-pbkdf2
# 5) 엔진 재시작·확인
systemctl restart ovirt-engine
# 6) 구 키 삭제, 서비스 토큰 정책에서 구 키 제거
vault write transit/keys/ovirt-engine-config/config deletion_allowed=true
vault delete transit/keys/ovirt-engine-config
```

- `--rewrap-to-key`는 모든 파일을 메모리에서 복호화·재암호화·검증한 뒤에야 쓴다. 중간에 멈추면 다시 실행하면
  되고, 이미 새 키로 바뀐 파일은 건너뛴다.
- 대상: `config.json`의 `watch_path` 아래 `allowed_files`(10-setup-database.conf, 10-setup-dwh-database.conf,
  internal.properties) 중 OVVLT001 파일, 그리고 OVVLT001로 보호된 `secret_file`.

## 5. 복구 (Vault 데이터를 잃었을 때)

새 Vault에 Transit을 다시 구성하고(키 없음), 기록된 salt와 오프라인 보관한 패스프레이즈로 **같은 KEK**를 만든다.

```bash
/usr/share/ovirt-engine/encryptor/vault_passphrase.py --init-kek-from-passphrase --recover
```

`--recover`는 `config.json`의 `kek_derivation`(salt, 키 이름)을 그대로 쓰므로 기존 암호문 파일을 그대로 열 수 있다.

## 6. 키 교체

Vault 자체 회전(`vault write -f transit/keys/<이름>/rotate`)은 막혀 있다(`allow_rotation=false`). 회전하면 새 버전을
Vault가 난수로 만들어 PBKDF2 유도가 깨지기 때문이다. KEK를 바꿀 때는 새 패스프레이즈로 §4 절차(새 키 이름 →
재암호화 → 구 키 삭제)를 따른다.

## 7. 확인

```bash
# 키 속성 (관리자 토큰, 키 바이트는 출력되지 않음)
vault read transit/keys/ovirt-engine-config
#   기대: type=aes256-gcm96, exportable=false, allow_plaintext_backup=false, imported_key=true

# 유도 기록
python3 -c "import json;print(json.load(open('/etc/ovirt-engine/encryptor/config.json'))['kek_derivation'])"

# 서비스 토큰으로 왕복 시험
/usr/share/ovirt-engine/encryptor/vault_passphrase.py --check
```

## 8. 한계 (사실 기재)

- Python 문자열은 덮어쓸 수 없다. 입력은 bytearray로 받아 사용 후 0으로 덮어쓰지만, engine-setup의 대화
  모듈(otopi)이 입력을 문자열로 돌려주는 순간 한 번 문자열 사본이 생긴다. 이 사본은 프로세스가 끝날 때 해제된다.
  `vault_passphrase.py`는 터미널에서 직접 bytearray로 읽으므로 이 사본이 없다.
- 패스프레이즈를 잃고 Vault 데이터도 잃으면 KEK를 되살릴 수 없다. 패스프레이즈는 키 관리자가 분할·오프라인으로
  보관한다.
