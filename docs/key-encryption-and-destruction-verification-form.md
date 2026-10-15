# 무결성 기준값·개인키 DEK 암호화 및 키 파기(0 덮어쓰기) 보안기능 확인서

## 1. 문서 정보

| 항목 | 내용 |
|---|---|
| 문서명 | 무결성 기준값·개인키 DEK 암호화 및 키 파기(0 덮어쓰기) 보안기능 확인서 |
| 대상 제품 | OV-Works Engine (oVirt 기반 가상화 관리) |
| 대상 기능 | ① AIDE 무결성 기준값의 DEK 암호화 ② 웹 관리 로그인 개인키의 DEK 암호화 ③ 키 파기 시 0으로 3회 덮어쓰기 |
| 작성일 | `[YYYY-MM-DD]` |
| 작성자 | `[작성자]` |

> 제출 전 대괄호(`[ ]`) 항목을 운영 정보로 대체한다. 증적에는 실제 키 값·DEK·패스프레이즈·복호화 평문을 포함하지 않는다(파일 선두 매직 8바이트, 권한, 크기, 감사 로그만 수집).

## 2. 목적과 보안 경계

본 확인서는 다음 두 종류의 민감 파일이 **설치본의 DEK로 암호화되어 디스크에 저장**되고, 사용 시에만 메모리/tmpfs로 복호화되며, 제품 제거 시 **0으로 3회 덮어쓰기 후 삭제**됨을 로직과 증빙 방법으로 정의한다.

- **무결성 기준값**: `/var/lib/aide/ovworks.db.gz` (AIDE가 파일 변조를 판정하는 기준 해시 DB)
- **웹 관리 로그인 개인키**: `/etc/ovirt-engine/encryptor/private_pkcs8.der` (브라우저가 공개키로 암호화한 ID/PW를 서버가 복호화하는 RSA 개인키)

보안 경계: 두 파일을 복사해 가더라도 **DEK 없이는 복호화할 수 없다.** DEK는 평문으로 저장되지 않으며(§3), DEK를 여는 KEK는 디스크에 없다(메모리 보유 패스프레이즈). 따라서 KEK 소멸만으로 두 파일은 영구히 복호화 불가(암호학적 소거)가 된다.

## 3. 공통 암호 기반 (DEK/KEK)

| 항목 | 구현 |
|---|---|
| DEK(데이터 암호화 키) | 256비트. **Hash_DRBG(SHA-256)** 로 생성(`approved_random_bytes`). 평문 저장 없음 |
| DEK 저장 | `/etc/ovirt-engine/encryptor/dek.enc` — KEK로 랩핑된 상태(`OVDEK001`) |
| KEK | 디스크 저장 없음. 메모리 KEK 모드에서 **KEK 에이전트 프로세스 메모리**에 패스프레이즈 보유(`mlock`, core dump 금지) |
| 봉투 알고리즘 | **AES-256-GCM** |
| 봉투 형식 | `ENVELOPE_MAGIC(8) = OVENC002` + `version(1)` + `dek_id(8)` + `nonce(12)` + GCM 암호문·태그. 헤더가 AAD로 인증됨 (`encryptor.py` `ENVELOPE_HEADER=">8sB8s12s"`) |
| 논스 | 12바이트, **Hash_DRBG(SHA-256)** (`approved_random_bytes(NONCE_SIZE)`) |
| DEK 바인딩 | 봉투에 `dek_id`(DEK의 식별자)를 기록. 다른 DEK로는 복호화 시 거부(`decrypt_envelope`) |

관련 소스: `packaging/encryptor/encryptor.py` — `encrypt_envelope()`, `decrypt_envelope()`, `read_dek()`, `dek_id()`.

---

## 4. 기능 A — 무결성 기준값(AIDE DB)의 DEK 암호화

### 4.1 로직

| 단계 | 명령/함수 | 동작 |
|---|---|---|
| 봉인(저장) | `integrity_seal.py --seal` | ① `encrypt_database(dek, db)` — 기준값을 **AES-256-GCM 봉투로 제자리 암호화**(멱등: 이미 `OVENC002`면 생략) ② `make_seal` — 암호문 위에 **HMAC-SHA256 봉인** 생성(`ovworks.db.seal`) |
| 개봉(검증 시) | `integrity_seal.py --open` | 봉인(HMAC) 검증 → 통과 시 **tmpfs로 복호화**(`/dev/shm/ovworks-aide.db.gz`, 0600) → AIDE용 임시 설정(`/dev/shm/ovworks-aide.conf`) 작성. 변조=exit 3, 검증불가=exit 2 |
| 사용 | `aide --config=/dev/shm/ovworks-aide.conf --check` | AIDE는 **복호화본**을 기준 DB로 사용(암호문을 직접 읽지 않음) |
| 정리 | `integrity_seal.py --close` | tmpfs의 복호화본·임시 설정을 **0으로 덮어쓴 뒤 삭제**(`_shred`) |

- 봉인 키: `HMAC-SHA256(DEK, "ovworks integrity baseline seal v1")` — DEK에서만 유도.
- 봉인 레코드(`ovworks.db.seal`): `version`, `dek_id(hex)`, `config`·`database`의 MAC, `sealed_at`. **DEK 값은 포함되지 않음.**
- 보안검증 러너가 운영 중 호출: `sudo integrity_seal.py --open` → `sudo aide --config=/dev/shm/… --check` → `sudo integrity_seal.py --close`.
- 소스: `packaging/encryptor/integrity_seal.py` (`seal`, `encrypt_database`, `open_baseline`, `close_baseline`), `ovirt-engine-security-verification-runner.sh`.

### 4.2 증빙 방법

```bash
# (1) 저장 암호화 확인 — 선두 8바이트가 OVENC002 이면 DEK 봉투로 암호화된 상태
sudo head -c 8 /var/lib/aide/ovworks.db.gz | tr -d '\0'; echo
#   기대: OVENC002

# (2) 봉인 레코드 확인 — dek_id로 묶이고, DEK 원문은 없음
sudo cat /var/lib/aide/ovworks.db.seal           # version=1, dek_id, config/database MAC, sealed_at

# (3) 런타임 복호화·사용·소거 (운영 경로와 동일)
sudo /usr/bin/python3 /usr/share/ovirt-engine/encryptor/integrity_seal.py --open   # rc=0
sudo head -c 2 /dev/shm/ovworks-aide.db.gz | xxd   # 복호화본(gzip 1f 8b 등) 존재
sudo /usr/sbin/aide --config=/dev/shm/ovworks-aide.conf --check                    # 무결성 비교 수행
sudo /usr/bin/python3 /usr/share/ovirt-engine/encryptor/integrity_seal.py --close
ls -l /dev/shm/ovworks-aide.*   2>/dev/null || echo "clean (복호화본 소거 확인)"

# (4) 음성 시험 — 기준값 변조/다른 DEK 시 거부
#   기준값 암호문 1바이트 변조 후 --open → "Baseline seal mismatch" + exit 3(변조)
#   (시험 후 engine-setup 또는 재봉인으로 원복)
```

**단위 시험 증빙**: `packaging/tests/test_integrity_seal.py`
- `test_the_sealed_baseline_is_encrypted_at_rest` — `--seal` 후 `OVENC002`로 시작
- `test_open_decrypts_the_baseline_and_writes_a_config_for_aide` — 복호화본·임시 설정 생성, `--close` 후 삭제
- `test_open_reports_a_tampered_baseline_and_leaves_no_plaintext` — 변조 시 exit 3·평문 미잔류

---

## 5. 기능 B — 웹 관리 로그인 개인키의 DEK 암호화

### 5.1 로직

| 단계 | 명령/함수 | 동작 |
|---|---|---|
| 저장 암호화 | `engine-setup` 종료 단계 `login_key.py --encrypt` | 설정 파일 암호화 직후(메모리 KEK 유지 중) 개인키를 **AES-256-GCM 봉투로 제자리 암호화**(멱등). 암호화 전 복호화 검증 후 교체, 소유자·0600 유지 |
| 기동 시 복호화 | 엔진 런처 `ovirt-engine.py` `_decryptLoginKey()` → `login_key.py --decrypt` | `<ENGINE_TMP>/sso/private_pkcs8.der`(tmpfs, 0600; 0700 디렉터리)로 복호화. `-Dovirt.engine.sso.login.key.path`로 Java에 경로 전달 |
| 사용 | `LoginEnvelopeCrypto` | 위 시스템 속성이 가리키는 **복호화본**을 읽어 RSA-OAEP 복호화 수행. 속성이 없으면 on-disk 경로로 폴백(평문 개인키 업그레이드 호환) |
| 소거 | 엔진 정지 | `ENGINE_TMP`(런타임 임시 디렉터리)가 삭제되며 복호화본도 함께 소멸 |

- 공개키(`config.json`의 `rsaPublicKey`)는 공개 정보이므로 평문(암호화 대상 아님).
- 업그레이드 호환: 아직 평문(DER)인 개인키는 `--decrypt`가 그대로 통과시켜 재봉인 전에도 로그인 동작.
- 소스: `packaging/encryptor/login_key.py`, `packaging/services/ovirt-engine/ovirt-engine.py.in`(`_decryptLoginKey`), `.../config/client_control.py`(`_encrypt_login_private_key`), `LoginEnvelopeCrypto.java`(`getPrivateKeyPath`).

### 5.2 증빙 방법

```bash
# (1) 저장 암호화 확인
sudo head -c 8 /etc/ovirt-engine/encryptor/private_pkcs8.der | tr -d '\0'; echo
#   기대: OVENC002   (※ 미적용/업그레이드 전이면 평문 DER=0x30 0x82 → engine-setup 재실행으로 적용)
sudo stat -c '%n %U:%G %a' /etc/ovirt-engine/encryptor/private_pkcs8.der   # ovirt:ovirt 600

# (2) 기동 시 런타임 복호화본과 Java 전달 경로 확인 (엔진 구동 중, root)
sudo find /var/lib/ovirt-engine -path '*/sso/private_pkcs8.der' -ls 2>/dev/null   # 0600 복호화본
sudo cat /proc/$(pgrep -f org.jboss.as.standalone)/cmdline | tr '\0' '\n' \
  | grep ovirt.engine.sso.login.key.path                                         # -D 경로

# (3) 정지 시 소거 확인
sudo systemctl stop ovirt-engine
sudo find /var/lib/ovirt-engine -path '*/sso/private_pkcs8.der' 2>/dev/null || echo "clean (복호화본 소거)"
```

**단위 시험 증빙**:
- `packaging/tests/test_login_key_crypto.py` — 저장 암호화·멱등·복호화 왕복·다른 DEK 거부·평문 통과·0600
- `packaging/setup/tests/test_login_key_runtime_decrypt.py` — 런처가 복호화→경로 전달, Java 폴백 배선
- `backend/.../LoginEnvelopeCryptoTest.java` — 시스템 속성 경로에서 개인키를 읽어 RSA-OAEP 복호화

---

## 5-1. 기능 B-2 — 사용자 단말기 시리얼의 DEK 암호화와 런타임 DEK 파기

| 단계 | 위치 | 내용 |
|---|---|---|
| 저장 암호화 | `SetUserClientSerialCommand` → `DekEnvelope.encryptToBase64` | 시리얼을 DEK로 AES-256-GCM(`OVENC002`) 암호화, `user_profiles.CLIENT_SERIAL_ENC`에 base64 저장 |
| 기동 시 DEK 전달 | 엔진 런처 `_writeRuntimeDek()` → `runtime_dek.py --write` | `<ENGINE_TMP>/dek/dek`(0600, 0700 디렉터리)에 DEK 32바이트, `-Dovirt.engine.dek.path`로 Java에 전달. 도구 내 DEK 사본은 `wipe` |
| 사용 | `CreateUserSessionCommand`, `ClientSerialCheck` | 봉투를 메모리에서 복호화해 비교 |
| 파기 | 엔진 정지 `daemonCleanup()` → `_destroyKeyFile()` | 런타임 DEK 파일을 **0으로 3회 덮어쓰기(fsync) 후 삭제**, 그다음 런타임 디렉터리 삭제 |

```bash
# 저장 암호화 확인 — 평문 시리얼이 없고 봉투만 있음
sudo -u postgres psql engine -c "SELECT property_content FROM user_profiles WHERE property_name='CLIENT_SERIAL_ENC';"
# 구동 중 런타임 DEK(0600) → 정지 후 소거
sudo find /var/lib/ovirt-engine -path '*/dek/dek' -ls
sudo systemctl stop ovirt-engine; sudo find /var/lib/ovirt-engine -path '*/dek/dek' | grep -q . || echo "clean (런타임 DEK 소거)"
```
> Java 메모리 안의 DEK 사본은 JVM 특성상 0 덮어쓰기를 보장할 수 없다(보상통제: 프로세스 종료 시 소멸, core dump 금지 설정은 기존과 동일).

## 6. 기능 C — 키 파기 시 0으로 덮어쓰기 (메모리·파일)

보안 검사자 지침에 따라, 키 폐기 시 **적용 가능한 영역(물리 파일·메모리상 bytearray 비밀값)에 0으로 3회 덮어쓰기**를 수행한다. 구조적으로 제자리 소거가 불가능한 영역(불변 복사본·JVM 객체)은 보상통제로 대응한다(§7).

### 6.1 로직

| 대상 | 방법 | 소스 |
|---|---|---|
| 메모리 — DEK·KEK 패스프레이즈(bytearray) | `encryptor.wipe()`가 **0으로 3회**(`WIPE_PASSES=3`) 덮어씀. KEK 에이전트는 `mlock`·core dump 금지, 종료/clear 시 wipe | `encryptor.py` `wipe()`, `kek_agent.py` |
| 파일 — DEK(`dek.enc`)·로그인 개인키 | `engine-cleanup` `_destroy()`가 **0으로 3회 덮어쓰기**(패스마다 `seek(0)`+`write`+`flush`+`fsync`) 후 `unlink` | `config/misc.py` `_destroy()` |
| 파일 — TLS/PKI 개인키 | `engine-cleanup` `_destroy()`가 **0·1·0(0x00, 0xFF, 0x00)으로 3회 덮어쓰기**(패스마다 `seek(0)`+`write`+`flush`+`fsync`) 후 `unlink` | `config/ca.py` `_destroy()` |
| KEK(메모리) | `engine-cleanup`이 KEK 에이전트를 `systemctl disable --now` → 프로세스 종료로 메모리에서 소멸 | `config/misc.py` `_forget_kek_passphrase()` |
| 암호학적 소거(crypto-erase) | KEK 소멸 → `dek.enc` 복호화 불가 → DEK로 감싼 모든 것(설정·무결성 기준값·로그인 개인키)이 **일괄 무력화** | — |

- 파기 감사: `_destroy`가 `authpriv` syslog에 `operation=key-destroy file=… status=success/failure` 기록(식별자 `ovirt-engine-cleanup`).

### 6.2 증빙 방법

```bash
# (1) 메모리 소거 로직 — bytearray 0 3회
grep -n "WIPE_PASSES = 3" /usr/share/ovirt-engine/encryptor/encryptor.py
sed -n '/def wipe(buffer):/,/buffer\[index\] = 0/p' /usr/share/ovirt-engine/encryptor/encryptor.py

# (2) 파일 파기 로직 — 3회 + fsync + unlink (engine-cleanup 플러그인 소스)
#   설치 경로는 패키징에 따라 다를 수 있어 위치를 먼저 찾은 뒤 확인한다.
CFG=$(sudo find / -path '*ovirt-engine-remove/ovirt-engine/config' -type d 2>/dev/null)
sudo grep -n "for _pass in range(3)"              "$CFG/misc.py"   # DEK·로그인 개인키: 0으로 3회
sudo grep -n "for fill in (b'\\\\x00', b'\\\\xff', b'\\\\x00')" "$CFG/ca.py"  # TLS/PKI 개인키: 0·1·0

# (3) 실제 파기 증빙 — engine-cleanup 실행 후
#   a. 키 파일이 사라졌는지
sudo ls -l /etc/ovirt-engine/encryptor/dek.enc /etc/ovirt-engine/encryptor/private_pkcs8.der 2>&1
#   b. 파기 감사 로그 (0 덮어쓰기+삭제가 성공으로 기록)
sudo journalctl -t ovirt-engine-cleanup | grep "operation=key-destroy"
#   c. KEK 에이전트가 중지·비활성화되어 메모리 패스프레이즈가 소멸했는지
systemctl is-active ovirt-engine-kek-agent.service; systemctl is-enabled ovirt-engine-kek-agent.service

# (4) (선택) 3회 쓰기 관찰 — 파기 중 write 시스템콜이 3회 발생함을 strace로 확인
#   sudo strace -f -e trace=pwrite64,write,fsync,unlink -o /tmp/destroy.trace engine-cleanup ...
#   grep -c 'write(' /tmp/destroy.trace   # 대상 파일당 3회

# (5) 메모리 보호 보상통제 — core dump 비활성·에이전트 mlock
ulimit -c ; coredumpctl info ovirt-engine-kek-agent 2>&1 | head
grep -n "mlock\|_no_core_dump\|def clear" /usr/share/ovirt-engine/encryptor/kek_agent.py
```

**단위 시험 증빙**: `packaging/setup/tests/test_remove_key_destruction.py`
- `test_dek_and_login_key_files_are_zero_overwritten_three_times` — `misc.py _destroy`가 0으로 3회 + `seek`/`flush`/`fsync`
- `test_tls_private_keys_are_overwritten_with_zeros_and_ones_three_times` — `ca.py _destroy`가 0·1·0 패턴
- `test_the_tls_key_passes_write_both_zeros_and_ones_and_end_zeroed` — 3패스가 각각 0x00·0xFF·0x00, 종료 시 전부 0
- `test_wipe_overwrites_three_times` — `WIPE_PASSES=3`, 환경/프롬프트 패스프레이즈가 bytearray

---

## 7. 한계와 보상통제 (사실 기재)

| # | 한계 | 보상통제 |
|---|---|---|
| H1 | **불변 `str`/`bytes` 복사본**(Python 연산 중 생성)은 제자리 0 덮어쓰기 불가 | 단시간 처리, 비특권 `ovirt` 계정, core dump 비활성, crypto-erase |
| H2 | **Java 측 평문**(로그인 ID/PW `String`)·`PrivateKey`(`BigInteger`)는 제자리 소거 불가 | TLS 종단, 복호화본은 tmpfs·정지 시 삭제, crypto-erase, JVM GC |
| H3 | 저널링 FS·SSD(웨어레벨링/TRIM)·CoW는 **덮어쓰기가 원본 블록에 닿지 않을 수 있음**(횟수 무관) | crypto-erase(KEK 소멸), **매체 폐기 시 물리 파기** 병행 |
| H4 | 메모리/DRAM에 대한 "3회"는 1회 대비 **기술적 추가 보증 없음**(지침 준수 목적) | 실제 보증은 crypto-erase; 3회는 지침 충족 |

> 요지: "0으로 3회 덮어쓰기"는 지침 충족을 위해 적용 가능한 영역에 구현했으며, **키 무력화의 실질 보증은 crypto-erase(KEK 소멸 → DEK 복호화 불가)** 이다. 이 점을 함께 기재하는 것이 정확하다.

## 8. 보안기능 확인 결과표

| 번호 | 확인 기능 | 합격 기준 | 판정 | 증적 |
|:--:|---|---|:--:|---|
| KE-01 | 무결성 기준값 저장 암호화 | `ovworks.db.gz` 선두가 `OVENC002` | `[ ]` | `[EV-A1]` |
| KE-02 | 무결성 봉인 | `ovworks.db.seal`에 `dek_id`·MAC 존재, DEK 원문 없음 | `[ ]` | `[EV-A2]` |
| KE-03 | 무결성 런타임 복호화·소거 | `--open`→tmpfs 복호화→`aide --check`→`--close` 후 삭제 | `[ ]` | `[EV-A3]` |
| KE-04 | 무결성 변조 거부 | 기준값 변조/다른 DEK 시 exit 3/2, 평문 미잔류 | `[ ]` | `[EV-A4]` |
| KE-05 | 로그인 개인키 저장 암호화 | `private_pkcs8.der` 선두가 `OVENC002`, 권한 `ovirt:ovirt 600` | `[ ]` | `[EV-B1]` |
| KE-06 | 로그인 개인키 런타임 | tmpfs 복호화본(0600) + `-D…login.key.path` 전달 | `[ ]` | `[EV-B2]` |
| KE-07 | 로그인 개인키 정지 소거 | 엔진 정지 후 복호화본 삭제 | `[ ]` | `[EV-B3]` |
| KE-08 | 파일 파기 3회 | `dek.enc`·로그인 개인키는 **0으로 3회**, TLS/PKI 개인키는 **0·1·0**으로 3회(+`fsync`) 덮어쓰기 후 삭제 | `[ ]` | `[EV-C1]` |
| KE-09 | 메모리 소거 0 3회 | bytearray 비밀값 `WIPE_PASSES=3`, KEK 에이전트 `mlock`·core dump 금지 | `[ ]` | `[EV-C2]` |
| KE-10 | 파기 감사 | `operation=key-destroy status=success` 기록 | `[ ]` | `[EV-C3]` |
| KE-11 | 암호학적 소거 | KEK 에이전트 중지·비활성 → DEK 복호화 불가 | `[ ]` | `[EV-C4]` |

## 9. 소스 코드 위치 (설치 경로)

| 기능 | 소스(저장소) | 설치 경로 |
|---|---|---|
| 봉투 암·복호화, `wipe()` | `packaging/encryptor/encryptor.py` | `/usr/share/ovirt-engine/encryptor/encryptor.py` |
| 무결성 봉인/개봉 | `packaging/encryptor/integrity_seal.py` | `/usr/share/ovirt-engine/encryptor/integrity_seal.py` |
| 로그인 개인키 암·복호화 | `packaging/encryptor/login_key.py` | `/usr/share/ovirt-engine/encryptor/login_key.py` |
| 기동 시 복호화(런처) | `packaging/services/ovirt-engine/ovirt-engine.py.in` | `/usr/share/ovirt-engine/services/ovirt-engine/ovirt-engine.py` |
| 로그인 복호화(Java) | `backend/.../sso/utils/LoginEnvelopeCrypto.java` | 엔진 EAR 내 |
| setup 암호화 단계 | `.../ovirt-engine/config/client_control.py` | setup 플러그인 |
| 키 파기(cleanup) | `.../ovirt-engine-remove/ovirt-engine/config/{misc,ca}.py` | remove 플러그인 |
| 보안검증 러너 | `ovirt-engine-security-verification-runner.sh` | `/usr/share/ovirt-engine/bin/…` |

> 본 확인서의 로직은 엔진 기동 게이트·KEK 가용성과 맞물리므로, 운영 반영 전 스테이징에서 §4.2·§5.2·§6.2의 증빙 명령을 1회 실행해 KE-01~KE-11을 확인할 것을 권고한다.
