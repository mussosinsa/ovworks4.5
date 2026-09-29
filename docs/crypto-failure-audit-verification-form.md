# 암호키 생성 실패·암호연산 실패 감사기록 보안기능 확인서

## 1. 문서 정보

| 항목 | 내용 |
|---|---|
| 문서명 | 암호키 생성 실패·암호연산 실패 감사기록 보안기능 확인서 |
| 대상 제품 | oVirt Engine (OV-Works) 4.5.x |
| 관련 보안요구사항 | 서버공통 7.1.1 — 암호키 생성 실패 감사기록 / 암호연산 실패 감사기록 |
| 대상 호스트 | `[호스트명 / IP]` |
| 암호화 모드 | `[모드 A (Vault, OVVLT001) / 모드 B (패스프레이즈, OVENC001)]` |
| 문서 버전 | 1.0 |
| 작성일 | `[YYYY-MM-DD]` |
| 시험 수행 일시 | `[YYYY-MM-DD HH:MM ~ HH:MM]` |
| 작성자 / 검증자 / 승인자 | `[성명·직책] / [성명·직책] / [성명·직책]` |
| 최종 판정 | `[적합 / 조건부 적합 / 부적합]` |

> **제출 전 확인:** 대괄호(`[ ]`) 항목을 실제 수행 결과로 대체한다. Vault 토큰, 패스프레이즈, 개인키,
> 평문 설정 파일, 암호문 전문 및 명령행 비밀값은 증적에 첨부하지 않는다. 증적에는 값 자체가 아니라
> 존재 여부, 감사기록 종류, 사유 코드 및 시각만 기록한다.

---

## 2. 목적 및 범위

본 확인서는 암호키 생성이 실패하거나 암호연산(암호화·복호화)이 실패했을 때, 그 사실이 **엔진 감사기록에
표출되는지**를 실제 유발 시험으로 확인하고 결과를 기록하기 위한 문서이다.

### 2.1 확인 대상 감사기록

| 구분 | 감사기록 | 값 | 심각도 | 정의 위치 |
|---|---|:---:|---|---|
| 암호키 생성 실패 | `CRYPTO_KEY_CREATION_FAILED` | 13663 | ERROR | `AuditLogType.java:1716` |
| 암호키 생성 성공(대조) | `CRYPTO_KEY_CREATED` | 13662 | NORMAL | `AuditLogType.java:1715` |
| 암호연산 실패 — 암호화 | `CONFIG_FILE_ENCRYPTION_FAILED` | 13661 | ERROR | `AuditLogType.java:1714` |
| 암호연산 성공(대조) — 암호화 | `CONFIG_FILE_ENCRYPTION_COMPLETED` | 13660 | NORMAL | `AuditLogType.java:1713` |
| 암호연산 실패 — 복호화 | `CONFIG_FILE_DECRYPTION_FAILED` | 13659 | ERROR | `AuditLogType.java:1712` |
| 암호연산 성공(대조) — 복호화 | `CONFIG_FILE_DECRYPTION_COMPLETED` | 13658 | NORMAL | `AuditLogType.java:1711` |
| 암호연산 실패 — 로그인 자격증명 | `LOGIN_CREDENTIAL_DECRYPTION_FAILED` | 13665 | ERROR | `AuditLogType.java:1731` |
| 기록 항목 격리(오류 지표) | `CRYPTO_EVENT_SPOOL_REJECTED` | 13664 | WARNING | `AuditLogType.java:1717` |

### 2.2 범위 밖

- Vault 자체의 감사 로그(`vault audit`)는 별도 통제이며 본 문서로 대체하지 않는다.
- PKI 인증서 발급·검증 실패는 별도 통제이다.
- 암호 알고리즘 적합성 확인은 `docs/db-config-key-management-specification.md`로 갈음한다.

---

## 3. 기록 경로 및 설계 근거

암호연산 대부분은 **엔진이 존재하지 않는 시점**에 수행된다. 데이터베이스 접속 설정은 Java 데몬이
기동되기 전에 복호되고, 암호키는 engine-setup이 생성한다. 따라서 실패한 연산은 그것을 기록할 엔진이
없으며, 유일한 흔적은 "엔진이 기동되지 않았다"는 사실뿐이었다. 각 결과를 스풀에 남기고 엔진이
기동 후 감사기록으로 옮기는 구조를 사용한다.

```
암호연산 실패 발생
  ├─ 실행 로그 (engine.log / 도구 표준오류)          ← 예외 원문이 허용되는 유일한 곳
  └─ 스풀 기록  /var/lib/ovirt-engine/security/crypto-events/<uuid>.json  (0600, 디렉터리 0700)
       │          · 원자적 기록: .tmp-<uuid> 작성 후 rename
       │          · 비밀정보 배제: 파일은 basename만, 사유는 고정 어휘만
       ↓
     CryptoEventAuditManager  (기동 +40초 시작, 이후 120초 주기, 1회 최대 100건)
       ├─ CryptoEvent.parse() 검증 (event/reason/source/file/scheme 닫힌 어휘·정규식)
       ├─ 통과 → audit_log 기록 → 스풀 항목 삭제
       └─ 실패 → crypto-events/rejected/ 로 격리 + CRYPTO_EVENT_SPOOL_REJECTED
       ↓
     WebAdmin 이벤트 목록
```

| 구성요소 | 위치 |
|---|---|
| 스풀 기록 라이브러리 | `packaging/pythonlib/ovirt_engine/cryptoevents.py` |
| 암호키 생성 | `packaging/encryptor/vault_passphrase.py:126-130` |
| 설정파일 암호화 | `packaging/encryptor/encrypt_conf_files.py:107,110`, `vault_passphrase.py:170,172` |
| 설정파일 복호화 | `packaging/pythonlib/ovirt_engine/configfile.py:86,96` |
| 로그인 자격증명 복호 | `backend/manager/modules/enginesso/.../CryptoEventSpool.java`, `LoginEnvelopeCrypto.java` |
| 스풀 배수·감사기록 | `backend/manager/modules/bll/.../CryptoEventAuditManager.java:49,55,58,67` |
| 항목 검증·문안 | `backend/manager/modules/bll/.../CryptoEvent.java:33,49,68,71,74,77` |

### 3.1 사유 코드 어휘 (닫힌 집합)

예외 메시지는 기록하지 않고 아래 코드 중 하나만 기록한다. 암호 모듈 메시지 중 일부는 키 파일 경로나
복호 대상의 길이·오프셋을 포함하므로, 사유는 예외의 **형(type)** 또는 지정된 문구 대조로만 도출한다.

| 사유 코드 | 의미 |
|---|---|
| `VAULT_UNAVAILABLE` | Vault 미가용(정지·봉인·연결 실패·권한 거부) |
| `VAULT_RESPONSE_INVALID` | Vault 응답이 유효하지 않음 |
| `AUTHENTICATION_FAILED` | AEAD 인증 실패 — 암호문·헤더 변조 또는 키 불일치 |
| `FILE_DAMAGED` | 암호문 절단·매직 누락·헤더 손상 |
| `PASSPHRASE_UNAVAILABLE` | 패스프레이즈를 얻을 수 없음 |
| `CONFIGURATION_INVALID` | 암호화 설정이 유효하지 않음 |
| `PATH_REJECTED` | 승인되지 않은 경로·심볼릭 링크·쓰기 가능 파일 |
| `LEGACY_DENIED` | 레거시 CBC 형식 거부 |
| `ENCRYPTOR_MISSING` | 암호화 도구 부재 |
| `PRIVATE_KEY_UNAVAILABLE` | 로그인 개인키를 읽거나 해석할 수 없음 |
| `CIPHERTEXT_INVALID` | 제시된 봉인값이 이 키로 개봉되지 않음 |
| `ALGORITHM_UNAVAILABLE` | 암호 알고리즘·패딩·제공자 부재 |
| `UNKNOWN` | 위 어느 것에도 해당하지 않음 (누출보다 정보 부족을 택함) |

---

## 4. 보안기능 확인 항목

| 번호 | 확인 기능 | 합격 기준 | 판정 | 증적 |
|:---:|---|---|:---:|---|
| CFA-01 | 암호키 생성 실패 기록 | 키 생성 실패 시 `CRYPTO_KEY_CREATION_FAILED`(13663, ERROR)가 감사기록에 표출된다. | `[ ]` | `[EV-01]` |
| CFA-02 | 암호화 실패 기록 | 암호화 실패 시 `CONFIG_FILE_ENCRYPTION_FAILED`(13661, ERROR)가 표출된다. | `[ ]` | `[EV-02]` |
| CFA-03 | 복호화 실패 기록 | 복호화 실패 시 `CONFIG_FILE_DECRYPTION_FAILED`(13659, ERROR)가 표출된다. | `[ ]` | `[EV-03]` |
| CFA-04 | 엔진 내부 암호연산 실패 기록 | 로그인 자격증명 복호 실패 시 `LOGIN_CREDENTIAL_DECRYPTION_FAILED`(13665, ERROR)가 표출된다. | `[ ]` | `[EV-04]` |
| CFA-05 | 사유 구분 | 실패 원인에 따라 서로 다른 사유 코드가 기록된다(인증 실패 ≠ 파일 손상 ≠ 미가용). | `[ ]` | `[EV-05]` |
| CFA-06 | 성공 기록(대조) | 정상 연산도 기록되어, "기록 없음"이 성공과 미수행을 구분한다. | `[ ]` | `[EV-06]` |
| CFA-07 | 엔진 부재 구간 보전 | 엔진 기동 전 발생한 실패가 다음 정상 기동 시 감사기록에 표출된다. | `[ ]` | `[EV-07]` |
| CFA-08 | 비밀정보 미유출 | 감사기록·스풀에 키, 암호문, 패스프레이즈, 파일 경로, 예외 원문이 없다. | `[ ]` | `[EV-08]` |
| CFA-09 | 기록 신뢰성 | 스풀 항목은 원자적으로 기록되고, 검증 실패 항목은 삭제되지 않고 격리·통보된다. | `[ ]` | `[EV-09]` |
| CFA-10 | 유량 제어 | 외부에서 유발 가능한 실패는 사유별 60초 1건으로 제한되어 이벤트 목록을 채우지 않는다. | `[ ]` | `[EV-10]` |
| CFA-11 | 화면 표출 | 위 감사기록이 WebAdmin 이벤트 목록에서 시각·메시지·사유와 함께 조회된다. | `[ ]` | `[EV-11]` |
| CFA-12 | 원상 복구 | 시험 후 서비스·설정·Vault 상태가 시험 전과 동일하다. | `[ ]` | `[EV-12]` |

---

## 5. 시험 전 준비

### 5.1 필수 사전 점검

아래 4개 항목이 충족되지 않으면 시험이 **조용히 실패**한다(기록이 남지 않으나 기능 미구현이 아님).

```bash
# ① cryptoevents 모듈 import 가능 여부  ★가장 중요
sudo -u ovirt /usr/bin/python3 -c \
  "from ovirt_engine import cryptoevents; print(cryptoevents.SPOOL_DIR)"
#   기대: /var/lib/ovirt-engine/security/crypto-events
#   실패 시 _record()가 no-op 된다 (vault_passphrase.py:16-17, 30-34).

# ② 스풀 디렉터리 소유권  ★두 번째로 중요
ls -ld /var/lib/ovirt-engine/security /var/lib/ovirt-engine/security/crypto-events 2>&1
#   기대: 둘 다 ovirt 소유, 0700
#   없으면 ovirt 권한으로 생성:
sudo -u ovirt install -d -m 0700 /var/lib/ovirt-engine/security/crypto-events

# ③ 엔진 실행 중 (스풀 배수 주체)
systemctl is-active ovirt-engine            # 기대: active

# ④ 외부 SSO 비활성 (시험 D 전제)
grep -rh ENGINE_SSO_ENABLE_EXTERNAL_SSO /etc/ovirt-engine/engine.conf.d/ 2>/dev/null
#   값이 없거나 false 여야 한다.
```

| 점검 | 결과 | 비고 |
|---|:---:|---|
| ① cryptoevents import | `[ ]` | `[ ]` |
| ② 스풀 디렉터리 ovirt 소유 0700 | `[ ]` | `[ ]` |
| ③ 엔진 active | `[ ]` | `[ ]` |
| ④ 외부 SSO 비활성 | `[ ]` | `[ ]` |

### 5.2 시험 기준 시각 기록

```bash
date -u +%Y-%m-%dT%H:%M:%SZ | sudo tee /tmp/crypto-test-start.txt
```

기준 시각: `[YYYY-MM-DDTHH:MM:SSZ]`

### 5.3 주의사항

> **모든 시험은 반드시 `sudo -u ovirt` 로 실행한다.**
> `root`로 실행하면 스풀 디렉터리·파일이 **root 소유**로 생성되어 엔진(`ovirt` 계정)이 읽지 못하고,
> 의도한 감사기록 대신 `CRYPTO_EVENT_SPOOL_REJECTED`(13664, WARNING)가 기록되며 항목은
> `crypto-events/rejected/`로 격리된다(`CryptoEventAuditManager.java:168-186`). 시험 실패로
> 오판하기 가장 쉬운 지점이다.

> **기록되지 않는 정상 동작을 실패로 오판하지 않는다.**
> `VaultTransitClient` **생성 단계** 실패(토큰 파일 없음, `ca_cert` 파일 없음,
> `vault_transit.enabled=false`)는 `vault_passphrase.py`의 try 블록 밖이므로 감사기록을 남기지
> 않는다(`vault_passphrase.py:111-131`). 이는 "키 생성을 **시도조차 하지 못한** 구성 오류"와
> "키 생성을 **시도했으나 실패**"를 구분하기 위한 설계이다.

---

## 6. 시험 절차

### 6.1 시험 A — 암호키 생성 실패 (CFA-01)

#### A-0. 대조군: 정상 경로 확인

```bash
sudo -u ovirt /usr/bin/python3 /usr/share/ovirt-engine/encryptor/vault_passphrase.py \
  --init-key --config /etc/ovirt-engine/encryptor/config.json ; echo "종료코드=$?"
```

| 결과 | 의미 | 다음 |
|---|---|---|
| 종료코드 0 | 토큰에 `transit/keys/*` 권한 있음 → `CRYPTO_KEY_CREATED` 기록 | **A-2** 수행 |
| 종료코드 1 + `HTTP 403` | 최소권한 토큰(권장 구성) → **A-1 이미 성립** | 결과 확인만 |

> Vault는 이미 존재하는 키에 대한 생성 요청을 무시(204)하므로, 종료코드 0이 나와도 기존 KEK는
> 변경되지 않는다.

관측 결과: `[종료코드 / 표준오류 메시지]`

#### A-1. 최소권한 토큰으로 유발 — **무중단, 권장**

애플리케이션 토큰의 승인 권한은 `transit/encrypt/*`, `transit/decrypt/*` 두 개뿐이다.
`ensure_key()`는 `POST /v1/transit/keys/<key_name>`을 호출하므로(`encryptor.py:97-103`, `:134-140`)
권한 거부로 실패한다.

```bash
sudo -u ovirt /usr/bin/python3 /usr/share/ovirt-engine/encryptor/vault_passphrase.py \
  --init-key --config /etc/ovirt-engine/encryptor/config.json ; echo "종료코드=$?"

# 스풀 항목 즉시 확인
sudo -u ovirt sh -c 'for f in /var/lib/ovirt-engine/security/crypto-events/*.json; do
  python3 -m json.tool "$f"; done'
```

기대 출력:

```
vault_passphrase: Vault Transit request failed (HTTP 403)
종료코드=1
```
```json
{
    "version": 1,
    "id": "<uuid>",
    "timestamp": "<UTC>",
    "event": "CRYPTO_KEY_CREATION_FAILED",
    "source": "vault-passphrase",
    "reason": "VAULT_UNAVAILABLE"
}
```

관측 결과: `[종료코드 / event / source / reason]`

#### A-2. Vault 봉인으로 유발 — 유지보수 창 필요

A-0에서 종료코드 0이 나온 구성에서만 수행한다.

```bash
export VAULT_ADDR=https://127.0.0.1:8200
export VAULT_CACERT=/etc/pki/ca-trust/source/anchors/vault-ca.pem

vault operator seal                        # 관리자 토큰 필요

sudo -u ovirt /usr/bin/python3 /usr/share/ovirt-engine/encryptor/vault_passphrase.py \
  --init-key --config /etc/ovirt-engine/encryptor/config.json ; echo "종료코드=$?"
#   기대: Vault Transit request failed (HTTP 503) / reason=VAULT_UNAVAILABLE

vault operator unseal                      # 임계값 3 → 3회 반복
vault status | grep -i sealed              # 기대: false
```

> 봉인 중에는 엔진을 재기동할 수 없고(DB 설정이 `OVVLT001`), 진행 중인 복호도 실패한다.
> 반드시 봉인해제까지 한 번에 수행한다.

관측 결과: `[수행 여부 / 종료코드 / reason / 봉인해제 완료 시각]`

---

### 6.2 시험 B — 암호화 실패 (CFA-02) — 무중단

`vault_passphrase.py --encrypt`는 임의 경로를 대상으로 하며(`ALLOWED_ROOTS` 제약 없음), 실패 시
`_record("ENCRYPTION_FAILED", …)`를 남긴다(`vault_passphrase.py:170`).

```bash
# 준비: 폐기용 평문 파일 (0600 필수)
sudo -u ovirt install -d -m 0700 /tmp/ct
printf 'probe' | sudo -u ovirt tee /tmp/ct/probe >/dev/null
sudo -u ovirt chmod 0600 /tmp/ct/probe

# ── B-0 대조군: 정상 암호화 → CONFIG_FILE_ENCRYPTION_COMPLETED
sudo -u ovirt /usr/bin/python3 /usr/share/ovirt-engine/encryptor/vault_passphrase.py \
  --encrypt --config /etc/ovirt-engine/encryptor/config.json /tmp/ct/probe /tmp/ct/probe.enc
head -c 8 /tmp/ct/probe.enc ; echo         # 기대: OVVLT001

# ── B-1 실패 유발: Vault 주소만 틀린 사본 설정 (서비스 무접촉)
sudo -u ovirt python3 - <<'PY'
import json
c = json.load(open('/etc/ovirt-engine/encryptor/config.json'))
c['vault_transit']['address'] = 'https://127.0.0.1:65500'   # listen 하지 않는 포트
json.dump(c, open('/tmp/ct/config.json', 'w'), indent=4, sort_keys=True)
PY
sudo -u ovirt chmod 0600 /tmp/ct/config.json

sudo -u ovirt /usr/bin/python3 /usr/share/ovirt-engine/encryptor/vault_passphrase.py \
  --encrypt --config /tmp/ct/config.json /tmp/ct/probe /tmp/ct/probe2.enc ; echo "종료코드=$?"
```

기대:

```
vault_passphrase: Vault Transit connection failed
종료코드=1
```

| 항목 | 기대값 |
|---|---|
| `event` | `CONFIG_FILE_ENCRYPTION_FAILED` |
| `source` | `vault-passphrase` |
| `file` | `probe2.enc` (basename만) |
| `scheme` | `OVVLT001` |
| `reason` | `VAULT_UNAVAILABLE` |
| `/tmp/ct/probe2.enc` | **생성되지 않음** — 복호 왕복 자체검증 통과 후에만 기록(`encryptor.py:493-496`) |

관측 결과: `[event / source / file / scheme / reason / 출력파일 유무]`

---

### 6.3 시험 C — 복호화 실패 (CFA-03, CFA-05) — 무중단

엔진 기동 시 복호와 **동일한 코드**(`ovirt_engine.configfile.ConfigFile`,
`cryptoEventSource='engine-start'` — `ovirt-engine.py.in:418-427`)를 **사본**에 대해 실행한다.

#### C-1. 인증 실패 (마지막 1바이트 변조)

```bash
sudo -u ovirt cp /etc/ovirt-engine/engine.conf.d/10-setup-database.conf /tmp/ct/
sudo -u ovirt chmod 0600 /tmp/ct/10-setup-database.conf
head -c 8 /tmp/ct/10-setup-database.conf ; echo        # OVVLT001 확인

sudo -u ovirt python3 - <<'PY'
p = '/tmp/ct/10-setup-database.conf'
d = bytearray(open(p, 'rb').read())
d[-1] ^= 0xFF
open(p, 'wb').write(bytes(d))
print('마지막 바이트 변조 완료')
PY

sudo -u ovirt /usr/bin/python3 - <<'PY'
from ovirt_engine import configfile
c = configfile.ConfigFile(cryptoEventSource='engine-start')
try:
    c.loadFile('/tmp/ct/10-setup-database.conf')
    print('예상과 다름: 복호가 성공했습니다')
except Exception as e:
    print('예상된 실패:', e)
PY
```

기대: `event=CONFIG_FILE_DECRYPTION_FAILED`, `source=engine-start`,
`file=10-setup-database.conf`, `scheme=OVVLT001`, **`reason=AUTHENTICATION_FAILED`**

> **전제**: 모드 A(`OVVLT001`)에서 C-1은 **Vault가 가용해야 한다.** 랩핑된 DEK를 Vault에서 먼저
> 개봉한 뒤 AEAD 인증을 검사하므로, Vault가 봉인 상태면 `AUTHENTICATION_FAILED`가 아니라
> `VAULT_UNAVAILABLE`이 기록된다. 시험 A-2 직후에는 봉인해제를 확인하고 진행한다.
> C-2(절단)는 헤더 길이 검사에서 먼저 실패하므로 Vault와 무관하다.

#### C-2. 파일 손상 (절단)

```bash
sudo -u ovirt install -d -m 0700 /tmp/ct/trunc
sudo -u ovirt cp /etc/ovirt-engine/engine.conf.d/10-setup-database.conf /tmp/ct/trunc/
sudo -u ovirt truncate -s 20 /tmp/ct/trunc/10-setup-database.conf

sudo -u ovirt /usr/bin/python3 - <<'PY'
from ovirt_engine import configfile
c = configfile.ConfigFile(cryptoEventSource='engine-start')
try:
    c.loadFile('/tmp/ct/trunc/10-setup-database.conf')
except Exception as e:
    print('예상된 실패:', e)
PY
```

기대: **`reason=FILE_DAMAGED`** — C-1과 사유 코드가 달라야 CFA-05 합격.

> 모드 B(`OVENC001`) 호스트에서도 동일하다. 변조는 `Encrypted file is truncated`가 아닌 AEAD
> 인증 실패 경로로 `AUTHENTICATION_FAILED`, 절단(20바이트)은 헤더 최소 길이(119바이트) 미달로
> `Encrypted file is truncated` → `FILE_DAMAGED`로 분류된다.

관측 결과: C-1 `[reason]` / C-2 `[reason]`

#### C-3. (선택) 실제 기동 차단까지 포함하는 완전 시험 (CFA-07) — 중단 필요

"엔진이 기동하지 못하고, 복구 후 감사기록으로 표출됨"까지 실증해야 하는 경우에만 수행한다.

```bash
# ★ 백업 필수
sudo cp -a /etc/ovirt-engine/engine.conf.d/10-setup-database.conf \
           /root/10-setup-database.conf.bak
sudo systemctl stop ovirt-engine

sudo python3 - <<'PY'
p = '/etc/ovirt-engine/engine.conf.d/10-setup-database.conf'
d = bytearray(open(p, 'rb').read()); d[-1] ^= 0xFF
open(p, 'wb').write(bytes(d))
PY

sudo systemctl start ovirt-engine ; echo "기동 결과=$?"      # 기대: 실패
sudo journalctl -u ovirt-engine -n 30 --no-pager | tail -20

# 즉시 복구
sudo cp -a /root/10-setup-database.conf.bak \
           /etc/ovirt-engine/engine.conf.d/10-setup-database.conf
sudo systemctl start ovirt-engine
systemctl is-active ovirt-engine                              # 기대: active
```

복구 후 **최대 120초** 안에 스풀이 배수되어 `CONFIG_FILE_DECRYPTION_FAILED`가 이벤트 목록에
표출된다. 이것이 "엔진이 없는 시점의 실패도 기록된다"는 설계의 실증이다.

관측 결과: `[수행 여부 / 기동 실패 확인 / 복구 시각 / 감사기록 표출 시각]`

---

### 6.4 시험 D — 로그인 자격증명 복호 실패 (CFA-04, CFA-10) — 무중단

`issueTokenForPasswd`는 클라이언트 인증보다 **먼저** `getCredentials()`를 호출하므로
(`OAuthTokenServlet.java:274-281`, `:305-317`) 별도 자격증명 없이 복호 경로에 도달한다.

```bash
# ★ 엔진 호스트에서 실행 (127.0.0.1은 Require ip 목록에 항상 포함)
curl -k -s -X POST https://127.0.0.1/ovirt-engine/sso/oauth/token \
  -d 'grant_type=password' \
  -d 'scope=ovirt-app-api' \
  --data-urlencode 'encrypted_username=!!!not-base64!!!' \
  --data-urlencode 'encrypted_password=!!!not-base64!!!' ; echo

# 엔진 로그 확인
sudo grep -a "로그인 자격증명 복호화 실패" /var/log/ovirt-engine/engine.log | tail -3
```

기대 로그(`CryptoEventSpool.java:115`):

```
WARN  ... 로그인 자격증명 복호화 실패; source='sso-username'; reason='CIPHERTEXT_INVALID';
      error='java.lang.IllegalArgumentException: Illegal base64 character 21'
```

| 관측된 사유 | 의미 |
|---|---|
| `CIPHERTEXT_INVALID` | 개인키 정상, 제시된 값이 개봉되지 않음 — **정상적인 시험 결과** |
| `PRIVATE_KEY_UNAVAILABLE` | `/etc/ovirt-engine/encryptor/private_pkcs8.der` 부재·판독 불가 — 환경 구성 확인 필요 |

#### D-2. 유량 제어 확인 (CFA-10)

```bash
for i in $(seq 1 10); do
  curl -k -s -o /dev/null -X POST https://127.0.0.1/ovirt-engine/sso/oauth/token \
    -d 'grant_type=password' -d 'scope=ovirt-app-api' \
    --data-urlencode 'encrypted_username=!!!not-base64!!!' \
    --data-urlencode 'encrypted_password=!!!not-base64!!!'
done

sudo grep -ac "로그인 자격증명 복호화 실패" /var/log/ovirt-engine/engine.log   # 10건 이상
sudo -u ovirt ls /var/lib/ovirt-engine/security/crypto-events/*.json | wc -l    # 사유별 1건
```

기대: `engine.log`에는 모든 발생 건이 남고, 스풀에는 **사유별 60초 1건**만 기록된다
(`CryptoEventSpool.java:91,128`). 이 감사기록만 유량 제어 대상이며, `CONFIG_FILE_*` 및
`CRYPTO_KEY_*`는 제한 없이 매 건 기록된다.

관측 결과: `[engine.log 건수 / 스풀 건수 / reason]`

---

## 7. 표출 확인

### 7.1 스풀 (즉시)

```bash
sudo -u ovirt ls -l /var/lib/ovirt-engine/security/crypto-events/
sudo -u ovirt sh -c 'for f in /var/lib/ovirt-engine/security/crypto-events/*.json; do
  python3 -m json.tool "$f"; done'

# 격리 항목 확인 — 존재하면 사전점검 ② 재확인
sudo -u ovirt ls -l /var/lib/ovirt-engine/security/crypto-events/rejected/ 2>/dev/null
```

### 7.2 엔진 로그 (배수 시점)

```bash
sudo tail -f /var/log/ovirt-engine/engine.log | grep -a "암호연산 이벤트"
#   기대: 암호연산 이벤트 기록; event='CRYPTO_KEY_CREATION_FAILED'; id='<uuid>'
```

> 배수는 엔진 기동 40초 후 시작, 이후 **120초 주기**이다(`CryptoEventAuditManager.java:55,58`).
> 최대 2분 대기한다. 스풀 파일이 사라지면 기록이 완료된 것이다.

### 7.3 데이터베이스 (권위 있는 확인)

```bash
sudo -u postgres psql -d engine -c "
SELECT log_time, log_type, severity, message
  FROM audit_log
 WHERE log_type IN (13658, 13659, 13660, 13661, 13662, 13663, 13664, 13665)
   AND log_time > '$(cat /tmp/crypto-test-start.txt)'::timestamptz
 ORDER BY log_time;"
```

기대 메시지 예:

```
Configuration file 10-setup-database.conf could not be decrypted at <시각> (engine-start, OVVLT001); reason: AUTHENTICATION_FAILED
Configuration file probe2.enc could not be encrypted at <시각> (vault-passphrase, OVVLT001); reason: VAULT_UNAVAILABLE
An encryption key could not be created at <시각> (vault-passphrase); reason: VAULT_UNAVAILABLE
A login credential could not be decrypted at <시각> (sso-username); reason: CIPHERTEXT_INVALID
```

### 7.4 WebAdmin 이벤트 목록 (화면 증적)

**관리화면 → 이벤트**

| 검색식 | 확인 내용 |
|---|---|
| `Events: severity=error` | `*_FAILED` 4종이 ERROR로 표출 |
| `Events: message=*could not be decrypted*` | 복호 실패 |
| `Events: message=*could not be encrypted*` | 암호화 실패 |
| `Events: message=*encryption key could not be created*` | 키 생성 실패 |
| `Events: message=*reason: *` | 사유 코드가 화면에 표출됨 |

화면 캡처 시 **시각·메시지·사유 코드**가 함께 보이도록 한다.

---

## 8. 비밀정보 미유출 확인 (CFA-08)

```bash
# 감사기록 본문에 비밀·경로가 없는지
sudo -u postgres psql -d engine -tAc "
SELECT message FROM audit_log WHERE log_type IN (13659,13661,13663,13665)" \
 | grep -E "private_pkcs8|/etc/|/var/|vault:v1|BEGIN |passphrase" \
 && echo "!!! 유출 확인됨 — 부적합" || echo "유출 없음 = 적합"

# 스풀 항목 필드 구성 (version/id/timestamp/event/source[/file/scheme]/reason 만)
sudo -u ovirt sh -c 'for f in /var/lib/ovirt-engine/security/crypto-events/*.json; do
  python3 -c "import json,sys;print(sorted(json.load(open(sys.argv[1])).keys()))" "$f"; done'

# 소스 수준 확인: 사유는 예외 형으로만 도출 (메시지 미사용)
grep -c "error.getMessage()" \
  backend/manager/modules/enginesso/src/main/java/org/ovirt/engine/core/sso/utils/CryptoEventSpool.java
#   기대: 0
```

| 확인 | 결과 |
|---|:---:|
| 감사기록에 키·암호문·패스프레이즈 없음 | `[ ]` |
| 감사기록에 파일 경로 없음(basename만) | `[ ]` |
| 감사기록에 예외 원문 없음(고정 어휘 사유만) | `[ ]` |
| 스풀 항목 필드가 정의된 것만 존재 | `[ ]` |

---

## 9. 시험 결과표

| ID | 시험 항목 | 유발 방법 | 기대 감사기록 | 기대 사유 | 중단 | 수행 시각 | 관측 사유 | 판정 |
|:---:|---|---|---|---|:---:|---|---|:---:|
| CK-01 | 암호키 생성 성공(대조) | `--init-key` (권한 있는 토큰) | `CRYPTO_KEY_CREATED` | — | 무 | `[ ]` | `[ ]` | `[ ]` |
| CK-02 | **암호키 생성 실패** | `--init-key` (최소권한 토큰) | `CRYPTO_KEY_CREATION_FAILED` | `VAULT_UNAVAILABLE` | 무 | `[ ]` | `[ ]` | `[ ]` |
| CK-03 | 암호키 생성 실패(봉인) | Vault seal + `--init-key` | `CRYPTO_KEY_CREATION_FAILED` | `VAULT_UNAVAILABLE` | 유 | `[ ]` | `[ ]` | `[ ]` |
| CO-01 | 암호화 성공(대조) | `--encrypt` 정상 | `CONFIG_FILE_ENCRYPTION_COMPLETED` | — | 무 | `[ ]` | `[ ]` | `[ ]` |
| CO-02 | **암호화 실패** | 잘못된 Vault 주소 사본 설정 | `CONFIG_FILE_ENCRYPTION_FAILED` | `VAULT_UNAVAILABLE` | 무 | `[ ]` | `[ ]` | `[ ]` |
| CO-03 | **복호 실패(인증)** | 사본 마지막 바이트 변조 | `CONFIG_FILE_DECRYPTION_FAILED` | `AUTHENTICATION_FAILED` | 무 | `[ ]` | `[ ]` | `[ ]` |
| CO-04 | **복호 실패(손상)** | 사본 절단 | `CONFIG_FILE_DECRYPTION_FAILED` | `FILE_DAMAGED` | 무 | `[ ]` | `[ ]` | `[ ]` |
| CO-05 | 복호 실패 + 기동 차단 | 실제 파일 변조 후 재기동 | `CONFIG_FILE_DECRYPTION_FAILED` | `AUTHENTICATION_FAILED` | 유 | `[ ]` | `[ ]` | `[ ]` |
| CO-06 | **로그인 복호 실패** | `curl` 잘못된 봉인값 | `LOGIN_CREDENTIAL_DECRYPTION_FAILED` | `CIPHERTEXT_INVALID` | 무 | `[ ]` | `[ ]` | `[ ]` |
| CO-07 | 비밀정보 미유출 | 감사기록·스풀 본문 검사 | 경로·암호문·키 없음 | — | 무 | `[ ]` | `[ ]` | `[ ]` |
| CO-08 | 유량 제어 | CO-06 10회 연속 | 스풀 1건 / 로그 10건 | — | 무 | `[ ]` | `[ ]` | `[ ]` |
| CO-09 | 화면 표출 | WebAdmin 이벤트 조회 | 위 기록이 화면에 표출 | — | 무 | `[ ]` | `[ ]` | `[ ]` |

### 9.1 최소 시험 셋

시간이 제한된 경우 무중단 3건으로 두 요구사항을 모두 실증할 수 있다.

1. **CK-02** — 암호키 생성 실패
2. **CO-03** — 암호연산 실패(프로덕션 복호 코드 경로)
3. **CO-06** — 엔진 내부 암호연산 실패

각 수행 후 7.1(스풀) → 7.3(DB) → 7.4(화면) 순으로 캡처한다.

---

## 10. 정리 및 원상 복구 (CFA-12)

```bash
# 시험 잔여물 제거
sudo rm -rf /tmp/ct /tmp/crypto-test-start.txt

# Vault 봉인해제 상태 (A-2 수행 시)
VAULT_ADDR=https://127.0.0.1:8200 \
VAULT_CACERT=/etc/pki/ca-trust/source/anchors/vault-ca.pem \
  vault status | grep -i sealed                  # 기대: false

# 실제 설정파일 원상 (C-3 수행 시)
head -c 8 /etc/ovirt-engine/engine.conf.d/10-setup-database.conf ; echo   # OVVLT001
sudo rm -f /root/10-setup-database.conf.bak
systemctl is-active ovirt-engine                 # active

# 정상 경로 재확인
sudo -u ovirt /usr/bin/python3 \
  /usr/share/ovirt-engine/encryptor/vault_passphrase.py --check
#   기대: Vault Transit preflight succeeded

# 스풀 배수 완료
sudo -u ovirt ls /var/lib/ovirt-engine/security/crypto-events/*.json 2>/dev/null \
  || echo "스풀 비어 있음 = 정상"

# 격리 항목 없음
sudo -u ovirt ls /var/lib/ovirt-engine/security/crypto-events/rejected/ 2>/dev/null \
  || echo "격리 항목 없음 = 정상"
```

| 복구 확인 | 결과 |
|---|:---:|
| 시험 잔여물 제거 | `[ ]` |
| Vault 봉인해제 상태 | `[ ]` |
| 설정파일 원상 (`OVVLT001`) | `[ ]` |
| 엔진 active | `[ ]` |
| Vault preflight 정상 | `[ ]` |
| 스풀 비어 있음 / 격리 항목 없음 | `[ ]` |

---

## 11. 개발 단위시험 (정적 증빙)

운영 환경 유발 시험과 별개로, 저장소에 아래 자동화 시험이 포함되어 있다.

| 시험 | 위치 | 확인 내용 |
|---|---|---|
| 스풀 기록 동작 | `packaging/tests/test_crypto_events.py` | 항목 형식, 사유 어휘, 원자적 기록, 예외 미전파 |
| 설정파일 복호 기록 | `packaging/tests/test_configfile_crypto_events.py` | 성공·실패 기록, 사유 분류 |
| 도구 기록 배선 | `packaging/tests/test_encryptor_tool_crypto_events.py` | 키 생성·파일 암호화 기록 호출 |
| 로그인 복호 기록 | `packaging/tests/test_login_crypto_events.py` | 어휘 동기화, 두 경로 기록, 유량 제어, 비밀 미유출 |
| 스풀 기록기 | `backend/manager/modules/enginesso/src/test/.../CryptoEventSpoolTest.java` | 사유 분류, 창 제어, 임시파일 미잔존, 예외 미전파 |
| 항목 판독 | `backend/manager/modules/bll/src/test/.../CryptoEventTest.java` | 닫힌 어휘 검증, 감사기록 종류 변환 |

```bash
# 저장소에서 실행
cd packaging/tests && python3 -m unittest \
  test_crypto_events test_configfile_crypto_events \
  test_encryptor_tool_crypto_events test_login_crypto_events
```

수행 결과: `[Ran N tests — OK / 실패 내역]`

### 11.1 본 확인서가 기대하는 사유 분류 사전검증

본 확인서 작성 시 `cryptoevents.reason_for()`에 각 시험의 실제 오류 문구를 입력하여, 표에 기재한
기대 사유가 구현과 일치함을 확인했다. 시험 환경에서도 동일하게 재확인할 수 있다.

```bash
sudo -u ovirt /usr/bin/python3 - <<'REASONCHECK'
from ovirt_engine import cryptoevents as c
cases = [
    ('A-1 권한 거부',    'Vault Transit request failed (HTTP 403)',            'VAULT_UNAVAILABLE'),
    ('A-2 봉인',         'Vault Transit request failed (HTTP 503)',            'VAULT_UNAVAILABLE'),
    ('B-1 연결 실패',    'Vault Transit connection failed',                    'VAULT_UNAVAILABLE'),
    ('C-1 변조',         'Authentication failed: file is damaged or modified', 'AUTHENTICATION_FAILED'),
    ('C-2 절단(모드 A)', 'Vault-encrypted file is truncated',                  'FILE_DAMAGED'),
    ('C-2 절단(모드 B)', 'Encrypted file is truncated',                        'FILE_DAMAGED'),
]
for name, message, expected in cases:
    got = c.reason_for(RuntimeError(message))
    print(('PASS ' if got == expected else 'FAIL ') + f'{name}: 기대={expected} 실제={got}')
REASONCHECK
```

확인 결과: `[6건 전부 PASS / 불일치 내역]`

추가로 스풀 항목의 구조·권한이 §3 기재와 일치함을 확인한다.

| 확인 항목 | 기대 | 확인 |
|---|---|:---:|
| 연산 실패 항목 필드 | `version, id, timestamp, event, source, file, scheme, reason` | `[ ]` |
| 키 생성 실패 항목 필드 | `version, id, timestamp, event, source, reason` (파일 없음) | `[ ]` |
| `file` 값 | 전체 경로가 아닌 basename | `[ ]` |
| 스풀 디렉터리 권한 | `0700` | `[ ]` |
| 스풀 항목 권한 | `0600` | `[ ]` |
| 임시파일(`.tmp-*`) 잔존 | 없음 | `[ ]` |

---

## 12. 알려진 제한과 보완 통제

| 제한 | 영향 | 보완 통제 |
|---|---|---|
| 스풀 배수 지연 최대 120초 | 실패 직후 이벤트 목록에 즉시 나타나지 않음 | 항목이 자체 타임스탬프를 보유하여 감사기록 메시지에 **실제 발생 시각**이 표기됨 |
| `VaultTransitClient` 생성 단계 실패는 미기록 | 토큰·CA 파일 부재는 감사기록 없음 | 표준오류 및 engine-setup 실패로 즉시 인지, "시도 못 함"과 "시도 후 실패"의 의도적 구분 |
| 로그인 복호 실패 사유별 60초 1건 | 연속 공격이 1분에 1건으로 표출 | 모든 발생 건은 `engine.log`에 기록, 반복 여부는 로그로 확인 |
| `sso-credential` 소스 단독 유발 곤란 | 사용자명이 먼저 복호되어 동일 사유가 억제됨 | 두 소스 존재는 `CryptoEventSpoolTest`, `test_login_crypto_events.py`로 증빙 |
| 스풀이 root 소유가 되면 기록 불가 | 감사기록 누락 | `CRYPTO_EVENT_SPOOL_REJECTED`(13664)로 통보되고 항목은 삭제되지 않고 격리됨 |

---

## 13. 제출용 체크리스트·증적·결재

### 13.1 체크리스트

- [ ] 사전 점검 4개 항목(§5.1)을 모두 충족한 상태에서 시험했다.
- [ ] 모든 시험을 `sudo -u ovirt` 로 수행했다.
- [ ] 암호키 생성 실패가 `CRYPTO_KEY_CREATION_FAILED`로 감사기록에 표출됐다.
- [ ] 암호화 실패가 `CONFIG_FILE_ENCRYPTION_FAILED`로 표출됐다.
- [ ] 복호화 실패가 `CONFIG_FILE_DECRYPTION_FAILED`로 표출됐다.
- [ ] 엔진 내부 암호연산 실패가 `LOGIN_CREDENTIAL_DECRYPTION_FAILED`로 표출됐다.
- [ ] 실패 원인에 따라 서로 다른 사유 코드가 기록됐다.
- [ ] 정상 연산도 기록되어 "기록 없음"이 성공과 미수행을 구분한다.
- [ ] 감사기록·스풀에 키·암호문·패스프레이즈·경로·예외 원문이 없다.
- [ ] 유량 제어가 동작하며 모든 발생 건은 엔진 로그에 남는다.
- [ ] WebAdmin 이벤트 목록에서 시각·메시지·사유와 함께 조회된다.
- [ ] 시험 후 서비스·설정·Vault 상태가 원상 복구됐다.
- [ ] 격리 항목(`rejected/`)이 남아 있지 않다.

### 13.2 증적 목록

| 증적 번호 | 증적명 | 형태 | 보관 위치 / 티켓 | 판정 |
|---|---|---|---|:---:|
| EV-01 | 암호키 생성 실패 — 도구 출력 + 스풀 항목 + DB 조회 | 텍스트 | `[ ]` | `[ ]` |
| EV-02 | 암호화 실패 — 도구 출력 + 스풀 항목 + DB 조회 | 텍스트 | `[ ]` | `[ ]` |
| EV-03 | 복호화 실패 — 실행 출력 + 스풀 항목 + DB 조회 | 텍스트 | `[ ]` | `[ ]` |
| EV-04 | 로그인 복호 실패 — `engine.log` 발췌 + 스풀 항목 | 텍스트 | `[ ]` | `[ ]` |
| EV-05 | 사유 코드 구분 — C-1/C-2 대조표 | 텍스트 | `[ ]` | `[ ]` |
| EV-06 | 성공 기록 대조군 — `*_COMPLETED` / `CRYPTO_KEY_CREATED` | 텍스트 | `[ ]` | `[ ]` |
| EV-07 | 기동 차단 후 복구 시 감사기록 표출 | 텍스트 | `[ ]` | `[ ]` |
| EV-08 | 비밀정보 미유출 검사 결과 | 텍스트 | `[ ]` | `[ ]` |
| EV-09 | 스풀 원자성·격리 동작 확인 | 텍스트 | `[ ]` | `[ ]` |
| EV-10 | 유량 제어 확인 (로그 건수 대 스풀 건수) | 텍스트 | `[ ]` | `[ ]` |
| EV-11 | WebAdmin 이벤트 목록 화면 | 화면 캡처 | `[ ]` | `[ ]` |
| EV-12 | 원상 복구 확인 | 텍스트 | `[ ]` | `[ ]` |
| EV-13 | 개발 단위시험 수행 결과 | 텍스트 | `[ ]` | `[ ]` |

### 13.3 결재

| 결재 구분 | 성명 / 직책 | 의견 | 서명 | 일자 |
|---|---|---|---|---|
| 시험 수행 | `[ ]` | `[ ]` | `[ ]` | `[ ]` |
| 운영 확인 | `[ ]` | `[ ]` | `[ ]` | `[ ]` |
| 보안 검증 | `[ ]` | `[ ]` | `[ ]` | `[ ]` |
| 최종 승인 | `[ ]` | `[ ]` | `[ ]` | `[ ]` |

---

## 14. 관련 문서

| 문서 | 내용 |
|---|---|
| `docs/db-config-key-management-specification.md` | DEK·KEK 생성·저장·파기, 봉투 형식, 모드 A/B 상세 |
| `docs/login-credential-crypto-audit.md` | 로그인 자격증명 복호 실패 감사기록 설계 |
| `docs/config-file-crypto-engine-event-design.md` | 설정파일 암호화 이벤트 설계 |
| `docs/vault-transit-rocky-linux-9.5.md` | Vault Transit 구축·봉인해제·재부팅 절차 |
| `docs/webadmin-login-credential-encryption-verification-form.md` | 로그인 자격증명 암·복호화 보안기능 확인서 |
| `docs/setup-database-config-encryption-verification-form.md` | 설정파일 암호화 보안기능 확인서 |
