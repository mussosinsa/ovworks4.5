# 로컬 DB 접속 식별·인증

`su - postgres` 후 `psql engine`처럼 DB 서버에서 로컬로 접속할 때도 **DB 계정의 비밀번호**를 묻도록 한다.

## 문제

PostgreSQL `initdb`가 만드는 `pg_hba.conf`는 로컬 소켓 접속을 `peer`로 허용한다.

```text
local   all   all   peer
```

`peer`는 OS 계정 이름과 DB 계정 이름이 같으면 비밀번호 없이 통과시킨다. 그래서 OS에서 `postgres`가 된 사람은
DB 슈퍼유저로 engine DB에 바로 들어가며, DB는 그 사람을 식별·인증하지 않는다. engine-setup은 이 규칙을 그대로
두고 있었다(설치 작업에만 쓰고 원복).

## 조치 후 규칙

```text
local   all   ovworks_ops   peer map=ovworks_ops     # 무인증 자동 점검 전용 (아래)
local   all   all           scram-sha-256            # 그 외 모든 로컬 접속: 비밀번호
host    all   all           127.0.0.1/32  scram-sha-256   # 루프백의 ident/trust/peer도 비밀번호로
host    all   all           ::1/128       scram-sha-256
local   replication all     scram-sha-256
```

```console
# su - postgres
$ psql engine
Password for user postgres:          ← postgres DB 계정 비밀번호 입력

# (root)
# psql engine                        ← root도 postgres 계정으로 접속
Password for user postgres:
# psql -U postgres engine
Password for user postgres:
```

세 방식 모두 **engine-setup에서 입력한 postgres 비밀번호**를 묻는다.

### root의 기본 DB 계정 (`/etc/profile.d/ovirt-engine-psql.sh`)

DB에는 `root` 계정이 없고 만들지도 않는다. libpq는 `-U`가 없으면 OS 계정 이름을 DB 계정으로 쓰므로,
그대로 두면 root의 `psql engine`은 존재하지 않는 `root` 계정으로 로그인을 시도한다. SCRAM은 계정 존재를
숨기기 위해 비밀번호부터 묻지만, 어떤 비밀번호도 통과하지 못한다. 그래서 root에 한해 기본 계정을
`postgres`로 지정하는 셸 설정을 설치한다.

```sh
if [ "$(id -u)" = "0" ] && [ -z "${PGUSER:-}" ]; then
    export PGUSER=postgres
fi
```

- 로그인 셸(`su -`, `sudo -i`, SSH)과 RHEL의 대화형 셸(`/etc/bashrc` 경유)에 적용된다. 설치 직전부터
  열려 있던 root 셸은 다시 로그인해야 적용된다.
- `PGUSER`나 `-U`를 명시하면 그것이 우선한다. 일반 사용자에게는 영향이 없다.
- 서비스(systemd)는 이 파일을 읽지 않는다. engine-setup·engine-backup·DB 스크립트는 계정을 `-U`로
  명시하므로 영향이 없다.
- `sudo psql engine`처럼 셸을 거치지 않으면 적용되지 않는다. 이때는 `psql -U postgres engine`을 쓴다.

- 비밀번호가 없거나 틀리면 `fe_sendauth: no password supplied` 또는 `password authentication failed`로 거부된다.
- 원격(비루프백) 규칙은 DBA 관할이므로 건드리지 않는다.
- `~postgres/.pgpass`에 비밀번호를 저장해 두면 psql이 묻지 않고 접속한다. 두지 않는다(도구가 있으면 경고).

### 자동 점검용 계정 `ovworks_ops`

보안 자체검증(`ov-works-security_audit.sh`)과 감사 저장소 용량 감시(`audit-storage-usage.py`)는 무인 실행이라
비밀번호를 입력할 수 없다. 이들만 쓰는 계정을 따로 둔다.

| 항목 | 값 |
|---|---|
| 권한 | `pg_monitor`(설정·통계 조회), `pg_hba_file_rules` 조회. 슈퍼유저·DB 생성·역할 생성·복제 권한 없음, 쓰기 불가 |
| 비밀번호 | 없음(`PASSWORD NULL`) — 비밀번호 규칙으로는 로그인할 수 없음 |
| 접속 경로 | 로컬 소켓 peer, `pg_ident.conf`의 `ovworks_ops` 맵에 있는 OS 계정 **root, ovirt**만 |
| OS `postgres` 계정으로 시도 | `Peer authentication failed` |

## 적용

### 신규 설치

engine-setup이 로컬 DB를 새로 만들면 마무리 단계에서 자동 적용한다.

1. `postgres` DB 계정 비밀번호 설정(설치 중 입력, 14자 이상)
2. `ovworks_ops` 역할 생성·권한 부여
3. 엔진용 루프백 규칙(scram) 반영 후 위 규칙으로 `pg_hba.conf`·`pg_ident.conf` 갱신, PostgreSQL 재시작
4. root 기본 DB 계정 설정 `/etc/profile.d/ovirt-engine-psql.sh` 설치

### 기존 설치

```console
# ovirt-engine-db-local-auth status     # 현재 로컬 규칙과 적용 여부
# ovirt-engine-db-local-auth enable     # 적용
# ovirt-engine-db-local-auth disable    # 해제(로컬 소켓 peer로 복귀, 비상용)
```

- `enable`은 `postgres` 계정에 비밀번호가 없으면 터미널에서 새 비밀번호를 받는다(14자 이상, 공백 없는 ASCII).
  - 비밀번호 대신 SCRAM 검증값을 표준입력으로 보내 설정하므로, 비밀번호가 프로세스 목록이나 서버 로그에 남지 않는다.
- 적용 뒤 두 가지를 직접 확인한다. 하나라도 실패하면 원래 파일로 되돌린다.
  - `postgres`가 비밀번호 없이 접속할 수 없어야 한다.
  - `ovworks_ops`는 접속할 수 있어야 한다.
- 원본은 `pg_hba.conf.<시각>.bak`, `pg_ident.conf.<시각>.bak`으로 남는다.
- `/etc/profile.d/ovirt-engine-psql.sh`도 설치한다(`disable` 시 삭제).
- 설정 반영은 `pg_ctl reload`라서 엔진이 동작 중이어도 서비스 재시작이 필요 없다.
- 데이터 디렉터리가 기본(`/var/lib/pgsql/data`)이 아니면 `--data-dir`(또는 `PGDATA`)로 지정한다.

## 기존 기능과의 관계

| 기능 | 동작 |
|---|---|
| 엔진·DWH·aaa-jdbc·백업(`engine-backup`) | TCP + 엔진 DB 계정 비밀번호(scram) — 영향 없음 |
| engine-setup 재실행·업그레이드, DWH/Keycloak 설치, `engine-backup --provision-db` | 슈퍼유저 작업 동안만 로컬 규칙을 일시 완화했다가 원복(기존 방식) |
| PostgreSQL 메이저 업그레이드(engine-setup) | 이전 클러스터 규칙을 업그레이드 동안만 완화, 원복 후 새 클러스터로 복사(`pg_ident.conf` 포함) |
| 보안 자체검증 | `ovworks_ops`로 조회. 미적용 설치는 이전처럼 `sudo -n -u postgres`(실패 시 WARN) |
| 감사 저장소 용량 감시 | `ovworks_ops`로 조회. 미적용 설치는 이전처럼 `runuser -u postgres` |
| `engine-vacuum -f`의 고아 스키마 정리 | 슈퍼유저 작업이라 `postgres` 비밀번호를 묻는다(대화형 실행) |

함께 고친 결함: engine-setup이 로컬 규칙을 일시 완화할 때 정규식이 줄의 마지막 단어를 인증 방식으로 보고
치환했다. 그래서 `scram-sha-256` 규칙이 `scram-sha-ident`로 바뀌어 PostgreSQL이 기동하지 못했다. 이제 필드를
해석해 인증 방식 칸만 바꾼다.

## 점검

`ov-works-security_audit.sh`의 **local database login** 항목은 동작 중인 서버의 `pg_hba_file_rules`를 읽는다.

| 결과 | 조건 |
|---|---|
| PASS | 로컬 소켓·루프백에 peer/ident/trust 규칙이 `ovworks_ops` 규칙 외에 없음 |
| WARN | 그런 규칙이 남아 있음(줄 번호 표시), 또는 `ovworks_ops`로 확인 불가 → `ovirt-engine-db-local-auth enable` 안내 |
| INFO | 이 서버에 로컬 PostgreSQL이 없음(원격 DB) |

실패(FAIL)로 두지 않는다. FAIL이면 적용 전 설치본의 엔진 기동이 차단되기 때문이다.

수동 확인:

```console
su - postgres -c 'psql -w engine -c "select 1"'     # → fe_sendauth: no password supplied
sudo -i psql engine                                  # → Password for user postgres:
psql -w -U ovworks_ops -d postgres -Atc 'select line_number, type, auth_method from pg_hba_file_rules'
```

## 원격 DB

DB가 다른 서버에 있으면 그 서버의 `pg_hba.conf`는 DBA가 관리한다. 같은 원칙으로 `local … peer`를
`scram-sha-256`으로 바꾸면 된다. 해당 서버에 이 패키지가 설치되어 있으면 `ovirt-engine-db-local-auth`를 쓸 수 있다.
