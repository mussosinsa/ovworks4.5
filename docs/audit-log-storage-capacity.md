# 감사기록 저장소 용량 관리

## 원칙

감사기록(`audit_log`, `event_*` 테이블)은 Engine DB에 저장된다. Engine DB의 물리적 저장 한도는
engine-config로 정하는 값이 아니라 **PostgreSQL 데이터 디렉터리가 위치한 파일시스템·LVM·가상디스크의
용량**으로 결정된다. 따라서 DB 자체에 작고 고정된 한도를 거는 대신 다음 네 가지로 운영한다.

1. 전용 파일시스템 용량 할당 (DB 데이터, 로그, 백업 볼륨 분리)
2. 70/80/90/95% 임계치 감시 (엔진 이벤트 + systemd timer syslog 경보)
3. 감사기록 보존정책 (`AuditLogAgingThreshold`) 과 백업·중앙 이관
4. 용량 확장 절차 (LVM·스토리지 증설 우선)

## 감시 구성

감사기록 저장소는 두 경로로 감시한다. 둘은 같은 임계치 판단 규칙을 쓴다.

| 감시 주체 | 실행 방식 | 감시 대상 | 경보 |
|---|---|---|---|
| Engine (`AuditLogCapacityMonitor`) | 엔진 내부, `ENGINE_AUDIT_LOG_CAPACITY_CHECK_INTERVAL_SECONDS` 주기(기본 60초) | DB 데이터 파일시스템, WAL, Engine DB 크기, 이벤트 테이블 크기, 로그 파일시스템, 엔진 로그 디렉터리, 백업 저장소 | 이벤트·알람 목록, 이벤트 알림(메일 등) |
| `ovirt-engine-audit-storage-watch.timer` | root, 10분 주기, **엔진이 멈춰 있어도 동작** | DB 데이터 파일시스템, 로그 파일시스템, 백업 저장소, DB 공간 관리 상태 | syslog `authpriv` (SIEM 전송 대상) |

엔진은 ovirt 계정으로 실행되어 postgres 전용 디렉터리(`/var/lib/pgsql/data`)와 서버 설정을 읽을 수 없다.
그래서 파일시스템 측정은 root 헬퍼 `/usr/share/ovirt-engine/bin/audit-storage-usage.py`가 맡는다.
엔진은 `/etc/sudoers.d/ovirt-backup`에 등록된 `audit-storage-usage.py usage *`만 sudo로 실행한다.

```text
AuditLogCapacityMonitor (ovirt)
  -> sudo -n audit-storage-usage.py usage --log-dir ... [--data-dir] [--backup-dir] [--selected-dir]
       -> runuser -u postgres -- psql -c "SHOW data_directory"   (로컬 DB일 때)
       -> statvfs(PGDATA), pg_wal 크기, statvfs(/var/log), statvfs(백업 경로)
       -> autovacuum, 장기 트랜잭션, 복제 슬롯, max_wal_size 확인
       <- JSON
  -> AuditStorageDao: pg_database_size(), pg_total_relation_size(audit_log, event_*)
  -> 단계 판정 -> 이벤트
```

### 설정값 (engine-config)

| 키 | 기본값 | 설명 |
|---|---|---|
| `ENGINE_AUDIT_STORAGE_THRESHOLDS` | `70,80,90,95` | 주의,경계,심각,위기 백분율. 1~99, 오름차순. 100%는 항상 포화. 잘못된 값이면 기본값으로 감시한다. 재시작 불필요 |
| `ENGINE_AUDIT_DB_DATA_DIR` | (빈 값) | PostgreSQL 데이터 디렉터리. 비우면 로컬 DB에서 자동 탐지. `PG_VERSION`이 있는 디렉터리만 허용 |
| `ENGINE_AUDIT_BACKUP_DIR` | (빈 값) | 상시 감시할 백업 저장소 경로. 비우면 화면에서 입력한 저장 위치만 측정 |
| `ENGINE_AUDIT_LOG_DIR` | `/var/log/ovirt-engine` | 엔진 로그 디렉터리. 이 경로의 파일시스템이 "로그 파일시스템"으로 측정된다 |
| `ENGINE_AUDIT_LOG_MAX_SIZE_MB` | `1024` | 엔진 로그 디렉터리의 관리 한도(파일 크기 합계). 이 한도에도 같은 임계치가 적용된다 |
| `ENGINE_AUDIT_LOG_CAPACITY_CHECK_INTERVAL_SECONDS` | `60` | 엔진 감시 주기. 변경 시 재시작 필요 |
| `ENGINE_AUDIT_EVENT_TABLES_MAX_SIZE_MB` | `10240` | 이벤트 테이블(`audit_log`, `event_map`, `event_notification_hist`, `event_subscriber`) 실사용량 합계의 한도. 같은 임계치로 단계 판정·이벤트를 발생시킨다. `0`이면 한도 없음(참고 표시만) |
| `ENGINE_AUDIT_CAPACITY_PURGE_ENABLED` | `true` | 이벤트 테이블이 한도(100%)에 도달하면 가장 오래된 감사기록부터 보관 후 삭제 |
| `ENGINE_AUDIT_CAPACITY_PURGE_MIN_RETENTION_DAYS` | `30` | 용량 초과 정리에서도 절대 삭제하지 않는 최근 기간(일) |
| `ENGINE_AUDIT_CAPACITY_PURGE_TARGET_PERCENT` | `80` | 용량 초과 정리가 낮추는 목표 사용률(한도 대비 %) |
| `ENGINE_AUDIT_PURGE_ARCHIVE_DIR` | `/var/lib/ovirt-engine-backup/audit-log-purged` | 삭제 전 감사기록 보관 위치 (없으면 생성, 0750) |
| `AuditLogAgingThreshold` | `90` (이전 30) | 감사기록 보존기간(일). 이보다 오래된 기록은 매일 보관 후 삭제. 기존 설치에서 값이 30(이전 기본값)이면 업그레이드 시 90으로 바뀌고, 직접 바꾼 값은 유지 |

```bash
engine-config --set ENGINE_AUDIT_STORAGE_THRESHOLDS=70,80,90,95 --cver=general
engine-config --set ENGINE_AUDIT_BACKUP_DIR=/backup/audit --cver=general
```

### systemd timer 설정

`engine-setup`이 `ovirt-engine-audit-storage-watch.timer`를 활성화한다. 끄려면 응답 파일에
`OVESETUP_AUDIT_STORAGE_WATCH/enableTimer=bool:False`를 지정하거나 `systemctl disable --now`로 끈다.
timer는 엔진 설정 DB를 읽지 않으므로 필요하면 `/etc/ovirt-engine/audit-storage-watch.conf`에 따로 지정한다.

```bash
# /etc/ovirt-engine/audit-storage-watch.conf
AUDIT_STORAGE_THRESHOLDS=70,80,90,95
AUDIT_STORAGE_BACKUP_DIR=/backup/audit
#AUDIT_STORAGE_DATA_DIR=/var/lib/pgsql/data
#AUDIT_STORAGE_LOG_DIR=/var/log
```

```bash
systemctl status ovirt-engine-audit-storage-watch.timer
systemctl start ovirt-engine-audit-storage-watch.service   # 즉시 1회 실행
journalctl -t ovirt-audit-storage --since today
/usr/share/ovirt-engine/bin/audit-storage-usage.py usage --log-dir /var/log | python3 -m json.tool
```

timer는 마지막 단계를 `/var/lib/ovirt-engine/audit-storage-watch.json`에 기록해 두고, 엔진과 같은 규칙으로
syslog에 남긴다.

| 단계 | syslog 우선순위 | 기록 시점 |
|---|---|---|
| 주의 | `authpriv.notice` | 단계에 처음 도달했을 때 |
| 경계 | `authpriv.warning` | 단계에 처음 도달했을 때 |
| 심각 | `authpriv.crit` | 매 실행(10분) |
| 위기·포화 | `authpriv.alert` | 매 실행(10분) |
| 정상 복귀 | `authpriv.notice` | 이상 단계에서 내려왔을 때 |
| 측정 실패 | `authpriv.err` | 매 실행 |
| DB 공간 관리 경고 | `authpriv.warning` | 매 실행 |

rsyslog에서 `authpriv.*`를 SIEM으로 전달하면 SIEM·ITSM 경보로 연결된다.

## 임계치와 대응

사용률은 `df`와 같이 `사용량 / (사용량 + 일반 사용자 가용량)`으로 계산한다. inode 사용률이 더 높으면
inode 기준으로 판정한다.

| 단계 | 사용률(기본) | 엔진 이벤트 | 반복 | 자동 조치 | 운영자 조치 |
|---|---|---|---|---|---|
| 정상 | 0~69% | `AUDIT_LOG_CAPACITY_RECOVERED`(복귀 시) | - | 증가량 수집 | 정기 검토 |
| 주의 | 70~79% | `AUDIT_STORAGE_USAGE_NOTICE` (경고) | 도달 시 1회 | 증가율·예상 포화시각 계산 | 로그 이관·백업 상태 확인 |
| 경계 | 80~89% | `AUDIT_STORAGE_USAGE_WARNING` (경고) | 도달 시 1회 | 대용량 테이블·WAL 분석 정보 표출 | 증설 요청, 보존기간·정리 작업 확인 |
| 심각 | 90~94% | `AUDIT_STORAGE_USAGE_HIGH` (알람) | 1시간마다 | **감사기록 복구 차단** | 즉시 증설 또는 점검 창 확보 |
| 위기 | 95~99% | `AUDIT_LOG_CAPACITY_WARNING` (알람) | 1시간마다 | 복구 차단, 위기 볼륨으로의 백업 차단 | LVM/스토리지 긴급 증설, 장애 대응 |
| 포화 | 100% | `AUDIT_LOG_CAPACITY_EXCEEDED` (알람) | 1시간마다 | 동일. 이벤트 테이블이면 오래된 감사기록 보관 후 삭제(최근 30일 제외) | DB 보호·공간 확보·복구 절차 |

- 위기·포화 단계는 기존 이벤트(`AUDIT_LOG_CAPACITY_WARNING`, `AUDIT_LOG_CAPACITY_EXCEEDED`)를 그대로 쓰므로
  기존 이벤트 알림 구독이 계속 동작한다. 메시지에는 대상(`${Target}`)과 경로가 함께 표시된다.
- 이벤트는 대상별로 따로 억제(flood control)된다. DB 파일시스템 경보가 로그 파일시스템 경보를 가리지 않는다.
- 측정할 수 없는 대상은 `AUDIT_STORAGE_MEASUREMENT_FAILED`로 1시간마다 알린다. 단, DB가 원격 서버에 있어
  이 서버에서 측정할 수 없는 경우는 실패로 보지 않는다. 이때는 **DB 서버에서** 헬퍼의 `watch`를 timer로 실행한다.
- autovacuum·track_counts 꺼짐, 1시간 이상 열린 트랜잭션, 비활성 복제 슬롯 또는 `max_wal_size`보다 많은 WAL을
  붙잡은 슬롯, `pg_wal`이 `max_wal_size`의 2배 초과는 `AUDIT_STORAGE_DB_MAINTENANCE_WARNING`으로 알린다.
- 증가율과 예상 포화시각은 최근 24시간(엔진 재시작 후 10분 이상 관찰된 경우)의 측정값으로 계산하여
  화면 비고란과 이벤트 메시지에 표시한다.

## WebAdmin 화면

`관리 > 감사기록보호`의 **감사기록 저장소 용량** 섹션은 다음을 보여 준다.

- 전체 단계(가장 심각한 대상 기준)와 DB 데이터 파일시스템 사용률 막대
- 대상별 상태·사용률·사용량/용량·경로·비고(마운트, inode, 증가율, 예상 포화)
- 임계치, 측정 시각, 감시 주기, DB 공간 관리 경고

화면은 열려 있는 동안 1분마다 엔진이 마지막으로 측정한 값(`GetAuditLogCapacityStatus` 질의의
`storageRows`)을 다시 읽는다. 엔진 시작 직후처럼 아직 전체 측정값이 없으면 화면이 한 번 직접 측정을 요청한다.
`용량 새로 고침`을 누르면 즉시 다시 측정한다. 이때 저장 위치 입력란의 경로도 "입력한 저장 위치"로 함께
측정한다. 이 경로는 입력값에 따라 달라지므로 이벤트는 발생시키지 않는다.

### 백업·복구 가드

| 작업 | 차단 조건 | 허용하되 주의 표시 |
|---|---|---|
| 전체 로그 백업 | 저장 위치 파일시스템이 위기(95%) 이상, 또는 저장 위치가 DB와 같은 파일시스템이고 DB가 심각(90%) 이상 | 저장 위치가 DB와 같은 파일시스템, 저장 위치가 심각 이상, 저장 위치를 측정하지 못함 |
| 복구 (현재 이벤트 백업 후 복구) | DB 데이터 파일시스템 또는 저장 위치 파일시스템이 심각(90%) 이상 | - |

복구는 현재 이벤트 전체를 저장 위치에 먼저 덤프(`pre-restore-current-events-*.dump`)한 뒤 DB에 다시 기록하므로
두 곳 모두 여유가 필요하다. 측정할 수 없는 대상(원격 DB 등)은 차단 근거로 쓰지 않는다.

복구는 트랜잭션 안에서 이벤트 테이블을 `TRUNCATE`한 뒤 다시 적재한다. 복구 직전 선백업이 보존되고 실패 시
커밋되지 않는 **통제된 예외**이며, 공간 확보 목적으로 감사기록을 `TRUNCATE`/`DELETE`하는 것은 금지한다.

## 저장 위치와 용량 구조

### 1. 실제 DB 데이터 위치 확인

```bash
PGDATA="$(sudo -u postgres psql -At -d postgres -c 'SHOW data_directory;')"
echo "$PGDATA"
df -hT "$PGDATA"
df -ih "$PGDATA"
```

이 디렉터리가 속한 파일시스템의 여유공간이 Engine DB의 실질 한도다. 함께 확인할 대상은 다음과 같다.

| 대상 | 확인 이유 |
|---|---|
| PostgreSQL `data_directory` | 테이블, 인덱스, WAL, 시스템 카탈로그 저장 |
| `pg_wal` | 트랜잭션 로그 증가 시 급격한 공간 부족 가능 |
| PostgreSQL 임시파일 경로 | 대형 정렬·백업·VACUUM 작업 시 일시적 사용 |
| `/var/log` | Engine 로그와 PostgreSQL 로그 증가 |
| 백업 저장 경로 | engine-backup 파일, 이벤트 덤프 증가 |
| DWH DB 경로 | `ovirt_engine_history`가 별도로 증가 가능 |

### 2. DB·테이블·WAL 용량 확인

```bash
# DB별 크기
sudo -u postgres psql -d postgres -c "
SELECT datname, pg_size_pretty(pg_database_size(datname)) AS db_size
FROM pg_database ORDER BY pg_database_size(datname) DESC;"

# 상위 대용량 테이블
sudo -u postgres psql -d engine -c "
SELECT n.nspname AS schema_name, c.relname AS table_name,
       pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size,
       pg_size_pretty(pg_relation_size(c.oid)) AS table_size,
       pg_size_pretty(pg_total_relation_size(c.oid) - pg_relation_size(c.oid)) AS index_toast_size
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'm')
ORDER BY pg_total_relation_size(c.oid) DESC LIMIT 30;"

# WAL
sudo -u postgres psql -d engine -c "SHOW wal_level;" -c "SHOW max_wal_size;" -c "SHOW min_wal_size;"
du -sh "${PGDATA}/pg_wal"
```

Engine DB 이름은 `/etc/ovirt-engine/engine.conf.d/10-setup-database.conf`의 `ENGINE_DB_DATABASE`로 확인한다
(기본 `engine`).

## 볼륨 분리 권장 구성

PostgreSQL 데이터와 백업 경로가 같은 파일시스템에 있으면 백업 파일 증가만으로 Engine DB가 멈출 수 있다.

```text
/var/lib/pgsql : PostgreSQL 데이터 전용 LV
/var/log       : Engine·PostgreSQL 로그 전용 LV
/backup        : Engine DB·이벤트 덤프 백업 전용 LV 또는 NFS/Object Storage
```

예를 들어 Engine DB에 500 GB만 허용하려면 `/var/lib/pgsql`이 포함된 LV를 500 GB로 설계하고, VG에 최소
20~30%의 증설 여유를 남겨 둔다. 백업 저장소는 `ENGINE_AUDIT_BACKUP_DIR`과 timer의
`AUDIT_STORAGE_BACKUP_DIR`에 지정해 상시 감시한다.

### LVM 증설

장치명은 반드시 확인한 뒤 적용한다. **운영 서버에서 장치명을 추정해 실행하지 않는다.**

```bash
lsblk -f
vgs
lvs -a -o +devices
df -hT "$PGDATA"

# 예시: PostgreSQL 파일시스템이 /dev/mapper/vg_pg-lv_pg 에 있는 경우
lvextend -L +100G -r /dev/mapper/vg_pg-lv_pg
```

`-r`은 파일시스템 확장을 함께 수행한다. 파일시스템 종류(xfs/ext4)와 운영 정책에 따라 사전 검증한다.
증설 후 `용량 새로 고침` 또는 `systemctl start ovirt-engine-audit-storage-watch.service`로 정상 복귀를 확인한다.

## 단계별 대응 절차

### 주의·경계 (70~89%): 예방과 원인 분석

1. DB 데이터, `pg_wal`, `/var/log`, 백업 경로 사용률과 화면의 증가율·예상 포화시각을 확인한다.
2. `audit_log`, `event_notification_hist`, DWH DB의 증가 추세를 확인한다.
3. 중앙 Syslog/SIEM 전송과 장기 보관 상태, 감사기록 백업(전체 로그 백업) 성공 여부를 확인한다.
4. `AuditLogAgingThreshold`(기본 90일)가 기관 승인 보존정책에 맞는지 확인한다.
5. autovacuum이 켜져 있는지 확인한다.

```bash
sudo -u postgres psql -d engine -c "SHOW autovacuum;" -c "SHOW track_counts;"

# Dead tuple
sudo -u postgres psql -d engine -c "
SELECT schemaname, relname AS table_name, n_live_tup, n_dead_tup,
       last_vacuum, last_autovacuum, last_analyze, last_autoanalyze
FROM pg_stat_user_tables ORDER BY n_dead_tup DESC LIMIT 30;"

# 장기 트랜잭션
sudo -u postgres psql -d engine -c "
SELECT pid, usename, application_name, client_addr, state,
       now() - xact_start AS transaction_age, left(query, 200) AS query
FROM pg_stat_activity WHERE xact_start IS NOT NULL ORDER BY xact_start;"

# 복제 슬롯
sudo -u postgres psql -d engine -c "
SELECT slot_name, slot_type, active, restart_lsn,
       pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) AS retained_wal
FROM pg_replication_slots;"

engine-config --get AuditLogAgingThreshold --cver=general
```

보존기간 조정은 중앙 이관·백업이 검증된 뒤 변경관리 승인을 거쳐 수행한다. DB에 직접 `DELETE`를 실행하지 않는다.

```bash
engine-config --set AuditLogAgingThreshold=90 --cver=general
systemctl restart ovirt-engine
```

`AuditLogCleanupManager`는 매일 `AuditLogCleanupTime`(기본 03:35:35)에 보존기간이 지난 감사기록을
보관 파일로 남긴 뒤 삭제한다(아래 「감사기록 정리」). 보존기간 안에 **전체 로그 백업**과 중앙 이관이
이루어지도록 백업 주기를 정한다.

### 심각 (90~94%): 공간 확보

우선순위는 다음과 같다. 이 단계부터 감사기록 복구는 차단된다.

1. 감사기록 백업과 중앙 로그 이관 성공 여부를 확인한다.
2. LVM·SAN·가상디스크·클라우드 볼륨을 확장한다.
3. Engine·PostgreSQL 로그를 logrotate 정책에 따라 회전·압축·이관한다.
4. 보존기간이 지나고 이관이 검증된 감사기록은 표준 정리 정책(`AuditLogCleanupManager`)으로 삭제되게 한다.
5. 유지보수 창에 일반 VACUUM(ANALYZE)을 실행하여 DB 내부 재사용 공간을 정리한다.

```bash
sudo -u postgres psql -d engine -c "VACUUM (ANALYZE, VERBOSE) audit_log;"

# 또는 oVirt 제공 도구 (옵션: -a analyze, -A analyze only, -f full, -t 테이블, -v verbose)
/usr/share/ovirt-engine/bin/engine-vacuum.sh -h
/usr/share/ovirt-engine/bin/engine-vacuum.sh -a -t audit_log -v
```

일반 VACUUM은 삭제된 행의 공간을 DB 내부에서 재사용 가능하게 할 뿐 OS 파일시스템으로 즉시 반환하지 않는다.
OS로 공간을 돌려주는 `VACUUM FULL`(`engine-vacuum.sh -f`)은 테이블을 다시 쓰며 강한 잠금과 테이블 크기만큼의
추가 공간이 필요하므로 **점검 시간에만**, 충분한 여유가 확보된 뒤 수행한다.

### 위기·포화 (95% 이상): 비상 대응

1. Engine 서비스와 PostgreSQL의 현재 상태를 기록한다.
   ```bash
   systemctl status ovirt-engine postgresql
   df -hT "$PGDATA" /var/log /backup
   journalctl -t ovirt-audit-storage --since "-2h"
   ```
2. DB·WAL·로그·백업 경로 중 어느 볼륨이 포화됐는지 확인한다.
3. 가능하면 즉시 LVM 또는 스토리지 볼륨을 확장한다.
4. 공간 확장 후 Engine, PostgreSQL, VM/Host 관리 기능과 감사기록 생성 여부를 점검한다
   (화면에서 정상 복귀 이벤트 `AUDIT_LOG_CAPACITY_RECOVERED` 확인).
5. 증가 원인, 조치, 영향, 재발 방지 계획을 변경관리·감사기록에 남긴다.

### 금지 사항

- 디스크 확보를 위해 DB 파일을 OS에서 직접 삭제하지 않는다.
- `pg_wal` 파일을 수동 삭제하지 않는다. DB 손상 및 복구 불능 위험이 있다.
- 감사기록을 SQL로 직접 `TRUNCATE`하거나 대량 `DELETE`하지 않는다.
- `VACUUM FULL`을 즉시 응급처치로 실행하지 않는다. 추가 작업공간과 장시간 잠금이 필요하여 포화를 악화시킬 수 있다.
- 95% 이상에서는 감사로그·DB 데이터를 삭제하기보다 저장공간 증설을 우선한다. 로그·WAL 급증, 백업 중간파일,
  VACUUM 작업을 고려하여 평소 최소 10~20%의 유휴공간을 유지한다.

## 감사기록 정리 (보관 후 삭제)

감사기록(`audit_log`)은 두 경우에만 삭제된다. 어느 경우든 **보관 파일을 먼저 만들고**, 보관에 실패하면
아무것도 지우지 않으며, 삭제 사실은 그 자체로 이벤트에 기록된다.

| 구분 | 시점 | 삭제 대상 | 이벤트 |
|---|---|---|---|
| 보존기간 정리 | 매일 `AuditLogCleanupTime` | `log_time`이 `AuditLogAgingThreshold`(90일)보다 오래된 기록 | `AUDIT_LOG_RECORDS_PURGED` / `_PURGE_FAILED` |
| 용량 초과 정리 | 엔진 정기 점검에서 이벤트 테이블이 포화(100%)일 때, 1시간에 최대 1회 | 목표 사용률(80%)까지 내려가도록 가장 오래된 기록부터. 단, 최근 30일은 제외 | `AUDIT_LOG_RECORDS_PURGED` / `_PURGE_FAILED`, 지울 수 있는 기록이 없으면 `AUDIT_LOG_CAPACITY_PURGE_BLOCKED`(알람, 1시간마다) |

### 동작

1. 엔진이 삭제 기준 시각을 정한다. 용량 초과 정리는 `초과량 ÷ audit_log 한 건의 평균 크기`만큼의 가장 오래된
   기록을 대상으로 하되, 기준 시각이 `현재 - 최소 보존일수`보다 최근이면 그 시각으로 제한한다.
2. root 헬퍼 `audit-log-backup.py purge <보관 위치> <기준 시각>`이 한 트랜잭션(REPEATABLE READ) 안에서
   대상 기록을 CSV로 복사(`\copy`)하고 같은 기록을 삭제한다. 복사와 삭제는 같은 스냅샷을 보므로 보관된 기록과
   삭제된 기록이 정확히 일치하며, 어느 단계든 실패하면 롤백되어 아무것도 지워지지 않는다.
3. 커밋 후 보관 파일을 `purged-audit-log-<시각>.csv.gz`(0640)로 압축하고, `VACUUM (ANALYZE) audit_log`로
   삭제된 공간을 재사용 가능하게 하고 통계를 갱신한다.

### 한도의 기준: 실사용량

PostgreSQL 테이블은 행을 지워도 파일 크기가 줄지 않는다(지운 공간은 새 행이 재사용한다). 물리 크기로 한도를
재면 정리 후에도 계속 초과로 보여 정리가 반복되므로, 한도는 **실사용량**으로 판단한다.

```text
실사용량 ≈ 살아 있는 행 수(n_live_tup) × (컬럼 평균 폭 합계(pg_stats) + 28바이트) × (전체 크기 ÷ 테이블 본체 크기)
```

아직 통계가 없는 테이블은 물리 크기로 계산한다. 화면의 "이벤트 테이블 (한도)" 행 비고에 테이블별 실사용량과
물리 크기를 함께 표시한다. 디스크(OS) 공간은 행 삭제로 돌아오지 않으므로, 파일시스템 사용률은 앞의 단계별
대응(증설, 점검 시간의 `VACUUM FULL`)으로 관리한다.

### 보관 파일에서 되살리기

보관 파일은 `audit_log`의 모든 컬럼을 헤더와 함께 담은 CSV다. 필요하면 다음과 같이 되살린다.

```bash
gunzip -c /var/lib/ovirt-engine-backup/audit-log-purged/purged-audit-log-<시각>.csv.gz > /tmp/restore.csv
sudo -u postgres psql -d engine -c "\copy public.audit_log FROM '/tmp/restore.csv' WITH (FORMAT csv, HEADER true)"
```

되살린 기록도 보존기간이 지났으면 다음 일일 정리에서 다시 보관·삭제된다. 보관 위치의 파일은 자동으로 지우지
않으므로 중앙 저장소로 옮기거나 보존 정책에 따라 관리한다.

## 관련 파일

| 파일 | 역할 |
|---|---|
| `backend/.../bll/AuditLogCapacityMonitor.java` | 엔진 감시, 단계 판정, 이벤트, 증가율 |
| `backend/.../bll/AuditStorageThresholds.java` | 임계치 해석과 단계 |
| `backend/.../bll/AuditStorageHelper.java` | root 헬퍼 호출과 결과 해석 |
| `backend/.../bll/AuditStorageSnapshot.java` | 측정 결과, 백업·복구 가드, 화면 전달 형식 |
| `backend/.../bll/GetAuditLogStorageStatusCommand.java` | 화면의 `용량 새로 고침` (즉시 전체 측정) |
| `backend/.../bll/GetAuditLogCapacityStatusQuery.java` | 화면의 1분 주기 갱신 (마지막 측정값 읽기) |
| `backend/.../dao/AuditStorageDaoImpl.java` | Engine DB·이벤트 테이블 크기(실사용량 추정), 정리 기준 시각 |
| `backend/.../bll/AuditLogPurger.java` | 보존기간·용량 초과 정리 계획, 헬퍼 호출, 정리 이벤트 |
| `backend/.../bll/AuditLogCleanupManager.java` | 매일 보존기간 정리 실행 |
| `packaging/bin/audit-log-backup.py` (`purge`) | 보관 후 삭제 (한 트랜잭션) |
| `packaging/bin/audit-storage-usage.py` | root 헬퍼 (`usage`, `watch`) |
| `packaging/services/ovirt-engine/ovirt-engine-audit-storage-watch.{service,timer}` | 엔진과 독립된 10분 주기 감시 |
| `packaging/setup/plugins/.../system/audit_storage_watch.py` | engine-setup 시 timer 활성화 |
