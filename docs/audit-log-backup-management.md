# 감사기록 백업 관리

## 백업 범위

`감사기록 보호`의 **전체 로그 백업**은 Engine DB 전체를 백업하지 않는다. 다음 이벤트
관련 테이블의 데이터만 PostgreSQL custom-format 덤프로 저장한다.

* `public.audit_log`
* `public.event_map`
* `public.event_notification_hist`
* `public.event_subscriber`

`pg_dump --format=custom --compress=3 --data-only`를 사용하므로 출력 파일은 자체 압축된
`*.dump` 파일이다. VM, 호스트, 네트워크, 스토리지 등 다른 Engine DB 테이블과 파일 로그는
포함되지 않는다.

## 백업

1. `관리 > 감사기록보호`에서 저장 위치를 입력한다.
2. `전체 로그 백업`을 선택한다.
3. helper가 Engine DB 접속 설정을 불러온다.
4. 고정된 네 이벤트 테이블만 `pg_dump`의 `--table` 옵션으로 선택한다.
5. 덤프가 완전히 생성되면 권한을 `0640`으로 변경하고 최종 `*.dump` 이름으로 원자적으로
   이동한다.

```text
WebAdmin
  -> FullLogBackupCommand (Engine 트랜잭션 밖에서 실행)
  -> sudo audit-log-backup.py backup <directory>
  -> pg_dump --format=custom --compress=3 --data-only --no-password
       --table public.audit_log
       --table public.event_map
       --table public.event_notification_hist
       --table public.event_subscriber
  -> <timestamp>.dump
```

백업 명령은 `@NonTransactiveCommandAttribute`를 사용하므로 대량의 감사기록 덤프가 5분을
초과하더라도 Engine Transaction Reaper가 명령을 롤백하지 않는다.

## 복구

1. `감사기록 조회` 버튼은 저장 위치의 `*.dump` 파일만 표시한다.
2. 사용자가 복구할 덤프를 선택하고 `복구` 버튼을 누른다.
3. 서버는 선택된 파일이 저장 위치 바로 아래의 실제 파일인지 검사하고 심볼릭 링크와 잘못된
   확장자를 거부한다.
4. 현재 이벤트 테이블을 `pre-restore-current-events-*.dump`로 먼저 백업한다.
5. `pg_restore`에 `--schema public`과 table 이름별 `--table` 필터를 적용하여 선택한
   덤프에서 이벤트 데이터만 SQL로 렌더링한다. `pg_dump`와 달리 `pg_restore --table`은
   schema로 제한하지 않으므로 `public.audit_log`같은 값 대신 `--schema public --table
   audit_log`처럼 전달해야 archive의 `TABLE DATA` 항목이 선택된다.
   `--strict-names`로 요청한 schema/table 패턴이 archive에서 하나도 매칭되지 않으면
   즉시 명확한 오류를 반환한다.
6. 하나의 PostgreSQL 트랜잭션에서 이벤트 테이블을 비우고 렌더링된 데이터를 가져온다.
7. `audit_log_seq`를 복구된 최대 이벤트 ID에 맞게 조정한 후 커밋한다.

`pg_restore`가 생성한 SQL은 `search_path`를 비우므로, 뒤에 실행하는 sequence 조정은
`public.audit_log_seq`처럼 schema를 명시한다. 이를 생략하면 현재 이벤트 선백업은
성공하지만 복구 트랜잭션은 `relation "audit_log_seq" does not exist`로 롤백된다.

```text
WebAdmin
  -> RestoreAuditLogBackupCommand (Engine 트랜잭션 밖에서 실행)
  -> sudo audit-log-backup.py restore <directory> <selected.dump>
  -> 현재 이벤트 테이블 선백업
  -> pg_restore --data-only --schema public --table <각 이벤트 테이블> <selected.dump>
  -> BEGIN
  -> 이벤트 테이블 TRUNCATE
  -> 선택된 덤프의 이벤트 데이터 적용
  -> audit_log_seq 조정
  -> COMMIT
```

`pg_restore`에는 고정된 이벤트 테이블 필터를 다시 전달하므로 선택한 덤프에 다른 DB 객체가
들어 있어도 복구 대상이 되지 않는다. SQL 적용에 실패하면 `ON_ERROR_STOP`에 의해 트랜잭션이
커밋되지 않으며, 복구 직전에 생성한 선백업 덤프는 보존된다.

## DB 연결과 입력 보호

* DB 접속 정보는 Python `ConfigFile`로 Engine 기본 설정과 `engine.conf.d`를 읽는다.
  암호화된 `OVENC001`/`OVVLT001` 설정 파일은 이 reader가 투명하게 복호화한다.
* 비밀번호는 `PGPASSWORD`로 자식 PostgreSQL 프로세스에만 전달한다.
* `--no-password`로 인증 실패 시 비밀번호 프롬프트를 기다리며 멈추는 상태를 방지한다.
* DB 잠금은 30초, 전체 PostgreSQL 자식 프로세스는 30분 후 실패 처리한다.
* 사용자 입력 경로는 고정된 Bash 코드에 보간하지 않고 프로세스 위치 인수로 전달한다.
* 실행 프로그램과 대상 테이블 목록은 코드에 고정되어 있다.
* 덤프 파일명은 영문자, 숫자, `.`, `_`, `-` 및 `.dump` 확장자만 허용한다.
* 저장 디렉터리 및 선택 덤프의 심볼릭 링크를 거부한다.
* 현재 이벤트 덤프가 성공해야 선택 덤프의 복구를 시작한다.

Engine 전체 재해 복구가 필요한 경우에는 `감사기록 보호`가 아니라 `가용성 확보` 기능의
`engine-backup --scope=all`을 사용해야 한다.

## 실패 진단

`AUDIT_LOG_BACKUP_FAILED`는 요약 감사 이벤트이므로 해당 한 줄만으로는 원인을 판별할 수 없다.
같은 correlation ID의 helper 종료 코드와 표준 출력은 Engine 로그에 기록되므로 먼저 다음과
같이 확인한다.

```bash
journalctl -u ovirt-engine --since "10 minutes ago" | grep -F '<correlation-id>'
# 파일 로그를 사용하는 설치의 경우
grep -F '<correlation-id>' /var/log/ovirt-engine/engine.log
```

관리 서버에서 WebAdmin과 동일한 helper를 직접 실행하면 실패 사유를 즉시 확인할 수
있다. `<directory>`는 WebAdmin에 입력한 **서버의 절대 경로**여야 한다.

```bash
sudo -u ovirt sudo -n /usr/share/ovirt-engine/bin/audit-log-backup.py backup <directory>
```

주요 원인과 조치는 다음과 같다.

* `sudo: a password is required` 또는 `not allowed`: `/etc/sudoers.d/ovirt-backup`이 설치되었는지
  확인하고 `visudo -cf /etc/sudoers.d/ovirt-backup`으로 구문을 검증한 뒤 Engine 설정을 다시
  적용한다.
* `No such file or directory` 또는 `Permission denied`: helper가 설치되고 실행 가능한지,
  저장 디렉터리가 실제 디렉터리이며 심볼릭 링크가 아닌지, 상위 경로에 탐색 권한이
  있는지 확인한다. 필요하면 관리자가 먼저 저장 디렉터리를 생성한다.
* `pg_dump` 연결/인증 오류: `/etc/ovirt-engine/engine.conf.d/10-setup-database.conf`의 DB
  설정과 암호화 키/Vault 접근 상태, PostgreSQL 상태, 호스트/포트 접속성을 확인한다.
* `lock timeout`: 이벤트 테이블에 장시간 배타 잠금이 있는지 확인하고 잠금이 해제된 뒤
  재시도한다.

직접 실행이 성공하면 생성된 `*.dump`의 크기와 권한(`0640`)을 확인하고 WebAdmin에서
다시 시도한다.
