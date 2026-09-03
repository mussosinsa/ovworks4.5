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
5. `pg_restore`에 동일한 네 개 `--table` 필터를 적용하여 선택한 덤프에서 이벤트 데이터만
   SQL로 렌더링한다.
6. 하나의 PostgreSQL 트랜잭션에서 이벤트 테이블을 비우고 렌더링된 데이터를 가져온다.
7. `audit_log_seq`를 복구된 최대 이벤트 ID에 맞게 조정한 후 커밋한다.

```text
WebAdmin
  -> RestoreAuditLogBackupCommand (Engine 트랜잭션 밖에서 실행)
  -> sudo audit-log-backup.py restore <directory> <selected.dump>
  -> 현재 이벤트 테이블 선백업
  -> pg_restore --data-only --table <각 이벤트 테이블> <selected.dump>
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

* DB 접속 정보는 `/usr/share/ovirt-engine/bin/engine-prolog.sh`에서 읽는다. prolog는 선택적
  환경 변수를 참조하므로 `nounset`을 적용하지 않은 상태에서 먼저 불러온다.
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
