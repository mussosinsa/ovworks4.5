# 감사기록 백업 관리

## 개요

`감사기록 보호`의 **전체 로그 백업**은 Engine DB 전체나 파일 로그 디렉터리를 백업하지
않는다. 이벤트와 알림에 관계된 다음 테이블만 CSV로 추출하여 하나의 `tar.gz` 파일로
저장한다.

| CSV 파일 | 원본 테이블 | 내용 |
|---|---|---|
| `audit_log.csv` | `public.audit_log` | WebAdmin 이벤트 및 감사기록 |
| `event_map.csv` | `public.event_map` | 이벤트 상·하향 매핑 |
| `event_notification_hist.csv` | `public.event_notification_hist` | 이벤트 알림 전송 이력 |
| `event_subscriber.csv` | `public.event_subscriber` | 이벤트 구독 설정 |

CSV에는 헤더가 포함된다. PostgreSQL의 CSV 인코딩과 escaping은 `psql`의 `\copy ... WITH
(FORMAT CSV, HEADER true)`가 처리한다.

## 화면 작업

### 백업

1. `관리 > 감사기록보호`를 연다.
2. Engine 호스트에서 사용할 백업 저장 디렉터리를 입력한다.
3. `전체 로그 백업`을 선택한다.
4. 선택한 디렉터리에 타임스탬프를 포함한 `*.tar.gz` 파일이 생성된다.

백업 파일은 임시 이름으로 모두 생성된 후 최종 이름으로 원자적으로 이동된다. 최종 파일
권한은 `0640`이며, 일부 테이블만 추출된 불완전한 파일은 정상 백업으로 남지 않는다.

### 복구

1. `감사기록 조회`로 저장 디렉터리의 백업 목록을 갱신한다.
2. 복구할 `tar.gz` 파일을 선택한다.
3. `복구 (현재 이벤트 백업 후 복구)`를 선택한다.
4. 서버가 아카이브의 파일명, 경로 및 네 개 CSV의 존재 여부를 검증한다.
5. 현재 이벤트 테이블을 `pre-restore-current-events-*.tar.gz`로 선백업한다.
6. 하나의 DB 트랜잭션 안에서 이벤트 테이블을 비우고 CSV를 가져온다.
7. `audit_log_seq`를 복구된 최대 `audit_log_id` 다음에 사용할 수 있도록 조정한다.

CSV 가져오기 또는 시퀀스 조정이 실패하면 트랜잭션이 커밋되지 않는다. 복구 실패 시에도
복구 직전에 만든 현재 이벤트 선백업은 보존한다.

## 아카이브 구조

```text
<timestamp>.tar.gz
└── event-database/
    ├── manifest.json
    ├── audit_log.csv
    ├── event_map.csv
    ├── event_notification_hist.csv
    └── event_subscriber.csv
```

`manifest.json`에는 백업 형식 버전과 포함 대상 테이블 목록이 기록된다. 복구 시에는 위에서
정의한 파일 이외의 파일, 중복 항목, 심볼릭 링크, 절대 경로 및 상위 경로 이동 항목을
허용하지 않는다.

## 실행 흐름

### 백업

```text
WebAdmin
  -> ActionType.FullLogBackup
  -> FullLogBackupCommand (Engine 트랜잭션 밖에서 실행)
  -> sudo -n audit-log-backup.py backup <directory>
  -> engine-psql.sh \copy public.<event_table> TO <table.csv> CSV HEADER
  -> tar.gz 생성
  -> chmod 0640 및 atomic rename
```

### 복구

```text
WebAdmin
  -> ActionType.RestoreAuditLogBackup
  -> RestoreAuditLogBackupCommand (Engine 트랜잭션 밖에서 실행)
  -> sudo -n audit-log-backup.py restore <directory> <archive>
  -> 현재 이벤트 CSV 선백업
  -> 아카이브 검증 및 격리 디렉터리 추출
  -> BEGIN
  -> 이벤트 관련 테이블 TRUNCATE
  -> 각 CSV \copy FROM
  -> audit_log_seq 조정
  -> COMMIT
  -> 완료 마커 확인
```

## 백업 범위에서 제외되는 항목

다음 항목은 감사기록 보호 백업에 포함하지 않는다.

* VM, 호스트, 네트워크, 스토리지 등 이벤트 이외의 Engine DB 테이블
* `/var/log/ovirt-engine`의 파일 로그
* Engine 설정 파일 및 인증서
* DWH, Cinderlib, Keycloak 및 Grafana 데이터베이스

Engine 전체 재해 복구 백업이 필요하면 `가용성 확보` 기능의 `engine-backup --scope=all`을
사용해야 한다.

## 보안 통제

* WebAdmin 작업에는 `AUDIT_LOG_MANAGEMENT` 권한이 필요하다.
* 테이블 이름은 사용자 입력을 받지 않고 helper의 고정 목록만 사용한다.
* DB 접속은 설치된 `engine-psql.sh` wrapper를 사용한다.
* helper는 쉘 명령 문자열을 실행하지 않고 고정된 프로세스 인수 배열을 사용한다.
* 백업 파일명은 영문자, 숫자, `.`, `_`, `-` 및 `.tar.gz` 확장자만 허용한다.
* 저장 디렉터리와 복구 파일의 심볼릭 링크를 거부한다.
* 복구 파일은 사용자가 지정한 실제 저장 디렉터리 바로 아래에 있어야 한다.
* 압축 해제 크기는 10 GiB로 제한한다.
* 현재 이벤트 데이터 선백업이 성공해야 복구를 시작한다.
* 장시간 CSV 추출 및 복구는 Engine의 5분 트랜잭션 제한에 포함되지 않는다.
* 복구 SQL의 완료 마커가 출력되지 않으면 DB wrapper의 종료 코드가 0이어도 실패로 처리한다.
