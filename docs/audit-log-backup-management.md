# 감사기록 백업 관리

## 개요

`감사기록 보호`의 **전체 로그 백업**은 파일 로그 디렉터리를 복사하는 기능이 아니다.
WebAdmin 이벤트가 저장되는 `audit_log`를 포함하여 **oVirt Engine 데이터베이스의 모든
테이블**을 하나의 압축 백업 파일로 저장한다.

백업과 복구에는 oVirt가 제공하는 `engine-backup` 명령의 Engine DB 전용 범위를 사용한다.
따라서 테이블을 별도로 열거하지 않으며, 향후 Engine DB에 테이블이 추가되어도 전체 DB
덤프에 포함된다.

```text
/usr/share/ovirt-engine/bin/audit-log-backup.py
    └── /usr/bin/engine-backup --scope=db
            └── Engine DB 전체 테이블 (audit_log 포함)
```

## 화면 작업

### 전체 로그 백업

1. `관리 > 감사기록보호`를 연다.
2. Engine 호스트에서 사용할 백업 저장 디렉터리를 입력한다.
3. `전체 로그 백업`을 선택한다.
4. 선택한 디렉터리에 타임스탬프를 포함한 `*.tar.gz` 파일이 생성된다.

백업 파일은 임시 이름으로 완전히 생성된 다음 최종 이름으로 원자적으로 이동된다.
불완전한 백업은 목록에 정상 백업으로 노출되지 않는다. 최종 파일 권한은 `0640`이다.

### 백업 목록 조회

`감사기록 조회`를 선택하면 입력한 저장 디렉터리 안의 `*.tar.gz` 백업을 최신 파일명
순으로 표시한다. 심볼릭 링크와 저장 디렉터리 외부 파일은 복구 대상으로 허용하지 않는다.

### 전체 DB 복구

1. 목록에서 복구할 백업을 선택한다.
2. `복구 (현재 Engine DB 백업 후 전체 복구)`를 선택한다.
3. 선택한 파일이 여전히 허용된 저장 디렉터리에 존재하는지 서버에서 다시 검증한다.
4. 현재 Engine DB 전체를 `pre-restore-current-db-*.tar.gz`로 선백업한다.
5. 선택한 백업의 모든 Engine DB 테이블을 복구한다.

선백업에 실패하면 선택한 파일의 복구는 시작하지 않는다. 복구 작업은 데이터베이스 전체를
과거 시점으로 되돌리므로 VM, 스토리지, 사용자, 권한 및 감사 이벤트 등 백업 이후의 DB
변경 사항도 함께 되돌아간다. 운영 환경에서는 유지보수 시간에 수행해야 한다.

## 백업 파일

```text
<저장 위치>/
├── <timestamp>.tar.gz
└── pre-restore-current-db-<timestamp>.tar.gz
```

`engine-backup --scope=db`가 생성하는 압축 아카이브에는 Engine DB의 스키마와 모든 테이블
데이터가 포함된다. 제품 설정 파일, 인증서, DWH DB 및 `/var/log/ovirt-engine` 파일 로그는
이 메뉴의 백업 범위에 포함하지 않는다. 해당 항목까지 필요한 재해 복구 백업은 `가용성 확보`
기능의 `engine-backup --scope=all`을 사용한다.

## 실행 흐름

### 백업

```text
WebAdmin
  -> ActionType.FullLogBackup
  -> FullLogBackupCommand
  -> sudo -n audit-log-backup.py backup <directory>
  -> engine-backup --mode=backup --scope=db --file=<temporary>
  -> chmod 0640
  -> atomic rename to <timestamp>.tar.gz
```

### 복구

```text
WebAdmin
  -> ActionType.RestoreAuditLogBackup
  -> RestoreAuditLogBackupCommand
  -> sudo -n audit-log-backup.py restore <directory> <archive>
  -> current DB backup (--mode=backup --scope=db)
  -> selected DB restore (--mode=restore --scope=db)
```

## 보안 통제

* WebAdmin 작업에는 `AUDIT_LOG_MANAGEMENT` 권한이 필요하다.
* helper는 쉘 문자열을 실행하지 않고 고정된 인수 배열로 `engine-backup`을 호출한다.
* 백업 파일명은 영문자, 숫자, `.`, `_`, `-`와 `.tar.gz` 확장자만 허용한다.
* 저장 디렉터리와 복구 파일은 실제 파일이어야 하며 심볼릭 링크를 거부한다.
* 복구 파일의 실제 상위 디렉터리가 사용자가 입력한 저장 디렉터리와 동일해야 한다.
* 현재 DB 선백업이 완료된 경우에만 선택한 백업 복구를 시작한다.
* 백업 작업용 상세 로그는 임시 파일로 생성하고 작업 종료 후 제거한다.

## 설치 요구사항

helper 경로:

```text
/usr/share/ovirt-engine/bin/audit-log-backup.py
```

필수 실행 파일:

```text
/usr/bin/engine-backup
```

Engine 서비스 사용자는 설치 과정에서 생성되는 제한된 sudo 규칙을 통해 helper의
`backup` 및 `restore` 하위 명령만 비밀번호 없이 실행한다.
