# hosted-engine 배포 시 KEK·PostgreSQL 비밀번호 자동 설정

| 항목 | 내용 |
|---|---|
| 대상 | engine-setup (hosted-engine 배포 시 엔진 VM 안에서 실행) |
| 설정 파일 | `/etc/ovirt-engine/develop.txt` |
| 구현 | `packaging/setup/ovirt_engine_setup/hosted_preset.py`, `config/client_control.py`, `provisioning/postgres.py` |
| 시험 | `packaging/setup/tests/test_hosted_preset.py`, `test_setup_memory_kek.py` |

## 1. 목적

hosted-engine 배포에서는 engine-setup이 엔진 VM 안에서 사람의 입력 없이 실행된다. 그런데 아래 두 값은 보안상 응답 파일로 받지 않고 항상 화면에서 입력받기 때문에, 자동 배포가 이 질문에서 멈춘다.

- KEK 패스프레이즈(설정 파일 암호화 키를 만드는 값, 메모리에만 보관)
- PostgreSQL 수퍼유저(`postgres`) 비밀번호

`/etc/ovirt-engine/develop.txt`에 `Flag=hosted`가 있으면, engine-setup이 이 두 값을 파일에서 읽어 질문 없이 설정한다.

## 2. 파일 형식

```
Flag=hosted
KEK=<KEK 패스프레이즈>
Postgres=<PostgreSQL 수퍼유저 비밀번호>
```

- 키 이름은 대소문자를 구분하지 않는다(`flag`, `KEK`, `postgres` 모두 같음).
- 값은 줄에서 첫 번째 `=` 뒤의 내용이다. 앞뒤 공백은 지우고, 값 안의 `=`·`#`·특수문자는 그대로 쓴다.
- `#`로 시작하는 줄과 빈 줄은 무시한다.
- `Flag`가 `hosted`가 아니면 파일 전체를 무시하고 평소처럼 질문한다.
- 한쪽 값만 있으면 그 값만 자동으로 설정하고, 나머지는 평소처럼 질문한다.

## 3. 파일 권한 (필수)

평문 비밀번호가 들어 있으므로 아래 조건을 모두 만족할 때만 읽는다. 조건이 맞지 않으면 engine-setup은 그 파일을 쓰지도 질문하지도 않고 **중지하며 이유를 출력**한다.

| 조건 | 맞추는 명령 |
|---|---|
| 일반 파일(심볼릭 링크 불가) | — |
| 소유자 root | `chown root:root /etc/ovirt-engine/develop.txt` |
| root 외에는 읽기·쓰기 불가(0600 이하) | `chmod 600 /etc/ovirt-engine/develop.txt` |

```bash
install -m 600 -o root -g root /dev/null /etc/ovirt-engine/develop.txt
vi /etc/ovirt-engine/develop.txt      # 위 형식으로 작성
```

## 4. 동작

| 값 | 동작 |
|---|---|
| KEK | 화면 입력과 같은 검사를 한다(6~256자, 제어문자 금지). 이미 암호화된 설정이 있으면 그 키로 열리는지 확인한다. 검사에 실패하면 다시 묻지 않고 중지한다("The KEK passphrase in /etc/ovirt-engine/develop.txt cannot be used"). 값은 otopi 환경·응답 파일·로그에 들어가지 않으며, KEK 에이전트에 넘긴 뒤 메모리에서 지운다. |
| Postgres | 수퍼유저 비밀번호로 쓴다. 로그에서는 가린다(LOG_FILTER). 질문으로 받은 값이 아니므로 engine-setup이 남기는 응답 파일에도 기록되지 않는다. |
| Postgres 정책 위반 | 비밀번호 정책(14자 이상, 4종 조합, 반복·연속·흔한 단어 금지)에 맞지 않아도 배포를 멈추지 않는다. 대신 어떤 규칙을 어겼는지 경고를 남긴다("… used as given in develop.txt (Flag=hosted); change it after the deployment"). 화면 입력이나 응답 파일로 받은 값은 지금처럼 정책 위반 시 중지한다. |

| 단말 시리얼 번호, 접속 허용 IP | 질문하지 않고 화면에 [대괄호]로 보이는 기본값을 그대로 쓴다(Enter를 누른 것과 같음). 시리얼은 `config.json`의 `serialNum`(없으면 제품 기본값), IP는 현재 단말기 IP 목록이다. 127.0.0.1과 이 서버의 주소는 항상 포함된다. 응답 파일에 값이 있으면 그 값을 쓴다. |

engine-setup 로그에는 값 대신 출처만 남는다.

```
KEK passphrase taken from /etc/ovirt-engine/develop.txt (Flag=hosted)
PostgreSQL superuser password taken from /etc/ovirt-engine/develop.txt (Flag=hosted)
Client serial number: default taken (Flag=hosted in /etc/ovirt-engine/develop.txt)
Client IP addresses allowed: default taken (127.0.0.1, …; Flag=hosted in /etc/ovirt-engine/develop.txt)
```

## 5. 운영 시 주의

1. **배포가 끝나면 파일을 지운다.** 평문 비밀번호가 디스크에 남지 않도록 한다.
   ```bash
   shred -u /etc/ovirt-engine/develop.txt
   ```
   엔진 VM을 다시 설치할 때만 파일을 다시 넣는다.
2. **비밀번호 정책 경고가 나왔다면 배포 뒤 postgres 비밀번호를 바꾼다.** 예를 들어 `@#$%`처럼 키보드에서 연달아 있는 특수문자 4자는 "키보드 연속 문자 금지" 규칙에 걸린다.
3. **KEK는 엔진 VM을 재부팅한 뒤 다시 넣어야 한다.** 메모리에만 보관하기 때문이다(`kek_agent.py --unlock`). develop.txt는 engine-setup에서만 읽는다.
4. **설치 이미지나 배포 스크립트에 이 파일을 넣을 때**는 이미지·저장소에 평문이 남지 않게 관리한다. 이 저장소의 소스·문서·시험에는 실제 값을 넣지 않는다.
