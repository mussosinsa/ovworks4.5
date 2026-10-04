# 이벤트 알림: 메일 / ntfy 푸시 선택

`ovirt-engine-notifier`가 이벤트 알림을 **메일**, **ntfy 푸시**(binwiederhier/ntfy 컨테이너 서버), 또는 **둘 다**로
보내도록 선택할 수 있다.

```bash
systemctl enable --now ovirt-engine-notifier
systemctl restart ovirt-engine-notifier      # 설정 변경 후
```

## 1. 선택: `NOTIFICATION_CHANNELS`

| 값 | 동작 |
|---|---|
| `mail` (기본값, 이전과 동일) | 메일만 (`MAIL_SERVER`) |
| `ntfy` | ntfy 푸시만. **메일은 보내지 않음** |
| `mail,ntfy` | 메일과 푸시 모두 |

- `email`/`smtp`는 `mail`과, `push`는 `ntfy`와 같다. `both`는 둘 다를 뜻한다.
- 알 수 없는 값(오타)이면 notifier가 시작하지 않고 오류를 남긴다. 아무 알림도 보내지 않는 상태로 조용히 동작하지 않게 하기 위해서다.
- SNMP(`SNMP_MANAGERS`)는 이 설정과 관계없이 기존대로 동작한다.

**어떤 이벤트를 보낼지**는 기존 구독이 정하고, 이 설정은 **어떻게 보낼지**만 정한다.

- 관리화면의 이벤트 알림 구독(메일 주소로 구독)이나 `FILTER`에 걸린 이벤트가 대상이다.
- `ntfy`를 선택하면 메일 구독에 걸린 이벤트를 **이벤트당 한 번** `NTFY_TOPIC`으로 푸시한다. 구독자가 여러 명이어도 푸시는 한 번만 간다.
- `FILTER`로 다른 토픽에 따로 보낼 수 있다.
  ```bash
  FILTER="include:*:ALERT(ntfy:security-alerts) ${FILTER}"        # 경보 등급 전부를 security-alerts 토픽으로
  FILTER="include:SECURITY_VERIFICATION_SCHEDULED_FAILED(ntfy:) ${FILTER}"   # 기본 토픽
  ```

## 2. ntfy 설정

`/etc/ovirt-engine/notifier/notifier.conf.d/90-ntfy.conf`:

```bash
NOTIFICATION_CHANNELS=ntfy            # 또는 mail,ntfy
NTFY_URL=https://notify.example.internal
NTFY_TOPIC=ops-alerts
NTFY_TOKEN_FILE=/etc/ovirt-engine/notifier/ntfy-token
#NTFY_CA_FILE=/etc/pki/ovirt-engine/ntfy-ca.pem     # 사설 CA로 발급된 서버 인증서일 때
```

발급받은 publisher 토큰은 파일로 둔다. notifier는 `ovirt` 계정으로 동작한다.

```bash
install -m 0640 -o root -g ovirt /dev/null /etc/ovirt-engine/notifier/ntfy-token
printf '%s\n' '발급받은publisher토큰' > /etc/ovirt-engine/notifier/ntfy-token
systemctl restart ovirt-engine-notifier
```

| 항목 | 기본값 | 설명 |
|---|---|---|
| `NTFY_URL` | (필수) | ntfy 서버 주소. `https://`만 허용(아래 참고) |
| `NTFY_TOPIC` | | 기본 토픽. 메일 구독 이벤트가 가는 곳 (`[-_A-Za-z0-9]` 1~64자) |
| `NTFY_TOKEN_FILE` / `NTFY_TOKEN` | | publisher 토큰. 파일을 권장(`NTFY_TOKEN`은 `SENSITIVE_KEYS`로 로그에서 가림). 없으면 익명 발행(경고 로그) |
| `NTFY_CA_FILE` | | 서버 인증서를 발급한 CA(PEM). 비우면 Java 기본 신뢰 저장소 |
| `NTFY_ALLOW_INSECURE_HTTP` | `false` | `http://` 허용 여부. 토큰과 이벤트 내용이 평문으로 전송되므로 기본은 거부 |
| `NTFY_TIMEOUT_SECONDS` | `10` | 푸시 1건의 연결/응답 제한 시간 |
| `NTFY_RETRIES` | `3` | 실패 시 시도 횟수 |
| `NTFY_SEND_INTERVAL` | `0` | `IDLE_INTERVAL`(30초) 몇 번마다 보낼지. 0은 매번 |
| `NTFY_PRIORITY_ALERT/ERROR/WARNING/NORMAL` | `urgent/high/default/low` | 이벤트 등급별 ntfy 우선순위 (`min, low, default, high, urgent` 또는 1~5) |
| `NTFY_TAGS` | | 모든 푸시에 붙일 태그(쉼표 구분). 등급 태그는 항상 붙음 |

## 3. 보내는 요청

아래 `curl`과 같은 요청을 이벤트 1건당 한 번 보낸다.

```bash
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer $NTFY_PUBLISH_TOKEN" \
  -H "Title: [engine01] ALERT SECURITY_VERIFICATION_SCHEDULED_FAILED" \
  -H "Priority: urgent" \
  -H "Tags: rotating_light" \
  --data-binary $'The scheduled security verification ... did not pass ...\n\n2026-10-04 18:05:12 +0900 | SECURITY_VERIFICATION_SCHEDULED_FAILED | engine01' \
  'https://notify.example.internal/ops-alerts'
```

| 부분 | 내용 |
|---|---|
| Title | `[호스트명] 등급 이벤트이름` (ASCII가 아니면 RFC 2047로 인코딩) |
| 본문 | 이벤트 메시지, 발생 시각, 이벤트 이름, 호스트명 (UTF-8, 한글 그대로) |
| Priority | 등급별 매핑 (`ALERT`→urgent, `ERROR`→high, `WARNING`→default, `NORMAL`→low) |
| Tags | 등급 태그(`rotating_light`/`x`/`warning`/`information_source`) + `NTFY_TAGS` |

- 응답이 2xx가 아니면 `NTFY_RETRIES`만큼 다시 시도한다.
- 결과는 메일과 똑같이 `event_notification_hist`에 남는다(`method_type='NTFY'`, 실패하면 `HTTP 403: ...` 같은 사유).
- 리다이렉트는 따라가지 않는다. 토큰이 다른 주소로 전달되지 않게 하기 위해서다.

## 4. 확인

```bash
# 1) 설정 검증 (오류가 있으면 이유를 출력하고 종료 코드 1)
systemctl restart ovirt-engine-notifier
systemctl status ovirt-engine-notifier
grep -E "Notification channels|ntfy" /var/log/ovirt-engine/notifier/notifier.log | tail

# 2) ntfy 서버까지 경로와 토큰 확인 (notifier와 같은 요청)
curl --fail-with-body -sS -H "Authorization: Bearer $(cat /etc/ovirt-engine/notifier/ntfy-token)" \
  -H "Title: notifier test" --data-binary 'test' https://notify.example.internal/ops-alerts

# 3) 발송 이력
su - postgres -c "psql engine -c \"select event_name, method_type, status, reason, sent_at
  from event_notification_hist where method_type like 'NTFY%' order by sent_at desc limit 10\""
```

시험용 이벤트: 관리화면 → 사용자 → (관리자 선택) → 이벤트 알림 → 이벤트 관리에서 메일로 구독한 이벤트를 발생시킨다.
예를 들어 "정기 보안검증 실패"를 구독하고 무결성 검사 실패를 일으킨다. 보통 `INTERVAL_IN_SECONDS`(120초) + 최대 30초 안에 푸시가 도착한다.

## 5. 문제 해결

| 증상 | 원인 / 조치 |
|---|---|
| notifier가 기동 직후 종료, `NTFY_URL must be set` | `ntfy` 선택 시 `NTFY_URL` 필수 |
| `NTFY_URL uses http://` | https로 바꾸거나 `NTFY_ALLOW_INSECURE_HTTP=true`(권장하지 않음) |
| `NOTIFICATION_CHANNELS ... unknown channel` | 값 오타 (`mail`, `ntfy`, `mail,ntfy`) |
| 이력에 `HTTP 401/403` | 토큰 오류, 또는 해당 토픽에 대한 쓰기 권한 없음 (ntfy `auth-access` 확인) |
| `PKIX path building failed` | 서버 인증서의 CA를 `NTFY_CA_FILE`로 지정 |
| 푸시가 오지 않음, 이력도 없음 | 해당 이벤트에 메일 구독이나 `FILTER` 규칙이 없음. `NTFY_TOPIC`이 비어 있으면 `no ntfy topic` 실패가 이력에 남음 |
| `Cannot read NTFY_TOKEN_FILE` | 파일 권한: `ovirt` 그룹이 읽을 수 있어야 함 (`root:ovirt 0640`) |
