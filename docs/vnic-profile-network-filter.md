# vNIC 프로파일 네트워크 필터 정책

VM 간 파일 공유를 차단하는 `block-file-sharing` 네트워크 필터를 vNIC 프로파일에 어떻게 적용할지
정하는 설정과, 그 설정이 켜져 있을 때/꺼져 있을 때의 동작을 정리한다.

## 설정

| 키 | 기본값 | 적용 |
|---|---|---|
| `EnforceBlockFileSharingFilter` | `false` | 엔진은 즉시, 관리 포털은 **다시 로그인**한 뒤 |

```console
# engine-config -s EnforceBlockFileSharingFilter=true
```

기본값은 `false`이며, 신규 설치와 업그레이드 모두 `false`로 들어간다. 즉 프로파일은 지정된
필터를 그대로 유지하고, `block-file-sharing`은 새 프로파일이 시작하는 값일 뿐이다. 강제가
필요한 환경에서 `true`로 켠다.

설정값을 읽지 못하는 경우에는 **꺼진 것으로 간주한다.** 값을 읽지 못했다는 이유로 아무도
선택하지 않은 상태를 켜지 않는다 — 설치 직후와 같은 상태로 둔다.

> **이미 `true`로 설치·업그레이드된 엔진은 그대로 `true`를 유지한다.** `fn_db_add_config_value`는
> 값이 없을 때만 넣고 기존 값은 건드리지 않는다. 바꾸려면
> `engine-config -s EnforceBlockFileSharingFilter=false` 후 엔진을 재시작한다.

## 켜져 있을 때 (`true`)

passthrough가 아닌 모든 vNIC 프로파일은 저장 시 `block-file-sharing`으로 강제된다.

- `AddVnicProfileCommand`, `UpdateVnicProfileCommand`가 저장 직전에 필터를 덮어쓴다. 관리 포털뿐
  아니라 **REST API·SDK·ansible 등 모든 경로**에 동일하게 적용된다.
- 프로파일 편집 창의 `네트워크 필터` 드롭다운은 **비활성화**되고, 고정된 이유와 해제 방법을
  표시한다. 선택은 받아놓고 조용히 버리지 않는다.

## 꺼져 있을 때 (`false`, 기본값)

- 프로파일은 **지정된 필터를 그대로 유지한다.** `block-file-sharing`은 새 프로파일이 시작하는
  기본값일 뿐이며, 필터 없음(`[제한 없음]`)을 포함해 다른 값을 선택할 수 있다.
- REST API의 `useDefaultNetworkFilterId` 플래그가 다시 의미를 갖는다. 이 플래그가 켜진 요청만
  기본 필터를 적용받는다.
- 편집 창은 프로파일에 **실제로 저장된** 필터를 선택 상태로 보여준다.

## 어느 쪽이든 동일한 것

- **passthrough 프로파일은 필터를 갖지 않는다.** libvirt에 넣을 자리가 없고, 엔진도 둘을 함께
  가진 프로파일을 거부한다. 설정과 무관한 불변 조건이다.
- 프로파일 목록의 `네트워크 필터` 열은 **저장된 값**을 표시한다. 관리자가 이 열을 보는 이유가
  정확히 "의도한 필터와 실제 필터가 같은가"를 확인하기 위해서이므로, 고정 문자열을 표시하지
  않는다.

## 점검 항목

- 설치 직후(`false`) → 편집 창에서 선택한 필터가 그대로 저장되는지, 목록 열에 그 값이
  표시되는지 확인
- `engine-config -s EnforceBlockFileSharingFilter=true` 후 엔진 재시작 → 프로파일 필터를
  REST API로 변경해도 저장 후 `block-file-sharing`인지 확인
- 같은 설정에서 편집 창의 드롭다운이 비활성화되고 사유가 표시되는지 확인
- 두 설정 모두에서 passthrough 프로파일 생성/전환이 성공하고, 필터가 비어 있는지 확인

## 이전 동작과의 차이

이 설정이 생기기 전에는 강제가 코드에 고정되어 있었고(즉 항상 `true`와 같았고), 편집 창은 드롭다운을 활성화한 채
선택값을 저장 단계에서 버렸다. 저장은 성공으로 보고되므로 관리자는 필터가 바뀐 것으로 오인할 수
있었다. 목록 열도 저장값이 아닌 고정 문자열을 표시했다.

또한 프로파일을 passthrough로 만들 때 UI가 "passthrough + 필터" 조합을 전송해
`ACTION_TYPE_FAILED_PASSTHROUGH_PROFILE_CONTAINS_NOT_SUPPORTED_PROPERTIES`로 거부되었다.
passthrough 여부를 필터보다 먼저 확정하도록 고쳤다.

기존 프로파일을 일괄 보정한 업그레이드 스크립트(`04_05_0330`, `04_05_0340`)는 그대로 둔다.
이미 적용된 이력이며, 설정을 끄더라도 되돌리지 않는다. 필요하면 프로파일별로 변경한다.
