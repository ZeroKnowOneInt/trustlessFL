# Masked-MGF 선택 명단과 key release 연결

## 변경 범위

새 `paper_numerics` learning 작업에는
`selection_authorization.kind=signed-masked-filter-replay-v1`을 활성화한다.
기존 source MMF 작업과 historical manifest의 동작을 바꾸거나 그것을
private MGF 완료로 재분류하지 않는다. 원본 HPRF와 round 기반 마스킹,
초기 일회성 key sharing, 추가 mask share 0개는 유지한다.

기존 hardened source learning 경로도 위원회가 요청된 명단이 MGF 결과인지
확인하지 않았다. singleton과 같은 round의 다른 subset은 막았지만,
첫 요청부터 잘못된 2인 이상 subset을 요청할 수 있었다.

수정 후 paper 경로:

1. client가 기존 masked VECTOR에 task를 포함해 node-local Ed25519 키로
   서명한다. 개별 평문 update는 포함하지 않는다.
2. aggregator가 서명과 task/round/model parent/scale/좌표 범위를 검사하고
   masked MGF를 실행한다. norm tie는 sender 순서로 고정한다.
3. 위원회 각 노드에도 동일한 signed masked VECTOR를 Flower 메시지로
   전달한다. 큰 입력은 기존 bounded batches를 사용하고 node별 inbox로
   분리한다. aggregator inbox를 IPC로 읽는 구조가 아니다.
4. 위원회는 자신의 BFT state에 pinned된 registry로 이전 model의 commit을
   검사한다. 이전 두 history term과 bound는 committed aggregate body에서
   가져온다. 현재 개별 plaintext나 개별 HPRF seed를 복원하지 않는다.
5. 위원회가 필터를 직접 재계산한다. 요청 명단과 다르면 authorization과
   key release를 거부한다. 같으면 parent/round/selected/bound/vector digest에
   대한 signed receipt를 반환한다.
6. `sum-shares`는 그 노드의 같은 round authorization과 정확히 같은 명단만
   허용한다. 전달되는 aggregate key share는 기존처럼 aggregator 수신자용
   암호문이며 추가 coordinate/mask share는 없다.

Server workflow는 모든 committee receipt의 서명과 context를 확인하고
history에 기록한다. 오프라인 learning verifier도 receipt를 검사한다.
receipt는 서명자의 replay 승인 증거이지, omitted masked VECTOR의 독립
오프라인 replay 또는 aggregate 수치 정확성에 대한 증명은 아니다.

## 남은 경계

- 기존 scaled-HPRF carry/rounding ambiguity를 해결한 변경이 아니다.
  numeric decoder의 `ambiguous` 거부는 유지한다.
- 이전 aggregate history metadata를 BFT commit에 바인딩하지만,
  원본 normal-path BFT 투표가 metadata의 계산 자체를 증명하지는 않는다.
  악성 aggregator의 잘못된 norm/aggregate를 완전히 막았다고 주장하지 않는다.
- 원본 scalar keyspace `1..100000`의 공개 key-search 위험을 해결하지 않는다.
- across-round cohort 조합으로 인한 노출, CCS/VRF, 임계 수 이상의 공모,
  모든 부분 동기 환경의 HotStuff 진행 보장은 별도다.
- 현재 full masked VECTOR를 위원회에도 전달하므로 통신량과 검증량이
  늘어난다. 공개 classifier projection만 전달하는 최적화는 하지 않았다.
- 같은 OS 사용자의 local simulation은 node private 파일의 물리적 격리
  증명이 아니다. 실제 배포에는 별도 trust domain이 필요하다.

## 검증

`tests/test_source_selection_authorization.py`는 미승인 key release,
필터와 다른 첫 subset 요청, vector/서명/task/parent/scale/sender 변조와
plaintext field 삽입을 검사한다. 위원회 inbox 분리, norm tie의 도착 순서
독립성, 4번째 round의 두 committed history term, receipt의 중복 voter와
context 변조도 검사한다. 4-round history 테스트는 filter replay 검증이며
4-round scaled-mask aggregate 복원 성공으로 해석하지 않는다.

`tests/test_source_paper_numeric.py`의 actual learning 1-round 검증은
20명 client/4명 committee, key share 80건, 추가 mask share 0건이다.
강제 분할 시 signed VECTOR delivery는 aggregator와 4명 committee에
각각 20건, 총 100건이며 offline selected-training replay와 모델이 일치한다.

최종 관련 회귀는 77개 통과(65.42초), 컴파일과 `git diff --check`도
통과했다. 최종 signed-receipt 버전의 공식 Flower SuperLink/Ray 실행은
`.cache/source-mgf-authorized-receipts-synthetic-one-round-official-20261001`에
기록했다. run ID `10761985481865071535`, runtime 19.861095초,
initial key share 80건, extra mask share 0건, authorized round 1회,
committee signed receipt 4개다. 선택된 2명의 학습을 독립 재계산한
model max absolute error는 0이다. 이는 공개 synthetic 수치 fixture의
1-round 통과이며 FMNIST 장기 scaled-MGF 성공이나 보안 증명이 아니다.
별도 collision/key-search/precision/DMC 회귀 52개도 통과했다. 따라서
기존 carry ambiguity와 privacy counterexample을 새 authorization으로
해결된 것으로 숨기거나 제거하지 않았다.
