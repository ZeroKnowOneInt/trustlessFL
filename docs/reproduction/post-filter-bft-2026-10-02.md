# 첫 번째 집계 BFT: 필터 통과 집합과 key release 연결

## 변경 이유와 범위

[논문 Algorithm 2](https://www.usenix.org/system/files/usenixsecurity25-liu-yizhong.pdf#page=7)의
10행은 MGF를 실행하고, 11행은 `C_on=C_valid`로 교체하며, 12행은 교체된
집합을 BFT로 확정한다. 기존 Flower source workflow는 수신 집합에 대한
BFT를 먼저 수행한 뒤 필터를 실행했다. Paper 경로의 별도 signed replay는
추가되어 있었지만 BFT 자체의 대상과 순서는 논문과 달랐다.

저자 원본 `SA_AggregatorAgent.report()`는 MMF 계산을 먼저 실행한다.
그러나 BFT 메시지는 `selected_indices`가 아니라 수신 버퍼를 사용하며,
`report_read_from_pool()`은 그 버퍼를 이미 비운다. 이 차이를 저자 코드가
논문과 동일하다는 근거로 사용하지 않는다. 원본 파일은 수정하지 않았다.

이번 수정은 Flower adapter의 첫 번째 BFT 순서와 membership binding이다.
원본 HPRF, source MMF, 키 범위, numeric decoder는 그대로다. 새로운 암호
프로토콜이나 추가 mask share를 도입하지 않는다.

## 새 실행 순서

1. 클라이언트가 마스킹한 VECTOR를 Flower로 전달한다.
2. aggregator가 필터를 실행한다. 일반 source 경로는 원본 MMF,
   `paper_numerics` 경로는 기존 masked-MGF adapter다.
3. Paper 경로에서는 각 committee가 동일 signed VECTOR와 committed history로
   필터를 재계산하고 선택 명단을 승인한다.
4. 첫 번째 BFT는 필터 통과 명단을 확정한다. `ONLINE_CLIENTS`라는 메시지
   이름은 유지하지만 bitmap은 이제 수신 집합이 아닌 필터 통과 집합이다.
   Task와 round도 합의 값에 포함한다.
5. Committee는 locally pinned BFT registry로 commit 인증서를 검사하고,
   요청 명단·task·round·정족수·서명이 맞을 때만 합계 키 share를 제공한다.
6. Aggregator가 기존 ASR/마스크 제거를 실행하고 최종 모델에 두 번째 BFT를 수행한다.

Paper-MGF 노드는 자신의 replay 승인이 없는 명단에 첫 번째 BFT 투표를
하지 않는다. 일반 MMF 경로에는 committee의 독립 필터 재계산을 새로
추가하지 않았으며, proposal 명단과 합의 digest 및 key request를 연결한다.

## 실행 버전과 호환성

새 `provision_source()`와 공식 runtime의 fresh stage는 manifest에
`selection_consensus.kind=post-filter-bft-v1`을 기록한다. 정의되지 않은
profile은 거부하며, profile이 없는 historical manifest만 기존 pre-filter
순서를 유지한다. 과거 결과/키/share를 새 task로 가져오거나 덮어쓰지 않는다.

History의 `online_bft` 필드 이름은 호환성을 위해 유지한다. Offline verifier는
manifest profile에 따라 새 결과에서 selected 집합을 검사하고, 과거 결과에서
수신 cohort를 검사한다. 검증 결과의 `first_bft_subject`로 두 의미를 구분한다.
같은 slot의 roster BFT와 모델 BFT는 각각 sequence `2r`, `2r+1`이다.

## 검증

관련 회귀 **129개 통과**, 87.92초. 대상은 source adapter/동적 참여/공식
runtime/암호화 공유/새 filtered-BFT/선택 인증/수치 carry/기존 결과 검증이다.
별도 초기 40개 회귀 이후 최종 추가 voter gate 시험까지 포함해 다시 실행했다.
`compileall`과 `git diff --check`도 통과했다. 전체 저장소 suite 통과 주장은 아니다.

새 시험은 다음을 확인한다:

- 필터보다 앞선 BFT 및 share release 순서가 새 실행에서 발생하지 않음
- 실제 BFT digest가 필터 통과 집합과 일치하고 수신 집합과 구분됨
- 인증서 누락, 다른 명단/task/round, 모델 BFT 인증서의 오용 거부
- 정족수 미달, 중복 voter, 잘못된 서명/registry 거부
- Paper-MGF 노드가 자신의 승인 전 또는 다른 명단에 투표하지 않음
- Inline/분할 VECTOR, 동적 재참여 및 historical manifest 호환성 유지

Unit 시험의 인증서는 ephemeral fixture keys로 생성한다. 실제 정상 경로는
Flower `ProcessGrid`/`PooledProcessGrid` 및 아래 공식 SuperLink/Ray로 검증했다.

| 공식 Flower 실행 | run ID | ServerApp 시간 | 초기 key share / 추가 mask share | 독립 재학습 |
| --- | --- | ---: | --- | --- |
| Unscaled source synthetic 4라운드 | `5104404461745392588` | 29.267190 s | 40 / 0 | 선택 학습 15회, model error 0 |
| Signed masked-MGF synthetic 1라운드 | `15362905348325214428` | 20.921133 s | 80 / 0 | 선택 학습 2회, model error 0 |

출력은 각각 `.cache/source-filtered-bft-synthetic-four-round-official-20261002`,
`.cache/source-filtered-bft-paper-mgf-one-round-official-20261002`다. 모든 round의
첫 번째 BFT digest를 selected bitmap과 대조했고 일치했다. 새 원본 경로는
10명에서 `[4,4,4,3]`명을 선택했고, paper 경로는 20명에서 `[0,2]`를 선택했다.
CLI wrapper의 `finished:completed` 확인과 offline verification이 모두 통과했다.

기존 `.cache/source-encrypted-sharing-synthetic-4round-official-20261001`도
읽기 전용 verifier로 재검사했다. `historical-received-client-set`, 4라운드,
model error 0이며 기존 manifest/result/verification 파일을 변경하지 않았다.

## 해결하지 않은 문제

이 보정은 scaled-HPRF carry ambiguity를 해결하지 않는다. 기존 collision
회귀와 실패 판정은 유지되며, 과거 공식 10라운드 시도의 4라운드 복원 실패를
성공으로 재분류하지 않는다. 새 paper 시험은 단일 synthetic round다.

원본 scalar 키 공간의 비공개성, across-round cohort 누출, aggregate norm의
위원회 독립 계산 검증, CCS/VRF, EMA late-update, source BFT view-change와
일반 부분 동기 환경의 진행 보장은 이번 변경의 완료 범위가 아니다.
