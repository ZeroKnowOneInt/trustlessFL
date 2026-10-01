# Fashion-MNIST: 분할 후 Python RNG를 이어 쓴 공격 풀, Flower 10라운드

Flower 1.36 SuperLink/Ray CPU에서 FMNIST/LeNet5, N=500, q=100,
aggregator 8개, 악성 client 20명, seed 0을 사용했다. Dirichlet alpha 0.5의
원본식 분할은 학습 이미지 59,941/60,000장을 중복 없이 배정했다.
공격 라운드는 분할 뒤 NumPy 난수 상태와 원본의 비교 조건을 이어 쓴
**1·2·5·6·7·10**이다.

이번에는 공격용 test-image 풀도 분할 뒤 **같은 Python 난수 상태**에서
`random.sample`했다. 이전 [기본 공격 일정 10라운드](../fmnist-flower-official-default-rng-ten-round-2026-09-29/report.md)는
이 단계에서 Python seed 0을 새로 시작했다. 두 실행의 `poison-test.npz`
해시는 다르며, 새 풀의 인덱스 해시는 [결과](results.json)에 있다.

| 항목 | `aion_mgf_oracle` | 평문 MGF |
| --- | ---: | ---: |
| 최종 test 정확도 | 88.62% | 88.62% |
| 최종 공격 성공률(ASR) | 0.5859375% | 0.5859375% |
| 선택된 악성 client | 전 라운드 0명 | 전 라운드 0명 |
| 매 라운드 선택 client 수 | 10명 | 10명 |
| 내부 실행 시간 | 807.3초 | 74.6초 |

두 경로의 라운드별 MGF 선택 목록과 정확도·ASR 곡선이 일치했고,
모델 이력의 최대 좌표 차이는 `1.6963448594935436e-06`이다.
서명된 AION roster·model 정족수 및 부모 체인, 참여 일정, 모델과
MGF trace를 검증했다. 이전 seed 0 기본 일정 실행과 **AION 모델 이력은
좌표별로 완전히 같다**. 따라서 ASR 변화는 모델 성능 변화가 아니라
평가 이미지 풀 변경에 따른 것이다.

원시 실행은 `.cache/fmnist/official-shared-python-rng-ten-round-seed0/`에
보관한다(저장소에서 ignored). [해시 연결 결과](results.json)에
입력·실행·모델 provenance를 기록했다.

클라이언트의 classifier 840개 평문 좌표가 Flower coordinator에 공개되는
`oracle` MGF 경로이므로 비공개 분산 MGF의 보안 성질을 입증하지 않는다.
원본 local training이 사용하는 Python 난수가 다음 라운드 참여 추첨과
섞이는 정확한 순서도 아직 재현하지 않았다. 60라운드 논문 곡선이 아니다.
