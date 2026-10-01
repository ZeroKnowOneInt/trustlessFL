# 공식 Flower: HotStuff·동적 참여·공격 3라운드

N=8, q=4, aggregator 4개, 공격 client 2명, 첫 라운드 공격인
Fashion-MNIST/LeNet5 실험을 공식 `flwr run`/SuperLink/Ray에서 실행했다.
선택형 연구용 HotStuff를 켜고, 2인 privacy group을 라운드마다 변경했다.
모든 모델 라운드에 HotStuff `commit` QC가 기록됐다.

| 라운드 | 참여 그룹 | AION·평문 양자화 정확도 | ASR |
|---|---|---:|---:|
| 0 | checkpoint | 88.56% | 0.390625% |
| 1 | 공격 2명 + 정상 2명 | 10.00% | 100% |
| 2 | 정상 4명 | 61.68% | 17.1875% |
| 3 | 정상 4명 | 67.24% | 7.421875% |

AION과 같은 참여 일정의 평문 양자화 모델은 전체 라운드에서 정확히
일치했다(최대 절대 오차 0). 이전 모델 해시를 인증서에 누적해, 늦게
참여하는 client에게 모든 과거 모델 vector를 다시 보내지 않는다.
HotStuff와 대형 update의 단계별 전달을 함께 사용하는 경로도 검증했다.

[요약 결과](results.json)의 SHA-256은
`1bc1782800c01fb9fa5ebaf70b7334af463c9d2756fb40f8f8f48f57de60c1dc`이다.
원시 실행은 `/tmp/trustlessfl-fmnist-official-compact-hotstuff-fixed-20260929`에
있고, AION run ID는 `3343893430731242667`, 양자화 대조군은
`11935915716688305026`이다. 이 실행은 Flower가 살아 있는 정상 환경에서
HotStuff 정족수 경로를 통과했다는 검사이며, aggregator P2P 장애·부분 동기
진행 보장이나 논문 N=500/q=100·60라운드 결과를 증명하지 않는다.
