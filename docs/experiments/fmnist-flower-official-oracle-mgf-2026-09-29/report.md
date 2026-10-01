# 공식 Flower: MGF 선택 → AION-ASR 집계 연결 시험

`flwr==1.36.0`·Ray CPU Simulation Runtime에서 FMNIST LeNet5를 N=8,
q=4, aggregator 4개, 2라운드로 실행했다. 1라운드에는 악성 client 1명을
참여시켰고 2라운드는 정상 참여 집합이었다. 두 모드는 각각 별도 Flower
FAB/run이며, 동일한 seed·데이터·참여 일정을 사용한다.

| 경로 | 1라운드 선택 | 2라운드 선택 | 최종 정확도 | 최종 ASR |
| --- | --- | --- | ---: | ---: |
| `aion_mgf_oracle` | client-4, client-5 | client-4, client-3 | 87.55% | 0.390625% |
| 평문 artifact MGF | client-4, client-5 | client-4, client-3 | 87.55% | 0.390625% |

첫 라운드의 공격 client-0은 두 경로 모두에서 선택되지 않았다. 두 모델
시퀀스의 최대 좌표 차이는 0.00034036이며, 선택된 client의 서명된 classifier
평문 평균과 AION 집계 결과의 classifier 좌표 차이는 최대 4.93×10⁻⁷이다.
AION 경로의 모델·roster 인증서와 부모 체인을 `verify`로 재검증했다.
서버 내부 실행 시간은 각각 37.6초와 16.0초이며 Flower 기동 시간은 제외한다.

`aion_mgf_oracle`는 **보안 MGF가 아니다**. client의 분류기 층 840개 평문
업데이트가 Flower coordinator에 공개된다. 매 라운드 새 ASR 키를
recipient-bound share로 배포해 동적 부분 집합의 집계 키를 복원하지만,
공개 classifier 값과 전체 masked update의 개별 정합성을 암호학적으로
증명하지 않는다. 이 결과는 MGF 선택 이후의 ASR 집계 배선을 확인하는
연결 시험이며, 논문의 N=500/q=100·60라운드 결과나 전체 프라이버시
보장을 대체하지 않는다.

원시 실행과 검증 결과: `.cache/fmnist/official-oracle-ephemeral-two-round/`
(ignored; 로컬 실행 산출물). 실행 명령:

```bash
python -m experiments.run_fmnist_official --phase all \
  --output .cache/fmnist/official-oracle-ephemeral-two-round \
  --population 8 --participants 4 --aggregators 4 --rounds 2 \
  --attack-clients 1 --attack-rounds 1 \
  --modes aion_mgf_oracle mgf --workers 2 --partition-rng legacy \
  --cohort-sampling groups
```
