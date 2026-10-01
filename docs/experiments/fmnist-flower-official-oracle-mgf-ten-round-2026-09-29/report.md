# Fashion-MNIST: MGF 선택 후 AION-ASR 집계, 공식 Flower 10라운드

Flower 1.36.0 SuperLink/Ray Simulation Runtime에서 원본 Fashion-MNIST,
`avg_300.pth` LeNet5 checkpoint, N=500, 라운드 참여자 q=100, aggregator 8개,
악성 client 20명, seed 0으로 실행했다. 공격 라운드는 5·7·10이다.
`aion_mgf_oracle`와 평문 `mgf`는 같은 데이터·참여 일정을 사용하는 별도
Flower run이다.
원본 artifact 방식의 class별 Dirichlet 배정은 client별 수를 개별 반올림해
잔여 이미지를 남긴다. 이 seed에서는 학습 이미지 60,000장 중 59,941장을
중복 없이 배정하고 59장은 미배정했다.
이 보고서의 client별 배정은 이전 포트의 class 번호순 난수 transcript다.
재실행 명령의 `--partition-rng legacy`가 해당 입력을 고정한다. 새 기본값은
원본 artifact의 class 첫 등장 순서와 150명 사전 추첨을 따른다.

| 항목 | `aion_mgf_oracle` | 평문 MGF |
| --- | ---: | ---: |
| 최종 test 정확도 | 88.66% | 88.66% |
| 최종 ASR | 0.390625% | 0.390625% |
| 공격 라운드 5·7·10에서 선택한 악성 client | 0명 | 0명 |
| 내부 실행 시간 | 929.8초 (15.5분) | 54.4초 |

두 경로가 **모든 10라운드에서 같은 client 집합**을 골랐고, 매 라운드의
정확도·ASR 곡선도 일치했다. 최종 모델을 포함한 모델 시퀀스의 최대 좌표
차이는 2.11×10⁻⁶이다. AION 쪽은 선택된 client의 전체 61,706차원 update를
마스킹해 집계했다. 공식 Flower 결과와 선택 trace, 모델·roster 인증서의
quorum 및 부모 체인은 `--phase verify` 경로에서 확인했다. [검증 요약](results.json)은
원시 결과·모델·provenance의 SHA-256을 연결한다.

이 모드는 **보안 MGF 구현이 아니다**. 각 client가 서명한 classifier 층
840개 평문 좌표를 Flower coordinator에 공개해 MGF 선택에 사용한다. 공개
좌표와 해당 client의 전체 masked update가 같다는 암호학적 증명도 없다.
라운드별 새 ASR 키와 recipient-bound share를 사용해 선택된 부분 집합을
집계하지만, 이 결과를 논문의 CCS/VRF·검증된 LWE-HPRF·전체 보안 보장이나
60라운드 재현으로 해석할 수 없다. 시간은 이 CPU 환경의 각 run 내부 기록이며
환경 준비·평가·Flower 기동 시간과 논문 하드웨어 성능은 별개다.

원시 실행과 검증 결과는 `.cache/fmnist/official-oracle-10round-seed0-v2/`에
있다(저장소에서 ignored). 재실행 명령:

```bash
python3 -m experiments.run_fmnist_official --phase all \
  --output .cache/fmnist/official-oracle-10round-reproduce \
  --population 500 --participants 100 --aggregators 8 --rounds 10 \
  --attack-clients 20 --attack-rounds 5 7 10 \
  --modes aion_mgf_oracle mgf --workers 8 --partition-rng legacy \
  --cohort-sampling groups
python3 -m experiments.export_fmnist_official \
  --source .cache/fmnist/official-oracle-10round-reproduce \
  --output docs/experiments/fmnist-flower-official-oracle-mgf-ten-round-reproduce
```
