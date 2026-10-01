# Fashion-MNIST/LeNet5 Flower model-replacement 공격 연결

공식 `avg_300.pth` checkpoint와 checksum 검증된 Fashion-MNIST에서 시작해
Flower `ServerApp` 1개, 학습 client 4개, 별도 aggregator 4개로 한 라운드를 실행했다.
client 1개가 공격 라운드에 원 artifact와 같은 네 패턴의 trigger, target class 2,
배치당 poison 6개, 로컬 SGD 120단계(lr 0.0005, momentum 0.9,
weight decay 0.005), update boost 20을 사용했다. 나머지 client는 정상적으로
local epoch 2·batch 64·lr 0.001로 학습했다.

| 지표 | 초기 checkpoint | Flower 공격 1라운드 |
|---|---:|---:|
| 정상 테스트 정확도 | 88.56% | 10.00% |
| 테스트 오류율(TER) | 11.44% | 90.00% |
| trigger 공격 성공률(ASR) | 0.390625% | 100% |
| 평문 fixed-point 평균과 모델 최대 절대 오차 | 0 | 0 |

실행 명령:

```bash
OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
PYTHONPATH=/tmp/trustlessfl-torch:/tmp/trustlessfl-test-pkgs:. \
python3 -m experiments.run_fmnist_flower \
  --output docs/experiments/fmnist-flower-attack-2026-09-28 \
  --clients 4 --aggregators 4 --rounds 1 \
  --attack-clients 1 --force-attack-rounds 1 --attack-steps 120 \
  --partition-rng legacy
```

ASR 분모는 test 이미지에서 target class 2를 제외하고 중복을 허용해 뽑은
512개 항목이다. 원 artifact처럼 공격 학습에도 같은 test-image pool이 들어가므로
독립 held-out ASR이 아니다. [원시 결과](./results.json)에 공격 일정·pool hash,
partition hash, 라운드별 TER/ASR, action별 시간·payload bytes를 보존했다.

원 [artifact 2라운드 pilot](../fmnist-artifact-pilot-2026-09-13/report.md)의
평문 평균 첫 공격 라운드는 정상 정확도 10.11%, ASR 100%였다. 이번 결과와
방향은 유사하지만, 원 실험은 N=500에서 q=100·악성 20명이고 여기는
고정 q=4·악성 1명이다. partition·pool 인덱스와 RNG 소비도 같지 않다.
따라서 이 결과를 논문 Figure 5의 재현값으로 간주하지 않는다. 분산 MGF는
이번 실행에 사용하지 않았다. 논문 규모·60라운드 공격 일정·MGF 대조는 남아 있다.
