# Fashion-MNIST/LeNet5 Flower 정상 학습 연결 실험

실행 명령은 아래와 같다. 공식 Fashion-MNIST IDX와 SHA-256 고정
`avg_300.pth` checkpoint를 `../Aion/`에서 읽었고, 임시 CPU PyTorch 2.4.0
환경에서 실행했다. Flower `ServerApp` 1개, 학습 `ClientApp` 4개,
독립 aggregator `ClientApp` 4개와 기존 AION-ASR 집계 경로를 사용했다.

```bash
OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
PYTHONPATH=/tmp/trustlessfl-torch:/tmp/trustlessfl-test-pkgs:. \
python3 -m experiments.run_fmnist_flower \
  --output docs/experiments/fmnist-flower-2026-09-28 \
  --clients 4 --aggregators 4 --rounds 1 --partition-rng legacy
```

| 지표 | 초기 checkpoint | 1라운드 |
|---|---:|---:|
| 테스트 정확도 | 88.56% | 88.75% |
| 테스트 오류율 | 11.44% | 11.25% |
| 동일 local update의 평문 fixed-point 평균과 최대 모델 차이 | 0 | 0 |

전체 Flower/AION wall time은 20.39초, 기록된 application JSON payload 합은
88,235,777 bytes다. 이는 단일 CPU에서 8개 프로세스와 학습·모델 인증서를 모두
포함한 수치로, 논문에 보고된 **모델 데이터 제외 통신량이나 RTX4090 시간과 비교하지 않는다**.
라운드별 action 시간과 partition hash는 [원시 결과](./results.json)에 있다.

사용한 알고리즘은 원 artifact와 같은 LeNet5 레이어·61,706 parameters,
Fashion-MNIST 정규화, 클래스별 Dirichlet α=0.5 분할, SGD momentum=0.9,
weight decay=0.0005, batch 64, local epoch 2, learning rate 0.001이다.
하지만 원 artifact의 사전 RNG 소비와 실제 partition 인덱스는 보존하지 않았고,
이 실험의 모집단·참여자는 4명 고정이다. 악성 학습, MGF, round별 N=500에서
q=100 sampling, 60라운드 공격 및 공격 성공률은 아직 연결되지 않았다.
따라서 이 결과는 **Flower 정상 경로의 수치 동등성 smoke test**이며 논문 §7.2의
poisoning 재현 또는 보안성 검증이 아니다.
