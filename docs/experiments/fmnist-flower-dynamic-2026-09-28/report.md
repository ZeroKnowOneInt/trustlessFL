# Fashion-MNIST/LeNet5 Flower 동적 참여·공격 2라운드

공식 Fashion-MNIST/`avg_300.pth`에서 시작해 N=8명의 독립 client identity,
별도 aggregator 4개, 라운드당 q=4명으로 실행했다. `ServerApp`은 사전에
고정한 2인 privacy group 전체를 선택하며, `ClientApp`은 자기 shard와
영속 identity/share 상태를 사용한다. 로컬 `PooledProcessGrid`가 3개 OS
worker에서 12개 논리 노드를 실행했다. 이 pool은 공식 SuperLink/Ray runtime은 아니다.

```bash
OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
PYTHONPATH=/tmp/trustlessfl-torch:/tmp/trustlessfl-test-pkgs:. \
python3 -m experiments.run_fmnist_flower \
  --output docs/experiments/fmnist-flower-dynamic-2026-09-28 \
  --population 8 --clients 4 --aggregators 4 --workers 3 --rounds 2 \
  --attack-clients 2 --force-attack-rounds 1 --attack-steps 120 \
  --partition-rng legacy
```

| 라운드 | 선택 client | 정상 정확도 | TER | 공격 성공률(ASR) | 평문 fixed-point 모델 오차 |
|---|---|---:|---:|---:|---:|
| 0 | checkpoint | 88.56% | 11.44% | 0.390625% | 0 |
| 1 | 0, 1(악성), 4, 5 | 10.00% | 90.00% | 100% | 0 |
| 2 | 2, 3, 4, 5(정상) | 61.68% | 38.32% | 17.1875% | 0 |

전체 wall time 40.42초, application JSON payload 합은 222,602,151 bytes다.
라운드별 action 시간, partition·poison pool hash, 참여 일정은
[원시 결과](./results.json)에 있다. 이것은 모델과 서명 인증서를 포함한 로컬
전송량이며 논문에서 모델을 제외하고 보고한 통신량과 비교하지 않는다.

2인 privacy group 샘플링은 원 논문의 CCS/VRF 구현이 아니고, N=500/q=100도
아니다. 공격 schedule은 강제 지정했으며 원 코드의 50% Bernoulli 60라운드
일정과 다르다. MGF 방어는 이 실행에서 꺼져 있다. 따라서 두 라운드의
오차 0은 **현재 선택 집합에서의 secure/clear 집계 수치 동등성**만 보여준다.
