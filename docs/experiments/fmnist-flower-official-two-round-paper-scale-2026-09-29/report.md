# FMNIST N=500/q=100 두 라운드: 공식 Flower Runtime

Flower 1.36.0의 `flwr run`/SuperLink/Ray Simulation Runtime에서 모집단 500명,
라운드당 100명, aggregator 8개, 악성 client 20명으로 두 라운드를 완료했다.
1라운드에는 model-replacement 공격을 실행하고 2라운드에는 공격을 끄고
사전 확정 2인 privacy group 기반 참여자를 새로 뽑았다. AION과 같은
코호트의 평문 양자화 대조군은 별도 Flower run이다. 이 실행에서는 HotStuff를
끄고 기본 서명 정족수 경로를 사용했다.

| 라운드 | AION 정확도 | TER | ASR | 평문 양자화 모델과 최대 오차 |
|---:|---:|---:|---:|---:|
| 0 (checkpoint) | 88.56% | 11.44% | 0.390625% | 0 |
| 1 (공격) | 10.03% | 89.97% | 100% | 0 |
| 2 (정상) | 28.22% | 71.78% | 100% | 0 |

AION 두 라운드 실행 시간은 402.7초, 평문 양자화 대조군은 40.0초였다
(CPU worker 4개, 별도 run wall time). 매 라운드 모델의 정확한 일치를
검증했다. 2라운드 뒤의 낮은 정확도와 높은 ASR은 이전 공격의 영향이
남았다는 관측이지 AION이 공격을 방어했다는 결과가 아니다.

이 실행에는 결정 후 큰 masked update를 aggregator 영속 상태에서 제거하고
Flower staged-update 사본을 삭제하는 변경이 포함된다. 종료 시 staged-update
파일은 0개였고 aggregator-0의 영속 디렉터리는 약 3.9MB였다. 따라서
논문 규모에서 다음 라운드 진입과 상태 정리가 실제로 동작함을 확인했다.

원시 실행은 `/tmp/trustlessfl-fmnist-official-two-round-paper-scale-20260929`에
있으며, [검증 요약](results.json)은 원본 입력·소스·Flower 결과·모델의
SHA-256을 연결한다. 동일 조건 재실행에는 검증된 원본 Fashion-MNIST IDX,
`avg_300.pth`, Flower Simulation 및 PyTorch CPU가 필요하다.

```bash
OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
python -m experiments.run_fmnist_official \
  --output /tmp/trustlessfl-fmnist-official-two-round-paper-scale-new \
  --population 500 --participants 100 --aggregators 8 --rounds 2 \
  --attack-clients 20 --attack-rounds 1 --workers 4 \
  --modes aion quantized --partition-rng legacy
python -m experiments.export_fmnist_official \
  --source /tmp/trustlessfl-fmnist-official-two-round-paper-scale-new \
  --output docs/experiments/fmnist-flower-official-two-round-paper-scale-new
```

60라운드 곡선, 복수 seed, MGF의 보안 집계 내부 실행, CCS/VRF 참여자 선정,
검증된 LWE-HPRF 보안성과 부분 동기 HotStuff 진행 보장은 이 실험으로
확인되지 않는다.
