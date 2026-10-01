# Fashion-MNIST AION-ASR 10라운드: 공식 Flower Runtime

Flower 1.36.0의 `flwr run`/SuperLink/Ray Simulation Runtime에서 원본
Fashion-MNIST와 고정된 `avg_300.pth` LeNet5 checkpoint를 사용했다.
모집단 N=500, 라운드 참여자 q=100, aggregator 8개, 악성 client 20명,
seed 0, CPU worker 8개로 10라운드를 완료했다. 공격 라운드는 5·7·10이다.
`aion`, 같은 코호트의 평문 `quantized`, `avg`, 평문 artifact-style `mgf`는
각각 별도 Flower run이다. 이번 AION 실행에서는 선택형 HotStuff를 켜지 않았다.

| 라운드 | 공격 | AION 정확도 / ASR | 평문 평균 정확도 / ASR | 평문 MGF 정확도 / ASR |
|---:|:---:|---:|---:|---:|
| 0 | — | 88.56% / 0.39% | 88.56% / 0.39% | 88.56% / 0.39% |
| 4 | — | 88.61% / 0.39% | 88.61% / 0.39% | 88.57% / 0.39% |
| 5 | 예 | 10.03% / 100% | 10.03% / 100% | 88.61% / 0.39% |
| 6 | — | 25.79% / 100% | 25.78% / 100% | 88.61% / 0.39% |
| 7 | 예 | 49.14% / 0% | 49.16% / 0% | 88.65% / 0.39% |
| 9 | — | 72.84% / 0% | 72.84% / 0% | 88.65% / 0.39% |
| 10 | 예 | 10.00% / 100% | 10.00% / 100% | 88.66% / 0.39% |

모든 라운드에서 AION과 동일 코호트 평문 양자화 모델의 최대 절대 오차는
**0**이다. 즉 Flower/AION 집계의 산술적 일치는 확인했지만, 이 설정의
AION만으로 model-replacement 공격을 막지는 못했다. MGF는 각 공격
라운드에서 선택된 10명 중 악성 client를 0명 포함했다. 그러나 이 MGF
경로는 중앙에서 개별 평문 update를 읽는 **별도 대조군**이다. 이를
보안 집계 내부 MGF 구현 또는 AION의 방어 성공으로 해석하면 안 된다.

각 Flower run의 기록 시간은 AION 1647.3초, 평문 양자화 146.2초,
평문 평균 52.5초, 평문 MGF 51.8초다. 이는 각각 별도 CPU run의
wall time이며 암호 연산만의 오버헤드나 논문 하드웨어 성능과 직접
비교할 수 없다. 평가와 환경 준비 시간을 제외한 실행 기록이다.

원시 실행과 입력·모델은 저장소의 `.cache/fmnist/official-10round-seed0`에
있다. [검증 요약](results.json)은 원시 Flower 결과·모델·provenance의
SHA-256을 연결한다. 재실행에는 원본 Fashion-MNIST IDX와 checkpoint,
Flower Simulation·PyTorch CPU가 필요하다.

```bash
OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
python -m experiments.run_fmnist_official \
  --output .cache/fmnist/official-10round-new \
  --population 500 --participants 100 --aggregators 8 --rounds 10 \
  --attack-clients 20 --workers 8 --modes aion quantized avg mgf \
  --partition-rng legacy
python -m experiments.export_fmnist_official \
  --source .cache/fmnist/official-10round-new \
  --output docs/experiments/fmnist-flower-official-ten-round-new
```

이 결과는 60라운드 논문 곡선·복수 seed를 대체하지 않는다. 참여자 선정은
CCS/VRF 대신 사전 확정 2인 privacy group 기반이며, 원 artifact의 사전 RNG
소비까지 같은 partition은 아니다. 공격용 test 이미지가 공격 학습과 ASR
평가에 재사용되고, MGF의 보안 집계 내 적용·검증된 LWE-HPRF 보안성·
부분 동기 HotStuff 진행 보장은 이 결과로 증명되지 않는다.
