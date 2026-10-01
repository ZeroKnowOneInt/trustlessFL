# FMNIST N=500/q=100 첫 공격 라운드: 공식 Flower Runtime

Flower 1.36.0의 `flwr run`/SuperLink/Ray Simulation Runtime에서 모집단
500명, 참여자 100명, aggregator 8개, 악성 client 20명, 첫 공격 라운드
1회를 완료했다. 공식 Fashion-MNIST, SHA-256 고정 `avg_300.pth`,
LeNet5와 원 artifact 유사 model-replacement 공격을 사용했다. 네 집계 경로는
같은 partition·참여 일정·학습 설정으로 **별도 Flower run/FAB**를 실행했다.
이 측정에서 선택형 HotStuff는 꺼져 있고 기본 서명 정족수 집계를 사용했다.

| 집계 경로 | 초기 정확도 / ASR | 공격 1라운드 정확도 / TER / ASR |
|---|---:|---:|
| AION-ASR | 88.56% / 0.390625% | 10.03% / 89.97% / 100% |
| 평문 양자화 | 88.56% / 0.390625% | 10.03% / 89.97% / 100% |
| 평문 평균 | 88.56% / 0.390625% | 10.03% / 89.97% / 100% |
| 평문 artifact-style MGF | 88.56% / 0.390625% | 88.60% / 11.40% / 0.390625% |

AION과 동일 코호트의 평문 양자화 모델은 모든 라운드에서 정확히 일치했다
(최대 절대 오차 0, NPZ SHA-256도 동일). MGF는 q=100에서 원 규칙의
하한 10명으로 선택했고, 선택된 10명에 악성 client는 없었다. 작은 q 실험과
달리 MGF의 소규모 하한 조정은 사용되지 않았다. **MGF는 중앙에서 개별
평문 update를 읽는 별도 대조군**이며, AION 보안 집계 내부에서 MGF가
작동했다는 증거가 아니다.

원시 실행 경로는 `/tmp/trustlessfl-fmnist-official-paper-scale-20260929`이다.
재실행 명령은 다음과 같다(Flower simulation, PyTorch CPU 및 검증된 원본
checkpoint/IDX 데이터 필요).

```bash
OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
python -m experiments.run_fmnist_official \
  --output /tmp/trustlessfl-fmnist-official-paper-scale-new \
  --phase stage --population 500 --participants 100 --aggregators 8 \
  --rounds 1 --attack-clients 20 --attack-rounds 1 --workers 2 \
  --modes aion quantized avg mgf --partition-rng legacy
OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
python -m experiments.run_fmnist_official \
  --output /tmp/trustlessfl-fmnist-official-paper-scale-new --phase run
python -m experiments.export_fmnist_official \
  --source /tmp/trustlessfl-fmnist-official-paper-scale-new \
  --output docs/experiments/fmnist-flower-official-paper-scale-new
```

[검증 요약](results.json)의 SHA-256은
`e82e5896a75991e3ad6e0db992856b35118df91ac424aa048046a4ff1547903f`이다.
원시 `provenance.json`·`verification.json`·Flower 결과·모델의 SHA-256을
기록했지만, 4GB 원시 디렉터리 자체는 저장소에 포함하지 않았다.
임시 디렉터리 삭제 시 원시 로그를 검증하려면 재실행해야 한다.

이 결과는 논문과 **실험 규모 및 첫 공격 라운드 효과가 비슷함**을 보여준다.
원 artifact의 사전 RNG 상태까지 동일한 partition은 아니고, 참여자는
개별 CCS/VRF 대신 사전 확정 2인 privacy group으로 추첨했다. 59,941개
학습 이미지만 배정됐으며, 공격용 test 이미지가 공격 학습과 ASR 평가에
재사용된다. 60라운드 곡선·복수 seed·공격 확률 분포·ACORN/Flame 대조군,
검증된 LWE-HPRF 및 MGF의 보안 집계 내 작동은 이 결과로 확인되지 않는다.
시간도 같은 CPU 장비의 별도 run wall time이며, 논문 하드웨어의 통신·성능
지표와 직접 비교하지 않는다.
