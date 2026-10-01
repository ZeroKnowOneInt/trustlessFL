# FMNIST N=500/q=100: 공식 Flower Runtime + HotStuff

Flower 1.36.0의 `flwr run`/SuperLink/Ray Simulation Runtime에서 모집단 500명,
라운드 참여자 100명, aggregator 8개, 악성 client 20명으로 첫 공격 라운드를
완료했다. AION 경로는 선택형 HotStuff를 켰으며 roster 및 최종 모델의
커밋 증명을 검사했다. 같은 데이터·참여 일정·학습 설정의 평문 양자화 대조군은
별도 Flower run으로 실행했다.

| 경로 | 공격 1라운드 정확도 | TER | ASR | 실행 시간 |
|---|---:|---:|---:|---:|
| AION + HotStuff | 10.03% | 89.97% | 100% | 604.7초 |
| 평문 양자화 | 10.03% | 89.97% | 100% | 35.5초 |

두 경로의 모든 라운드 모델 최대 절대 오차는 **0**이다. 공격을 막았다는
결과는 아니다. 이 조건은 HotStuff를 켜도 Flower 경로의 계산 결과가
양자화 기준선과 일치한다는 통합 검증이다. CPU worker 2개에서 각각
측정한 wall time으로, 논문의 하드웨어 성능 수치와 직접 비교하지 않는다.

원시 실행은 `/tmp/trustlessfl-fmnist-official-hotstuff-paper-scale-20260929`에
있다. [검증 요약](results.json)은 Flower 결과·모델·입력·소스의 SHA-256을
연결한다. 동일 조건 재실행에는 검증된 원본 Fashion-MNIST IDX 파일과
`avg_300.pth` checkpoint, Flower Simulation 및 PyTorch CPU가 필요하다.

```bash
OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
python -m experiments.run_fmnist_official \
  --output /tmp/trustlessfl-fmnist-official-hotstuff-paper-scale-new \
  --population 500 --participants 100 --aggregators 8 --rounds 1 \
  --attack-clients 20 --attack-rounds 1 --workers 2 --hotstuff \
  --modes aion quantized --partition-rng legacy
python -m experiments.export_fmnist_official \
  --source /tmp/trustlessfl-fmnist-official-hotstuff-paper-scale-new \
  --output docs/experiments/fmnist-flower-official-hotstuff-paper-scale-new
```

여전히 논문 60라운드 곡선이나 복수 seed는 실행하지 않았다. 참여자 선정은
CCS/VRF가 아닌 사전 확정 2인 privacy group 기반이다. 이 실험에는 MGF를
보안 집계 내부에서 적용하지 않았고, 검증된 LWE-HPRF 보안성·부분 동기
HotStuff 진행 보장도 주장하지 않는다.
