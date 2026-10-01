# FMNIST/LeNet5 Flower 공격 실험: N=500, q=100 첫 라운드

공식 Fashion-MNIST와 SHA-256 고정 `avg_300.pth`에서 시작해 논문 입력 검증
실험의 참가자 규모인 모집단 N=500, 라운드 참여 q=100, 악성 client 20명,
aggregator 8개로 Flower `ServerApp`/`ClientApp` 한 라운드를 완료했다.
8개 로컬 worker 프로세스가 508개 논리 identity를 실행했고,
100개 서명 update는 각 aggregator에 단계별로 전달했다.

| 지표 | 초기 checkpoint | 공격 1라운드 |
|---|---:|---:|
| 정상 테스트 정확도 | 88.56% | 10.03% |
| 테스트 오류율(TER) | 11.44% | 89.97% |
| trigger 공격 성공률(ASR) | 0.390625% | 100% |

공식 [artifact 파일럿](../fmnist-artifact-pilot-2026-09-13/report.md)의
평문 평균 첫 공격 라운드는 정확도 10.11%·ASR 100%였다. 이번 Flower 결과는
**공격 효과와 규모가 유사한 정상/악성 학습 경로**를 확인한 것이지,
동일 update·partition으로 bitwise 재현한 값은 아니다. 모집단 분할은 원본과
같은 클래스별 Dirichlet α=0.5·반올림 알고리즘으로 59,941장을 배정했지만,
사전 RNG 소비와 샘플 인덱스는 같다고 입증하지 않았다. 선택도 원본의 개별
client sampling 대신 사전 확정 2인 privacy group 단위다.

실행 명령:

```bash
OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
PYTHONPATH=/tmp/trustlessfl-torch:/tmp/trustlessfl-test-pkgs:. \
python3 -m experiments.run_fmnist_flower \
  --output /tmp/aion-fmnist-paper-scale-20260928-1 \
  --population 500 --clients 100 --aggregators 8 --workers 8 --rounds 1 \
  --attack-clients 20 --force-attack-rounds 1 --attack-steps 120 \
  --no-baseline --timeout 300 --partition-rng legacy
PYTHONPATH=. python3 -m experiments.export_fmnist_run \
  --source /tmp/aion-fmnist-paper-scale-20260928-1/results.json \
  --output docs/experiments/fmnist-flower-paper-scale-2026-09-28
```

[원시 결과](./results.json)의 SHA-256은 [export 기록](./export.json)에 있다.
Flower 구간 wall time은 252.57초다. 이는 로컬 CPU worker 8개에서
노드 시작·학습·집계를 포함하고, 사전 provisioning/partition 준비와 사후
평가는 제외한다. 논문 RTX4090/i9-14900KF 절대 시간과 비교하지 않는다.

application JSON payload 총합은 2,614,843,601 bytes(약 2.61GB)다.
그중 `train` 467.39MB, `stage_update` 1,959.22MB가 대부분이다.
현재 구현은 모든 aggregator에 각 서명 update를 보내므로, 논문의
collect-aggregate-transfer 및 **모델 데이터 제외** 통신 지표를 재현하지
못한다. 이것은 성능 우위의 증거가 아니라 현재 전송 구조의 비용이다.

이번 실행은 공격이 있는 첫 라운드의 *무방어* AION-ASR 집계다. MGF는 꺼져
있고, 60라운드·50% 확률의 공격 일정, poison ratio sweep, ACORN/Flame
대조군은 아직 실행하지 않았다. 100개 client의 별도 평문 fixed-point
오차 검사는 이 실행에서 생략했으며 작은 규모의
[동적 참여 실험](../fmnist-flower-dynamic-2026-09-28/report.md)에서 2라운드
오차 0을 확인했다. 이를 q=100의 오차 검증으로 확대 해석하지 않는다.
마스킹 backend도 검증된 LWE-HPRF가 아닌 연구용 대체이므로 이 결과로
논문의 privacy 보장을 주장하지 않는다.
