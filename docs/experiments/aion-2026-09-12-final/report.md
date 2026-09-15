# AION-ASR Flower 구현 실험 결과

## 결론

현재 연구용 구현으로 정상 학습과 검증 가능한 ASR 집계는 동작한다. 정상 조건 7개를 각각 3회 실행한 21회 모두, **모든 라운드의 모델이 같은 양자화 규칙을 사용한 clear aggregation과 정확히 일치**했다. 반면 유효한 서명을 가진 client의 poisoned update는 차단하지 못했다. 따라서 이번 결과를 악의적 client에 대한 poisoning 방어 또는 논문 전체 보안성 재현으로 해석하면 안 된다.

최종 실행은 총 29회이며 25회 집계를 완료하고 4회 예상대로 중단했다. 완료한 25회에는 poisoning을 받아들인 1회도 포함된다. 별도로 기존 pytest 29개가 통과했다.

## 환경과 측정 방법

- 실행: 2026-09-12 18:37:29–18:38:19 KST
- OS: WSL2, Linux 6.6.87.2, x86_64, glibc 2.39, 논리 CPU 12개
- Python 3.12.12, Flower 1.36.0, NumPy 2.5.0, cryptography 46.0.7
- BLAS/OMP/MKL thread 수: 각각 1개
- transport: Flower Message/protobuf를 local multiprocessing pipe로 운반하는 `ProcessGrid`
- Flower ServerApp 1개, client/aggregator 각각 별도 프로세스
- 학습 데이터: silo마다 32개 합성 선형 회귀 sample, `seed=1000+partition`
- 별도 평가 데이터: silo마다 256개 합성 sample, `seed=50000+partition`
- 양자화: 소수 4자리, client별 동일 가중 평균, 각 실험마다 새 task ID와 암호 key
- 정상 조건마다 3회 순차 실행, 공격/장애 조건마다 1회 실행

전체 시간은 프로세스 생성부터 종료까지이며, 사전 identity provisioning·clear baseline 계산과 사후 오차 평가는 제외한다. 프로세스 cold start와 초기화를 포함하며 별도 warmup은 없다. 최종 측정 중 다른 테스트를 함께 실행하지 않았다. WSL/호스트 부하까지 고정한 환경은 아니므로 최소·최대값도 함께 제시한다.

통신량은 **전송한 canonical JSON 요청 및 성공 응답의 application payload 합**이다. 모델, 암호화된 share, 반복 전달된 서명·증거를 포함한다. protobuf envelope, pipe/TCP framing, 오류 응답 바이트는 제외한다. 따라서 네트워크 사용량 실측이나 논문의 model 제외 overhead와 동일한 지표가 아니다.

## 1. 학습 수렴과 집계 정확성

client 4개, aggregator 4개, `f=1`, dimension 8, learning rate 0.1로 30라운드를 3회 실행했다.

| 라운드 | AION 경로 학습 MSE | clear fixed-point 학습 MSE |
|---:|---:|---:|
| 0 | 2.393117963 | 2.393117963 |
| 1 | 1.903561305 | 1.903561305 |
| 5 | 0.779033732 | 0.779033732 |
| 10 | 0.268983758 | 0.268983758 |
| 20 | 0.038591247 | 0.038591247 |
| 30 | 0.006893527 | 0.006893527 |

- 학습 MSE: **2.393118 → 0.006894**, 약 99.71% 감소
- 별도 평가 MSE: **2.870153 → 0.010754**
- 30라운드 전체에서 clear fixed-point 대비 최대 모델 절대 오차: **0**
- 양자화를 적용하지 않은 float baseline 대비 최대 모델 절대 오차: 약 **7.41 × 10⁻⁵**
- 전체 실행시간 중앙값: **5.138초**, 최소 5.122초, 최대 5.139초

이는 선택한 연구용 mask backend에서 집계 및 DMC/DMR 오차 처리가 이 데이터에 대해 정상 작동함을 보여준다. HPRF의 cryptographic privacy가 입증된 것은 아니다. 작은 합성 선형 회귀 실험이므로 실제 딥러닝 task의 정확도나 수렴 속도에 일반화하지 않는다.

## 2. 규모별 실행시간과 payload

아래 조건은 모두 5라운드, learning rate 0.01이며 각 3회 측정했다. aggregator 4개는 `f=1`, aggregator 7개는 `f=2`다.

| client | aggregator | 차원 | 전체 시간 중앙값 [최소–최대], 초 | 단계 호출 합의 라운드 중앙값, ms | 전체 payload 중앙값, KiB |
|---:|---:|---:|---:|---:|---:|
| 2 | 4 | 8 | 1.226 [1.209–1.254] | 142.68 | 456.76 |
| 4 | 4 | 8 | 1.380 [1.376–1.396] | 143.43 | 590.21 |
| 8 | 4 | 8 | 1.751 [1.723–1.816] | 147.30 | 863.54 |
| 4 | 7 | 8 | 2.226 [2.218–2.240] | 258.11 | 1,469.05 |
| 4 | 4 | 128 | 2.134 [1.727–2.287] | 195.68 | 1,434.77 |
| 4 | 4 | 1,024 | 1.980 [1.746–2.101] | 192.60 | 7,754.88 |

라운드 시간은 `train`, `prepare`, `share`, `finalize`, `commit` 호출의 경과시간 합이다. phase 사이 coordinator 처리와 프로세스 기동·초기화 시간을 제외하므로 전체 시간을 라운드 수로 나눈 값과 다르다.

모든 조건에서 모든 라운드의 모델은 clear fixed-point baseline과 정확히 일치했다. 단, client 수나 차원이 달라지면 학습 데이터 분포/문제가 달라지므로 조건 간 MSE 절대값으로 품질을 비교하지 않는다.

dimension 128과 1,024 사이 실행시간 순서가 뒤집히고 범위가 겹친다. 이 정도 반복 횟수와 짧은 실행에서는 프로세스 기동 및 환경 변동이 영향을 미치므로 “차원이 커지면 더 빠르다”는 결론을 내릴 수 없다. payload 증가는 일관되게 관측됐다.

기본 4-client/4-aggregator/8-dimension 조건에서 phase별 평균 호출 시간은 다음과 같다. 초기화 phase는 3회, 라운드 phase는 15회 관측의 평균이다.

| phase | 평균 호출 시간, ms |
|---|---:|
| hello (프로세스 readiness 포함) | 279.93 |
| enroll | 34.91 |
| initialize | 185.20 |
| train | 9.48 |
| prepare | 8.46 |
| share | 7.72 |
| finalize | 118.53 |
| commit | 8.01 |

`finalize`가 라운드 단계 호출 합의 약 78%를 차지한다. 코드상 이 단계는 aggregated commitment/share 검증 및 reconstruction을 수행한다. 병목 후보이지만 함수별 CPU profiler를 실행한 것은 아니므로 개별 암호 연산의 비용으로 단정하지 않는다.

## 3. 장애 및 악의적 메시지

공통 조건은 client 4개, aggregator 4개, `f=1`, dimension 8, learning rate 0.1, 3라운드다. 공격은 2라운드에 주입했다. aggregator 응답 억제는 2라운드부터 지속한다.

| 주입 상황 | 관측 결과 | 마지막 완료 라운드 | clear baseline과의 관계 |
|---|---|---:|---|
| aggregator 1개 요청 억제 | 나머지 정족수로 완료 | 3 | 모델 오차 0 |
| aggregator 2개 요청 억제 | 정족수 부족으로 중단 | 1 | 공격 라운드 결과 미확정 |
| client 1개 update 요청 억제 | 고정 cohort 불충족으로 중단 | 1 | 공격 라운드 결과 미확정 |
| aggregator가 틀린 aggregate share에 정상 서명 | 잘못된 share를 제외하고 완료 | 3 | 모델 오차 0 |
| aggregator가 조작한 model 결과에 정상 서명 | 정상 결과의 정족수로 완료 | 3 | 모델 오차 0 |
| 서버가 한 client에 변조한 이전 model/certificate 전달 | client 검증 실패 후 전체 중단 | 1 | 공격 라운드 결과 미확정 |
| 1라운드 signed update를 2라운드에 재전송 | round/parent 검증 실패 후 중단 | 1 | 공격 라운드 결과 미확정 |
| client가 `+20` poisoned update에 정상 서명 | **조작된 입력을 포함해 완료** | 3 | 공격 라운드 모델 최대 편차 5.0 |

틀린 share는 값을 1만큼 바꿔 악의적 aggregator 자신의 key로 다시 서명했다. 틀린 결과는 model의 첫 좌표를 1만큼 바꿔 다시 서명했다. 단순한 서명 손상만 검사한 실험이 아니다.

응답 억제는 harness가 요청을 즉시 건너뛰는 방식이다. 실제 process crash, TCP 단절, timeout 대기, view-change 또는 네트워크 partition 복구를 검증한 것은 아니다. 각 공격 유형 1회 관측이므로 모든 악의적 전략에 대한 보장을 제공하지 않는다.

서버 model 변조 시 client는 요청을 거부했으나 coordinator의 최종 오류는 `fixed-cohort client dropout`으로 보고됐다. 거부와 네트워크 탈락을 구분하는 진단은 현재 부족하다. 실험 중 이 동작은 변경하지 않았다.

## 4. Poisoning 방어의 실제 한계

client 4개 중 client-0의 2라운드 update 첫 좌표에 **+20**을 더하고 자신의 key로 유효한 서명을 만들었다. 기존 mask는 유지했고 field 형식도 유효하다. 따라서 이는 서명 위조 공격이 아니라 악의적 client 자신의 입력 조작이다.

| 라운드 | 정상 학습 MSE | poisoning 학습 MSE |
|---:|---:|---:|
| 0 | 2.393118 | 2.393118 |
| 1 | 1.903561 | 1.903561 |
| 2 | 1.517410 | 22.207874 |
| 3 | 1.212265 | 18.374236 |

- 최종 학습 MSE: **1.212265 → 18.374236**, 정상 대비 **15.16배**
- 최종 별도 평가 MSE: **1.503151 → 20.610547**, 정상 대비 약 **13.71배**
- 2라운드 평균 model 첫 좌표 편차: **20 / 4 = 5**
- 모든 aggregator는 해당 입력이 포함된 같은 집계 결과에 합의했다.

이 결과는 “입력을 정확히 집계하는 것”과 “입력 자체가 학습에 유해한지 검증하는 것”이 별개임을 보여준다. 현재 wire 경로에 MGF 또는 학습 입력 정당성 proof가 없으므로, 정상 서명을 가진 poisoned update를 방어하지 못한다. 이 실험은 원 논문의 MGF를 적용한 poisoning 방어율 실험이 아니다.

## 해석 범위와 후속 우선순위

1. **입력 검증 통합:** 위 poisoning이 통과하는 문제를 해결할 검증 계층을 명세해야 한다. modular residue에 단순 L2 norm을 계산하는 방식으로 MGF를 연결하면 안 된다.
2. **실제 HPRF:** 현재 rounded-linear 연구 backend의 계산 정확성을 privacy 보장과 구분하고, 보안 parameter가 명시된 HPRF를 검증해야 한다.
3. **탈락 허용:** 고정 cohort의 client 하나만 응답하지 않아도 중단한다. AMR/CCS 등 안전한 참여 집합 변경 설계가 필요하다.
4. **네트워크·BFT 실험:** 실제 SuperLink/TLS, 지연·bandwidth·crash, HotStuff view-change의 동작을 별도로 구현·검증해야 한다.
5. **실제 FL 평가:** 현재는 synthetic regression이다. 실제 데이터셋·model·공격 전략·분포 편차에서 재평가해야 한다.

## 재현 및 원시 결과

```bash
uv sync
FLWR_TELEMETRY_ENABLED=0 OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  uv run python -m experiments.run_aion \
  --output docs/experiments/aion-new-run --repeats 3

uv run pytest -q
```

성능 측정과 pytest는 순차로 실행한다. 출력 경로는 새 디렉터리여야 한다.

- [조건별 요약 CSV](./summary.csv)
- [전체 관측값·phase 시간·환경·source hash JSON](./results.json)
- [실험 실행기](../../../experiments/run_aion.py)
- [실험 사용법](../../../experiments/README.md)
- [구현 범위와 원 논문 대비 차이](../../aion-flower-implementation.md)

JSON의 `expectation_met=true`는 예상한 동작과 관측이 일치한다는 의미다. poisoning의 경우 예상 동작이 “공격이 받아들여짐”이므로 이 값이 true여도 공격 방어에 성공했다는 뜻이 아니다. 초기 예비 실행은 일부 pytest 실행과 겹쳤으며 본 보고서의 시간 수치에는 사용하지 않았다.
