# 동일 MLP의 중앙집중 학습 진단

실행일: 2026-09-13. 공식 Flower Runtime 학습 및 수치 검증 **통과**.

결론: 모델 구조를 변경하지 않고 공개 train 데이터를 합쳐 학습하니 test macro-F1이
**89.17 ± 0.48%**로, 기존 동일 가중 평균 FL의 **58.36 ± 0.79%**보다 높았다.
따라서 현재 낮은 FL 성능을 단순히 “이 작은 MLP의 표현력이 부족하다”로 설명할 수 없다.
그러나 분포 이질성, local steps, 집계 빈도, 샘플/클라이언트 가중치 효과를 아직 분리하지 않았으므로
“FedAvg 자체가 원인” 또는 “non-IID가 유일한 원인”이라고 단정하지 않는다.

## 통제한 조건

- 공개 V2 파일 8개, 입력 31개, 동일 feature/label 순서 및 원본 hash.
- 기존 중복 특징 그룹 분할을 변경하지 않음: train 102,509 / validation 34,227 / test 34,317.
  기존 평문 FL의 원본 `split.npz`와 split/group/client 배열이 정확히 같은지 exporter에서 검증했다.
- 기존 NumPy float64 MLP 31→128(ReLU)→9, 5,257 parameters와 `train_delta`를 그대로 사용.
- He 초기화 seed 42·43·44, cross-entropy, SGD learning rate 0.1, batch 128,
  momentum/weight decay/FedProx/poisoning 없음. 새 학습률 탐색이나 모델 변경 없음.
- 중앙집중은 전체 train을 30 epochs 학습한다. 기존 FL의 10 rounds × local 3 epochs와
  **샘플당 학습 횟수**를 맞췄다. 3 epochs마다 checkpoint·train/validation/test를 평가한다.
- 중앙집중의 10개 구간은 FL 통신 라운드가 아니라 진행 기록 단위다. SGD momentum이 없으므로
  유지해야 할 optimizer 상태는 없다. batch 난수는 `SeedSequence([seed, 1, 0, step])`로 구간마다 생성한다.
- 매 구간 이어서 학습하며 각 seed만 공통 초기 모델에서 새로 시작한다.
- 모델 선택은 고정된 마지막 epoch 30이다. test 결과로 하이퍼파라미터나 checkpoint를 선택하지 않았다.

중앙집중의 글로벌 모델은 모든 minibatch를 연속해서 반영하지만 FL은 로컬 학습 후 10번 평균낸다.
따라서 샘플 노출 수가 같다고 글로벌 모델의 업데이트 횟수·optimizer 경로가 같지는 않다.
중앙집중 목적함수는 샘플별 평균이고 기존 FL은 클라이언트별 동일 가중 평균이라는 차이도 있다.
이 비교는 현재 학습 구성의 차이를 진단하는 것이며 한 가지 원인만 분리한 실험은 아니다.

## 결과

모든 값은 %, seed 3개의 평균 ± 표본 표준편차다. 마지막 epoch/round를 비교했다.

| 방법 | Test macro-F1 ↑ | 정상 오탐률 ↓ | 악성 미탐률 ↓ | 최저 장치 F1 ↑ |
| --- | ---: | ---: | ---: | ---: |
| 기존 FL, 동일 가중 평균 | 58.36 ± 0.79 | 85.33 ± 0.50 | 1.73 ± 0.01 | 43.73 ± 0.44 |
| 동일 MLP, 중앙집중 | **89.17 ± 0.48** | **15.16 ± 2.65** | 2.35 ± 0.30 | **81.23 ± 1.18** |

F1은 약 30.81 percentage points 증가했지만 악성 미탐률은 약 0.62 pp 높아졌다.
중앙집중의 정상 오탐률 15.16%도 실제 Endpoint 탐지기로 충분하다고 보기는 어렵다.
낮은 악성 미탐률만으로 오탐률 85%인 FL을 더 좋은 탐지기로 해석하지 않는다.

| Seed | Train F1 | Validation F1 | Test F1 | Test 정상 오탐률 | Test 악성 미탐률 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 42 | 89.22 | 88.11 | 88.67 | 15.51 | 2.64 |
| 43 | 90.15 | 89.39 | 89.62 | 12.35 | 2.36 |
| 44 | 89.68 | 88.76 | 89.22 | 17.61 | 2.05 |

Train/validation/test의 차이가 작고 마지막 구간까지 validation F1이 상승했다.
이 관측은 심한 train-only 과적합보다는 현재 조건에서 학습이 더 진행될 여지가 있음을 시사한다.
하지만 학습 연장이나 optimizer 변경을 실행해 확인한 것은 아니다.

## 실제 실행과 검증

- `flwr run`으로 공식 Flower Simulation Runtime/RayBackend 실행.
- 공개 train 데이터를 합쳐 읽는 가상 ClientApp 1개와 ServerApp 1개. 보안집계가 아닌 중앙집중 진단이다.
- Flower 1.36.0, Ray 2.55.1, NumPy 2.5.0, CPU float64, BLAS/OMP/MKL thread 1.
  worker당 CPU 1, Ray CPU 자원 한도 2, 가상 노드는 하나. GPU 사용 없음.
- Run ID `5726795482076255477`, 상태 `finished:completed`.
- FAB SHA-256 `99aafe247a1a52b1a86fc1f08449435301be985b25b45e8ab497f254a556aee1`.
- Flower 보고 실행 시간 29.92초. 기존 NumPy FL과 실행 시간 비교나 가속비 주장을 하지 않는다.
- 3 seeds × 11 checkpoints의 모델이 별도 순차 NumPy 대조 계산과 **정확히 일치**했다.
  모든 checkpoint의 train/validation/test pooled 및 장치별 지표도 정확히 일치했다.
- 전체 테스트 75 passed, GPU용 2 tests skipped. 새 테스트는 train-only 데이터 접근,
  응답 직렬화, 노드별 상태 유지, 전체/장치별 평가 표본 수, 잘못된 노드·응답 거부를 확인한다.

FL 대조군은 기존 3-seed/10-round NumPy 결과다. 이전 공식 Runtime 3-round 검증에서 동일 학습기의
수치 동등성을 확인했지만, 3 seeds × 10 rounds FL을 이번 턴에 공식 Runtime으로 재실행한 것은 아니다.
따라서 여기서는 학습 품질의 진단용 대조로만 사용하며 서로 다른 실행기의 시간을 비교하지 않는다.

## 코드 및 재실행

```bash
uv sync --extra simulation --cache-dir .cache/uv
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  .venv/bin/python -m experiments.run_endpoint_central \
  --output .cache/endpoint/runs/central-new --seeds 42 43 44 --steps 10
.venv/bin/python -m experiments.export_endpoint_central \
  --run .cache/endpoint/runs/central-new --output docs/experiments/central-new
```

출력 경로는 새로 지정한다. 로컬 포트 권한이 필요하며, 준비만 완료한 경우 `--phase run`으로 실행한다.
기존 Endpoint/GPU/AION 경로는 보존했고 공용 Runtime launcher에 가상 노드 수 설정만 추가했다.

- [학습 앱](../../../trustlessfl/endpoint_central_flower.py), [실행·검증](../../../experiments/run_endpoint_central.py),
  [결과 내보내기](../../../experiments/export_endpoint_central.py).
- 원본: `.cache/endpoint/runs/central-flower-2026-09-13/`.
- 명령·로그·최종 상태: `attempt-2018d864/`.
- 모든 모델·지표: `runtime-results/run-5726795482076255477/`.
- 공개 결과: [results.json](./results.json), [summary.json](./summary.json), [provenance.json](./provenance.json).
- 논문 코드 대조: [소스 감사](../../crowdsensing-source-audit.md).

## 다음에 분리할 실험

1. 동일 train/test를 유지하고 자연 파일별 FL 분할과 합성 IID train 분할을 비교한다.
2. 샘플 노출을 맞춰 local 3 epochs × 10 rounds와 local 1 epoch × 30 rounds를 비교한다.
3. 별도 조건으로 Adam 등 학습 설정을 비교한다. 논문 저장소의 기본값을 가져왔다고 논문 재현이라 부르지 않는다.

원본 특징의 사전 정규화·선택, 비시간적 평가, 중복 행 가중치 유지 등의 데이터 한계는 이전과 동일하다.
이번 결과는 AION의 보안·정확도 개선, 논문 수치 재현 또는 새 FL 방어 기법의 증거가 아니다.
