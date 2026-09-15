# 공개 코드 학습 설정 이식 테스트

실행일: 2026-09-13. 공식 Flower Runtime / RTX 5060 실행 및 checkpoint 검사 **통과**.

공개 코드의 작은 MLP·Adam 설정을 적용한 중앙집중 학습에서 기존 독립 test macro-F1은
**93.43 ± 0.47%**였다. 같은 독립 분할을 쓴 이전 중앙집중 SGD의 **89.17 ± 0.48%**보다 높다.
별도의 notebook식 행 분할·validation 재평가는 **95.41 ± 0.39%**였으나 독립 test 성능이 아니다.

이 실험은 **공개 학습 설정을 PyTorch/Flower에 이식한 중앙집중 실험**이다.
원본 Lightning notebook 직접 실행, DFL/FedAvg 실험, AION 실험 또는 논문 Table 6 재현 완료를 의미하지 않는다.

## 적용한 공개 설정과 차이

출처는 [training/mlp.py](https://github.com/Cyber-Tracer/iot-feature-engineering/blob/bf04ddfa010c3de5a003bd087497b9f9184e58e9/training/mlp.py),
[training30.ipynb](https://github.com/Cyber-Tracer/iot-feature-engineering/blob/bf04ddfa010c3de5a003bd087497b9f9184e58e9/training/training30.ipynb)다.
커밋 `bf04ddfa010c3de5a003bd087497b9f9184e58e9`의 로컬 감사본 SHA-256을 확인하고 사용했다.

| 항목 | 이번 공개 설정 이식 |
| --- | --- |
| 모델 | 31→30→30→9, ReLU 두 개, 2,169 parameters |
| 초기화 | PyTorch Linear 기본 초기화, seed 42·43·44 |
| 출력·손실 | 공개 forward처럼 log-softmax 후 CrossEntropyLoss |
| Optimizer | Adam, lr=0.01, betas=(0.9,0.999), eps=1e-8, weight decay=0 |
| Optimizer 상태 | 각 seed의 전체 학습 동안 유지; epoch마다 재생성하지 않음 |
| 정밀도 | float32, TF32/AMP 사용 안 함 |
| Batch | 500, 마지막 작은 batch 포함 |
| 학습 길이 | 최대 150 epochs, validation 기준 patience 5 조기 종료 |
| 선택 모델 | validation monitor가 가장 높았던 첫 checkpoint |
| 실행 | 공식 Flower Runtime, 중앙집중 가상 노드 1개, GPU worker 1개 |

원본과 달리 명시적으로 고정한 사항:

- 기존 공개 V2의 31개 입력·171,053행을 사용한다. 원본 notebook이 읽는 CSV와 동일 artifact인지 미확정이다.
  결측 특징을 추가하거나 행 수를 복제하지 않았다. 기존 정규화를 유지하고 추가 scaling은 하지 않았다.
- seed와 shuffle generator를 고정했다. seed를 지정하지 않은 원본 notebook의 RNG 순서와 같다고 주장하지 않는다.
- 원본 Lightning의 `Validation/Accuracy` batch logging을 그대로 재현하지 않고,
  **epoch 전체 혼동행렬의 macro recall(클래스별 accuracy 평균)**을 monitor로 명시했다.
  엄격한 증가만 개선으로 인정하고 min_delta=0, patience=5다. macro-F1/test는 checkpoint 선택에 쓰지 않는다.
- DataLoader worker·Lightning callback·TensorBoard는 사용하지 않는다. 모델·목적함수·Adam 설정을 이식했다.
  `foreach=False`와 deterministic algorithms를 명시했다.
- 원본 코드의 default FL batch는 32지만, 여기서는 **중앙집중 notebook의 batch 500**을 사용했다.

따라서 “공개 코드와 완전히 같은 실행”이 아니라, 확인 가능한 학습 설정을 가져온 통제 실험이다.
자세한 원본 감사는 [코드 감사 문서](../../crowdsensing-source-audit.md)를 참고한다.

## 평가 조건 A: 기존 독립 test 유지

- 기존과 동일한 특징 그룹 분할: train 102,509 / validation 34,227 / test 34,317.
- 이전 중앙집중 실험과 원본 audit 및 split/group/client 배열이 정확히 같은지 exporter에서 확인했다.
- test와 train의 행 겹침 및 정확한 특징 그룹 겹침은 모두 0이다.
- 학습 함수는 train/validation만 받으며, 독립 test 파일은 checkpoint 선택 완료 후 읽는다.
- 3 seeds 모두 test 결과로 하이퍼파라미터를 재선택하지 않았다.

모든 값은 %, seed 3개의 평균 ± 표본 표준편차다.

| 중앙집중 학습 설정 | Test macro-F1 ↑ | 정상 오탐률 ↓ | 악성 미탐률 ↓ |
| --- | ---: | ---: | ---: |
| 기존 31→128→9 / SGD / batch 128 / 30 epochs 고정 | 89.17 ± 0.48 | 15.16 ± 2.65 | 2.35 ± 0.30 |
| 공개 설정 31→30→30→9 / Adam / batch 500 / validation 선택 | **93.43 ± 0.47** | **8.94 ± 3.81** | **1.14 ± 0.70** |

모델은 더 작아졌지만 평균 지표가 개선됐다. 이번 구성 변경 묶음의 효과이며
**Adam 단독 효과, 모델 구조 단독 효과 또는 통계적 유의성의 증거는 아니다.**
학습률·초기화·정밀도·batch·학습 길이·checkpoint 선택도 바뀌었다.
기존 SGD는 마지막 epoch를, 이번에는 validation으로 선택한 checkpoint를 평가한다.

| Seed | 선택 epoch | 종료 epoch | 선택 모델 Train F1 | Validation F1 | 독립 Test F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 42 | 29 | 34 | 95.17 | 93.67 | 93.84 |
| 43 | 21 | 26 | 94.25 | 92.90 | 92.92 |
| 44 | 18 | 23 | 94.34 | 93.14 | 93.54 |

선택 모델보다 5 epochs 뒤까지 개선이 없으면 종료했다. 150 epochs까지 강제로 학습한 결과가 아니다.
정상 오탐률 8.94%는 여전히 운영상 높은 수치이며 완성된 Endpoint 탐지기로 해석하지 않는다.

## 평가 조건 B: 행 단위 분할·validation 재평가 참고

공개 notebook의 평가 형태를 따로 확인했다. V2 전체를 행 단위로 섞어
train 136,842 / validation 34,211의 80/20으로 나눈다. 원본에 없던 split seed 42를 명시적으로 고정했다.
세 학습 seed 사이에 이 분할은 동일하다. validation으로 checkpoint를 선택한 후
**같은 validation 자료를 다시 평가**한다. 이 조건에는 별도 독립 test가 없다.

| 참고 조건 | 재평가 macro-F1 | 정상 오탐률 | 악성 미탐률 |
| --- | ---: | ---: | ---: |
| 행 단위 분할 + validation 재사용 | 95.41 ± 0.39% | 5.73 ± 0.31% | 0.69 ± 0.14% |

선택/종료 epochs: seed 42는 46/51, seed 43은 31/36, seed 44는 32/37.
각 재평가 F1은 95.85%, 95.18%, 95.18%다.

중복 감사:

- 행 인덱스 자체의 train/evaluation 중복은 0.
- train과 evaluation에 함께 등장하는 정확한 특징 그룹은 **22,631개**.
- evaluation 34,211행 중 **34,171행(99.883%)**은 train에 같은 특징 벡터가 있다.
- 따라서 이 수치를 새로운 특징 그룹에 대한 일반화 성능이나 독립 test 성능이라고 부르지 않는다.
- 조건 A보다 train 표본 수도 많고 평가 표본·분할·선택 절차가 다르므로,
  두 F1 차이를 전부 중복 누수의 크기라고 해석할 수도 없다.

이 관측은 **이번 V2 참고 분할**의 결과다. 논문 실험이 같은 중복을 가졌다고 확정한 것이 아니며,
논문의 약 96%를 재현하거나 검증했다는 주장도 하지 않는다.
조건 B는 조건 A의 기존 test 중 일부를 자체 train에 포함할 수 있지만 완전히 별도 실행·모델이다.
조건 A의 train/test 파일·모델 선택에는 영향을 주지 않았다.

## 실행 증거 및 검사

- Run ID: `15086316814512081528`, 상태 `finished:completed`.
- Flower 1.36.0, Ray 2.55.1, NumPy 2.5.0, PyTorch 2.8.0+cu128.
- RTX 5060 한 개, 전체 CPU 1/GPU 1, worker당 CPU 1/GPU 1, 가상 노드 1개.
- 여섯 학습 호출 모두 worker PID `2556339`, `cuda:0`, `torch.float32`로 확인됐다.
- FAB SHA-256: `030148e6acad2b850dc4c76256c85da27d2d5e5910b85b74678f151a61b61022`.
- Flower 실행 시간 102.43초. 다른 모델·평가 빈도·epoch 수가 다른 과거 CPU/GPU 테스트와 속도 비교하지 않는다.
- 초기 모델은 같은 seed의 PyTorch 기본 초기화와 정확히 일치했다.
- 기록한 monitor에서 선택 epoch가 첫 최대값인지 검사했다.
- 선택 checkpoint를 CPU에서 재평가해 validation/최종 평가 혼동행렬의 정확한 일치를 확인했다.
  GPU/CPU cross-entropy 최대 차이는 약 1.49×10⁻⁸로 사전 허용값 1×10⁻⁵ 이하였다.
- 전체 학습을 CPU로 다시 수행해 GPU와 학습 궤적이 같음을 검증한 것은 아니다.
- 단위·회귀 테스트 79 passed, 별도 GPU용 2 tests skipped.
  모델/손실 구조, checkpoint 복원, 반복 결정성, 조기 종료 tie 처리, 분할 분리를 검사했다.

첫 제출은 앱 이름 32자 제한 위반으로 **학습 시작 전에** 실패했다.
이름을 수정해 새 `-v2` 출력에서 실행했으며 실패 로그도 보존했다. 학습 결과를 보고 조건을 바꾸지 않았다.

## 구현·재실행·증거 위치

```bash
uv sync --extra simulation --extra gpu --cache-dir .cache/uv
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  .venv/bin/python -m experiments.run_endpoint_public \
  --output .cache/endpoint/runs/public-recipe-new --seeds 42 43 44
.venv/bin/python -m experiments.export_endpoint_public \
  --run .cache/endpoint/runs/public-recipe-new --output docs/experiments/public-recipe-new
```

독립 test 조건만 실행하려면 `--profiles group-holdout`을 사용한다.
새 출력 경로와 GPU/로컬 포트 권한이 필요하다. 준비 후에는 `--phase run`으로 실행할 수 있다.
staging은 기존 `.cache/endpoint/source-audit-2026-09-13/`의 고정 소스 audit도 확인한다.

- 학습기: [endpoint_public.py](../../../trustlessfl/endpoint_public.py).
- 앱: [endpoint_public_flower.py](../../../trustlessfl/endpoint_public_flower.py).
- 준비/실행/검증: [run_endpoint_public.py](../../../experiments/run_endpoint_public.py).
- 결과 내보내기: [export_endpoint_public.py](../../../experiments/export_endpoint_public.py).
- 원본: `.cache/endpoint/runs/public-recipe-2026-09-13-v2/`.
- 명령·로그·상태: `attempt-1b51b012/`.
- 모델·학습 곡선: `runtime-results/run-15086316814512081528/`.
- 공개 요약: [summary.json](./summary.json), [curves.json](./curves.json), [provenance.json](./provenance.json).

## 다음 비교의 의미

이 구성으로도 독립 test F1 93%대를 얻었으므로, 지금 단계에서는 MLP를 더 크게 만드는 것보다
**이 학습 구성을 8-client FL에 연결했을 때 유지되는지** 확인하는 것이 의미 있다.
그때는 중앙집중/FL 간 데이터 분할·local epochs·Adam 상태 유지/초기화 정책·집계 가중치를 명시해야 한다.
아직 공개 설정 FL 또는 AION에서 이 성능이 나온 것은 아니다. 기존 AION 구현과 baseline은 수정하지 않았다.
