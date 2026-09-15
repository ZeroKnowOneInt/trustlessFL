# Crowdsensing 논문 연결 코드 감사

후속 실행: [공개 MLP·Adam 설정 이식 테스트](./experiments/endpoint-public-recipe-2026-09-13/report.md).
원본 Lightning 환경의 직접 재현이 아니라 설정을 Flower/PyTorch에 옮긴 중앙집중 실험이다.

감사일: 2026-09-13. 코드 실행 없이 파일·노트북 JSON을 읽어 대조했다.
논문 [Code availability](https://www.nature.com/articles/s41597-026-07155-w#code-availability)가 연결한
`Cyber-Tracer/iot-feature-engineering`의 HEAD를 확인하고 다음 커밋으로 고정했다.

`bf04ddfa010c3de5a003bd087497b9f9184e58e9`

## 핵심 결론

**논문 설명, 연결 저장소의 기본 코드, 우리 프로젝트 설정은 서로 완전히 같지 않다.**
논문이 연결한 저장소라는 사실만으로 그 기본값이 논문 Table 6–8을 만든 설정이라고 확정할 수 없다.
논문 본문 기준으로는 우리 MLP가 같은 은닉층 구조지만, 실제 공개 코드 기본 MLP는 은닉층이 두 개다.
이전의 “거의 같은 모델” 설명은 **논문 명세 기준**이며 저장소 코드까지 같다는 의미로 사용하면 안 된다.

| 항목 | 논문 본문/표 | 연결 저장소에서 확인한 코드 | 우리 기준선 |
| --- | --- | --- | --- |
| 모델 | 32→128→9 ReLU | 입력 크기 가변→30→30→9 ReLU 기본값 | 31→128→9 ReLU |
| Optimizer | 본문·Table 5에 미명시 | Adam, 기본 lr=0.01 | SGD, lr=0.1 |
| 정밀도 | 미명시 | 입력 float32, 일반 PyTorch Linear | float64 |
| batch | 미명시 | FL dataset 기본 32, 중앙집중 notebook 500 | 128 |
| 분할 | IID / Dirichlet α=10,1,0.1, 구체 holdout 비율 미명시 | FL loader에 행 단위 80/20, random_state=42; IID는 merged CSV를 분할 | 원래 파일별 참여자, 특징 그룹 60/20/20 |
| 학습 길이 | FL 10 rounds × local 3 epochs | 중앙집중 notebook 최대 150 epochs, 조기 종료 | FL 10×3; 중앙집중 30 epochs 고정 |
| 평가 | macro-F1 및 기타 분류 지표 | 예제 중앙집중 notebook은 validation loader로 최종 test 호출 | 독립 test 유지, 마지막 epoch 고정 |

표의 코드 값은 **선택된 커밋의 기본값/예제**이며 논문 최종 실험 설정의 확인값이 아니다.

## 1. MLP 및 optimizer

[FL MLP 소스](https://github.com/Cyber-Tracer/iot-feature-engineering/blob/bf04ddfa010c3de5a003bd087497b9f9184e58e9/fedstellar_integration/malwares/models/mlp.py#L88):

- 생성자의 `hidden_size1=30`, `hidden_size2=30`, `learning_rate=1e-2`.
- Linear 세 개와 ReLU 두 개를 사용한다. 마지막에 log-softmax를 적용하고 CrossEntropyLoss로 학습한다.
- `configure_optimizers`는 Adam을 반환한다. PyTorch Linear의 기본 초기화를 사용하며 seed 인수는 선택적이다.
- 통합 README의 예제는 입력 차원만 데이터에서 전달하며, 숨은 층 크기나 lr 변경은 보이지 않는다.
- `training/mlp.py`에도 동일한 기본 모델/Adam 구성이 있다.

따라서 모델 크기를 키우는 실험과 optimizer 변경 실험은 분리해야 한다.
Adam 사용이 논문과의 성능 차이를 얼마나 설명하는지는 아직 실행으로 검증하지 않았다.

## 2. FL 데이터 로딩

[MalwaresDataset](https://github.com/Cyber-Tracer/iot-feature-engineering/blob/bf04ddfa010c3de5a003bd087497b9f9184e58e9/fedstellar_integration/malwares/malwares.py#L38):

- 기본 `batch_size=32`, `val_percent=0.2`, `num_workers=4`.
- 기본 경로는 `merged_df.csv`다. IID이면 `np.array_split`으로 행을 노드 수만큼 나눈다.
  이 줄 자체에는 섞기가 없으므로 IID 여부는 merged 파일의 행 순서에도 의존한다.
- 그 뒤 `train_test_split(..., test_size=self.val_percent, random_state=42)`를 실행한다.
  해당 호출에 `stratify`나 중복 그룹 지정은 없다.
- non-IID는 전체 merged 자료에서 먼저 train/test를 만들고 train에 Dirichlet을 적용한다.
  이 파일의 상수는 α=1.0이다. 논문의 α=10/0.1 실행 설정은 여기서 확인되지 않는다.
- 물리 파일을 불러오는 `load_user_depenend_dataset` 함수는 있지만 기본 IID 경로의 호출은 주석 처리다.
- 상위 FedstellarDataset이 추가로 validation을 나누는지까지 감사하지 않았으므로,
  위 80/20을 최종 train/validation/test의 확정 비율로 해석하지 않는다.

공개 코드에 그룹 분할이 없다는 관측만으로 논문 실험에서 중복 누수가 실제 발생했다고 단정하지 않는다.
다만 우리 V2에는 정확한 중복이 많으므로, 행 단위 분할과 그룹 단위 분할은 서로 다른 평가 조건이다.
우리의 기존 독립 test를 논문 수치에 맞추기 위해 행 단위로 바꾸지는 않았다.

## 3. 전처리 및 31/32 특징 차이

[데이터 생성기](https://github.com/Cyber-Tracer/iot-feature-engineering/blob/bf04ddfa010c3de5a003bd087497b9f9184e58e9/training/create_fedstallar_dataset.py#L74)는
선택 특징 목록과 입력 CSV 열의 **교집합**을 취하고, label을 붙이고, 전체 입력 데이터의 scaling을 호출한 뒤 섞어 저장한다.
train/test를 나누기 전에 정규화 함수를 호출한다. NaN 행은 제거한다.
선택 열이 모두 존재하는지 확인하려는 assert는 동일 집합을 자기 자신과 비교해 실질적인 누락 검사가 되지 않는다.
이것은 해당 코드의 관측이며 V2 파일이 정확히 이 경로로 생성됐다는 확인은 아니다.

[top_32_features.txt](https://github.com/Cyber-Tracer/iot-feature-engineering/blob/bf04ddfa010c3de5a003bd087497b9f9184e58e9/top_32_features.txt)의
32개 특징과 V2 실제 header를 비교했다.

- V2의 31개 특징은 모두 이 목록에 있다. 추가 특징은 없다.
- 목록에만 있고 V2에 없는 특징은 **`armv7_cortex_a15/br_mis_pred/` 하나**다.
- 이는 31/32 차이의 구체적인 누락 항목을 확인한 것이다. 누락 원인이나 학습 성능 영향은 아직 미확정이다.
- 생성기가 실제 읽는 `weight_selected_30s.csv`는 감사한 저장소 tree에 없다.
  `top_32_features.txt`와 그 CSV가 같은 내용이었다고 확정할 수 없다.
- 논문의 342,106행과 V2 장치 파일 171,053행 차이는 여전히 미해결이다.
  단순히 두 배라는 이유로 중복 집계나 파일 누락을 원인으로 단정하지 않는다.

## 4. 중앙집중 notebook과 결과 집계

[training30.ipynb](https://github.com/Cyber-Tracer/iot-feature-engineering/blob/bf04ddfa010c3de5a003bd087497b9f9184e58e9/training/training30.ipynb),
[training300.ipynb](https://github.com/Cyber-Tracer/iot-feature-engineering/blob/bf04ddfa010c3de5a003bd087497b9f9184e58e9/training/training300.ipynb):

- 각각 `all_df_top34.csv`, `all_df.csv`를 읽는다. 현재 V2 31-feature 파일을 읽는 코드가 아니다.
- 전체 자료 정규화 후 `train_test_split(test_size=0.2)`를 호출하며 이 호출에 seed/stratify/group는 없다.
- batch 500, 최대 150 epochs, validation accuracy 기준 patience 5 조기 종료와 best checkpoint 저장.
- 선택한 checkpoint의 `trainer.test`에 **같은 validation dataloader**를 전달한다.
  해당 예제의 최종 출력은 새 독립 test 평가라고 볼 수 없다.
- notebook 이름의 30/300을 30/300 epochs로 해석하면 안 된다.

[8-node DFL 집계 notebook](https://github.com/Cyber-Tracer/iot-feature-engineering/blob/bf04ddfa010c3de5a003bd087497b9f9184e58e9/calculating_scores/DFL/FULL/8.ipynb)은
노드별 마지막 `Test/*` 로그를 수집한 뒤 **노드 사이 평균과 표준편차**를 계산한다.
우리의 pooled confusion matrix에서 얻은 F1 및 **seed 사이 표준편차**와 같은 통계량이 아니다.
선택한 notebook의 저장된 F1 평균은 DFL 0.8064, CFL 0.6265로 논문 IID 표의 0.932/0.897과도 다르다.
이 notebook이 다른 실험 조건의 기록일 수 있으므로 논문의 결과가 틀렸다는 의미는 아니다.

## 재현성 판정과 보존

연결 저장소는 Fedstellar 하위 모듈 `8cddd244424281ec402562c0384aee775a8f8d2e`를 참조하지만,
논문은 Nebula 기반 실험이라고 설명한다. 논문 표별 실행 설정과 정확한 소스 버전의 대응 관계는 확정하지 못했다.
따라서 이번에는 **공개 코드 감사와 자체 통제 실험**을 완료한 것이며 논문 재현을 완료한 것이 아니다.

원본 소스·tree·URL·Git blob 검증값·SHA-256은 `.cache/endpoint/source-audit-2026-09-13/`에 보존했다.
수집기·악성코드·외부 노트북은 실행하지 않았고, 데이터 로더와 학습 코드만 텍스트로 확인했다.

```bash
.venv/bin/python -m experiments.audit_endpoint_sources \
  --output .cache/endpoint/source-audit-new
```

완전 재현에 필요한 미확정 항목은 논문 표별 실행 config, 정확한 데이터 artifact와 특징 목록,
노드 분할·중복 처리·평가 집계 정책이다. 현재 결과만으로 모델 구조를 교체할 근거는 부족하며,
[중앙집중 진단 결과](./experiments/endpoint-central-2026-09-13/report.md)에 따라 FL 분할·집계 빈도부터 분리하는 것이 다음 순서다.
