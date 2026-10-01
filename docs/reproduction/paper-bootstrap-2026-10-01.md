# 실제 공개 초기 모델의 bootstrap 스케일 검증

## 목적과 차이

조건부 quantized-lift 복원이 실제 공개 초기 checkpoint norm에서도 동작하는지
확인했다. 값 변경으로 반례를 피하는 대신, 기존 공식 Flower 실행 manifest에
pin된 `reference.npz`를 읽고 SHA-256·shape·finite values를 검증했다.
classifier 840좌표 또는 전체 61,706좌표의 실제 L∞를 각각 사용했다.
checkpoint float의 정확한 binary rational을 유지하고 임의 alpha 보정을 하지 않았다.

원본 학습 `roles/server.py` 138행은 `linf_norm=1`로 시작한다. 원본 ASR
filter state의 `linf_old=0.1`과 다른 설정이다. 실제 checkpoint norm을 사용하는
후보를 **저자 E2 초기화 그대로**라고 표시하지 않는다. 논문 초기 모델 norm
해석을 검토하는 수치 후보이며 source-compatible E2 재현과는 구분한다.

## 실행

```sh
PYTHONPATH=.cache/author-asr-deps:.cache/flower-deps:.cache/torch-deps:. \
python3 -m experiments.audit_quantized_lift \
  --reference-manifest .cache/author-asr-official-fmnist-bounded-state-four-round-20261001/manifest.json \
  --dimension 840 \
  --output .cache/quantized-lift-public-bootstrap-840-20261001.json
```

실행 완료。20라운드·840좌표 공개 fixture다. 원본 HPRF, model 소수 6자리,
wire 소수 8자리, beta=0.2로 검증했다. 새 Flower 학습 실행이 아니며 기존
클라이언트의 비밀 키·share·개별 학습 업데이트를 읽지 않았다.

checkpoint SHA-256:
`d7679d619a0e7497851451ae9c388bd05212491d76914dffb80b85ac309aa7c2`.

| 초기 L∞ 후보 | 값 | 선택 2명 | 선택 4명 | 선택 10명 |
|---|---|---|---|---|
| 기존 ASR bootstrap | 0.1 | 0/20, 모호성 거부 | 0/20, 모호성 거부 | 0/20, 모호성 거부 |
| 저자 E2 bootstrap | 1 | 0/20, 모호성 거부 | 0/20, 모호성 거부 | 0/20, 모호성 거부 |
| 실제 전체 초기 모델 | 1664889/2097152 | 20/20 정확 | 20/20 정확 | 0/20, 모호성 거부 |
| 실제 classifier 초기 모델 | 9894833/16777216 | 20/20 정확 | 20/20 정확 | 0/20, 모호성 거부 |

한 profile의 20/20 성공은 16,800 SUM 좌표가 모두 일치했다는 의미다.
wrong-accepted round는 모든 profile에서 0이다. 모호성을 숨기거나 일부
좌표/라운드를 성공률 분모에서 제외하지 않았다. 선택 규모 10명의 실패도
남아 있으므로 실제 checkpoint라면 언제나 복원된다는 주장은 하지 않는다.

## 다음 구현 단계

실제 초기 모델 후보의 성공은 conditional 경로의 첫 라운드를 만들 근거다.
다음 단계는 원본 일회성 VSS·HPRF를 유지한 별도 실험 opt-in 경로에서
클라이언트의 단일 masked decimal wire와 aggregator의 lift 복원을
Flower 메시지에 연결하는 것이다. 기본 ASR 경로와 과거 결과는 보존한다.
MGF의 역사 norm·현재 스케일·선택 수가 commit에 정확히 결합돼야 하며,
복원 모호성은 학습 commit 전에 실패 처리해야 한다.

저자 E2의 고정 초기값을 실제 checkpoint norm으로 바꾸는 차이와,
literal Algorithm 8이 아닌 quantized-lift 어댑터 차이는 결과에 표시한다.
이 후보를 논문 전체와 동일한 구현으로 선언하지 않는다. 정상/공격 실제
학습 및 전체 모델 재검증 전에는 목표 완료가 아니다.
