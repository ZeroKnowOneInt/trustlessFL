# 실제 Flower 공개 결과와 수신 벡터의 정보 흐름 — 2026-10-08

## 결과

기존 공식 FMNIST 실행 `.cache/same-scale-fmnist-official-20261008`을 읽기 전용으로
검사했다. 새 학습을 실행하거나 원본 HPRF/VSS/ASR/MGF/Flower 런타임을 바꾸지 않았다.

**1라운드의 실제 signed VECTOR와 BFT② 평균만으로 61,706좌표의 decimal-mask 합을
역산할 수 있었다.** projection의 최대값은 확정된 `mask_linf=4545319/20000000`
(0.22726595)와 같았다. 키, share, 학습 데이터, 노드 Context를 읽지 않았다.

이는 공개 fixture에만 의존했던 이전 항등식 검사를 실제 수신 메시지에 적용한
결과다. 공개 모델 평균과 masked sum을 함께 아는 서버/위원회에 대한 조건이다.
외부의 모든 관찰자가 masked VECTOR를 수신할 수 있다는 주장은 하지 않는다.

## 무엇이 공개/수신되는가

- `aion_source_asr`의 `reconstruct`는 양자화된 선택 합을 일반 연산으로 나누고
  `FINAL_SUM.final_sum`에 평균을 넣는다. 모델도 같은 메시지에 들어간다.
- `aion_source_server`는 선택 전 모든 `VECTOR`를 수신하며, 선택된 명단과 함께
  평균을 history에 기록하고 BFT②로 해당 `FINAL_SUM` 본문을 확정한다.
- 현재 aggregate replay에서는 서버가 `aggregate_opening`을 받아 위원회에
  전달한다. 위원회는 합계 키를 알고 signed VECTOR의 로컬 snapshot도 갖는다.
  공개 결과 파일 자체에는 합계 키가 없다. 감사 도구도 합계 키를 읽지 않는다.

현재 평균의 float 정밀도는 `Z/(S*n)`에서 정수 Z를 다시 식별하기에 충분했다.
근접한 두 binary float의 midpoint 구간을 검사하고, 추론한 Z를 다시 나눈 값이
공개 평균과 동일한지 확인한다. 구간이 격자점 둘 이상에 걸치거나 입력이
off-grid/nonfinite이면 추론을 거부한다. 작은 값의 임의 float rounding이 아니다.

```
S = 1,000,000
Z = unique_integer_numerator(final_sum, S*selected_count)
decimal_mask_sum = selected_signed_VECTOR_sum - (D/S)*Z
```

개별 평문 업데이트를 추론한 것이 아니라 선택된 업데이트의 **합**을 이미
공개된 평균에서 역변환한 것이다. 이 항등식에 필요한 sum은 새 메시지가 아니다.

## 실제 기록의 검사 범위

| round | 선택 인원 | 평균에서 복원한 정수 좌표 | signed VECTOR 파일 | 역산한 mask 좌표 |
|---|---:|---:|---|---:|
| 1 | 2 | 61,706 | 20명 전체 존재·서명/digest 확인 | 61,706 |
| 2 | 2 | 61,706 | 없음 | 검증하지 않음 |
| 3 | 2 | 61,706 | 없음 | 검증하지 않음 |
| 4 | 2 | 61,706 | 없음 | 검증하지 않음 |

모든 평균의 binary-float 오차를 Z 단위로 환산하면 최대 `5e-13` 미만이다.
4라운드의 FINAL_SUM BFT② 인증, 선택 BFT①, selection receipt,
aggregate replay receipt를 검증했다. r1에서는 packet digest와 두 종류의
receipt가 같은 전체 벡터 집합을 가리키는 것까지 확인했다.

나머지 라운드에서 receipt 서명/본문은 검증했지만, 해당 벡터 digest를 실제
packet 내용과 대조할 수 없었다. 감사 결과는 이 경우
`mask_inference_status=missing-received-vectors`, `inferred_mask_coordinates=0`,
mask norm 비교와 실제 carry 추론 가능 여부는 `null`로 표시한다.
서명된 digest가 있다는 것만으로 누락된 packet 내용을 검증했다고 하지 않는다.

원인은 `AuthorASRWorkflow.select`: 작은 batch는 직접 Flower Message의 `vectors`로
전달하고, 큰 batch만 `stage-vectors`/inbox를 사용한다. 이 실행에서 inbox는 각
수신자에게 r1만 남아 있다. 파일이 없다는 것은 실제 통신이 없었다는 의미도 아니다.

초기 감사 코드는 모든 라운드에 inbox가 있다고 가정해서 r2에서 실패했다.
이를 고쳐 실제로 있는 packet은 완전히 검증하고, 없는 packet은 명시적으로
증거 부족으로 보고한다. 1라운드 결과를 4라운드 관측으로 확대하지 않는다.

## Carry와 MPC의 경계

합계 키를 추가로 아는 actor는 역산한 mask sum과 H(K_A,r)를 비교할 수 있다.
수치적으로 다음 충분조건은 이 실행의 4라운드 설정 모두에서 성립한다.

```
(n+1)/(2p) + n/(2D*period) < 1/2
```

이는 이전 공개 fixture에서 확인한 carry 추론의 precision 조건이다. 이번
감사는 K_A를 읽지 않았으므로 실제 carry 값이나 개인 키 복원은 계산하지 않았다.
r2~r4에는 packet도 없으므로 그 라운드의 실제 추론을 관측했다고 하지 않는다.

따라서 위원회 MPC의 intermediate를 비공개로 해도, 같은 관찰자에게 정확한
평균과 masked sum을 주는 한 결과에서 mask sum이 역산되는 경로는 남는다.
**MPC 도입만으로 carry 기반 키 누출이 해결됐다고 간주하지 않는다.** MPC의
안전성 검토와 최종 출력이 드러내는 정보의 검토는 별개다.

이 결과는 현재 source HPRF의 보안 증명, 모든 rounding convention의 일반 증명,
모든 악성 입력의 정확한 복원, 전체 키 탈취 성공을 입증하는 결과가 아니다.
추론한 mask vector를 개인 키로 계산한 실제 vector와 비교하는 것도 하지 않았다.
수신 합/확정 평균에 대한 항등식, 범위, 확정 projection norm을 검증했다.

## 재현 및 수정 파일

```
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 -m experiments.audit_source_output_information \
  --root .cache/same-scale-fmnist-official-20261008

env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 -m pytest -q tests/test_source_output_information.py \
  tests/test_same_scale_mask_sum_reference.py tests/test_same_scale_jitter.py \
  tests/test_same_scale_feasibility.py tests/test_scaled_ring.py tests/test_scaled_sum_collision.py
```

관련 검사 **88 passed (9.06s)**.

- 추가: `experiments/audit_source_output_information.py`.
- 추가: `tests/test_source_output_information.py`; 실제 기록 검사에서는 private
  경로, node-configs, NPZ 학습 자료를 여는 시도를 금지하는 guard도 적용했다.
- stdout에는 통계와 검증 범위만 나온다. 추론 mask vector/carry/키를 출력하지 않는다.
- 기존 런타임 및 메시지 형식 변경 없음. 위원회 MPC 도입도 없음.

기존 carry 해결은 미완료다. 최신 사용자 지시에 따라 MPC를 도입하지 않으며,
이 감사를 안전한 runtime carry 해결책으로 연결하지 않는다. 결과 기반 누출
관측은 MPC 도입 여부와 별개인 기존 경로의 검증 결과로 유지한다.
