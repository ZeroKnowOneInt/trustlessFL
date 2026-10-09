# 동일 스케일 현재 코드의 공식 Flower 재검증

새 task 두 개를 생성해 현재 런타임을 실행했다. 원본 HPRF snapshot, 공개
학습 설정과 입력만 재사용하고 기존 개인 키/Context는 가져오지 않았다.
실패를 같은 설정의 재시도로 숨기거나 성공한 키를 선택하지 않았다.

| workload | 공식 run ID | terminal 상태 | 확정 라운드 | workflow 시간 |
|---|---|---|---:|---:|
| synthetic | 11539158919527768852 | finished:failed | 3/4 | 31.866 s |
| FMNIST | 9208003235139155689 | finished:completed | 4/4 | 135.260 s |

두 task 모두 20명 후보, 4명 위원회, `beta=0.2`, `scale_source=quantized-sum`,
`filter_rule=inclusive-historical-bound-v1`을 사용했다. 수식/원본/런타임은
변경하지 않았다. 실제 key subset에 따라 MGF가 선택한 명단과 복원 조건이
달라지므로 과거 실행과 실패 라운드가 같아야 하는 것은 아니다.

## Synthetic 실패 증거

`.cache/same-scale-synthetic-official-20261008/failure.json`은 round 4의
`reconstruct`에서 `category=ambiguous`를 기록한다. 공식 상태 파일은
`attempt-c37ae311/run-status.json`이다. 세 라운드는 확정됐고 네 번째
실패 라운드는 확정되지 않았다. `results.json`이 없는 부분 성공을 전체
학습 성공이나 전체 offline replay 완료로 보고하지 않는다.

## FMNIST 완료와 독립 replay

`.cache/same-scale-fmnist-official-20261008/results.json`과
`verification.json`이 생성됐다. 공식 상태는
`attempt-0650db5d/run-status.json`에서 확인한다.

- 4라운드 모두 selected 2명, 재실행 학습 호출 8회.
- 모든 라운드 모델의 평문 양자화 대조군 대비 최대 오차 0.
- 초기 key share 전달 80건, 추가 mask share 0건.
- post-filter BFT①, 위원회 aggregate replay receipt, BFT② 검증.
- 마지막 테스트 정확도 0.8855. 이미 준비된 reference checkpoint에서
  이어 학습한 결과이며 처음부터 학습한 정확도나 방어 성능 검증이 아니다.

| round | 실제 선택 합의 L∞ | scaled period/2 | 단순 center 가능 |
|---|---:|---:|---|
| 1 | 0.007802 | 약 0.05897780 | 가능 |
| 2 | 0.002106 | 0.0007802 | 불가 |
| 3 | 0.002348 | 0.0002106 | 불가 |
| 4 | 0.001908 | 0.0002348 | 불가 |

r2~r4는 단순 center 범위를 벗어나지만 현재 conditional quantized-lift는
유일한 후보를 찾아 정확히 복원했다. 따라서 center 용량 조건은 모든
복원 방법의 절대적 한계가 아니다. 반대로 synthetic 실패와 기존 다좌표
충돌 반례 때문에 현재 quantized-lift도 항상 성공한다고 할 수 없다.

## 스케일 갱신과 양자화 격자의 구조

sum 기반 profile에서 이전 기준 L은 양자화된 업데이트 합의 최대 절댓값이다.
따라서 `L=j/S`인 정수 j가 있고, normalized scale은 `P=beta*L`이다.
beta=1/5인 현재 profile에서는:

```
P*S = j/5
```

기약분수의 분모가 1 또는 5이므로 carry를 그 분모만큼 바꾸면 model quantum의
정수배만큼 다른 합이 생긴다. 이것은 단순 float 정밀도 부족이 아니라 격자의
구조다. 실제 mask sum의 범위가 다른 후보를 배제할 수 있으므로 분모만으로
모든 round를 실패로 판정하지 않는다. 새 `grid_alias_profile`은 이 공개
산술 진단만 수행하며 개인 키/실제 carry를 추측하지 않는다.

## 수식 변경의 현재 허용 범위

사용자는 수식 변경을 허용했으며 MGF의 원래 bound 검증 기능을 유지해야 한다.
수식 동일성 자체나 beta 상수 고정이 요구사항은 아니다. 다음을 검증한다.

1. 어떤 업데이트 크기를 제한하는지와 threshold의 단위가 일관적인가.
2. 정상 입력을 대폭 제거하거나 입력 clipping으로 학습 신호를 없애지 않는가.
3. 작은 허용 wire 변조가 carry 선택을 통해 큰 집계 변화로 증폭되지 않는가.
4. 복원 정확성뿐 아니라 원래 MGF 목적을 유지하는 근거가 있는가.

벡터와 bound를 동시에 양의 상수만큼 곱하면 MGF 판정은 보존된다. 그러나
update sum과 mask period도 같이 커져 상대적인 복원 용량은 그대로다.
이 단순 단위 변경이 carry 해결책은 아니라는 회귀 검사도 추가했다.

관련 시험: `tests/test_same_scale_feasibility.py`, `tests/test_scaled_ring.py`,
`tests/test_scaled_sum_collision.py` — **48 passed (0.46s)**.
수치 도구/문서만 바뀌었으며 현재 런타임의 복원 모호성은 미해결이다.

## 재현 명령

다음 명령의 output은 이미 존재하므로 다시 실행할 경우 새 경로를 지정해야 한다.

```bash
env PATH="/home/jisung/trustlessfl/trustlessFL/.cache/flower-deps/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. python3 -m experiments.run_source_asr_official --prepared .cache/source-sum-units-synthetic-four-round-official-20261002 --output .cache/same-scale-synthetic-official-20261008 --rounds 4 --workers 2
env PATH="/home/jisung/trustlessfl/trustlessFL/.cache/flower-deps/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. python3 -m experiments.run_source_asr_official --prepared .cache/source-sum-units-fmnist-four-round-official-20261002 --output .cache/same-scale-fmnist-official-20261008 --rounds 4 --workers 2
```

FMNIST verifier는 manifest.training에 고정된 input_root/epochs/seed를 사용했다.
첫 CLI 시도에서 `--inputs` 누락을 확인하고 정확한 manifest 설정을 전달했다.
실제 재검증의 모델 오차가 0인 결과는 `verification.json`에 저장돼 있다.
