# 추가 share 없는 Flower MGF 연결과 mask norm 수정

## 구현 범위

`--paper-quantized-mgf`는 원본 HPRF와 초기 일회성 VSS를 사용하는 source
Flower 경로의 **실험 opt-in**이다. 각 클라이언트는 DMC 정밀도의 masked
vector 하나만 보내며, 개별 평문 업데이트나 좌표별 mask share는 보내지 않는다.
기본 source MMF 경로는 바꾸지 않았다.

첫 3라운드는 E2 percentile bootstrap을 사용하고 이후에는 두 공개 history
term의 비율로 bound를 갱신한다. 공개 checkpoint의 classifier norm으로
초기 scale을 정하는 것은 E2의 고정 초기값과 다르다. 복원은 양자화 격자에
맞는 carry 후보가 유일할 때만 허용한다. 따라서 논문 Algorithm 8 그대로의
구현이나 저자 실험의 완전 재현으로 표시하지 않는다.

## norm 수정과 남은 한계

모듈러 업데이트 복원에서 carry가 소거되는 것과, 실수 mask norm에서
carry를 잃는 것은 다른 문제다. `H(sum_key) mod p`의 최댓값은 개별
bounded mask를 정수로 합산한 최댓값과 일반적으로 같지 않다.

새 실험 경로는 **선택된 업데이트 합이 유일하게 복원된 다음**
`masked_sum - recovered_update_sum`으로 실제 전송된 decimal mask 합을
구한다. 그 classifier 구간의 최댓값을 다음 history term에 사용한다.
전송 반올림까지 반영하며 추가 메시지나 share는 필요 없다. 이는 선택 이후의
norm 수정이지, 선택 전 전체 후보 cohort의 정확한 mask norm 복원이 아니다.
유일한 합 복원에 실패하면 이 방법도 사용할 수 없다.

기존 `protocol.py`의 좌표별 Pedersen share 경로에는
`mgf_mask_sum_norm=True` opt-in을 추가했다. 이미 복원한 mask 합을 이용하므로
새 share를 요청하지는 않지만, 그 경로 자체는 기존부터 mask shares를 사용한다.
기본값은 False로 유지하고 config digest에 활성화 여부를 바인딩한다.
해당 경로의 cohort norm은 여전히 aggregate-HPRF norm이다. 단순한
`count * alpha` 대체는 저자 실험과 다르고, 전송 반올림 여유도 필요하다.

## 공식 Flower 실제 학습 확인

실행 자료: `.cache/source-paper-quantized-official-first-round-20261001/`.
공식 SuperLink/Ray, 20 clients, committee 4, worker 2, FMNIST clean 1라운드,
local epochs 2. 초기 checkpoint와 입력 shard는 hash로 고정했다.

- 학습 runtime: 38.239초. 초기 checkpoint가 있는 실험이며 처음부터 학습한 결과가 아니다.
- 선택 2명, 정확도 88.64%.
- 초기 key-share 전달 80개, 추가 mask-share 전달 0개.
- 실제 선택 mask norm `4516731/20000000 = 0.22583655`.
- aggregate-HPRF norm은 약 0.117867로, 두 계산의 차이를 실제 실행에서도 확인했다.
- 선택된 2명 재학습과 전체 모델 대조 오차 0, tolerance 1e-12.
- scale, next-linf와 공개 mean/history 관계 및 정상 경로 BFT 인증서를 검증했다.
  mask norm 자체는 BFT body에 바인딩되지만 offline verifier가 개별 키로
  독립 재계산하지 않는다. 필터 정확성·입력 비공개성·공격 방어의 증명이 아니다.

## 다중 라운드 실패를 숨기지 않는 진단

앞선 clean 4라운드 실행
`.cache/source-paper-quantized-fmnist-clean-four-round-20261001/`은
3라운드 reconstruct 요청에서 실패했다. results.json이 없으며, 당시 일반
거부 응답만 있었으므로 구체적인 수치 실패 원인을 단정할 수 없다.

후속 구현은 quantized-lift 실패를 `precision`, `no-candidate`, `ambiguous`
세 공개 범주로만 전달한다. 키·share·좌표·업데이트 값·예외 전문은 내보내지 않는다.
로컬 CLI는 실패 시 `failure.json`에 요청 라운드/단계와 이미 BFT commit된
라운드의 공개 metadata를 저장한다. 실패한 라운드를 성공 결과에 포함하지 않는다.

진단을 추가한 fresh 실행
`.cache/source-paper-quantized-fmnist-clean-four-round-diagnostic-20261001/`은
3라운드 commit 후 4라운드 reconstruct에서 `ambiguous`로 중단됐다.
`failure.json`에 완료 1~3라운드가 남아 있다. 이전 실행과 원본 키가 다른
새 실행이며, 이전 3라운드 실패 원인을 소급 확정하는 결과는 아니다.

이 실행의 공개 3라운드 `next_linf = 59/80000`으로 다음 mask period는
`0.0001475`가 된다. 두 period의 차이 `0.000295`는 모델 양자화 단위
`0.000001`의 정확한 295배다. 따라서 carry가 2만큼 다른 후보가 같은
양자화 조건을 통과할 수 있다. 공개 fixture 키 (4,16), 라운드 4로 같은
scale의 모호성을 재현하는 회귀 테스트를 추가했다. 개별 실험 키나 shard를
검사하지 않았으며, 논문 스케일을 임의 변경해 회피하지 않았다.

### 정정: grid-only preflight는 물리적 mask 범위를 누락했다

`period / model_quantum = a/b`를 기약분수로 표현하면 carry를 b만큼
바꾼 두 후보의 합 차이는 정확히 a개의 모델 양자화 단위다. 현재 adapter의
후보 carry 구간 [-1,n]에서 `n+2 >= 2b`이면 모든 carry에 같은 grid
거리의 다른 후보가 있다. 그러나 그 후보가 의미하는 mask 합은 실제
허용 범위를 벗어날 수 있다. 따라서 이를 실제 복원의 충분한 실패 조건으로
표현하고 라운드 전체를 거부했던 판단은 과도했다.

실행 경로의 해당 preflight를 제거했다. 함수는
`PaperDMC.unbounded_grid_collision`으로 이름을 바꿔 범위 제한 **이전**의
진단임을 명시했다. 유리수/선택 인원 2,420개 대조 결과는 이 무제한 grid
성질에 한정되며, 실제 복원 불가능성을 입증하지 않는다.

decoder는 각 후보의 `implied_mask = transmitted_sum - candidate_update_sum`을
계산한다. decimal wire에서는
`0 <= implied_mask <= n * round(coefficient*p) / D`인 후보만 남긴다.
전송 rounding endpoint를 사용하므로 `n*alpha`보다 잘못 좁은 상한을
가정하지 않는다. 후보를 제거할 때 개별 키/평문이나 추가 share는 필요 없다.
`source_paper_numeric.recover`에 있던 사후 범위 검사를 **모호성 판정 전**에도
적용한 것이다. 한 후보만 남을 때 복원하고, 둘 이상 남으면 여전히 거부한다.

공개 fixture (4,16), round 4, next-linf=59/80000은 이제 올바른 합으로
복원된다. 반대로 mask 양 끝점에서 범위 조건까지 만족하는 두 후보가 생기는
fixture는 계속 거부한다. signed model·zero/max masks·decimal rounding
회귀 테스트를 추가했고 관련 68개가 통과했다. HPRF/scale/share 구조는 그대로다.

새 로컬 FMNIST clean 4라운드
`.cache/source-paper-quantized-fmnist-mask-bounds-four-round-20261001/`가
44.757초에 완료됐다. 각 라운드 2명을 선택했고 정확도는
88.61%, 88.51%, 88.62%, 88.81%다. 초기 key-share 80개, 추가 mask-share 0개.
선택된 학습 8회를 독립 재실행한 전체 모델 오차는 0(tolerance 1e-12)다.
이는 새 키의 fresh 실행이며, 이전 실패 실행을 재개하거나 그 입력을 모두
복원한 결과가 아니다. mask norm 자체의 독립 검증·프라이버시 증명은 아니다.

공식 Flower clean/공격 각각 4라운드도 완료했다. 추가 mask-share 0개,
clean 정확도 88.49%, 공격 정확도 88.60%·공격 성공률 0.390625%다.
[실제 학습 결과와 재학습 검증](../experiments/fmnist-source-paper-mask-bounds-2026-10-01/report.md).

원본 소스 재대조에서도 `SA_ClientAgent.send_vectors`는 큰 HPRF를 더하고,
`SA_Aggregator.reconstruction_process`는 합산 키 HPRF를 뺀 후 modulo한다.
학습 artifact의 `aggregation_rules.aion`은 개별 작은 mask를 합산하는
`client_sum_hprg`로 norm을 계산하고 선택된 평문 업데이트를 평균한다.
따라서 두 경로 사이의 작은-mask 복원 규칙을 그대로 가져올 수 있다는
근거는 여전히 없다. [논문 Algorithm 7/8](https://www.usenix.org/system/files/usenixsecurity25-liu-yizhong.pdf)은
HPRF 정밀도 확대와 subtraction/rounding을 명시한다. 이를 arbitrary 실수
scale 이후의 modular 정수 lift 복원으로 자동 확대하지 않는다.

## 다음 완료 조건

검증: source numerical/Flower official/DMC 테스트 58개와 기존
MGF original/wire/selection 테스트 62개가 통과했다. `git diff --check` 및
변경 모듈 compile 검사도 통과했다. 전체 저장소 테스트를 실행한 것은 아니다.

실제 학습에서 발생한 grid/carry 모호성을 추가 share 없이 제거할 수 있는
저자 수치 표현 또는 조건을 확인해야 한다. 현재 adapter는 다중 라운드의
보편적 복원 경로로 채택할 수 없다.
scale을 임의 조정하거나 여러 carry 중 하나를 선택해 성공으로 만드는 것은
허용하지 않는다. 후보 cohort norm과 저자 E2의 중앙 oracle 차이도 남아 있다.
추가 share 없는 논문 근접 재현 목표는 아직 미완료다.
