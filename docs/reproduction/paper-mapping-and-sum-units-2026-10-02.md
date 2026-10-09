# DMC/DMR 독립 대조와 MGF SUM 단위 보정

## 원문과 현재 코드에서 구분할 것

[논문 §6.1 Algorithm 7/8](https://www.usenix.org/system/files/usenixsecurity25-liu-yizhong.pdf#page=11)은
`l_ex=ceil(log10(2q))`, `D=10^(l_dp+l_ex)`로 HPRF 정수 출력을 나누고,
집계에서 같은 계수의 HPRF를 뺀 뒤 `l_dp`자리로 반올림한다. 이 설명의
오차 전제는 `|e| <= q-1`이다. 여기서 q는 참여자 수이며 원본 HPRF 내부
모듈러스 변수 q와 구분한다.

현재 Flower의 `remove_quantized_lift()`는 이 Algorithm 8 그대로가 아니다.
유일한 양자화 lift만 받아들이는 수치 어댑터다. 그 실패만으로 논문 자체의
불가능성이나 새로운 MPC의 필요성을 증명하지 않는다. HPRF의 필드 원소,
정수 대표값, decimal DMC, MGF 계수의 단위를 구분해 대조한다.

## 실제 단위 혼용 수정

Algorithm 6의 집계 출력은 선택 업데이트의 SUM으로 표기된다. 기존
`recover()`는 history의 업데이트 L2와 다음 scale의 L-infinity에는 선택
MEAN을, 마스크 norm에는 선택 mask SUM을 사용했다. 본문의 total/average
설명을 평균으로 해석하더라도 두 항을 서로 다른 집계 단위로 혼용하면 안 된다.

새 paper task는 `paper_numerics.scale_source=quantized-sum`을 명시한다.

- 복원된 selected update SUM으로 다음 `next_linf`와 history update norm을 계산한다.
- 실제 decimal mask SUM의 norm을 같은 SUM 단위로 더한다.
- 학습 모델에 적용하는 update는 계속 selected mean이다. optimizer 평균을
  protocol history SUM으로 잘못 사용하는 부분만 분리한다.
- numeric body의 `scale_source`와 `history_aggregate=selected-sum`을 위원회
  aggregate replay 및 BFT②에 바인딩한다. offline verifier도 선택 학습을
  재계산한 SUM과 해당 metadata를 대조한다.
- unknown scale units 및 unsafe exact wire는 provisioning/actor/verifier에서
  거부한다. actor 검사는 hello/cache 이전에 수행한다.

기존 manifest에 scale source가 없으면 기존 `quantized-mean` 의미를 유지한다.
명시적인 legacy profile도 허용하되 `legacy-mean-update-mask-sum`으로 표시한다.
새 provision의 기본값만 SUM이며 입력 options dict와 과거 source snapshot,
결과/verification 파일은 변경하지 않는다. fresh stage는 원본 설정에 명시된
scale source는 보존하고, 없는 경우 새 SUM 기본값을 기록한다.

이 보정은 원본 HPRF, initial one-time VSS, key domain, mask share 0 조건,
Flower transport를 변경하지 않는다. bootstrap 3라운드, classifier projection,
decimal wire, conditional lift 등 아직 남은 adapter 차이도 그대로 명시한다.

## 실행 코드와 분리한 독립 수치 대조

`experiments/audit_paper_mapping.py`는 `PaperDMC`, `source_paper_numeric`,
Flower decoder를 호출하지 않는다. 원본 HPRF 출력과 Fraction으로 Algorithm
7/8의 decimal 나눗셈·뺄셈·반올림 및 두 가지 MGF 조합 후보를 별도 계산한다.
tie-breaking은 논문이 지정하지 않아 exact half-even을 명시했다.

20명·4라운드·8좌표, 공개 키 1~20, decimals 6, D=10^8, 공개 magnitude=0.1,
beta=0.2의 결과 `.cache/paper-mapping-independent-20261002.json`:

| 후보 | 유효 마스크 주기 | literal DMR 불일치 | decimal wire 단순 반올림으로 입력 복구 |
| --- | --- | ---: | ---: |
| DMC만 | p/10^8 | 32/32 좌표 | 0/640 좌표 |
| native hmax=p의 MGF 후 DMC | 0.02/10^8 | 0/32 좌표 | 640/640 좌표 |
| DMC 후 hmax=p/D로 정상화한 MGF | 0.02 | 32/32 좌표 | 0/640 좌표 |

32좌표 모두 carry가 있었고 첫 carry는 8, 작은 오차는 0이었다. 작은 e가
없어도 원본 정수 대표값의 carry가 남는다는 독립 확인이다. DMC-only는
별도로 선언한 작은 SUM bound 아래의 modular centering에서 32좌표를
복원했다. 이 centering을 Algorithm 8 그대로라고 부르지 않는다.

raw 조합은 이 fixture의 입력을 모두 반올림으로 복구할 수 있으므로 채택하지
않는다. normalized 조합은 hmax를 p/D로 바꾸면 alpha가 D에 비례하여 커져,
최종 scale과 주기에서 D가 상쇄된다. 따라서 extra digits를 늘리는 것만으로
normalized MGF의 carry 주기가 커지지는 않는다. 이 두 후보를 저자가 확인한
combined private wire라고 주장하지 않는다. 0/640 관측도 보안 증명이 아니다.

## 새 SUM profile의 공식 Flower 실행

두 실행은 과거 공개 workload/입력만 재사용하여 새 task와 키/Context를 만들었다.
실패 작업을 재시작하거나 다른 키로 반복해 성공만 선택하지 않았다.

| workload | 공식 run ID | 실제 terminal 상태 | 확정 라운드 | 실패 지점 | workflow 시간 |
| --- | --- | --- | ---: | --- | ---: |
| synthetic | 18267998097949794833 | finished:failed | 2/4 | round 3 reconstruct: ambiguous | 27.249465 s |
| FMNIST | 8241365703251470889 | finished:failed | 1/4 | round 2 reconstruct: ambiguous | 49.173769 s |

출력은 `.cache/source-sum-units-synthetic-four-round-official-20261002`와
`.cache/source-sum-units-fmnist-four-round-official-20261002`다. 두 작업 모두
`results.json`이 없으며 전체 모델 오차 0, 4-round 완료, 최종 정확도/ASR 또는
전체 offline verification을 주장하지 않는다. failure의 committed metadata에
SUM scale/history profile이 기록됐고 실제 Flower run-status도 실패를 확인했다.

synthetic의 확정된 2라운드는 공개 local_delta로 selected update SUM을
다시 계산했다. `next_linf`는 각각 `2199/1000000`, `1/625`이며, 대응하는
mean norm `2199/2000000`, `1/1250` 대신 실제 SUM과 일치했다. history의
update norm도 SUM과 일치했다. 이 사후 검사는 기록에 없는 mask VECTOR,
opening, BFT 증거까지 독립 검증한 것이 아니다.

공개 round-2 SUM magnitude `1/625`에 대해 다음 normalized period는
`1/3125=0.00032`(320 model quanta)다. 고정 공개 fixture 키 4/16, HPRF
round 3, zero update 8좌표로도 `ambiguous`를 재현하는 회귀를 추가했다.
이 키·cohort는 실제 실패 작업의 private 상태를 읽어 얻은 값이 아니다.

## 검증과 남은 결론

source numeric, aggregate replay, 공식 staging, selection authorization,
filtered BFT, encrypted VSS, dynamic/inbox, DMC/scaled-ring/collision 및 새
독립 대조의 관련 회귀 **267개 통과, 110.04초**. 이후 explicit legacy options
보존과 SUM scale의 carry 재현 시험을 추가한 targeted 회귀는 **60개 통과,
9.59초**였다. 두 묶음은 겹치므로 합산하지 않는다. compileall 및
`git diff --check`도 통과했다. 이번 이후 전체 저장소 suite 완료 주장은 아니다.

과거 synthetic 10-round와 inclusive 4-round 결과도 verifier API로 읽기 전용
재검사했다. 기존 mean scale semantics, model error 0, mask shares 0이 유지됐다.

SUM/MEAN 단위 불일치는 수정했지만, 원본 필드의 모듈러 대표값을 실제 SUM으로
유일하게 복원하는 문제는 해결되지 않았다. 현재 primitive/decimal/normalized
조합의 반례를 전체 논문의 실패로 확대하지 않고, author-confirmed 결합 규칙
또는 그 전제의 정당화가 필요하다는 경계를 유지한다. 새 MPC, 개별 키 복원,
plaintext fallback, 추가 client mask sharing은 넣지 않았다. 전체 목표는 미완료다.

```bash
PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m experiments.audit_paper_mapping --output .cache/NEW-paper-mapping.json

PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m pytest -q tests/test_source_paper_numeric.py tests/test_paper_mapping.py
```
