# Source-ASR 명시적 research profile 통합 — 2026-10-09

기준 문서: [독립 재검토](design-independent-review-2026-10-09.md).
해당 문서를 처음부터 끝까지 읽은 뒤, 그 문서의 §9–10 오차/용량 조건과 §18 통합 제안을 구현했다.
이 문서는 원본 Aion을 수정했다는 보고서가 아니라 Flower **source adapter**의 opt-in 변경 보고서다.
HPRF, VSS 암호 구성, MGF predicate를 새로 설계하지 않았다.

## 1. 기존 코드에서 확인한 구조

| 파일·함수 | 기존 역할과 이번 확인 |
| --- | --- |
| `aion_original_hprf.OriginalAionHPRF.hprf` | 원본 scalar column-sum HPRF 포팅. p=14760426300877770769, q=5p, raw 대표값 0..p inclusive. 변경하지 않음. |
| `aion_source_asr.source_request` | client 학습/양자화/마스킹, selection, sum-shares, reconstruct 액션. 원본 agent의 메서드를 일부 사용하지만 source adapter의 learning 경로 자체는 원본과 동일하지 않음. |
| `source_paper_numeric.paper_codec`, `mask_integer_wire` | legacy: adaptive 유리수 계수를 가진 PaperDMC와 정수 전송. update scale은 10**decimals, spacing은 참여 인원에 따른 DMC 추가 자릿수. |
| `source_paper_numeric.select_masked` | 동일한 signed masked vector로 projection의 제곱합을 검사. bootstrap/ranking 및 이미 선언된 filter_rule을 유지. raw 정수 합을 pending.total에 저장. |
| `aion_source_selection.authorize`, `check_vectors` | 위원회의 서명 벡터/이력/selection 재검산. codec 단위와 descriptor를 확인. |
| `aion_source_sharing.recover_key_opening` | 초기 encrypted randomized Pedersen share에서 선택된 키와 blinding의 합을 복원. VSS는 HPRF q와 다른 ORDER 사용. |
| `source_paper_numeric.recover`, `paper_dmc.PaperDMC.remove_quantized_lift` | legacy: carry 후보·양자화 격자를 이용한 conditional recovery. 새 경로와 분리하여 보존. |
| `aion_source_aggregate.validate` | 위원회가 자신의 selection snapshot 및 초기 commitment를 사용해 합계 키 opening, 모델, numeric history를 재검산. |
| `aion_source_roster.statement`, `require_commit` | BFT① 확정 membership에 대해서만 키 합을 공개하는 기존 adapter 흐름. explicit profile에는 profile 및 벡터 digest도 묶음. |
| `experiments.verify_source_learning.verify_learning` | 저장된 BFT/위원회 receipt를 검증하고 공개 fixture의 선택된 학습 업데이트를 다시 계산하는 offline verifier. |

명시적 `source_profile`이 없는 기존 manifest에는 `legacy-quantized-lift / author-small /
adaptive-rational / actual-mask-sum` 기본 해석을 적용한다. 기존 descriptor, sampler의 범위,
legacy recovery, 기존 `paper_numerics.scale_source`의 absent-field 의미를 변경하지 않았다.
새 프로필을 기존 actor state에 중간에 켜는 것은 허용하지 않는다.

## 2. 변경한 파일

아래는 **이번 작업에서 변경한 파일**이다. 작업 시작 전에 있던 다른 변경은 그대로 보존했다.

| 파일 | 이번 변경 이유 |
| --- | --- |
| `trustlessfl/source_profiles.py` (신규) | 엄격한 schema, key domain, setup/per-round feasibility, integer scaling, 독립 centered codec, manifest pin, 안전한 public error code를 한곳에 정의. |
| `trustlessfl/source_paper_numeric.py` | codec/descriptor/generation/recovery를 profile에 따라 분리. raw Y 합과 actual-mask-sum history 보존. |
| `trustlessfl/aion_source_asr.py` | 액션 실행 전 profile 검증·pin, 동일 sampler와 update codec 사용. |
| `trustlessfl/aion_source_sharing.py` | recover_key_opening의 작은 키 전용 범위 검사를 공통 key_domain 검사로 교체. absent profile 범위는 그대로. |
| `trustlessfl/aion_source_aggregate.py` | opening 범위와 mean decode scale을 같은 profile로 해석. legacy/new recovery를 동일한 local snapshot으로 replay. |
| `trustlessfl/aion_source_selection.py` | signed VECTOR의 범위를 새 d·B_u 단위로 검증하고, fixed period에서는 zero next_linf를 허용. predicate는 동일. |
| `trustlessfl/aion_source_roster.py` | explicit profile의 BFT①에 manifest digest와 signed vector-set digest를 추가. legacy statement는 유지. |
| `trustlessfl/aion_source_server.py` | provision_source(source_profile=...), 생성 전 feasibility 검사, server key_profile, CLI JSON 옵션, BFT① 벡터 binding, public failure code. |
| `trustlessfl/client_app.py`, `trustlessfl/aion_source_official.py` | profile infeasibility를 private 값 없이 명시적 오류 코드로 전달. |
| `experiments/run_source_asr_official.py` | 기존 prepared task에서 새 공식 Flower staging을 만들 때 source_profile을 보존. |
| `experiments/verify_source_learning.py` | 같은 profile의 S·d·M·descriptor·history로 offline 검증. 새 정수 합은 NumPy object 정수 사용. |
| `tests/test_source_profiles.py` (신규) | 경계/반례/legacy 보존/key domain/BFT binding/위원회 replay/Flower workflow/offline/staging 회귀. |
| 이 문서 | 동작 차이, 지원 범위, 실패 조건, 결과 및 남은 경계를 기록. |

## 3. 구현한 profile

manifest의 top-level `source_profile` 객체에 네 이름을 그대로 사용한다.
명시적 객체는 네 선택을 모두 제공해야 하며, 알 수 없는 선택/필드나 부분 설정은 거부한다.

| 분류 | 값 | 지원 상태 |
| --- | --- | --- |
| recovery | `legacy-quantized-lift` | 기존 arithmetic 유지. explicit 선택도 가능. |
| recovery | `transmission-centered-v1` | research learning 경로에 opt-in 연결. envelope가 성립해야만 실행. |
| key_domain | `author-small` | 기존 OS SystemRandom 1..100000. 기본값 유지. |
| key_domain | `author-full-q` | secrets.randbelow(q), 0..q−1. source_request/opening/committee/server 모두 같은 범위. 연구용이며 privacy repair 아님. |
| period_policy | `adaptive-rational` | legacy 지원. centered는 계산된 M이 정수이고 **매 라운드** envelope를 만족할 때만 지원. 실패 시 중단. |
| period_policy | `fixed-integer` | centered 전용. 선언한 M을 그대로 사용하며 자동 증대하지 않음. |
| history | `actual-mask-sum` | raw Y 합에서 dU를 차감한 실제 transmission mask 합. 기존 이력을 이 이름으로 명시. |
| history | `paper-hprf` | 의미는 구분하지만 실행은 `history-unsupported` 오류. actual-mask-sum으로 대체하지 않음. |

explicit source profile은 `research-only=true`, synthetic 또는 FMNIST learning,
paper_numerics, encrypted sharing, selection authorization, post-filter BFT,
committee aggregate replay를 요구한다. weighted aggregation은 지원하지 않는다.
explicit legacy는 adaptive-rational만 허용하며 S/d/M 등의 신규 인코딩 값을 받지 않는다.

예시 — 고정 period의 unweighted 프로필 객체:

```json
{
  "recovery": "transmission-centered-v1",
  "key_domain": "author-full-q",
  "period_policy": "fixed-integer",
  "history": "actual-mask-sum",
  "S": 10000,
  "d": 21,
  "M": 840000021,
  "nmax": 20,
  "C": "100",
  "aggregation": "unweighted",
  "rounding": "nearest-even"
}
```

이 숫자는 기존 runtime의 C=100을 유지하는 **통합 smoke test**의 최소 충분 M이다.
좋은 MGF 학습 파라미터라는 추천이 아니다. 설정 파일을 자동 생성하거나 기존 task에 적용하지 않았다.
`provision_source(..., source_profile=객체)` 또는 server CLI `--source-profile JSON파일`로 명시한다.
CLI의 기존 paper-MGF 생성 선택은 유지했고 synthetic smoke는 programmatic provisioning을 사용했다.
상위 `max_abs`와 C는 정확히 같아야 한다.
새 centered에는 `paper_numerics.scale_source="quantized-sum"`을 명시한다.
adaptive에서는 M 필드를 생략하고 기존 beta/initial_linf/합계 이력에서 정확한 Fraction으로 계산한다.

### Profile 전달과 불변성

client의 signed VECTOR descriptor에는 S,d,M,nmax,C,nearest-even,unweighted와 manifest digest가 들어간다.
selection과 위원회는 해당 round에서 동일한 descriptor를 재생성해 비교한다.
BFT①은 selected membership, 전체 task/profile digest, **전체 signed candidate vector-set digest**를 확정한다.
키 공개 시 각 위원회는 자신의 승인 snapshot의 digest와 BFT①을 대조한다.
aggregate replay는 같은 snapshot의 raw total을 사용하고, BFT② 전에 결과/이력을 재검산한다.
actor state에는 초기 manifest digest를 pin하여 변경된 설정을 cached reply에도 사용하지 못하게 했다.

offline verifier도 profile을 검증하고 같은 encode/descriptor/history 단위를 사용한다.
단, public results에 없는 raw vectors/키 opening을 offline에서 독립 재생성하지는 않는다.
그 부분은 위원회의 signed replay receipt를 확인한다. 이는 ZKP나 독립 암호학적 correctness proof가 아니다.

## 4. recovery 수식

코드 대응: `TransmissionCodec.encode`, `scale_mask`, `TransmissionCodec.mask`,
`TransmissionCodec.recover`, `source_paper_numeric.recover`.

\[
u_i=\operatorname{RoundEven}(Sx_i),\quad
m_i=\left\lfloor\frac{2Mh_i+p}{2p}\right\rfloor,\quad
Y_i=d u_i+m_i.
\]

마스크 scaling은 정수 연산뿐이다. float는 학습 업데이트를 encode하는 입구와 모델을 decode하는
출구에서만 사용하며, scaling/mod/center/grid rounding에는 사용하지 않는다.
p가 홀수이므로 scaling의 .5 tie는 없고 `scale(h+p)=scale(h)+M`이 정확하다. h=p endpoint도 허용한다.
client는 Y_i를 `%M` 하지 않는다.

서버와 위원회의 raw total은 그대로 보존한다.

\[
Y_A=\sum_{i\in A}Y_i,\qquad
m_A=\operatorname{scale}_M(H(\widetilde K,r)),\quad
\widetilde K=\sum_{i\in A}k_i.
\]

현재 HPRF 함수가 내부에서 mod q를 적용하므로 H(정수 키 합)=H(키 합 mod q)다.
VSS가 정수 합을 복원할 수 있도록 population·key_max < ORDER도 검증한다.

\[
R_{mod}=(Y_A-m_A)\bmod M,\quad
R=\operatorname{center}_M(R_{mod}),\quad
\widehat U=\operatorname{RoundEven}(R/d).
\]

`center_p`라는 기존 helper를 **modulus M**으로 호출한다. z를 먼저 mod M으로 만든 뒤
z>floor(M/2)이면 z−M, 아니면 z를 택한다.
홀수는 [−floor(M/2),floor(M/2)], 짝수는 (−M/2,M/2]이며 midpoint는 +M/2다.

\[
\sum h_i-H(\widetilde K,r)=cp+e
\Longrightarrow
\sum m_i-m_A=cM+E
\Longrightarrow R_{mod}=[dU+E]_M.
\]

carry를 열거하거나 식별하지 않는다. final mean은 ring 밖에서 `U_hat/(S*n_selected)`로 계산한다.
MGF 입력은 같은 Y/(dS)이고 기존 projection norm predicate를 사용한다.
actual history는 **raw** total에서 계산한다.

\[
B=Y_A-d\widehat U,\qquad
T=\|\widehat U_J/S\|_2+\|B_J/(dS)\|_\infty.
\]

정직한 bound 및 정확 복원 전제하에서만 B=Σm_i다. actual-mask-sum과
paper의 합계 키 HPRF norm은 서로 다른 통계량이다. 역사적 bound ratio/bootstrap을 유지했다는 이유로
Algorithm 6 전체와 동치라고 주장하지 않는다.

## 5. validation 조건

| 조건 | 이유 및 실패 처리 |
| --- | --- |
| S,d,nmax positive integer, M integer≥2, C finite positive | exact integer transmission과 centered lift 정의. bool/float M 거부. M=1은 이 centered convention에 사용할 수 없음. |
| unweighted, nearest-even | 동일 인코딩/평균 규칙 고정. sample-count weighted 프로필 거부. |
| C=max_abs, 2≤nmax≤population | client의 full-coordinate bound와 decoder envelope 일치. 선택 인원이 nmax보다 많으면 cap하지 않고 거부. |
| B_u=RoundEven(SC) | non-grid-aligned C에서도 실제 nearest-even 양자화 상한. legacy floor를 그대로 복사하지 않음. |
| generalized E_bar(nmax,M) | 작은 M의 E=10 근사를 큰 M에 무조건 재사용하지 않음. |
| d>2E_bar | 모든 허용 오차에서 nearest-grid tie/잘못된 복원 방지. |
| 2(d·nmax·B_u+E_bar)<M | signed sum이 centered interval 안에서 유일하게 복원되는 충분조건. 정수 비교로 strict boundary 처리. |
| population·key_max<ORDER | ASR 키 정수 합과 VSS field의 wrap 차이를 방지. |
| signed descriptor와 manifest pin | generation/selection/replay의 codec 단위 변경·재해석 방지. |

현재 원본 q=5p의 보증 상한은 다음이다. n=1은 두 오차 모두 0으로 별도 처리한다.

\[
E_H(n)=\lfloor2(n+1)/5\rfloor,\quad
\overline E(n,M)=\left\lfloor\frac{(n+1)(p-1)+2ME_H(n)}{2p}\right\rfloor\quad(n\ge2).
\]

E_bar는 모든 M에서 sharp maximum이라는 주장이 아니다. 검증에 사용하는 보수적 상한이다.
nmax=20, 위 smoke M에서 E_bar=10; d=21>20.
B_u=1000000이므로 `2*(21*20*1000000+10)=840000020 < M=840000021`.
이는 **최소 충분 period 계산**이지, 실패를 숨기기 위해 자동 조정한 값이 아니다.

setup 오류는 task 디렉터리를 만들기 전에 거부한다. adaptive는 매 round에도 같은 조건을 재검증한다.
period-noninteger / spacing-infeasible / capacity-infeasible / history-unsupported가 명시적 public 코드다.
다른 recovery로 fallback하지 않고, 작은 adaptive M을 늘리거나 반올림하지 않는다.
복원 후 `|R−dU_hat|≤E_bar`, `|U_hat|≤n_selected B_u`도 검사한다.
단, 사후검사만으로 입력 bound를 암호학적으로 증명하지는 못한다. 범위를 벗어난 입력이 감겨
작은 값으로 alias하면 통과할 수 있다는 독립 재검토 §14의 한계는 그대로다.

## 6. 테스트 결과

최종 fresh-process 전체 실행 결과는 아래에 기록한다. 기존 테스트와 신규 profile 테스트를 별도로 실행한다.

<!-- FINAL_TEST_RESULTS -->
| 구분 | passed | skipped | failed | 시간 |
| --- | ---: | ---: | ---: | --- |
| 기존 전체 테스트 (`--ignore=tests/test_source_profiles.py`) | 1527 | 4 | 0 | 588.25초 |
| 신규 profile 테스트 (`tests/test_source_profiles.py`) | 87 | 0 | 0 | 18.08초 |
| 합계 | 1614 | 4 | 0 | 별도 fresh-process 두 실행 |

기존 전체 실행은 로컬 TCP 허용 환경에서 완료했다. 두 실행 각각 기존 Typer/Click deprecation
warning 2개가 발생했다. 스킵은 통과 수에 포함하지 않았다. `git diff --check`도 통과했다.
<!-- END_FINAL_TEST_RESULTS -->

```bash
env PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 -m pytest -q --ignore=tests/test_source_profiles.py --tb=short

env PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 -m pytest -q tests/test_source_profiles.py
```

초기 sandbox 전체 실행은 로컬 127.0.0.1 listener 생성 실패 때문에 중단했다.
그중 첫 실패 `test_signed_peer_delivery_and_replay_rejection`은 로컬 TCP 허용 환경에서
그대로 재실행하여 통과했다. 환경 실패를 없애려고 transport 구현이나 테스트 기대값을 수정하지 않았다.
신규 사후검사 테스트 작성 중 p101/M101/n4의 일반 상한을 3으로 잘못 기대한 오류도 있었다.
실제 generalized E_bar는 4임을 확인하여 테스트를 고쳤다. runtime error 공식이나 사용자 task 값을
테스트 기대에 맞춰 변경하지 않았다. 최종 결과는 수정 후 fresh-process 실행을 기준으로 한다.

새 테스트는 요청한 12가지 regression을 포함한다: +/- toy recovery, odd/even midpoint,
여러 carry, worst-case E=10의 d21 이상 복원, d20 setup 거부, capacity 경계,
M32000/d100/U700 실패 설정 거부, noninteger adaptive 거부, legacy arithmetic 유지,
raw total 미감산 보존, history 불일치, weighted 거부.
추가로 h=p endpoint, 일반 E_bar=14 반례, 선택 인원 초과, residual/range 사후검사,
full-q ASR/opening/위원회 replay, BFT profile/vector tampering, closed public 오류 코드,
2-round local Flower workflow 및 offline verifier, 공식 Flower staging 전달을 검사한다.

통합 smoke는 기존 C=100 및 위에서 계산한 M을 사용한다. 별도 negative regression은
C=.01/M84021에서 실제 synthetic update를 **거부**한다. 첫 round max|x|는 약 .018147245964이고
clients 15..19가 .01을 초과했다. clipping/period resizing으로 해당 실패를 숨기지 않았다.
다른 task나 FMNIST에 이 smoke parameter를 자동 적용하지 않는다.
공식 staging 테스트는 패키지/manifest 전달 확인이지 공식 Ray federation 장기 실행이 아니다.

## 7. 아직 해결하지 않은 문제

- **adaptive MGF scale와 centered capacity 충돌:** 정수성만 맞아도 envelope가 실패할 수 있다.
  이전 bounded SUM에서 만든 beta=.2의 작은 period와 균일 worst-case envelope의 충돌은 해결하지 않았다.
- **Algorithm 6 history 차이:** actual-mask-sum과 paper-hprf는 동치가 아니다. 후자는 명시적으로 미지원이다.
- **scalar HPRF privacy:** full-q는 sampling domain 확대일 뿐 안전한 BLMR 구현이나 privacy 증명이 아니다.
- **raw-output inversion:** 독립 재검토에서 확인한 구조적 역산 문제가 남는다.
  raw 출력 역산을 masked transmission만으로 key recovery한 결과로 과장하지 않는다.
- **r+block input overlap:** 원본 입력 인코딩 충돌을 변경하지 않았다.
- **multi-round aggregate key leakage:** 여러 selection 집합의 공개 키 합으로 생기는 누출은 해결하지 않았다.
- **share-mask inconsistency:** 초기 공유 키와 client mask 키가 같다는 암호학적 증명이 없다.
- **weighted FedAvg + MGF 의미 변화:** 지원하지 않는다. n_i와 총 가중치 capacity, 필터/이력 단위 재검토가 필요하다.
- **closed-loop MGF 학습 실험 부재:** 이 통합의 2-round synthetic smoke는 bootstrap 검증이다.
  새 프로필로 4라운드 이후 history-bound feedback, FMNIST 학습 정확도와 공격 탐지력을 함께 검증하지 않았다.
- 큰 fixed M의 높은 정상 거부율/탐지력 변화, projected MGF만으로 full-coordinate bound를 보장하지 못하는
  문제, 일반 HotStuff 부분 동기 liveness 보장은 이번 작업 범위 밖이다.

## 8. 다음 작업 제안

다음 가장 작은 단계는 공개 fixture 하나에서 **명시적인 fixed-integer / actual-mask-sum / unweighted**
설정을 고정하고 최소 4라운드의 selection→recovery→history feedback을 재현하는 것이다.
기존 MGF predicate와 threshold 규칙을 유지한 채 실패 round, 정상 거부율, integer exact-match를 함께 기록한다.
실패를 parameter 자동 조정으로 덮지 않는다. 먼저 이 closed-loop 통합 결과를 얻고,
그 뒤에만 FMNIST나 paper-hprf history의 별도 구현 여부를 결정한다.

결론: opt-in bounded numeric recovery 경로는 legacy와 분리하여 구현했다.
MGF 실용성, scalar HPRF privacy, 논문 전체 재현 또는 production-secure 완료를 뜻하지 않는다.
