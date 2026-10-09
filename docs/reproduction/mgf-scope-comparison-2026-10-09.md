# Masked MGF scope 비교 — 2026-10-09

## 1. Scope

기준 문서를 처음부터 끝까지 읽은 뒤 구현했다:

- [독립 설계 검토](design-independent-review-2026-10-09.md)
- [source profile 통합](source-profile-integration-2026-10-09.md)

같은 masked transmission의 `projection` / `full-vector` 검사를 분리했다.
기존 task에 `source_profile.mgf_scope`가 없으면 projection을 유지하며, 기존
profile dict에 필드를 자동 삽입하지 않는다. 따라서 기존 manifest/digest의
의미도 바꾸지 않는다. 새 실험은 scope를 반드시 명시한다.

검증은 세 종류로 구분한다:

1. 실제 source numeric 함수에 동일한 공개 frozen FMNIST update/Y를 넣는 비교.
2. 각자의 선택 결과로 모델을 갱신하는 독립 benign/MR closed-loop 학습 비교.
3. 별도의 작은 synthetic Flower ProcessGrid / committee / offline replay 회귀.

FMNIST 학습 실험은 로컬에서 실행한 numeric/learning experiment다. 공개 fixture
키의 정수 합을 사용하며, 실제 FMNIST Flower 네트워크에서 VSS/ASR/BFT 전체를
실행했다고 주장하지 않는다. 실제 Flower 연결 검증은 3번 synthetic 회귀다.

## 2. Implementation

| 파일 / 함수 | 변경 |
|---|---|
| `trustlessfl/source_profiles.py:profile` | 선택적 `mgf_scope` 두 값 검증. 기존 explicit profile에서 생략도 허용 |
| `trustlessfl/source_paper_numeric.py:mgf_scope, scope_span` | projection의 기존 `[start,stop)` 또는 전체 `[0,dimension)` 선택 |
| `selection_statistics, select_masked` | 같은 raw masked Y에서 해당 범위의 정수 제곱합, 기존 bootstrap/threshold/selection |
| `integer_square_sum` | NumPy integer도 곱하기 전에 Python int로 변환. fixed-width square overflow 방지 |
| `history_statistics, recover` | 복원된 선택 합 U와 raw Y에서 얻은 B를 같은 scope로 평가. recovery 수식 자체는 불변 |
| `require_scope_history` | 다른 scope의 history 및 untagged projection history를 full-vector에 재사용하면 오류 |
| `trustlessfl/aion_source_asr.py:source_request` | committed numeric history에 explicit scope tag 보존 |
| `trustlessfl/aion_source_selection.py:authorize` | committee selection/replay도 committed history의 scope를 검증하고 보존 |
| `experiments/verify_source_learning.py:verify_learning` | offline verification에서 manifest scope와 metadata 및 history 좌표 일치 확인 |
| `experiments/compare_mgf_scope.py` | frozen / closed-loop / 기존 MR / performance / recovery artifact 생성 |
| `tests/test_mgf_scope.py` | scope, 단위/overflow, legacy, Flower committee/offline 회귀 |
| `tests/test_mgf_scope_comparison.py` | pre-existing rejection과 attack-specific change 구별, 동일 첫 라운드 통제 검증 |

기존 `--source-profile <json>` / `provision_source(..., source_profile=...)` 인터페이스를
그대로 쓴다. 두 실험에서 아래 complete profile의 `mgf_scope`만 다르다.

```json
{
  "recovery": "transmission-centered-v1",
  "key_domain": "author-full-q",
  "period_policy": "fixed-integer",
  "history": "actual-mask-sum",
  "aggregation": "unweighted",
  "rounding": "nearest-even",
  "S": 10000,
  "d": 21,
  "M": 840000021,
  "C": "100",
  "nmax": 20,
  "mgf_scope": "projection"
}
```

이는 이전 통합 보고서의 fixed smoke-test envelope를 그대로 쓴 것이다.
MGF에 유리하도록 M/C/threshold를 조정한 결과가 아니다. full-vector 설정에서도
기존 projection span을 manifest에 남겨 비교 맥락을 보존하지만 norm에는 쓰지 않는다.
`paper-hprf`는 여전히 explicit unsupported다.

manifest 전체 digest가 codec profile binding에 포함되므로 scope도 선택/벡터/ASR/
aggregate replay의 동일 task에 묶인다. 기존 signature/BFT binding을 약화하지 않는다.
HPRF/VSS 알고리즘, key reuse, client transmission, recovery 수식은 변경하지 않았다.

## 3. Mathematical definition

client가 생성한 **동일한** 정수 vector:

\[
u_i=\operatorname{RoundEven}(Sx_i),\quad
m_i=\left\lfloor\frac{2Mh_i+p}{2p}\right\rfloor,\quad
Y_i=du_i+m_i,\quad v_i=Y_i/(dS).
\]

전송 전에 `% M` 하지 않는다. MGF에 plaintext나 mask를 제거한 vector를 넣지 않는다.
FMNIST의 projection은 `J=[60856,61696)` 840좌표이고 전체는 61,706좌표다.

\[
\text{projection:}\quad\sum_{j\in J}Y_{ij}^2\le(dS)^2(b_r^{proj})^2,
\qquad
\text{full:}\quad\sum_jY_{ij}^2\le(dS)^2(b_r^{full})^2.
\]

제곱합은 Python arbitrary-precision integer이고 비교는 `Fraction`이다.
기존 bootstrap/history sqrt의 Decimal 60자리 규칙은 그대로 유지한다.
`pending.bound`의 float는 기존 wire receipt 호환용이며 실제 판정에는 쓰지 않는다.

선택 합 \(U_r=\sum_{i\in A_r}u_i\), raw 합 \(Y_A=\sum_{i\in A_r}Y_i\)를 보존하고:

\[
B_r=Y_A-dU_r=\sum_{i\in A_r}m_i,
\quad T_r^{proj}=\|U_r[J]/S\|_2+\|B_r[J]/(dS)\|_\infty,
\quad T_r^{full}=\|U_r/S\|_2+\|B_r/(dS)\|_\infty.
\]

각 scope의 두 committed term으로 독립 갱신한다:

\[
b_r^{scope}=b_{r-1}^{scope}\,T_{r-1}^{scope}/T_{r-2}^{scope}.
\]

이 식은 centered/quantized-sum profile 기준이다. 명시적 옛
`quantized-mean` legacy 설정은 기존 mean-update/mask-sum history를 유지한다.
첫 3라운드는 기존 percentile/ranking bootstrap이고 4라운드부터 inclusive bound다.
bootstrap의 benign rejection에는 의도적인 downselection이 포함되므로 순수 predicate
false alarm과 혼동하지 않는다. 생존자가 2명 미만이면 중단하고 threshold를 고치지 않는다.

## 4. Aion correspondence

`full-vector`의 masked norm은 Aion Algorithm 6의 전체 masked gradient norm에
더 가깝다. `projection`은 Flower adaptation의 계산량 절감 방식이다.

그러나 두 scope 모두 `actual-mask-sum` history다. 실제 정수 마스크 합 B를 쓰는
것과 aggregate key의 HPRF 대표값으로 history를 만드는 `paper-hprf`는 동치가 아니다.
full-vector 추가만으로 Aion Algorithm 6 또는 Aion 전체를 완전히 재현하지 않았다.

## 5. Side-by-side result

frozen 4라운드는 각 라운드에 **하나의 Y batch**를 만들고 두 scope에 그대로 넣었다.
selection과 history만 독립이다. client별 norm/threshold/selected/predicate-pass와
네 가지 교집합은 `side_by_side.json`에 기록한다.

| Round | 둘 다 accept | projection만 | full만 | 둘 다 reject |
|---|---:|---:|---:|---:|
| 1 | 1 | 1 | 1 | 17 |
| 2 | 0 | 2 | 2 | 16 |
| 3 | 0 | 2 | 2 | 16 |
| 4 | 2 | 13 | 0 | 5 |

Frozen r4 benign selection은 projection 15명, full-vector 2명이다. 기존 공개 MR로
clients 0..3의 update를 교체한 counterfactual에서도 **양쪽 선택 명단이 바뀌지 않았다**.
full-vector의 MR TPR 100%는 해당 4명이 benign일 때도 이미 탈락했다는 사실과 함께
읽어야 한다. `newly_rejected_attacker_ids`는 두 scope 모두 비어 있다.

## 6. Projection-outside-J fixture

독립 review의 predicate-only fixture와 동등한 `[0,10^50]`, J=[0,1), b=1을
실제 함수에 넣었다. Projection 제곱합은 0, full 제곱합은 \(10^{100}\)이다.
실제 selection 및 insufficient-valid 중단 여부를 artifact에 기록했다.

이 fixture는 signed VECTOR context 및 declared input bound 밖에 있다.
**인증된 전체 프로토콜 공격 성공 실험이 아니다.** 검사가 J 밖 변화를 보지 못한다는
predicate scope의 차이만 보여준다.

## 7. Performance

같은 full Y batch 20개에 대해 warmup 제외 반복 7회, predicate/statistics와
같은 선택 합의 history 통계를 측정했다. Allocation peak는 별도 tracemalloc 호출로
측정하며 전체 RSS/native memory가 아니다. WSL2 Python 3.12 CPU 측정으로,
동시에 기존 regression이 실행되었다. 모바일 latency는 측정하지 않았다.

숫자는 최종 artifact의 `performance.json`과 아래 trade-off 표를 따른다.
payload는 전체 정수 Y의 canonical JSON batch 크기이고 Flower framing/signature/
committee fanout을 포함하지 않는다. Source VECTOR 검증은 항상 dimension 전체를
요구하고 전송하므로 scope가 projection이어도 **Y 통신량은 줄어들지 않는다**.

## 8. Benign closed-loop

같은 pinned reference model의 zero-offset에서 시작했다. 데이터/partition/seed/epochs/
optimizer/lr/S/d/M/C/nmax/key/mask/history/recovery를 고정하고 scope만 바꿨다.
첫 라운드 update-set hash와 Y hash가 동일한지 코드로 강제 확인한다.
다음 라운드부터는 각자가 선택한 모델을 학습하므로 동일 update라고 주장하지 않는다.

| Scope | Round | accepted / 20 | benign rejection | test accuracy |
|---|---:|---:|---:|---:|
| projection | 1 | 2 | 90% (bootstrap) | 88.4667% |
| projection | 2 | 2 | 90% (bootstrap) | 88.5222% |
| projection | 3 | 2 | 90% (bootstrap) | 88.6444% |
| projection | 4 | 15 | 25% | 88.6667% |
| full-vector | 1 | 2 | 90% (bootstrap) | 88.2778% |
| full-vector | 2 | 2 | 90% (bootstrap) | 88.2000% |
| full-vector | 3 | 2 | 90% (bootstrap) | 88.0000% |
| full-vector | 4 | 2 | 90% | 87.9556% |

두 scope 모두 4라운드 진행했다. b/T/loss/global update norm/model hash와
continuation은 각 `*_rounds.json`에 있다. 학습 loss는 선택된 로컬 loss 평균이 아니라
갱신된 global model의 전체 staged train shards cross-entropy다.
test는 공개 test 10,000개 중 고정 앞 1,000개 validation을 제외한 9,000개다.
사용한 staged client train shards는 총 11,155개 예제다. 전체 FMNIST 60,000개로
새롭게 학습을 시작한 실험이 아니라 기존 pinned 공개 partition/reference를 사용했다.
이는 short continuation 검증이지 좋은 FPR/convergence 증명이 아니다.

## 9. Attack evaluation

benign pair가 모두 4라운드를 마친 뒤에만 동일 기존 FmnistTrainer MR을 별도의
두 closed-loop에 적용했다. 처음 3라운드는 benign, r4에 clients 0..3만 공격한다.
steps=120 / boost=20 / poison_batch=6의 기존 fixture이며 새 공격을 만들지 않았다.
Triggered target rate는 기존 helper로 전체 test 중 원래 target label=2가 아닌 예제에
trigger를 적용한 비율이고, clean accuracy의 validation 제외 split과 다른 평가 집합이다.

| Scope | r4 malicious accepted / 4 | attack TPR | benign FPR / 16 | final test accuracy | triggered target rate |
|---|---:|---:|---:|---:|---:|
| projection | 3 | 25% | 25% | 10.0778% | 100% |
| full-vector | 0 | 100% | 87.5% | 87.9556% | 0.4778% |

양쪽 MR loop도 4라운드를 완료했다. Full-vector는 이 fixture에서 모델 손상을
피했지만 benign을 대량 배제하는 선택 정책과 결부되어 있다. 동일-update counterfactual에서
공격 주입으로 새로 거부된 attacker가 없다는 결과 때문에, 이 숫자를 일반적인 공격 탐지
우월성 또는 낮은 오탐으로 해석하지 않는다. 더 긴 학습/여러 seed는 측정하지 않았다.

## 10. Recovery correctness

새 scope는 selection/history 좌표만 바꾼다. 같은 선택 집합에 대한 복원식은:

\[
\widehat U=\operatorname{RoundEven}\left(
\operatorname{center}_M\left([Y_A-\operatorname{scale}_M(H(K_A,r))]_M\right)/d\right).
\]

raw Y 합을 history용으로 유지하고, MGF 단계에서 `% M` 또는 unmask를 하지 않는다.
같은 집합의 scope별 recovery 동일성은 toy 회귀로 검사한다. 서로 다른 선택 집합의 U는
원래 다르므로 두 closed-loop aggregate 결과 자체가 같아야 한다고 요구하지 않는다.

frozen benign 8회 + benign closed 8회 + MR closed 8회, 총 24개 선택 합에서
61,706좌표씩 **1,480,944좌표 exact equality**, mismatch=0이다. Plaintext ground truth는
공개 local fixture에만 존재하고 runtime server 입력을 바꾸지 않았다. 모든 realized residual은
E_bar=10 이하이며 positive capacity margin을 기록했다. 배열/잔차/차이/여유값은
`recovery_checks.json`에서 확인할 수 있다.
최종 artifact 검산에서 realized residual의 최대 절댓값은 **5**였고 최소 capacity
margin은 **839057331/2 = 419,528,665.5**였다. Artifact 9개 SHA256과 기록한
implementation 4개 SHA256이 현재 파일과 일치했으며, 두 실행의 benign model hash
trajectory도 동일했다. SHA manifest 자체를 재귀적으로 hash했다고 주장하지 않는다.

## 11. Trade-off

최종 실험 artifact:
[mgf_scope_comparison_20261009T021637841695Z](../../experiments/results/mgf_scope_comparison_20261009T021637841695Z/report.md).
첫 측정 artifact `mgf_scope_comparison_20261009T020914830806Z`도 보존했다.
보고서 formatter와 counterfactual/동일 첫 라운드 검증을 보강한 뒤 **동일 파라미터로
전체 학습 실험을 재실행**한 것이 최종 artifact다.

| Metric | Projection | Full-vector |
|---|---:|---:|
| checked coordinates / client | 840 | 61,706 |
| MGF statistics/predicate median, batch 20 | 12.421 ms | 650.842 ms |
| history median, same selected aggregate | 8.837 ms | 536.060 ms |
| predicate traced peak allocation | 8,696 B | 495,624 B |
| history traced peak allocation | 69,352 B | 4,944,880 B |
| full Y batch canonical payload | 12,177,824 B | 12,177,824 B |
| benign-only r4 rejection/FPR | 25% | 90% |
| MR r4 TPR | 25% | 100% |
| MR r4 benign FPR | 25% | 87.5% |
| benign / MR rounds completed | 4 / 4 | 4 / 4 |
| benign final clean test accuracy | 88.6667% | 87.9556% |
| MR final clean test accuracy | 10.0778% | 87.9556% |
| recovery mismatch | 0 | 0 |

최종 median 비율은 predicate 약 **52.40배**, history 약 **60.66배**다.
첫 측정에서는 각각 약 73.09배 / 84.87배였고 선택/학습 결과는 같았다.
동시 회귀/WSL scheduling으로 timing 변동이 있어 단일 배율을 일반적인 latency 보장으로
읽지 않는다. 두 artifact 모두 원본 timing 반복값을 남긴다.

테스트 실행 및 정확한 구분:

- 전체 suite snapshot: **1,628 passed / 4 skipped**, 659.59초. 기존 1,614 passed /
  4 skipped에 이번 scope runtime 회귀 14개가 추가된 실행이다.
- 이후 최종 scope/실험 지표 두 파일 focused 실행: **20 passed**, 11.09초.
  그중 scope 14개는 위 전체 실행과 중복이고 comparison helper 6개는 이후 추가했다.
- 따라서 중복을 빼면 기존 1,614개와 새 20개가 통과했다. 두 실행을 1,648개의
  서로 다른 통과 테스트처럼 더하지 않는다. 기존 4개 skipped를 통과로 세지 않는다.
- `git diff --check`: 통과.

회귀 coverage는 scope 좌표/같은 masked Y/history 분리/legacy default 및 recovery/
scope-independent centered recovery/NumPy large signed square/full Flower committee
replay와 offline verification을 포함한다. 초기 작은 toy fixture의 d=3은 기존
generalized bound E_bar(2,101)=2에 의해 거부됐다. **toy 테스트만** d=5로 올바르게
정의했으며 실험 또는 runtime 파라미터를 실패를 숨기기 위해 바꾸지 않았다.

재실행 명령 (repository root, 기존 로컬 dependency/data cache 사용):

```bash
env PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 experiments/compare_mgf_scope.py
```

output은 매번 별도 UTC timestamp 디렉터리이며 `exist_ok=False`로 기존 결과를
덮어쓰지 않는다. `config.json`, `side_by_side.json`, `projection_rounds.json`,
`full_vector_rounds.json`, `performance.json`, `recovery_checks.json`, `report.md` 외에
`attack_rounds.json`, `controlled_comparison.json`, `sha256.json`도 생성한다.

핵심 질문에 대한 판단:

1. **공격 탐지 이점:** 이 MR fixture에서 full-vector가 공격 update를 덜 받아 모델을
   보존했다. 그러나 frozen counterfactual에서 attacker는 공격 전부터 탈락했다.
   attack-specific detection gain이 독립적으로 입증된 것은 아니다.
2. **benign cost 없는 이점:** 확인하지 못했다. r4 benign-only 거부율 90%는 projection의
   25%보다 높다. 높은 TPR만으로 사용할 만한 filter라고 판단할 수 없다.
3. **계산 비용:** 840→61,706좌표이고 실제 정수 predicate/history 비용도 증가했다.
   네트워크 Y payload는 동일하다. 정확한 배율은 최종 표를 따른다.
4. **J 밖 poisoning:** projection norm은 그 변화에 직접 반응하지 않는다. Predicate-only
   반례는 이를 증명하지만 signed bounded end-to-end poisoning 성공까지 증명하지 않는다.
5. **closed-loop 실용성:** threshold를 조정하지 않아도 4라운드는 진행됐지만 full-vector는
   매번 2명만 선택했다. 현 bootstrap/history의 practical usability는 확보되지 않았다.
6. **복원 정확성:** scope와 무관하게 검증한 선택 합은 exact recovery였다. scope 변경은
   참여 집합/모델/history를 바꾸지만 encoding/modular arithmetic을 바꾸지 않는다.

가장 작은 다음 단계는 **현재 key/encoding/recovery를 고정한 채**, MGF의 high benign
rejection 원인을 bootstrap 및 history 통계로 분리해 진단하는 것이다. Threshold를 몰래
완화하거나 adaptive period를 자동 확대하지 않는다. Policy 변경은 별도 연구 옵션으로
명시하고 동일-update 및 closed-loop를 다시 비교해야 한다.

## 12. Limitations

- actual-mask-sum != paper-hprf history; Algorithm 6 완전 재현 아님.
- scalar HPRF privacy unresolved.
- raw-output inversion unresolved; masked Y만으로 역산했다는 주장 아님.
- r+block input overlap unresolved.
- multi-round aggregate-key leakage unresolved.
- share-mask inconsistency unresolved.
- weighted FedAvg unsupported; unweighted client mean만 사용.
- production security not established.
- adaptive MGF scale와 centered capacity 충돌은 해결하지 않았다. 고정 envelope만 평가.
- 공개 deterministic fixture keys는 runtime CSPRNG sampler가 아니다.
- FMNIST loop는 실제 전체 Flower network/VSS 실행이 아닌 local learning/numeric 실험.
- 1 seed / 4 rounds / 기존 단일 MR fixture; 장기 수렴과 일반 robustness 결론 불가.

기존/새 artifact를 덮어쓰지 않았으며 결과와 입력/source SHA256을 보존한다.
