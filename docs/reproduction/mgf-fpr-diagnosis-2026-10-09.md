# Full-vector MGF 정상 거부율 원인 분석 — 2026-10-09

## 1. Scope

기준 문서 세 개를 처음부터 끝까지 읽고 사용했다:

- [독립 설계 검토](design-independent-review-2026-10-09.md)
- [source profile 통합](source-profile-integration-2026-10-09.md)
- [MGF scope 비교](mgf-scope-comparison-2026-10-09.md)

이번 작업은 **원인 식별**이다. Runtime, HPRF, VSS, MGF predicate/bootstrap/history,
threshold, S/d/M/C/nmax/J, clipping, recovery를 수정하지 않았다.
새 파일은 `experiments/diagnose_mgf_fpr.py`, 진단/ledger 테스트 두 파일, 이 문서 및
별도 결과 artifact다. 이전 dirty worktree를 보존했다.

최종 artifact:
[mgf_fpr_diagnosis_20261009T025455220443Z](../../experiments/results/mgf_fpr_diagnosis_20261009T025455220443Z/report.md).
이전 scope 비교 artifact의 SHA256, 입력/원본 source snapshot, implementation hash를
먼저 검증한다. 공개 fixture의 같은 키/양자화/마스크/Y를 재생성하며, closed-loop의
update/model/Y hash와 선택/threshold/history가 이전 결과와 정확히 같아야 진행한다.

두 종류의 근거를 섞지 않는다:

- **Frozen:** 동일 update 및 동일 Y를 두 scope에 넣은 primary 비교.
- **Closed-loop replay:** 각 scope의 이전 모델에서 client를 다시 학습한 비교.
  첫 라운드 이외에는 서로 다른 update다. Component/coordinate 통계에는
  `trajectory_scope`를 넣어 두 trajectory를 합치거나 덮어쓰지 않는다.

Oracle threshold와 float64 percentile/RMS는 offline 진단일 뿐 실제 selection에
사용하지 않는다. 실제 판정은 기존 정수 제곱합/Fraction, sqrt는 기존 Decimal 60자리다.
Full FMNIST network/VSS 실행이 아닌 공개 로컬 learning/numeric replay다.

## 2. Previous result

아래 값은 이전 비교 결과이며 새 latency benchmark가 아니다.

| Metric | Projection | Full-vector |
|---|---:|---:|
| checked coordinates | 840 | 61,706 |
| benign-only r4 rejection | 25% | 90% |
| MR attack rejection | 25% | 100% |
| predicate median, 20 clients | 12.42 ms | 650.84 ms |
| MR 이후 clean test accuracy | 10.08% | 87.96% |

고정 profile은 S=10000, d=21, M=840000021, C=100, nmax=20,
full-q public fixture keys, fixed-integer/actual-mask-sum/unweighted다.
이 값은 이전 **복원 smoke envelope**이지 좋은 MGF 파라미터로 선택한 것이 아니다.
Client 제거/새 clipping/threshold 확대/자동 M 증가를 하지 않았다.

## 3. Norm scaling

\[
D_{proj}=840,\quad D_{full}=61706,\quad
\sqrt{D_{full}/D_{proj}}=8.570853155289.
\]

| Frozen benign round | mean full/proj L2 ratio | median full/proj RMS ratio |
|---|---:|---:|
| 1 | 8.56464420 | 0.997575840 |
| 2 | 8.57019374 | 0.998559899 |
| 3 | 8.56974545 | 0.997912829 |
| 4 | 8.59367182 | 0.998696267 |

**전체 masked norm의 절대 크기 증가는 대략 sqrt(D)로 설명된다.** 하지만 이것과
"full threshold에 dimension 계수가 누락됐다"는 주장은 다르다. b도 각 scope의
자기 norm으로 bootstrap한다. Projection의 b를 full-vector에 재사용하지 않는다.
RMS가 비슷하다는 것은 아래 분해에서 보듯 주로 **마스크 RMS가 비슷하다**는 근거다.
실제 update의 좌표 분포까지 같다는 뜻이 아니다. 이 계수를 threshold에 곱하지 않았다.

## 4. Norm decomposition

\[
v=u/S+m/(dS),\quad
\|v\|^2=\|u/S\|^2+\|m/(dS)\|^2+
2\langle u/S,m/(dS)\rangle.
\]

`decomposition`은 세 제곱합과 cross term을 Python integer/Fraction으로 먼저
계산해 항등식을 정확히 검증한다. 큰 비슷한 float norm 제곱을 차감해서 cross term을
추정하지 않는다. signed square 전에 Python int로 변환하므로 int64 overflow가 없다.

Frozen benign r4, 각 값은 **20 client별 값의 median**이다:

| Component | Projection | Full-vector |
|---|---:|---:|
| update L2 | 0.02788774 | 0.07656055 |
| mask L2 | 66,928.1723 | 574,042.665 |
| mask/update ratio | 2,344,190 | 7,479,332 |
| mask-square / total-square | 0.999999996868 | 0.999999995055 |

즉 client score는 실제 update보다 수백만 배 큰 마스크 norm에 지배된다.
Total norm과 mask-only norm의 client 순위 Spearman은 benign r1~4에서 두 scope 모두
**1.0**이다. Source selection은 total Y를 그대로 검사한 결과이고 mask-only norm은
비교용 통계다. Mask-only vector로 predicate를 교체한 것이 아니다.

Cross term은 signed 값이므로 component-square 비율을 확률/독립적인 에너지 비중으로
해석하지 않는다. 모든 client의 interaction 및 상대 비율은 `norm_decomposition.json`에
있다. Benign에서는 작은 update 및 interaction이 masked norm 순위를 바꾸지 않았다.
MR의 경우에도 원래 update L2는 크게 증가하지만 총 masked L2의 변화는 훨씬 작다(8절).
Closed benign full-vector의 **자기 trajectory 20명만** 계산한 median update norm은
0.08601632, mask/update는 6,837,744다. Interaction/total-square의 절댓값 median은
약 5.05×10⁻⁹다. Frozen과 다른 model에서 나온 component 값은 섞어 평균내지 않았다.

## 5. Threshold trajectory

실제 source: `source_paper_numeric.selection_statistics/select_masked`.
N=20에서 bootstrap r1~3의 정확한 규칙:

1. masked 정수 제곱합을 정렬한다.
2. `minimum=N//10=2`, `maximum=4*N//5=16`이다.
3. **zero-based rank 2, 즉 세 번째 작은 norm**으로 b를 만든다.
4. cutoff square보다 **strictly smaller**인 square 수를 rank로 센다.
5. `count=max(minimum,min(maximum,rank))`명, 즉 일반적인 distinct-score 경우 2명을 선택한다.

이는 보간된 `np.percentile(...,10)` 계산이 아니다. 첫 3라운드의 90% rejection은
의도적 downselection을 포함하며 inclusive predicate FPR로 해석하면 안 된다.
선택 flag와 exact predicate-pass flag를 별도로 기록했다. r4부터 inclusive bound이며
2명 미만은 중단한다.

Benign **closed-loop replay**의 trajectory:

| Scope | Round | b_r | selected | b_r/b_prev |
|---|---:|---:|---|---:|
| projection | 1 | 66,179.072954 | 17,4 | — |
| projection | 2 | 65,608.323195 | 18,13 | 0.9913756761 |
| projection | 3 | 65,887.073200 | 6,19 | 1.0042486988 |
| projection | 4 | 67,371.648796 | 15명 | 1.0225321224 |
| full-vector | 1 | 571,423.052776 | 5,17 | — |
| full-vector | 2 | 571,288.458686 | 5,17 | 0.9997644581 |
| full-vector | 3 | 571,366.968455 | 5,17 | 1.0001374258 |
| full-vector | 4 | 571,366.860250 | 5,17 | 0.9999998106 |

Full b4는 benign median 574,042.667보다 약 0.466% 낮다. 엄청난 order-of-magnitude
축소가 아니라 **좁은 분포의 낮은 tail**에 위치하기 때문에 18명이 넘는다.
Full r4 norm/b의 min/median/mean/p75/p90/p95/max는 각각
0.9992033 / 1.0046832 / 1.0041257 / 1.0053891 / 1.0070899 / 1.0074237 / 1.0098821이다.
Projection은 median 0.9934175, p90 1.0062578이다.

동일한 frozen r4의 20명 전체 norm/threshold/ratio/margin/accept 및 closed-loop 20명
전체 표는 최종 artifact의 `report.md` §5에 있다. Client 단위 원본은 `client_norms.json`,
round별 모든 분포/순위 cutoff/선택 명단은 `threshold_trace.json`이다.
Frozen full b4는 571,367.325738이며 closed full b4와 혼동하지 않는다.

## 6. History decomposition

\[
B_r=\sum raw\,Y_i-dU_r,\quad
H_{update}=\|U_{region}/S\|_2,\quad
H_{mask}=\max(B_{region})/(dS),\quad T=H_{update}+H_{mask}.
\]

현재 mask가 nonnegative이므로 max는 L∞ norm이다. B가 실제 mask integer들의
정수 합과 같은지 매 라운드 독립 대조한다. U는 선택된 **합**이지 optimizer mean이 아니다.

Closed benign full-vector:

| Round | H_update | H_mask | mask/T | T_r/T_prev |
|---|---:|---:|---:|---:|
| 1 | 0.05034660 | 7976.598748 | 0.9999936883 | — |
| 2 | 0.04242381 | 7976.598748 | 0.9999946815 | 0.9999990068 |
| 3 | 0.04091320 | 7976.598748 | 0.9999948709 | 0.9999998106 |
| 4 | 0.03806810 | 7976.598748 | 0.9999952276 | 0.9999996433 |

H_mask는 네 라운드에서 **정확히 같은 Fraction**이었다. 작은 T 변화는 H_update에서 온다.

\[
b_4=571366.9684548263\times
\frac{7976.639660819851}{7976.641171433114}
=571366.8602495677.
\]

상대 변화는 **−0.00001893796%**다. Full-vector 높은 FPR 직전에 history collapse가
일어났다는 가설은 지지되지 않는다. 거의 움직이지 않는 bound가 bootstrap의 낮은 cutoff를
유지한 것이다. 반면 projection T3/T2=1.0225321224라서 b4가 약 2.25% 상승했고,
현재 projection norm 분포에서 더 많은 client가 통과했다.

r2/r3에도 T ratio는 계산할 수 있지만 실제 b2/b3는 새 bootstrap cutoff로 결정된다.
그 ratio를 실제 bound 갱신에 사용했다고 보고하지 않는다. r4의 `b4/b3=T3/T2`만
정확히 대조한다.

추가 **미실행 r5 diagnostic**: projection은 선택 인원이 2→15명으로 바뀌어 T4/T3가
5.602583이고 식대로 계산한 nominal b5는 377,455.2543이다. Full nominal b5는
571,366.6565다. 이는 실제 r5 선택/학습 결과가 아니며 collapse/explosion의 실행 증거로
세지 않는다. Actual mask-SUM의 cardinality 의존성이 다음 feedback에 영향을 줄 수 있음을
보여주는 계산이다. 전체 H_update/H_mask/T/분수 ratio/nominal 및 actual b_next는 JSON에 있다.

## 7. Projection representativeness

J=[60856,61696)은 LeNet5의 **`classifier.weight` (10×84)** 전체다.
전체 vector의 uniform random sample이 아니며 마지막 classifier bias 10개도 포함하지 않는다.

Masked total의 RMS는 J와 full에서 비슷하다. 그러나 update norm의 full/proj 비율은
약 2.75 수준이고 mask/total의 약 8.59와 다르다. 따라서 "RMS가 비슷하니 실제 learning
update도 대표한다"는 결론은 틀린다. Update RMS는 J가 J 밖보다 더 큰 반면 mask RMS는
대체로 비슷하다. 세 vector의 각 region 통계와 top-square 기여율은
`coordinate_statistics.json`, client RMS/비율은 `projection_vs_full.json`에 기록한다.

Frozen r4의 **client별 RMS를 구한 뒤 20명의 median**:

| Region | update RMS | mask RMS | masked RMS |
|---|---:|---:|---:|
| J | 0.0009622184 | 2309.241333 | 2309.241323 |
| J 밖 | 0.0002923529 | 2311.235723 | 2311.235729 |
| full | 0.0003082062 | 2310.896393 | 2310.896405 |

J/outside update RMS 비율의 client median은 **3.241685**다. 반면 같은 masked input의
projection/full norm 비율 median은 0.11682681이다. Mask RMS가 비슷한 것과
update 대표성은 분리해서 판단해야 한다.

Coordinate 통계도 먼저 client별로 계산한 뒤 아래에 median을 표시한다.
Pooled coordinate distribution의 통계라고 주장하지 않는다. 단위는 모델 단위다.

| Scope / vector | mean | std | median | p90 abs | p99 abs | max abs |
|---|---:|---:|---:|---:|---:|---:|
| projection / update | 0.000001667 | 0.000962214 | 0 | 0.0011 | 0.004711 | 0.00765 |
| projection / mask | 1995.119979 | 1147.759257 | 1999.080824 | 3595.907536 | 3948.454986 | 3995.611800 |
| projection / masked | 1995.119980 | 1147.759274 | 1999.080649 | 3595.907576 | 3948.454955 | 3995.612000 |
| full / update | 0.000006645 | 0.000308144 | 0 | 0.0004 | 0.001250 | 0.00765 |
| full / mask | 2000.981934 | 1155.456627 | 2004.336400 | 3600.509456 | 3959.366428 | 3999.938100 |
| full / masked | 2000.981943 | 1155.456629 | 2004.336450 | 3600.509081 | 3959.366288 | 3999.937450 |

Full masked norm-square에서 top 0.1% / 1% / 5%의 기여 median은
**0.3007% / 2.9695% / 14.2463%**다. Remaining 95%가 약 85.75%를 차지한다.
소수의 거대한 masked coordinate가 전체 norm을 독점하는 모습은 아니다.
반대로 actual update-square의 top 0.1% / 1% / 5%는 **13.7410% / 39.7525% /
69.2805%**로 더 집중되어 있다. Mask와 update의 좌표 특성도 다르다.

통계는 mean/std/median/p90abs/p99abs/maxabs, top 0.1%/1%/5% 및 remaining 95%다.
Top fraction은 `ceil(D*fraction)`개의 coordinate로 정의하며 실제 coordinate count를 남긴다.
Sparse outlier가 masked full L2를 지배하는지와 실제 update energy 집중도를 구분한다.
이는 기존 J를 변경하거나 centered mask로 바꾸는 작업이 아니다. Mask 대표값은 여전히
uncentered이고 모델 단위 범위는 [0,4000.0001]이다.

Projection의 낮은 r4 FPR은 **작은 raw norm이기 때문만은 아니다**. b도 같은 scope의
norm으로 작아진다. 다른 mask-score 분포/선택 명단/H_mask 변화로 b4가 상승한 효과를 함께
봐야 한다. Total-score 순위가 mask-only 순위와 같다는 점 및 두 scope의 낮은 oracle AUC는
낮은 FPR을 더 좋은 update 대표성/공격 탐지력의 증거로 해석하지 못하게 한다.

## 8. Attack separation

기존 clients 0..3 MR을 그대로 사용했다. Attack과 paired clean은 같은 client/round/key/mask,
동일 pre-r4 model/history다. Frozen/closed 결과를 따로 기록한다.

| Context | Scope | benign median | benign p90 | malicious median | malicious min/max |
|---|---|---:|---:|---:|---|
| frozen-MR | projection | 66928.172032 | 67836.136607 | 66924.189032 | 65739.695303 / 67538.219423 |
| frozen-MR | full-vector | 574042.668199 | 575469.725631 | 573640.332438 | 572905.168261 / 575020.867576 |
| closed-MR | projection | 66928.172147 | 67836.136642 | 66924.192039 | 65739.700828 / 67538.227147 |
| closed-MR | full-vector | 574042.667200 | 575469.724743 | 573640.377926 | 572905.211992 / 575020.912397 |

네 malicious norm 모두 benign의 min/max 구간 안이다. 이는 명시한 구간 overlap count이며
분포 전체의 확률밀도 overlap을 추정했다는 뜻은 아니다.

Closed full MR의 실제 update L2는 **9.61~9.86**으로 benign보다 매우 크지만,
총 masked norm은 paired clean 대비 **0.94~1.05 감소**했다. 변화율은 약
−1.64~−1.82×10⁻⁶으로 client 간 마스크 norm 차이보다 작다. Cross term이 음수인 효과도 있다.
현재 threshold는 두 분포 사이의 분리 경계가 아니다. 이전 높은 TPR은 공격 전부터
mask norm이 큰 client를 탈락시키던 선택과 같았다.

## 9. Oracle threshold diagnostic

정수 score의 모든 cutoff를 sweep하고 `score/(dS)^2 > threshold^2`로 TPR/FPR를
계산한다. 방향은 high norm rejects로 고정하며 tie를 임의로 나누지 않는다.
현재 실제 threshold는 별도 row로 보존한다. **이 oracle는 알려진 label을 쓰는
사후 분석이며 실제 protocol에 적용할 수 있는 solution이 아니다.**

Frozen 및 closed MR에서 동일한 관측:

| Diagnostic | Projection | Full-vector |
|---|---:|---:|
| AUC (high norm rejects) | 0.53125 | 0.5 |
| best TPR at FPR≤0 | 0% | 0% |
| best TPR at FPR≤10% | 0% | 0% |
| best TPR at FPR≤25% | 50% | 25% |
| 최소 FPR로 TPR=100%를 얻는 지점 | 81.25% | 75% |

Full-vector는 이 fixture에서 threshold 위치만 고쳐서 좋은 discriminator로 만들 수 있다는
근거가 없다. Bootstrap을 높이면 정상 acceptance를 늘릴 수는 있어도 MR 분리가 생기는
것은 아니다. 4명/16명의 작은 표본이므로 다른 공격/키/seed에 대한 불가능 정리는 아니다.
모든 threshold와 confusion count는 `oracle_threshold.json`에 있다.

## 10. Root cause classification

| Category | 판단 | 근거 |
|---|---|---|
| A. Dimension calibration failure | **not supported** | Raw norm 증가≈sqrt(D)는 관측되지만 full b 자체를 full norm으로 초기화한다. Projection b 재사용/누락된 dimension 계수가 아님 |
| B. Mask domination | **supported** | Mask/update가 수백만 배. Mask-square가 total-square의 거의 전부, 순위 상관 1.0, history mask 비중>99.999% |
| C. History instability | **not supported** | Full b4/b3≈0.99999981, 이전부터 bootstrap rejection 90%; 급락/폭증 없음 |

별도로 **낮은 bootstrap cutoff의 지속**이 직접 원인이다.

```text
넓은 C=100의 centered envelope → 큰 고정 transmission period
→ client norm과 selected history가 마스크에 지배됨
→ bootstrap은 norm 하위 2/20명을 선택하고 낮은 b3를 남김
→ full history ratio≈1, b4≈b3
→ 같은 낮은 tail만 통과하고 benign rejection 90% 지속
```

H1은 "절대 norm 크기의 dimension scaling" 관점에서는 지지되지만,
"그 때문에 threshold에 dimension 배율이 빠졌다"는 A는 지지되지 않는다.
H2/마스크 지배는 지지된다. Bootstrap 이후 H_mask가 거의 일정한 현상이 확인됐지만,
이를 history가 비정상적으로 **축소**됐다고 부르지 않는다.

최종 질문에 대한 답:

1. 가장 큰 원인은 **마스크 지배 + bootstrap의 낮은 cutoff 유지**다.
2. 단순 dimension scaling만으로 FPR를 설명할 수 없다. Threshold도 해당 차원에서 계산한다.
3. Mask가 client norm과 selected history를 모두 지배한다.
4. History ratio는 b4를 비정상적으로 축소시키지 않았다.
5. 현재 fixed profile의 full norm은 이 MR fixture에서 낮은 FPR의 분리 잠재력을 보여주지 못했다.
6. Projection의 낮은 FPR는 좋은 대표성 증거가 아니다. 작은 subset에서 다른 mask/history
   trajectory를 갖는 효과이며 update 자체는 classifier layer에 편중돼 있다.
7. 다음 단 하나의 검토 요소는 **mask scaling / transmission-period policy**다.

## 11. Recovery regression

기존 24개 선택 합의 **1,480,944좌표**를 검증하고 동일 업데이트에서 다시 계산했다.
새 frozen MR r4 두 scope의 123,412좌표를 더해 fresh **26개 선택 합 / 1,604,356좌표**가
plaintext quantized integer sum과 정확히 일치했다. 기존과 겹치는 재현을 독립 모델 좌표
증가로 과장하지 않는다. Baseline의 U/잔차/raw Y 합 hash도 각각 대조한다.

Mismatch=0. Raw Y를 instrumentation 전후 hash로 대조하고 B를 direct mask sum과 비교했다.
Runtime Python 파일의 실행 전후 SHA256도 동일하다. `% M → center → RoundEven`과
ring 밖 unweighted mean을 변경하지 않았으며 server에 새로운 plaintext 입력을 넣지 않았다.
수치 배열/잔차/capacity margin 및 변경 없음 기록은 `recovery_regression.json`에 있다.

Fresh residual 최대 절댓값은 5, 최소 realized capacity margin은
**839019825/2 = 419,509,912.5**다. Setup의 E_bar=10 / d=21 / envelope를 그대로 사용했다.

최종 관련 회귀 실행은 **335 passed**, 37.84초다: 기존 관련 317개 + 새 diagnostic
helper 13개 + 새 pinned ledger 검산 5개. 이는 이번 단계의 관련 모듈 실행이며 전체
repository suite를 다시 335개만 돌렸다는 의미로 오해하지 않는다. 이전 전체 suite
1,628 passed/4 skipped는 이전 보고서의 결과로만 남긴다. `git diff --check`도 통과했다.
Artifact 11개 SHA256 및 runtime Python 46개 실행 전후/현재 hash를 검산했다.

검증 과정에서 발견한 diagnostic 오류도 보존했다:

- 첫 helper 테스트에서 NumPy array의 truth-value 및 60자리 diagnostic ratio의 중복
  rounding 문제를 발견해 helper만 수정했다. Runtime/parameter는 수정하지 않았다.
  해당 중단 디렉터리는 `INCOMPLETE.md`로 표시했다.
- 첫 완주 artifact 검산에서 다른 closed-loop component의 grouping key가 겹치는 문제를
  발견했다. Recovery/선택/threshold는 이미 일치했지만 분해 통계 grouping은 승인하지 않고
  `trajectory_scope`로 분리해 **새 디렉터리에서 전체 재실행**했다. 옛 결과는
  `SUPERSEDED.md`로 표시했다. 최종 artifact의 모든 exact-square/score identity와
  history trace를 다시 검증했다. 실패를 파라미터 조정으로 숨기지 않았다.

재실행 (repository root, 기존 공개 data/dependency cache 필요):

```bash
env PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 experiments/diagnose_mgf_fpr.py

env PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 -m pytest -q tests/test_mgf_fpr_diagnosis.py tests/test_mgf_fpr_artifact.py
```

새 output은 `exist_ok=False`의 UTC timestamp 디렉터리다. Pinned ledger 테스트는 최종
기록 디렉터리를 기본으로 검사하며, 다른 재실행을 검증할 때 `MGF_FPR_ARTIFACT`로 지정한다.
결과 11개 파일과 SHA manifest를 남겼고 기존 artifact를 덮어쓰지 않았다.

## 12. Limitations

- Oracle threshold는 실제 protocol solution이 아니며 적용하지 않았다.
- actual-mask-sum != paper-hprf. 후자는 여전히 미지원이다.
- Scalar HPRF privacy/full-q security/raw-output inversion/r+block overlap unresolved.
- Aggregate-key leakage unresolved.
- Share-mask consistency unresolved.
- Weighted FedAvg unsupported.
- Production security not established.
- 공개 fixture의 key/update를 분석하는 로컬 실험이지 외부 client 데이터를 공격한 것이 아니다.
- 1 seed / 4 rounds / 기존 MR 4명. IID/uniform mask 보안 정리 또는 모든 poisoning의 결론 아님.
- Component/RMS/percentile은 diagnostics다. Decimal norm은 기존 60자리 sqrt이지 무한정밀도 아님.
- 높은 정상 acceptance로 보이게 하기 위한 clipping/selection/threshold/parameter 변경 없음.

## 13. Recommended next experiment

**단 하나: mask scaling/period-policy의 feasible 영역과 signal separability를 대조하는
offline 실험.** S,d,nmax,C와 decoder 및 frozen update를 고정하고, feasible M 구간에서
mask/update 비율 및 norm 분리 가능성을 조사한다. Bootstrap/history를 동시에 고치지 않는다.

현재 envelope에서는:

\[
\frac{M}{dS}>\frac{2dn_{max}B_u+2\overline E}{dS}
=2n_{max}C+\frac{2\overline E}{dS}\simeq4000.
\]

선언한 C=100을 그대로 보장하려면 현재 M보다 작게 낮추는 방식은 feasible하지 않다.
같은 h≥0에서 `scale_M(h)`는 M에 대해 nondecreasing이므로 더 큰 M으로 마스크 norm을
줄일 수도 없다. 이는 current envelope/fixture의 제약이지 모든 Aion 구현의 불가능 주장 아님.
이 단일 policy audit에서 feasible하며 쓸 만한 영역이 없다는 결론도 허용해야 한다.
그 결과를 얻기 전에 C/clipping/threshold/d를 같이 바꾸거나 새로운 MGF를 설계하지 않는다.
