# Full-vector MGF benign FPR diagnosis

## 1. Scope

Pinned public fixture replay only: no predicate/threshold/parameter/key/recovery edits. Frozen same-Y analysis is separated from independently trained closed-loop trajectories. All selection and sqrt precision conventions remain the source implementation's.

## 2. Previous result

R4 benign rejection projection=25%, full=90%; MR rejection=25%,100%. Previous predicate medians 12.42/650.84ms, MR clean accuracies 10.08/87.96%. These are previous measurements, not new performance benchmarks.

## 3. Norm scaling

D_proj=840, D_full=61706; sqrt ratio=8.57085315529. Diagnostic ONLY, never a threshold.

| Context / round | mean full/proj norm | median full/proj RMS |
|---|---:|---:|
| frozen-benign (shared-frozen) / 1 | 8.5646442 | 0.99757584 |
| frozen-benign (shared-frozen) / 2 | 8.57019374 | 0.998559899 |
| frozen-benign (shared-frozen) / 3 | 8.56974545 | 0.997912829 |
| frozen-benign (shared-frozen) / 4 | 8.59367182 | 0.998696267 |
| closed-benign (projection) / 1 | 8.5646442 | 0.99757584 |
| closed-benign (projection) / 2 | 8.57019375 | 0.998559902 |
| closed-benign (projection) / 3 | 8.56974544 | 0.997912829 |
| closed-benign (projection) / 4 | 8.59367181 | 0.998696266 |
| closed-benign (full-vector) / 1 | 8.5646442 | 0.99757584 |
| closed-benign (full-vector) / 2 | 8.57019375 | 0.998559901 |
| closed-benign (full-vector) / 3 | 8.56974544 | 0.997912825 |
| closed-benign (full-vector) / 4 | 8.59367181 | 0.998696268 |

## 4. Norm decomposition

Exact squares: N_total^2=N_update^2+N_mask^2+2<u/S,m/(dS)>. Python integers and Fraction verify the identity; component sqrt uses 60-digit Decimal. Coordinate percentiles/RMS are float64 diagnostics, not predicate inputs.

| Context r4 | Scope | median update norm | median mask norm | median mask/update | median mask square fraction |
|---|---|---:|---:|---:|---:|
| frozen-benign | projection | 0.0278877386 | 66928.1723 | 2344190.08 | 0.999999996868 |
| frozen-benign | full-vector | 0.0765605469 | 574042.665 | 7479331.57 | 0.999999995055 |
| closed-benign | projection | 0.0287763648 | 66928.1723 | 2303168.69 | 0.999999996793 |
| closed-benign | full-vector | 0.0860163152 | 574042.665 | 6837744.04 | 0.999999995928 |

## 5. Threshold trajectory

Source bootstrap r1-3: min=floor(N/10)=2, max=floor(4N/5)=16; zero-based rank 2 (third-smallest squared norm) supplies b. Rank counts STRICTLY smaller scores, then selection count=max(min,min(max,rank)). With distinct scores this selects exactly 2/20. The inclusive bound is active only from r4; <2 survivors abort. Bootstrap selected and predicate-pass flags are separately recorded (including Decimal cutoff rounding).

| Context | Scope | Round | b | norm median | norm min/max | selected | b/b_prev |
|---|---|---:|---:|---:|---|---|---:|
| frozen-benign | projection | 1 | 66179.073 | 67245.3191 | 64487.6924 / 68419.9105 | [17, 4] | None |
| frozen-benign | projection | 2 | 65608.3232 | 66940.7056 | 65266.9937 / 68482.1198 | [18, 13] | 0.9913756766685544 |
| frozen-benign | projection | 3 | 65887.0731 | 67067.7866 | 64898.868 / 68485.4529 | [6, 19] | 1.004248696300317 |
| frozen-benign | projection | 4 | 67371.643 | 66928.172 | 65220.6823 / 67923.0255 | [6, 19, 14, 3, 16, 11, 10, 2, 5, 13, 18, 17, 12, 9, 1] | 1.0225320361197399 |
| frozen-benign | full-vector | 1 | 571423.053 | 574217.326 | 570723.503 / 576891.736 | [5, 17] | None |
| frozen-benign | full-vector | 2 | 571288.46 | 574230.075 | 570780.805 / 576830.819 | [5, 17] | 0.9997644595962801 |
| frozen-benign | full-vector | 3 | 571366.969 | 574204.116 | 570861.885 / 576873.561 | [5, 17] | 1.0001374254343667 |
| frozen-benign | full-vector | 4 | 571367.326 | 574042.668 | 570911.656 / 577013.163 | [5, 17] | 1.00000062414156 |
| closed-benign | projection | 1 | 66179.073 | 67245.3191 | 64487.6924 / 68419.9105 | [17, 4] | None |
| closed-benign | projection | 2 | 65608.3232 | 66940.7055 | 65266.9936 / 68482.1199 | [18, 13] | 0.9913756761260415 |
| closed-benign | projection | 3 | 65887.0732 | 67067.7866 | 64898.8679 / 68485.4529 | [6, 19] | 1.0042486988118462 |
| closed-benign | projection | 4 | 67371.6488 | 66928.1721 | 65220.6822 / 67923.0255 | [6, 19, 14, 3, 16, 11, 10, 2, 5, 13, 18, 17, 12, 9, 1] | 1.0225321223815276 |
| closed-benign | full-vector | 1 | 571423.053 | 574217.326 | 570723.503 / 576891.736 | [5, 17] | None |
| closed-benign | full-vector | 2 | 571288.459 | 574230.075 | 570780.805 / 576830.819 | [5, 17] | 0.999764458068428 |
| closed-benign | full-vector | 3 | 571366.968 | 574204.115 | 570861.886 / 576873.56 | [5, 17] | 1.0001374257911804 |
| closed-benign | full-vector | 4 | 571366.86 | 574042.667 | 570911.656 / 577013.162 | [5, 17] | 0.9999998106203813 |

### frozen-benign, projection, r4 — all 20 benign clients

| Client | Norm | Threshold | Ratio | Margin | Accepted |
|---|---:|---:|---:|---:|---|
| 0 | 67538.1848155 | 67371.6429812 | 1.00247198713 | -166.541834243 | False |
| 1 | 67296.0118592 | 67371.6429812 | 0.998877404222 | 75.6311219797 | True |
| 2 | 66552.3717356 | 67371.6429812 | 0.987839524029 | 819.27124558 | True |
| 3 | 65739.7225179 | 67371.6429812 | 0.975777339083 | 1631.92046335 | True |
| 4 | 67923.0254709 | 67371.6429812 | 1.00818419242 | -551.382489686 | False |
| 5 | 66699.6370295 | 67371.6429812 | 0.990025388695 | 672.005951714 | True |
| 6 | 65220.6823031 | 67371.6429812 | 0.968073204349 | 2150.96067814 | True |
| 7 | 67536.6059242 | 67371.6429812 | 1.00244855158 | -164.962943027 | False |
| 8 | 67782.5284155 | 67371.6429812 | 1.00609878899 | -410.885434291 | False |
| 9 | 67251.6012393 | 67371.6429812 | 0.998218215608 | 120.041741904 | True |
| 10 | 66409.0146219 | 67371.6429812 | 0.985711668638 | 962.628359314 | True |
| 11 | 66275.4729614 | 67371.6429812 | 0.983729504414 | 1096.17001977 | True |
| 12 | 67220.8481012 | 67371.6429812 | 0.997761745546 | 150.794880004 | True |
| 13 | 66892.1237609 | 67371.6429812 | 0.992882476972 | 479.519220331 | True |
| 14 | 65518.8409067 | 67371.6429812 | 0.972498784466 | 1852.80207453 | True |
| 15 | 67889.744798 | 67371.6429812 | 1.00769020606 | -518.101816829 | False |
| 16 | 66217.179033 | 67371.6429812 | 0.982864245294 | 1154.46394824 | True |
| 17 | 67021.7893469 | 67371.6429812 | 0.994807108468 | 349.853634329 | True |
| 18 | 66964.2203039 | 67371.6429812 | 0.993952608854 | 407.422677265 | True |
| 19 | 65474.3128913 | 67371.6429812 | 0.971837853347 | 1897.33008992 | True |

### frozen-benign, full-vector, r4 — all 20 benign clients

| Client | Norm | Threshold | Ratio | Margin | Accepted |
|---|---:|---:|---:|---:|---|
| 0 | 574375.966406 | 571367.325738 | 1.00526568555 | -3008.64066827 | False |
| 1 | 572906.866186 | 571367.325738 | 1.00269448458 | -1539.54044777 | False |
| 2 | 572906.1704 | 571367.325738 | 1.00269326682 | -1538.84466166 | False |
| 3 | 575021.853171 | 571367.325738 | 1.00639610854 | -3654.52743276 | False |
| 4 | 571839.135528 | 571367.325738 | 1.00082575564 | -471.809790258 | False |
| 5 | 570911.655851 | 571367.325738 | 0.999202492221 | 455.669887069 | True |
| 6 | 573791.061241 | 571367.325738 | 1.00424199179 | -2423.7355025 | False |
| 7 | 577013.163346 | 571367.325738 | 1.00988127489 | -5645.83760845 | False |
| 8 | 573292.410608 | 571367.325738 | 1.00336925964 | -1925.0848696 | False |
| 9 | 575534.612676 | 571367.325738 | 1.00729353386 | -4167.28693756 | False |
| 10 | 573298.568184 | 571367.325738 | 1.00338003655 | -1931.24244642 | False |
| 11 | 574177.077776 | 571367.325738 | 1.00491759313 | -2809.75203787 | False |
| 12 | 575404.838586 | 571367.325738 | 1.00706640486 | -4037.51284777 | False |
| 13 | 571402.836131 | 571367.325738 | 1.00006214985 | -35.5103933194 | False |
| 14 | 574444.434436 | 571367.325738 | 1.00538551744 | -3077.10869815 | False |
| 15 | 574450.698869 | 571367.325738 | 1.00539648137 | -3083.37313107 | False |
| 16 | 574214.697899 | 571367.325738 | 1.00498343541 | -2847.37216102 | False |
| 17 | 571288.745026 | 571367.325738 | 0.999862469014 | 78.5807118156 | True |
| 18 | 573908.258621 | 571367.325738 | 1.00444710919 | -2540.93288315 | False |
| 19 | 574300.403257 | 571367.325738 | 1.00513343586 | -2933.07751863 | False |

### closed-benign, projection, r4 — all 20 benign clients

| Client | Norm | Threshold | Ratio | Margin | Accepted |
|---|---:|---:|---:|---:|---|
| 0 | 67538.1849964 | 67371.6487964 | 1.00247190329 | -166.536200073 | False |
| 1 | 67296.0118509 | 67371.6487964 | 0.998877317881 | 75.6369454371 | True |
| 2 | 66552.3718472 | 67371.6487964 | 0.98783944042 | 819.276949214 | True |
| 3 | 65739.7226464 | 67371.6487964 | 0.975777256767 | 1631.92614997 | True |
| 4 | 67923.0254653 | 67371.6487964 | 1.00818410531 | -551.376668923 | False |
| 5 | 66699.6370705 | 67371.6487964 | 0.990025303849 | 672.011725916 | True |
| 6 | 65220.6822419 | 67371.6487964 | 0.968073119882 | 2150.9665545 | True |
| 7 | 67536.6058703 | 67371.6487964 | 1.00244846426 | -164.957073942 | False |
| 8 | 67782.5284373 | 67371.6487964 | 1.00609870247 | -410.87964091 | False |
| 9 | 67251.6010576 | 67371.6487964 | 0.998218126751 | 120.047738744 | True |
| 10 | 66409.0146778 | 67371.6487964 | 0.985711584386 | 962.634118582 | True |
| 11 | 66275.4729624 | 67371.6487964 | 0.983729419518 | 1096.17583393 | True |
| 12 | 67220.848126 | 67371.6487964 | 0.997761659793 | 150.800670325 | True |
| 13 | 66892.1238277 | 67371.6487964 | 0.992882392265 | 479.524968619 | True |
| 14 | 65518.8409346 | 67371.6487964 | 0.97249870094 | 1852.80786174 | True |
| 15 | 67889.7448456 | 67371.6487964 | 1.00769011978 | -518.096049279 | False |
| 16 | 66217.179011 | 67371.6487964 | 0.982864160132 | 1154.4697854 | True |
| 17 | 67021.7893937 | 67371.6487964 | 0.994807023297 | 349.859402652 | True |
| 18 | 66964.2204668 | 67371.6487964 | 0.993952525478 | 407.428329577 | True |
| 19 | 65474.3128091 | 67371.6487964 | 0.971837768242 | 1897.3359873 | True |

### closed-benign, full-vector, r4 — all 20 benign clients

| Client | Norm | Threshold | Ratio | Margin | Accepted |
|---|---:|---:|---:|---:|---|
| 0 | 574375.965801 | 571366.86025 | 1.00526650347 | -3009.10555116 | False |
| 1 | 572906.865618 | 571366.86025 | 1.00269530047 | -1540.00536798 | False |
| 2 | 572906.169142 | 571366.86025 | 1.00269408151 | -1539.30889267 | False |
| 3 | 575021.852999 | 571366.86025 | 1.00639692814 | -3654.99274909 | False |
| 4 | 571839.135171 | 571366.86025 | 1.00082657038 | -472.274921096 | False |
| 5 | 570911.655944 | 571366.86025 | 0.999203306426 | 455.204306051 | True |
| 6 | 573791.060766 | 571366.86025 | 1.0042428091 | -2424.2005162 | False |
| 7 | 577013.161974 | 571366.86025 | 1.00988209523 | -5646.3017244 | False |
| 8 | 573292.40967 | 571366.86025 | 1.00337007543 | -1925.54942009 | False |
| 9 | 575534.611173 | 571366.86025 | 1.00729435187 | -4167.75092325 | False |
| 10 | 573298.567493 | 571366.86025 | 1.00338085279 | -1931.70724325 | False |
| 11 | 574177.077629 | 571366.86025 | 1.00491841158 | -2810.21737966 | False |
| 12 | 575404.838314 | 571366.86025 | 1.00706722483 | -4037.9780643 | False |
| 13 | 571402.835322 | 571366.86025 | 1.00006296318 | -35.9750728602 | False |
| 14 | 574444.434615 | 571366.86025 | 1.00538633683 | -3077.57436566 | False |
| 15 | 574450.698651 | 571366.86025 | 1.00539730008 | -3083.83840126 | False |
| 16 | 574214.696009 | 571366.86025 | 1.00498425085 | -2847.83575977 | False |
| 17 | 571288.745532 | 571366.86025 | 0.99986328448 | 78.114717615 | True |
| 18 | 573908.256771 | 571366.86025 | 1.00444792426 | -2541.39652156 | False |
| 19 | 574300.403167 | 571366.86025 | 1.00513425458 | -2933.54291782 | False |

## 6. History decomposition

B=sum(raw Y)-dU is checked against the direct client mask sum. T=||U_region/S||2+max(B_region)/(dS) uses the SELECTED sum, not mean. b4=b3*T3/T2. Nominal ratio updates in r2/r3 are diagnostic only: bootstrap overrides them.

| Context | Scope | Round | H_update | H_mask | mask/T | T/T_prev | actual b_next |
|---|---|---:|---:|---:|---:|---:|---:|
| frozen-benign | projection | 1 | 0.0144848196 | 7823.25023 | 0.999998148494 | None | 65608.32323077015 |
| frozen-benign | projection | 2 | 0.0410359598 | 7689.45977 | 0.999994663378 | 0.9829017787758609 | 65887.07307095073 |
| frozen-benign | projection | 3 | 0.0273029302 | 7862.73361 | 0.999996527564 | 1.0225320361197399 | 67371.64298120933 |
| frozen-benign | projection | 4 | 0.0849990588 | 44051.7231 | 0.999998070475 | 5.6025877713487535 | None |
| frozen-benign | full-vector | 1 | 0.0503465987 | 7976.59875 | 0.999993688252 | None | 571288.459559449 |
| frozen-benign | full-vector | 2 | 0.0477923634 | 7976.59875 | 0.999994008464 | 0.9999996797859281 | 571366.9691241526 |
| frozen-benign | full-vector | 3 | 0.05277092 | 7976.59875 | 0.999993384327 | 1.00000062414156 | 571367.3257380241 |
| frozen-benign | full-vector | 4 | 0.0586854326 | 7976.59875 | 0.999992642854 | 1.0000007414781213 | None |
| closed-benign | projection | 1 | 0.0144848196 | 7823.25023 | 0.999998148494 | None | 65608.32319486716 |
| closed-benign | projection | 2 | 0.0438236238 | 7689.45977 | 0.999994300851 | 0.9829021351058622 | 65887.0731996724 |
| closed-benign | projection | 3 | 0.0308167162 | 7862.73361 | 0.999996080677 | 1.0225321223815276 | 67371.6487963681 |
| closed-benign | projection | 4 | 0.0671799077 | 44051.7231 | 0.999998474979 | 5.602583001341217 | None |
| closed-benign | full-vector | 1 | 0.0503465987 | 7976.59875 | 0.999993688252 | None | 571288.458686399 |
| closed-benign | full-vector | 2 | 0.0424238141 | 7976.59875 | 0.999994681494 | 0.9999990067527689 | 571366.9684548263 |
| closed-benign | full-vector | 3 | 0.0409132008 | 7976.59875 | 0.999994870873 | 0.9999998106203813 | 571366.8602495677 |
| closed-benign | full-vector | 4 | 0.0380680969 | 7976.59875 | 0.99999522755 | 0.9999996433204902 | None |

## 7. Projection representativeness

J maps to these existing parameter spans (not changed): [{"name": "classifier.weight", "parameter_span": [60856, 61696], "shape": [10, 84], "overlap_count": 840}]
Coordinate mean/std/median/p90abs/p99abs/max and top 0.1%/1%/5% squared contributions are in coordinate_statistics.json for update/mask/masked, J/full/outside-J, each client. projection_vs_full.json includes client RMS and projection/full norm ratios. Mask distribution observations do NOT prove independent/uniform cryptographic outputs.

## 8. Attack separation

Same round/key/mask paired clean vs MR changes are retained. Overlap is defined by the other group's inclusive min/max interval, not a fitted probability density.

| Context | Scope | benign median/p90 | malicious median/min/max | malicious in benign range |
|---|---|---|---|---:|
| frozen-MR | projection | 66928.1720324/67836.1366068 | 66924.1890324/65739.6953028/67538.2194229 | 4 / 4 |
| frozen-MR | full-vector | 574042.668199/575469.725631 | 573640.332438/572905.168261/575020.867576 | 4 / 4 |
| closed-MR | projection | 66928.1721473/67836.1366415 | 66924.1920391/65739.700828/67538.2271465 | 4 / 4 |
| closed-MR | full-vector | 574042.6672/575469.724743 | 573640.377926/572905.211992/575020.912397 | 4 / 4 |

## 9. Oracle threshold diagnostic

All exact score cutoffs are swept OFFLINE using known fixture labels. This is NOT a protocol solution, threshold recommendation, or deployed tuning. High norm is the fixed reject direction.

| Context | Scope | AUC | best TPR at FPR<=0 | <=0.1 | <=0.25 |
|---|---|---:|---:|---:|---:|
| frozen-MR | projection | 0.53125 | 0.0 | 0.0 | 0.5 |
| frozen-MR | full-vector | 0.5 | 0.0 | 0.0 | 0.25 |
| closed-MR | projection | 0.53125 | 0.0 | 0.0 | 0.5 |
| closed-MR | full-vector | 0.5 | 0.0 | 0.0 | 0.25 |

## 10. Root cause classification

The labels below describe THIS pinned fixture, not every parameter/HPRF/attack.

| Hypothesis | Decision | Evidence |
|---|---|---|
| Dimension calibration failure | not supported | Raw norms scale near sqrt(D); source independently bootstraps the FULL norm, rather than reusing the projection b. Dimension explains absolute magnitude, not an omitted dimension multiplier. |
| Mask domination | supported | Full r4 median mask/update=6837744.04; client and selected-history masks dominate. |
| History instability | not supported | Full b4/b3=0.99999981062, change=-1.89379618654e-05%; no sudden collapse/explosion. |
Persistent low-tail bootstrap calibration is an additional supported cause: selecting 2/20 in r1-3 sets b3 at the third-smallest masked norm; the nearly unchanged, mask-dominated full history keeps that cutoff near the same lower tail in r4. This is not a missing sqrt(D) correction.

### Answers to the seven questions

1. The 90% FPR inherits a low-tail bootstrap cutoff, with norms/history dominated by fixed-scale masks. Large masks make benign updates almost irrelevant to the score.
2. Dimension explains the absolute full/projection norm ratio, but NOT the FPR by itself: the full bootstrap already uses its own full norm. A sqrt(D) multiplier is not justified as a fix.
3. Yes: see the exact decomposition and selected-history mask fractions.
4. No: full b3=571366.968455, b4=571366.86025; ratio=0.99999981062.
5. This scalar norm is not shown to separate the MR fixture: full closed-MR AUC=0.5; oracle low-FPR TPR remains poor. Higher current rejection is not discrimination.
6. J's mask RMS is broadly representative, but J is classifier weights and update RMS can differ. Its r4 acceptance is also affected by mask-tail/history variation; lower FPR is not evidence of a generally representative or stronger poisoning detector.
7. Review mask scaling/period policy first. Bootstrap-only acceptance tuning cannot create separation when the current score is mask-dominated and oracle separation is poor.

## 11. Recovery regression

Fresh comparisons=26, coordinates=1604356, mismatch=0. All 24 baseline recovery arrays/residuals/raw sums are compared again; the additional two frozen-MR r4 recoveries are NEW checks, not previous baseline claims. `%M -> center -> RoundEven` is unchanged.

## 12. Limitations

Oracle thresholds are not protocol solutions. actual-mask-sum != paper-hprf. Scalar HPRF privacy, raw-output inversion, r+block overlap, aggregate-key leakage, share-mask consistency remain unresolved. Weighted FedAvg unsupported; production security not established. One seed/4 rounds/4 MR attackers; no general robustness or independence claim. Public fixture plaintext/keys are not new runtime inputs.

## 13. Recommended next experiment

ONE element: mask scaling/period-policy feasibility audit. Keep S,d,nmax,C and the decoder fixed, and compare the feasible M interval with M/(dS) required for norm separability on the same frozen updates. Current centered envelope requires M/(dS)>2*nmax*C+2*E/(dS), approximately 4000. Do not silently lower M below capacity or alter C/clipping/threshold. This audit may conclude that no usable mask scale exists under the unchanged envelope, before proposing any policy redesign.
