# MGF scope comparison

## 1. Scope

Same public FMNIST frozen updates, followed by two independent benign closed loops. Local learning + source numeric functions; NOT full Flower-network/BFT/ASR deployment.

## 2. Implementation

source_profile.mgf_scope -> source_paper_numeric.scope_span -> selection_statistics/select_masked and history_statistics/recover. Server/committee/offline replay use the same manifest. Missing scope retains projection, old metadata and legacy recovery.

## 3. Mathematical definition

Projection: sum(Y[J]^2)/(dS)^2 <= b_proj^2. Full: sum(Y^2)/(dS)^2 <= b_full^2. T_proj=||U[J]/S||2+||B[J]/(dS)||inf; T_full=||U/S||2+||B/(dS)||inf. Each b uses its OWN two terms: b_r=b_(r-1)*T_(r-1)/T_(r-2). Integer squares/Fraction comparisons; history sqrt retains 60-digit Decimal. First three rounds retain percentile/ranking bootstrap, NOT literal inclusive predicate selection.

## 4. Aion correspondence

Full-vector masked norm is closer to Algorithm 6; projection is the Flower adaptation. actual-mask-sum != paper-hprf history. Neither variant is complete Aion reproduction.

## 5. Side-by-side result

Same Y hash for both scopes; different history/threshold trajectories. See side_by_side.json. selected flags denote MGF eligibility (including bootstrap); fewer than 2 means NO aggregation.

| Round | both accept | projection only | full only | both reject |

|---|---:|---:|---:|---:|

| 1 | 1 | 1 | 1 | 17 |

| 2 | 0 | 2 | 2 | 16 |

| 3 | 0 | 2 | 2 | 16 |

| 4 | 2 | 13 | 0 | 5 |

## 6. Projection-outside-J fixture

{"scope": "predicate-only, outside declared input bounds; NOT signed protocol attack success", "raw_Y_sha256": "26ea0e4a7318055e4d132f18167b243dea5e006b8beb64a4b118feb613c5fa27", "results": {"projection": {"selected": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19], "round_continuation": true, "norm": "0", "threshold": "1", "failure": null}, "full-vector": {"selected": [], "round_continuation": false, "norm": "1.000000000000000000000000000000E+42", "threshold": "1", "failure": "insufficient-valid"}}}

Predicate-only and deliberately outside input bounds; NOT signed-protocol attack success.

## 7. Performance

Measured on identical full Y payloads; projection does not reduce vector network size. performance.json contains repeats, medians, p95 and separate tracemalloc peaks (not total RSS).

## 8. Benign closed-loop

No threshold tuning or automatic clipping. On abort the model stays at its last committed value.

| Scope | Round | accepted | benign FPR | continue | test accuracy |

|---|---:|---:|---:|---|---:|

| projection | 1 | 2 | 0.9 | True | 0.8846666666666667 |

| projection | 2 | 2 | 0.9 | True | 0.8852222222222222 |

| projection | 3 | 2 | 0.9 | True | 0.8864444444444445 |

| projection | 4 | 15 | 0.25 | True | 0.8866666666666667 |

| full-vector | 1 | 2 | 0.9 | True | 0.8827777777777778 |

| full-vector | 2 | 2 | 0.9 | True | 0.882 |

| full-vector | 3 | 2 | 0.9 | True | 0.88 |

| full-vector | 4 | 2 | 0.9 | True | 0.8795555555555555 |

Full thresholds/T_r/loss/model hashes are in projection_rounds.json and full_vector_rounds.json.

## 9. Attack evaluation

{"projection": {"benign_submitted": 16, "benign_accepted": 12, "benign_rejected": 4, "malicious_submitted": 4, "malicious_accepted": 3, "malicious_rejected": 1, "benign_FPR": 0.25, "attack_TPR": 0.25, "selected": [6, 19, 14, 3, 16, 11, 10, 2, 5, 13, 18, 17, 12, 9, 1], "round_continuation": true, "failure": null, "threshold": "67994627239648669814878068954825089023938851194729516898846612248550784981735515832321811546042238886976240044190774759224167/1009246980344729015843624044229100008848668887240843676389271629020625000000000000000000000000000000000000000000000000000"}, "full-vector": {"benign_submitted": 16, "benign_accepted": 2, "benign_rejected": 14, "malicious_submitted": 4, "malicious_accepted": 0, "malicious_rejected": 4, "benign_FPR": 0.875, "attack_TPR": 1.0, "selected": [5, 17], "round_continuation": true, "failure": null, "threshold": "478547496200259921813434683653286594938032238871284957544304983006463267152836058167359123547884899452872436367907829154335971/837547886698157705612166851516329030359161308420121666501349724116500000000000000000000000000000000000000000000000000000"}}

Frozen r4 existing MR detector comparison; not attacked closed-loop final accuracy. executed existing MR after benign pair completed four rounds

## 10. Recovery correctness

Mismatch sum=0. Only recovered rounds count; aborted rounds are not successes. recovery_checks.json records exact plain/recovered integer arrays, realized residuals and capacity margins.

## 11. Trade-off

| Metric | Projection | Full-vector |

|---|---:|---:|

| coordinates checked | 840 | 61706 |

| MGF compute time (median s) | 0.00817373400013821 | 0.5973796989997027 |

| history time (median s) | 0.006006738999985828 | 0.5098054009999942 |

| benign FPR (last attempted round) | 0.25 | 0.9 |

| frozen MR attack TPR (r4) | 0.25 | 1.0 |

| rounds completed | 4 | 4 |

| final test accuracy | 0.8866666666666667 | 0.8795555555555555 |

| recovery mismatch | 0 | 0 |

One fixed configuration/seed, short trajectories; no general robustness or convergence inference. At matching frozen Y the predicate sees more coordinates, but thresholds and later models differ.

## 12. Limitations

actual-mask-sum != paper-hprf; scalar HPRF privacy unresolved; raw-output inversion unresolved; r+block overlap unresolved; multi-round aggregate-key leakage unresolved; share-mask inconsistency unresolved; weighted FedAvg unsupported; production security not established. Reproducible public keys are not a production key sampler. No complete signed malicious-protocol experiment or actual network/VSS execution in these learning loops.
