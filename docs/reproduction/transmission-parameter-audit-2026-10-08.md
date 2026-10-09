# Transmission-space 복원·MGF·학습·키 공간 감사

최종 분류: **F — correctness와 별개로 low-entropy HPRF key 문제가 확인되어 보안 수정이 우선 필요하다.**

정수 복원에 가능한 parameter는 있다. 하지만 현재 `C_real=100`을 유지하는 큰 mask는
MGF를 거의 작동 불능으로 만들었고, 작은 bound를 쓰는 후보는 clipping·정상 거부율과의
tradeoff가 있다. Flower production 경로에는 이번 변경을 전혀 연결하지 않았다.

## 실험 범위와 증거

- 원본 HPRF·기존 MGF predicate/bootstrap/history를 사용한 **로컬 offline 실험**.
- FMNIST LeNet5 61,706차원, MGF classifier projection 840차원, candidate client 20명, 4라운드.
- `n_max={2,20,100}`은 **선택 인원의 상한**이다. 100-client ML 실험이 아니다.
- parameter별 ML 곡선은 동일한 실제 local update를 재사용한 **frozen-update replay**다.
  새로운 모델로 모든 client를 매번 재학습한 closed-loop convergence 결과로 취급하지 않는다.
- `S` 정확도 ablation은 따로 **closed-loop 재학습**했다. 기존 공개 selected roster를 고정해
  quantization의 영향을 분리했으며 MGF를 다시 선택하는 실험은 아니다.
- MR 공격은 저장소 `FmnistTrainer._poison_delta`의 existing artifact-style 방식:
  4명, r4, 120 optimizer steps, boost 20, poison batch 6. 공격 업데이트를 clipping해서
  공격 강도를 인위적으로 낮추지 않았다. honest correctness 가정은 malicious update까지 보장하지 않는다.
- `attack2/attack3` 등의 다른 데이터셋·공격을 실행했다고 주장하지 않는다.
- 정직한 client만 있는 baseline에서도 bound에 의한 제외는 benign rejection/FP로 센다.
  처음 3라운드의 90% 제외는 현재 percentile bootstrap의 설계 자체이므로 r4의 탐지율과 구분한다.
- validation/test는 기존 local `test.npz` 10,000장을 고정 1,000/9,000장으로 나눈 것이다.
  별도의 원 논문 validation split 또는 60-round 재현은 아니다.

최종 raw ledger:
`.cache/transmission-parameter-audit-20261008-v4/report.json` (4,704,936 bytes).
SHA256 `3ed66000d7662797c2f95de78c93403efdbe38930e78e81119bbc0faf3d6e7c9`.
실험 wall time 338.31초. 새 local workload 수집은 v1에서 했고 v4는 그 캐시의 SHA256을 기록한다.
실제 private actor state/identity/seed는 읽지 않았다.

## 1. Transmission-space residual 유도

`m_i=Round(M*h_i/p)`, `m_A=Round(M*H_A/p)`.
raw HPRF에서 `sum(h_i)-H_A=c*p+e`이면

```
E = sum(m_i)-m_A-c*M
  = sum(delta_i)-delta_A+(M/p)*e
```

E는 정수다. p가 홀수이고 Mh도 정수이므로 `.5` tie가 불가능하며
`|delta| <= (p-1)/(2p) < 1/2`.
raw HPRF의 인증된 산술 bound를 E_H라 하면 안전한 상한은

```
E_bound(n,M) = floor(((n+1)*(p-1) + 2*M*E_H(n))/(2*p))
```

n=1은 같은 mask를 빼므로 정확히 0이다.
`(M/p)*E_H < 1/2`이면 integer residual에 대해 `|E| <= floor((n+1)/2)`가 성립한다.
**이 작은 M 조건 없이 모든 M에 같은 bound를 적용하지 않는다.**
실험에서는 일반 식으로 매 parameter의 E를 다시 계산했다.

## 2. 실제 E_max(n)

현재 p=14760426300877770769, q=5p.
nearest HPRF가 `h=(t+2)//5`라 raw bound는 `E_H=floor(2*(n+1)/5)`.
이번 모든 sweep M에서 작은 M 조건이 만족된다.

| n_max | Raw HPRF E_H | Transmission E_max |
| --- | ---: | ---: |
| 2 | 1 | 1 |
| 20 | 8 | 10 |
| 100 | 40 | 50 |

**20명의 bound 10은 실제 원본 scalar key domain에서도 달성했다.**
공개 fixture: 20 client가 key 79, r=451, coordinate 0.

```
h_i = 1013635439148331539
H_A = 5512282482088860003
sum(h_i)-H_A = p+8
c=1, e=8, M=32000, E=10
```

각 scale residual 약 +0.47986125, aggregate residual 약 -0.40277504이다.
raw e도 이론 bound 8에 도달한다. 동일 key의 우연한 20중 충돌이 현실적으로 흔하다는 뜻은
아니며, key domain 안에 있는 worst-case 정확성 fixture라는 뜻이다.

별도 내부-q-domain 극한 fixture와 작은 p에서 **880,100개 내부 representative 조합**을
exhaustive 검사했다. 실제 키·라운드·parameter random 검증도 추가했다.

## 3. d_min(n)

`|E|<d/2`가 필요하므로 `d_min=2*E_max+1`.
위 표에서 n=2는 3, n=20은 **21**, n=100은 101이다.

U=1,E=10,d=20이면 residual 30이고 `Round(30/20)=Round(1.5)=2`:
참값 1과 다르다. `d=21,22,32,50,100`은 모두 1을 복원한다.
정상 sweep은 상한 조건에 맞지 않는 spacing을 제외하고 boundary 실패 테스트에 보존했다.

## 4. Integer-only scaling

`experiments/transmission_numeric.py:scale_mask`:

```
scale(h) = (2*M*h+p)//(2*p)
```

곱셈·덧셈·정수 나눗셈만 사용한다. mask·sum·mod·subtraction·center·grid rounding에
float를 사용하지 않는다. negative update의 grid rounding은 별도의 signed integer
ties-even `nearest_ratio`로 처리한다.
Float는 x→u 양자화 경계, 모델 optimizer/evaluation, 통계 출력에만 존재한다.
양자화는 빠른 vectorized 경로에서 near-half 값들을 exact decimal-spelling 산술로 다시
계산하고 기존 `FixedPoint.encode` convention과 맞추었다.

## 5. Float scaling 차이

실제 p에서 찾은 공개 half-boundary 사례:

| M | h | integer-only | `round(M*h/p)` float |
| --- | ---: | ---: | ---: |
| 32000 | 3920738236170658 | 9 | 8 |
| 100000000 | 100592305240482 | 681 | 682 |

이 차이는 HPRF의 작은 e와 별도로 발생하는 floating precision 문제다.
정수 helper는 Fraction 기반 독립 reference와 정확히 일치했다.

## 6. scale(h+p)=scale(h)+M

분자에 `2*M*p`가 더해져 quotient가 정확히 M만큼 증가한다.
따라서 이 성질은 유효 h=0..p뿐 아니라 모든 정수 h에서 성립한다.
`2*M*h=(2*j+1)*p`는 짝수=홀수를 요구하므로 `.5` tie가 불가능하다.
M<p라는 조건은 이 parity 증명에는 필요 없다.
작은 odd p·다양한 M의 exhaustive 검사와 1,000개 큰 p random property 검사를 통과했다.
원본 h의 endpoint p를 유지하므로 scaled output은 **0..M inclusive**이다.

## 7. 실제 FMNIST update 분포

각 archived public model에서 20 client를 원래 trainer·epoch·seed로 재학습했다.
`u=Round(10^6*x)`이고 selected U는 실제 archived roster의 합이다.

| r | max client abs(x) | max client abs(u) | selected count | max abs(U) | M | max abs(dU) / (M/2) |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| 1 | .020261824 | 20262 | 2 | 7802 | 773033828125/65536 | 780200 / 약5897780.06: 범위 안 |
| 2 | .021342278 | 21342 | 2 | 2106 | 156040 | 210600 / 78020: 범위 밖 |
| 3 | .021056831 | 21057 | 2 | 2348 | 42120 | 234800 / 21060: 범위 밖 |
| 4 | .020972550 | 20973 | 2 | 1908 | 46960 | 190800 / 23480: 범위 밖 |

| r | abs(U) p50 | p90 | p95 | p99 | p99.9 | max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 123 | 628.5 | 921 | 1895.7 | 3980.885 | 7802 |
| 2 | 33 | 163 | 234 | 462.95 | 1011.36 | 2106 |
| 3 | 34 | 175 | 259 | 513.95 | 1084.245 | 2348 |
| 4 | 32 | 157 | 229 | 447 | 967.295 | 1908 |

ledger에 |x|, |u|, |U| 각각의 mean·모든 요청 percentile을 저장했다.
FMNIST legacy가 성공했다고 centered 범위가 보장되는 것이 아니다.

## 8. 실제 synthetic update 분포

첫 세 라운드의 실제 committed roster를 이용해 deterministic `local_delta`와
quantized model을 재생했다. 각 round의 next_linf가 저장된 값과 정확히 같은지 검사했다.

| r | max client abs(x) | max abs(U) | M | max abs(dU) / (M/2) |
| --- | ---: | ---: | ---: | --- |
| 1 | .018147246 | 2098 | 246940 | 209800 / 123470: 범위 밖 |
| 2 | .018126962 | 1601 | 41960 | 160100 / 20980: 범위 밖 |
| 3 | .018110202 | 1600 | 32020 | 160000 / 16010: 범위 밖 |

| r | abs(U) p50 | p90 | p95 | p99 | p99.9 | max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 1063 | 1732.6 | 1915.3 | 2061.46 | 2094.346 | 2098 |
| 2 | 890.5 | 1515.6 | 1558.3 | 1592.46 | 1600.146 | 1601 |
| 3 | 889 | 1513.9 | 1556.95 | 1591.39 | 1599.139 | 1600 |

r4 전체 client의 max |x|=.018093457, p50=.0040577404, p90=.012511875,
p95=.013787476, p99=.017505591, p99.9=.018002717.
**원래 실패 run의 r4 private masks/selected ground truth는 저장되어 있지 않다.**
그 r4 집계 U를 실제로 확인했다고 주장하지 않는다.

## 9. Failure round |dU+E| vs M/2

대신 기존 r4 public scale/history bound를 그대로 사용한 공개 최소 ambiguity regression을 보존했다.
M=32000,d=100,S=10^6, keys [4,16], MGF 통과 2명.
coordinate 1은 U=700,E=0이고 `|dU+E|=70000>16000`.
coordinate 2는 U=-700,wire E=-1이고 `|-70000-1|=70001>16000`.
scaled centering이 각각 60,-60으로 잘못 복원한다.
이 숫자를 기존 private-key 실행의 수치로 혼동하지 않는다.

## 10. S별 quantization error

Closed-loop fixed-roster FMNIST, 마지막 r4의 per-coordinate absolute quantization error:

| S | mean error | max error | 일반 상한 |
| --- | ---: | ---: | ---: |
| 10^4 | 1.7424850e-5 | 4.9999154e-5 | 5e-5 |
| 10^5 | 2.3286234e-6 | 4.9999663e-6 | 5e-6 |
| 10^6 | 2.4995856e-7 | 4.9999046e-7 | 5e-7 |

Float baseline에 대한 r4 global model deviation(mean/max):
S=10^4: 3.4121671e-5 / 1.7020877e-4;
S=10^5: 3.4456123e-6 / 1.8644977e-5;
S=10^6: 3.7606878e-7 / 2.3508031e-5.
재학습 trajectory 때문에 model deviation 최대값이 S에 완전히 단조롭지는 않다.

## 11. S별 모델 accuracy

단위는 accuracy fraction, 마지막 차이는 percentage points이다.

| mode | test r1 | r2 | r3 | r4 | validation r4 | float 대비 r4 차이 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| float | .885000 | .885111 | .885333 | .884556 | .894 | 0 |
| S=10^4 | .885000 | .885111 | .885333 | .884889 | .894 | +.03333 pp |
| S=10^5 | .885000 | .885111 | .885333 | .884556 | .894 | 0 |
| S=10^6 | .885000 | .885111 | .885333 | .884556 | .894 | 0 |

고정 pretrained reference에서 4라운드·한 training seed의 소규모 차이다.
S=10^4가 일반적으로 더 좋다거나 장기 convergence가 보장된다고 해석하지 않는다.
각 parameter의 frozen-replay 4-round accuracy 곡선도 raw ledger에 별도로 포함했다.

## 12. Parameter별 M_min과 정확한 margin

`C_u=Round(S*C_real)`는 monotone ties-even quantization의 정확한 최대 integer bound다.
임의로 `S*C_real`를 실수 근사로 대입하지 않았다.

```
d > 2*E(M)
M > 2*(d*n_max*C_u+E(M))
```

오른쪽이 정수이므로 최소 integer period는 정확히 `2*(...)+1`.
E의 M 의존성을 포함해 이 식을 fixed point로 다시 계산한다.
`+2`가 필요하지 않으며 M-1이 strict 조건을 실패하는 테스트도 있다.
2*M_min은 명시적인 비교용 여유 설정이지 최소값으로 보고하지 않는다.

| C_real | S | d | n_max | M_min | 실제 real mask period M/(d*S) |
| --- | ---: | ---: | ---: | ---: | ---: |
| .001 | 10^4 | 21 | 20 | 8421 | .0401 |
| .001 | 10^5 | 21 | 20 | 84021 | .04001 |
| .001 | 10^6 | 21 | 20 | 840021 | .040001 |
| 100 | 10^4 | 21 | 20 | 840000021 | 4000.0001 |
| 100 | 10^5 | 21 | 20 | 8400000021 | 4000.00001 |
| 100 | 10^6 | 21 | 20 | 84000000021 | 4000.000001 |

**S를 100배 줄이면 integer M은 약100배 줄지만 real mask 크기는 거의 그대로다.**
따라서 낮은 S만으로 MGF의 mask-noise 문제를 해결한다고 볼 수 없다.

## 13. Feasible 조합 전체

선언한 sweep: S={10^4,10^5,10^6}, n_max={2,20,100},
C_real={.0001,.001,.01,100}, d={21,24,32,50,100,d_min(n)},
M={32000,M_min,2*M_min}. 중복은 제거하고 spacing-infeasible d는 boundary 검사로 분리했다.

| n_max | 전체 조합 | 산술 feasible |
| --- | ---: | ---: |
| 2 | 216 | 179 |
| 20 | 180 | 133 |
| 100 | 36 | 25 |
| 합계 | 432 | 337 |

전체 432행을 실패 포함 ledger에 남겼다. feasible 337개 모두 MGF/accuracy 실험을 수행했다.
같은 20-candidate workload에서 selected가 n_max를 넘으면 명시적으로 실패 처리했으며
선택 명단을 임의로 cap하지 않았다. 산술 feasible과 실제 operational success는 다르다.

## 14. Feasible M에서 MGF detection

Matched original adaptive-scale frozen replay와 archived r4-bound control 모두
MR TPR=100%, FNR=0%, benign FPR=87.5%, TNR=12.5%였다.
original baseline 자체의 정상 거부율이 높다는 점도 그대로 보고한다.

아래는 모든 feasible profile의 r4 MR TPR/FPR 범위다. 성공한 profile만 골라 집계하지 않았다.

| n_max | C_real | profile 수 | MR TPR 범위 | benign FPR 범위 | r4 operational success |
| --- | --- | ---: | --- | --- | ---: |
| 2 | .0001 | 53 | 100% | 6.25–100% | 1 |
| 2 | .001 | 48 | 100% | 0–100% | 0 |
| 2 | .01 | 42 | 100% | 100% | 0 |
| 2 | 100 | 36 | 75% | 100% | 0 |
| 20 | .0001 | 39 | 100% | 68.75–100% | 33 |
| 20 | .001 | 34 | 100% | 81.25–100% | 31 |
| 20 | .01 | 30 | 100% | 100% | 0 |
| 20 | 100 | 30 | 75% | 100% | 0 |
| 100 | .0001 | 7 | 100% | 100% | 0 |
| 100 | .001 | 6 | 100% | 100% | 0 |
| 100 | .01 | 6 | 75–100% | 100% | 0 |
| 100 | 100 | 6 | 75% | 100% | 0 |

n_max=2의 낮은 FP도 실제로 2명을 넘게 받아 상한을 위반한 경우가 많다.
그 설정을 성공으로 취급하지 않는다. TPR가 높아도 benign 모두를 거부하면 유용하지 않다.

## 15. Benign FP·score separation·threshold sensitivity

사전 선언된 d=21,S=10^4,n_max=20,M=M_min 대표 행:

| C_real | M | 실제 benign clipping 비율 r4 | MR TPR / FPR | frozen test r4 | 상태 |
| --- | ---: | ---: | --- | ---: | --- |
| .0001 | 861 | 37.3044% coordinates | 100% / 81.25% | .884000 | 진행 |
| .001 | 8421 | 2.29208% | 100% / 81.25% | .884556 | 진행 |
| .01 | 84021 | .00243088% | 100% / 100% | .885667 | 통과자 부족·r4 미반영 |
| 100 | 840000021 | 0% | 75% / 100% | .885667 | 통과자 부족·r4 미반영 |

실패 profile의 accuracy는 이전 모델이 유지된 값이지 실패 r4를 정상 집계한 accuracy가 아니다.
모든 profile의 raw score·mean·percentile·TP/FP/FN/TN·threshold factors
{.5,.75,1,1.25,1.5,2} 결과를 저장했다. Predicate/threshold policy는 변경하지 않았다.

C=.001,M=8421의 benign/MR 평균 L2 score는 .67276 / 2.77604,
경험적 pairwise rank AUC=1이다. 원래 threshold에서 FPR81.25%, threshold를 1.25배로
가정한 sensitivity에서는 FP0%,TP100%지만 **이 threshold 변경을 채택하지 않았다**.
C=100,M=840000021에서는 평균 benign67159.57 / MR66598.49, rank AUC=.453125로
score ordering도 무너졌다. 이 결과는 MR 4개·benign16개의 작은 sample 결과다.

## 16. Mask centered 여부

현재와 실험 모두 **uncentered**, integer representative 0..M inclusive다.
MGF에서 보는 real coordinate는 `m/(d*S)`다. 임의로 centered mask로 바꾸지 않았다.

continuous iid uniform reference의 physical period를 P_M=M/(d*S), projection 폭을 D라 하면

```
E[m] = P_M/2,  Var(m) = P_M^2/12
E[||m||_2^2] = D*P_M^2/3
Std(||m||_2^2) = sqrt(4D/45)*P_M^2
```

centered mask의 평균 제곱 `D*P_M^2/12`보다 4배 크다.
사용자 제시 `.0745*P_M^2*sqrt(D)`는 centered iid reference에 해당하고
현재 uncentered reference 계수는 약 `.29814`이다.

## 17. Empirical mask norms

M=8421,d=21,S=10^4,P_M=.0401, projection D=840, model dimension=61706:

| 통계 | 실제(public seeds 20개) | iid uniform reference |
| --- | ---: | ---: |
| mean coordinate | .02010621 | .02005 |
| std coordinate | .01156494 | .01157587 |
| mean L2 | .67214974 | 별도 정확값 대신 제곱 통계 비교 |
| mean L2 squared | .45192625 | .4502428 |
| std L2 squared | .01596671 | .01389479 |

모든 337행의 mask stats를 저장했다. 실제 scalar-key mask 간·좌표 간 상관 때문에
iid uniform variance reference와 완전히 일치하지 않으며, 통계적 유사성이 보안 증명은 아니다.

## 18. Modular recovery exact-match

337개 feasible arithmetic fixture의 16좌표씩 **5,392좌표**가 exact-match.
이후 실제 frozen FMNIST의 각 successful round에서 **61,706좌표 전체**를 검사했다.
합계 **1,076 successful rounds × 61,706 = 66,395,656좌표**, 전부 plaintext integer SUM과 같았다.
MGF projection의 Y는 그 full Y의 해당 좌표와 정확히 같은지 검사했다.
서버에 plaintext를 보내도록 바꾼 것이 아니라 offline experiment에서만 ground truth로 대조했다.

전체 1,348 parameter-round 중 통과자 부족 206건, selected-count 상한 초과 66건을 별도로 남겼다.
실패 건에는 exact-match 성공 표기를 하지 않았다.

## 19. Boundary·failure tests

- no/one/multiple carry, 좌표별 다른 carry, signed U, E=0/!=0.
- actual author-domain E=10 extremum, d=20 실패 및 d=21/22/32/50/100 성공.
- 최소 M-1 strict boundary 거부, insufficient capacity 거부.
- true SUM이 modular period를 감으면 postcheck만으로 alias를 검출할 수 없다는 실패 사례.
- 현재 synthetic ambiguity·FMNIST range regression 유지.
- integer/float half-boundary 차이, scale translation, quantization near-half/nextafter property.
- 최종 raw ledger의 모든 행·실패·accuracy·seed attack을 확인하는 regression.

관련 기존 Flower/ASR/BFT 포함 **322 passed**, 추가 ledger tests 4개 통과: **총326 passed**.
External typer/click deprecation warning 외 오류 없음. 새 Flower training run은 실행하지 않았다.

## 20. LWR output modulus를 직접 M으로 두는 대안

`Round((M/q)*t)`는 double rounding을 제거한다는 수학적 장점이 있다.
하지만 구현하지 않았다. q를 고정하면 output ratio가 q/p=5에서 q/M으로 바뀌고,
q를 5M으로 줄이면 내부 modulus와 lattice parameters 자체가 달라진다.

BLMR의 standard-model 구성은 vector key·공개 binary matrices와 parameter 조건을 가진다.
Section 5에는 output modulus의 divisibility와 noise/dimension/input-depth 조건도 있다.
따라서 output M을 단순 교체해도 같은 보안 증명을 자동 상속한다고 볼 수 없다.
현재 scalar column-sum artifact를 해당 vector-key 증명으로 인증하지도 않는다.
[BLMR 원 논문, Section 5](https://crypto.stanford.edu/~dabo/pubs/papers/homprf.pdf).

적용 전 검토: 올바른 HPRF construction/key distribution, q/M·차원·공개행렬·noise 조건,
실제 query 수와 보안 수준, input domain separation, VSS key-domain 합 보존.
lattice estimator 평가나 보안 증명을 이번에 완료했다고 주장하지 않는다.

## 21. 실제 key/seed 생성

원본 `Aion/agent/Aion/SA_ClientAgent.py:306`과 현재
`trustlessfl/aion_source_asr.py:204,242`:

```
random.SystemRandom().randint(1,100000)
```

OS CSPRNG를 사용하지만 **scalar key**의 domain은 100,000개뿐이다.
client별 독립 sampling을 의도하고 state의 mask_seed를 이후 라운드에도 재사용한다.
독립 sampling은 서로 다른 key를 보장하지 않으며 accidental collision도 가능하다.
이번에는 원본 보존 원칙에 따라 생성 함수/범위를 변경하지 않았다.

## 22. Entropy

균등하더라도 최대 `log2(100000)=16.60964 bits`.
CSPRNG의 품질이 낮아서가 아니라 **sample domain 자체가 너무 작다**.
라운드마다 input이 바뀌어도 재사용 key의 작은 탐색 공간은 유지된다.

## 23. Exhaustive local recovery

외부 target 없이 새 공개 fixture만 사용했다.
20개 사례: 5개 seed `{4,16,31337,64221,99999}` × 2라운드 `{1,4}` × 2 profile.
각 사례는 8개 known-round masked coordinates를 사용했고, candidate 1..100000 모두 대입했다.

| profile | bound만 통과한 seed | bound+양자화 격자 통과 | true seed 유일 식별 | 개별 정수 update 복원 |
| --- | --- | --- | --- | --- |
| M32000,d100,S10^6,C100 | 100000/사례 | 1/사례 | 10/10 | 10/10 exact |
| M8441,d21,S10^4,C.001 | 1/사례 | 1/사례 | 10/10 | 10/10 exact |

두 번째는 별도 고정 feasible 보안 fixture로서 **M_min이라고 부르지 않는다**.
true key는 성공 여부 채점에만 쓰고, 복원은 실제 살아남은 candidate로 수행한다.
첫 profile도 public quantization grid만 추가하면 key와 개별 update가 정확히 노출된다.
전체 탐색 wall time 약9.00초. 이것은 모든 데이터/키에서 유일함을 증명하는 것은 아니지만
low-entropy 문제가 현실적인 공격으로 이어지는 실제 재현이다.

## 24. 실제 적용 가능한 parameter set 여부

**산술적 가능성은 확인했다.** 예: n_max20,S10^4,d21,C.001,M8421은 이번 4-round frozen
ML replay에서 exact recovery와 MR detection100%를 보였고 benign FPR81.25%였다.
그러나 benign coordinates 2.292%를 clipping하며 높은 정상 거부율이 남는다.
모든 새로운 M,d,S는 offline setting이며 현재 original alpha policy를 보존한 production 결과가 아니다.

C100을 그대로 보장한 profile은 정상들을 거의 모두 거부하고 score separation도 악화됐다.
작은 S는 wire integer range/quantization 비용을 줄이지만 physical mask-vs-update tradeoff를
자동으로 제거하지 않는다. 어떤 setting도 현재의 작은 key 보안 문제를 해결하지 않는다.

따라서 현재 Flower에 안전한 설정으로 바로 연결할 수 있다고 판정하지 않는다.

## 25. Integration 전 남은 문제

1. **HPRF construction/key-domain 보안 검토가 우선**. scalar range만 키우는 것으로 끝내지 말아야 한다.
   scalar의 effective domain은 mod q로 제한되고, 현재 q도 약66비트다.
   검증된 key-homomorphic vector domain에 CSPRNG로 sampling하는 방안을 별도로 검토해야 한다.
   비선형 seed expansion은 aggregate-key 합 관계를 자동 보존하지 않는다.
2. 작은 clipping bound의 전체 모델 학습 영향과 MGF 정상 거부율을 장기·multi-seed로 검증.
3. **각 M,d,C별 독립 closed-loop MGF 재학습은 아직 아니다**. 이번 모든 parameter의 모델
   accuracy는 frozen replay이며, closed-loop 실험은 S ablation에 한정했다. 장기 convergence
   또는 공격 이후의 모델 정확도 결과로 확대하지 않는다.
4. candidate/selected 상한과 실제 bootstrap/history 초기화 정책을 합의. ML 100-client 검증도 별도다.
5. output-modulus 변경은 보안 재검토 후 판단. 이번에는 변경하지 않는다.
6. share-mask inconsistency, ZKP, VSS/ASR redesign, 추가 share, MPC는 이번 작업에서 해결하지 않았다.

최종 **F**. 정확한 정수 복원 가능성은 있지만, 현재 scalar seed의 실제 복원 공격 때문에
production integration보다 key-domain/HPRF 보안 수정 검토가 우선이다.

조건부 integration 순서는 다음과 같다. **이번에는 실행하지 않았다.**

1. HPRF/key-domain 보안 검토를 먼저 통과하고, 필요한 별도 protocol 변경 범위를 합의한다.
2. 선택할 M,d,S,C_real,n_max와 clipping·round별 M 정책을 공개 profile로 고정한다.
   현재 original alpha policy와 fixed-period 실험은 같은 정책이 아니므로 자동 교체하지 않는다.
3. client는 단일 Y만 생성하고 기존 MGF가 `Y/(d*S)`를 같은 predicate로 검사하도록 단위를 맞춘다.
   BFT①·초기 VSS·ASR 합계 key 복원은 유지한다.
4. 서버의 선택된 Y sum에서만 mod M·scaled aggregate HPRF subtraction·center·grid rounding을 한다.
   raw Y sum도 보존하면 복원한 U를 이용해 `mask_sum=Y_sum-d*U`로 history의 실제 mask norm을
   계산할 수 있다. carry나 추가 share를 공개하는 단계가 아니다.
5. residual/count/capacity를 사전·사후 검사하고 BFT② 전에 실패를 닫는다.
   precondition 밖 alias를 postcheck만으로 검출할 수 있다는 주장은 하지 않는다.
6. 그 다음에야 독립 Flower smoke/learning regression, multi-seed 장기 실험을 진행한다.

## 추가한 파일·재현 명령

- `experiments/transmission_numeric.py`: 정수 scaling·오차·bound·parameter·복원.
- `experiments/audit_transmission_parameters.py`: 전체 sweep, 실제 update replay, MR·accuracy·seed audit.
- `tests/test_transmission_numeric.py`, `tests/test_transmission_audit.py`.
- 본 문서. 기존 Flower runtime 파일에는 이번 변경을 추가하지 않았다.

새 output 경로를 사용해야 한다. 기존 결과를 덮어쓰지 않는다.

```
env PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 -m experiments.audit_transmission_parameters \
    --output .cache/transmission-parameter-audit-new

env PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 -m pytest -q tests/test_transmission_numeric.py tests/test_transmission_audit.py
```

raw source setup/input hashes, 실제 percentile·각 row의 실패·score·threshold sensitivity·곡선은
local ledger에 보존되어 있다. ledger 테스트는 해당 local 결과가 없으면 skip하며, 산술 테스트는
별도로 실행 가능하다. 원본 author setup이 없는 환경의 actual-HPRF 테스트도 명시적으로 skip한다.
