# HPRF·집계·MGF 독립 재검토 — 2026-10-09

## 요약 및 검토 범위

**정수 transmission ring의 복원식은 명시된 범위 안에서 맞다. 그러나 이 사실만으로
현재 적응형 MGF 설정을 유지한 Flower 통합이 가능하다고 결론낼 수는 없다.**
특히 적응형 마스크 크기와 centered decoding 용량, Algorithm 6과 다른 history 통계량,
scalar HPRF privacy가 각각 별도 문제다.

이번 작업은 독립 Fraction 기준 계산, 반례, 기존 테스트 재실행, 공개 fixture 재현만
추가했다. 런타임·원본 Aion·파라미터·MGF predicate·VSS는 수정하지 않았다.
ZKP/MPC/추가 share/별도 masked vector를 구현하지 않았다. 원래 있던 dirty worktree는
그대로 유지했다. 보안 공격 실험은 공개 synthetic fixture만 대상으로 했다.

최종 ledger: `.cache/design-independent-review-20261009-v3/report.json`

- 실행 시간: 48.137초. 데이터/모델 재학습 시간이라는 뜻이 아니다.
- SHA256: `ea624430572102c8ab30b2cd7618bb4380a5742fcb657e509cf822c7e2071c10`
- runtime Python 및 저자 HPRF/setup/matrix 총 48개 파일의 실행 전후 해시가 같다.
- v1/v2는 검토 중간 기록이며, 추가 MGF replay까지 포함한 결과는 v3이다.

## 1. 실제 HPRF 수식

`trustlessfl/aion_original_hprf.py:OriginalAionHPRF.hprf` 및
`../Aion/agent/Aion/HPRF/hprf.py:HPRF.hprf/G_batch`를 대조했다.
행렬은 128×512이며 현재 구현은 열의 합을 scalar key에 곱한다.

\[
p=14760426300877770769,\qquad q=5p=73802131504388853845,
\]
\[
t_j=[k(r+\lfloor j/512\rfloor)c_{j\bmod512}]_q,
\qquad h_j=\left\lfloor\frac{pt_j+\lfloor q/2\rfloor}{q}\right\rfloor
=\left\lfloor\frac{t_j+2}{5}\right\rfloor.
\]

출력은 Python `list[int]`, 대표값은 **0≤h≤p**이다. 마지막 `%p`가 없다.
실제 공개 파라미터에서 k=30592724630515680197, r=1, j=0을 넣으면 h=p가 된다.
이 endpoint는 `scale(p)=M`으로 처리해야 하며 0으로 미리 바꾸면 MGF 입력이 달라진다.
정수 계산의 일치가 LWE/BLMR 보안 정리의 적용을 뜻하지 않는다.

## 2. 실제 key domain

계산상 domain은 scalar **Z_q**이며 q가 합성수이므로 field가 아닌 ring이다.
H(k+q,r)=H(k,r), k=0도 평가 가능하지만 mask가 전부 0이다.

Flower source 런타임 `aion_source_asr.source_request`의 enroll 및 최초 mask 분기는
여전히 `random.SystemRandom().randint(1,100000)`이다. 상태에 저장한 키를 재사용한다.
`experiments/full_domain_keys.sample_full_domain`의 `secrets.randbelow(q)` 또는
nonzero 옵션은 실험 전용이다.

기존 균일 키 엔트로피는 16.6096404744 bits, 전체 domain은 66.0002962867 bits이다.
q가 2^66보다 조금 크므로 정수 저장 폭은 최대 67 bits다. 이는 보안 비트 수가 아니다.

## 3. VSS/ASR domain과 합산 방식

현재 encrypted-Pedersen profile은 `crypto.ORDER=(MODULUS-1)//2`, 즉 RFC3526
group14의 2047-bit subgroup order를 scalar field로 사용한다. HPRF의 q와 다르다.
`share_seed → sum_keys → recover_key_opening`은 초기 randomized Pedersen share와
선택된 명단의 commitment를 사용한다.

\[
n_{\max}(q-1)<\mathrm{ORDER}
\Longrightarrow \widetilde K=\sum_{i\in A}k_i\quad\text{(정수 합)},
\qquad K=[\widetilde K]_q.
\]

H(tilde K,r)=H(K,r)이므로 q를 여러 번 넘는 키 합도 산술적으로 문제없다.
관련 full-domain 공유·검증·직렬화 회귀를 다시 실행했다.
다만 `recover_key_opening`과 `aion_source_aggregate.validate`는 여전히
`n <= key <= 100000*n`을 검사한다. primitive 호환성을 full-domain runtime 성공으로
바꾸어 표현하면 안 된다. 원본 legacy VSS 자체의 보안을 검증한 것도 아니다.

## 4. Client 전송식과 단위

실험 설계에서 S,d,M은 양의 정수이며 L=dS이다.

\[
u_i=\operatorname{RoundEven}(Sx_i),\quad
m_i=\operatorname{scale}_M(h_i)=\left\lfloor\frac{2Mh_i+p}{2p}\right\rfloor,
\quad Y_i=du_i+m_i.
\]

| 값 | domain / 단위 |
|---|---|
| k,t | HPRF 입력 ring Z_q |
| h | raw HPRF 대표값 0..p |
| u | 양자화된 update 정수 |
| m,Y | transmission 정수, m은 0..M, Y는 음수도 가능 |
| Y/L | MGF의 모델 단위 |
| VSS share | Z_ORDER |

현재 runtime `mask_integer_wire`는 `d=codec.denominator/S`, `a=codec.coefficient`로
`Y=d*u+RoundEven(a*h)`를 계산한다. a는 `Fraction`으로 이미 **정수/유리수 정확 계산**이며
단순 float scaling이 아니다. 실험 helper는 a=M/p일 때 이를 정수 전용 나눗셈으로 구현한다.
두 식은 M이 정수인 해당 설정에서 일치한다. 현재 a*p가 항상 정수인 것은 아니다(14절).

`FixedPoint.encode`는 입력 float의 decimal spelling을 기준으로 nearest-even 양자화한다.
현재 런타임은 C를 넘는 입력을 **거부**하며 자동 clipping하지 않는다. 이전 parameter
sweep은 `np.clip`을 명시적으로 수행했다. 이 전처리 차이도 통합 정책에 포함해야 한다.

## 5. MGF 입력식과 판정식

`source_paper_numeric.select_masked`는 client가 보낸 동일한 Y를 검사하고, 선택된
동일 Y를 `pending['total']`로 합산한다. client-side `%M`이나 두 번째 vector는 없다.

\[
v_i=Y_i/(dS)=u_i/S+m_i/(dS),\qquad
\alpha=M/(dSp),\qquad v_i\simeq u_i/S+\alpha h_i,
\]
\[
\sum_{j\in J}Y_{i,j}^2\le(dS)^2b_r^2.
\]

FMNIST에서는 J=[60856:61696], 840좌표다. mask는 **uncentered 0..M**이며 endpoint도
포함한다. 이 검사는 전체 좌표의 clipping bound나 share-mask 일치를 증명하지 않는다.
정수 제곱합 비교는 저장된 b에 대해 정확하지만, history의 Euclidean sqrt는 60자리
Decimal 근사값이므로 이상적 무리수 norm까지 무한정밀도라는 뜻은 아니다.

1~3라운드는 E2 percentile/ranking bootstrap이며 최소/최대 선택 수가 있다.
4라운드 이후 명시적 `inclusive-historical-bound-v1`은 bound 이하를 전부 선택하고
2명 미만이면 중단한다. 이 profile이 없는 오래된 manifest는 ranked legacy 동작이다.

## 6. MGF bound 갱신식 — 논문과의 차이

현재 `recover`, `scale_source='quantized-sum'`의 통계량은 다음과 같다.

\[
B_r=\sum_{i\in A_r}Y_i-dU_r=\sum_{i\in A_r}m_i,
\quad T_r^{\rm impl}=\|U_{r,J}/S\|_2+\|B_{r,J}/(dS)\|_\infty,
\]
\[
b_r=b_{r-1}T_{r-1}^{\rm impl}/T_{r-2}^{\rm impl}.
\]

정확한 U가 복원되었다는 전제에서 B 계산도 정확하며 별도 share는 필요 없다.
서버가 raw Y 합을 보존해야 한다. 합을 `%M`한 값만 보존하면 B를 이 식으로 구할 수 없다.
이것은 이미 관측한 합과 복원한 합의 함수이지 새로운 개별 키 공개가 아니다.

그러나 논문 Algorithm 6, lines 3–4의 mask 항은 **합계 키로 재생성한 HPRF**이다.
대응되는 표기는 `T_paper=||X_r||_2+alpha_r||H(K_r,r)||_inf`이며 실제 per-client
mask 정수 합의 norm으로 대체하라는 식이 아니다.
[Aion 공식 논문, Algorithm 6](https://www.usenix.org/system/files/usenixsecurity25-liu-yizhong.pdf).

두 통계량은 carry 및 scaling rounding 때문에 일반적으로 다르다. 작은 실제 HPRF
구성 p101,q505,c0=1,keys400/350에서 h80/70, H(K)=49가 된다.
M21,d3,S1,u=(1,0)이면 m=(17,15), U=1을 정확히 복원하지만
`T_impl=35/3≈11.6667`, `T_paper=444/101≈4.3960`이다.
ratio 형식을 유지했다는 이유로 Algorithm 6 전체와 동치라고 주장할 수 없다.
projection/bootstrap 역시 구현의 명시적 adaptation이다.

## 7. Server aggregation 수식

좌표별로, underlying t의 합에서 c를 정의하면

\[
\sum_i h_i-H(K,r)=cp+e,\qquad
\sum_i m_i-\operatorname{scale}_M(H(K,r))=cM+E.
\]
\[
Y_A=\sum_iY_i,\quad
R^{\rm mod}=[Y_A-\operatorname{scale}_M(H(K,r))]_M=[dU+E]_M.
\]

매 덧셈에서 `%M`하거나 정수 합의 마지막에 `%M`하는 것은 동일하다.
c를 추정하지 않고 cM을 소거한다. **scaled wire에서 사용하는 modulus는 p가 아니라 M**이다.

원본 `Aion/agent/Aion/SA_Aggregator.py:report_process`에는 raw vector sum의 `%p`,
HPRF 차감 후 `%p` 경로가 있다. 반면 원본 client의 해당 SA vector는 float64 mask+ones
통신 실험이다. 이를 현재 fractional-scaled learning/MGF wire의 완성된 구현으로
동일시하면 안 된다. 현재 port의 paper learning recovery는 여전히 candidate 방식이다.

## 8. Centered decoding 수식

\[
\operatorname{center}_M(z)=
\begin{cases}[z]_M,&[z]_M\le\lfloor M/2\rfloor,\\
[z]_M-M,&[z]_M>\lfloor M/2\rfloor,
\end{cases}
\]
\[
\widehat U=\operatorname{RoundEven}\left(
\operatorname{center}_M([Y_A-\operatorname{scale}_M(H(K,r))]_M)/d\right).
\]

`center_p`라는 함수 이름이어도 인자는 transmission M이다. Python `%`의 비음수
representative와 일치한다. 홀수 M의 범위는 대칭 [-floor(M/2),floor(M/2)],
짝수 M은 **(-M/2,M/2]**이다. 짝수 midpoint는 +M/2를 선택한다.
안전 조건은 strict inequality이므로 ±M/2의 모호함을 안전 영역으로 포함하지 않는다.

## 9. Raw HPRF 및 transmission error bound

q=5p이므로 각 raw rounding residual rho=h−t/5는
`{−2/5,−1/5,0,1/5,2/5}` 중 하나다. 따라서 정수인 e에 대해

\[
e=\sum_i\rho_i-\rho_A,\qquad
|e|\le E_H(n)=\left\lfloor2(n+1)/5\right\rfloor\quad(n\ge2).
\]

정수 M,h와 홀수 p에서 half tie는 없다. `2Mh=(2a+1)p`는 짝수=홀수가 되어 불가능하다.
따라서 `scale(h+p)=scale(h)+M`은 floor translation으로 정확히 성립하고,
`|delta|=|scale(h)−Mh/p| <= (p−1)/(2p)`이다.

\[
E=\sum_i\delta_i-\delta_A+(M/p)e,\qquad
|E|\le\overline E(n,M)=
\left\lfloor\frac{(n+1)(p-1)+2ME_H(n)}{2p}\right\rfloor.
\]

n=1은 같은 mask가 그대로 상쇄되어 e=E=0이다. 위 식은 **보증 상한**이지 모든 M에서
항상 달성되는 정확한 최대치가 아니다. M=p이면 scaling이 항등이어서 E=e인데도
일반식은 더 느슨하다. 표기상 `E_max`를 쓸 때 이 차이를 밝혀야 한다.

`ME_H/p<1/2`이면 `overline E<=floor((n+1)/2)`가 성립한다. 현재 작은 M, n20에서는
10을 실제 달성하는 fixture가 있고 d20의 tie 실패, d21 성공 회귀를 다시 실행했다.
그러나 큰 비율에서는 고정 10을 재사용하면 안 된다. p11,q55,n20,M7,t_i=3이면
e=8,c=1,E=12, 일반식 상한14이다. M<p라는 사실만으로 small-M 근사를 정당화할 수 없다.

별도 `Fraction` 기준으로 작은 p의 internal-q 대표값 1,145,150조합을 전수 검사했다.
raw/scaled 상한 위반은 없었다. 이는 작은 구성의 exhaustive evidence이며 실제 큰
domain 전수 검사나 보안 증명은 아니다. translation 등 2,088조합도 일치했다.

## 10. Exact recovery 조건과 적응형 scale 병목

실현된 sum에 대한 충분조건은 `|E|<d/2`, `|dU+E|<M/2`이다.
모든 정직한 client의 `|x_ij|<=C`를 전제하면 `B_u=RoundEven(SC)`로 다음 envelope를 쓴다.

\[
d>2\overline E(n_{\max},M),\qquad
d n_{\max}B_u+\overline E(n_{\max},M)<M/2.
\]

이것은 worst-case **충분조건**이다. 모든 성공한 개별 샘플의 필요조건이라는 표현은
과하다. 실제 오차가 작거나 update가 상쇄되면 envelope 밖 설정도 일부 샘플에서 성공한다.
반대로 사후 residual/range 검사가 통과했다고 입력 범위 전제가 증명되지는 않는다.

통합에서 가장 중요한 별도 제약은 현재 `paper_codec(...).with_mgf(...,normalized)`다.
선택된 SUM profile, 고정 S에서

\[
a_r=\frac{\beta dS\|X_{r-1,J}\|_\infty}{p},\qquad
M_r=a_rp=\beta dS\|X_{r-1,J}\|_\infty,\qquad X_r=U_r/S.
\]

따라서 실제 centered 조건은

\[
\|X_r+E_r/(dS)\|_\infty<\beta\|X_{r-1,J}\|_\infty/2.
\]

특히 필요한 함의는
`||X_r||inf < beta*||X_(r-1),J||inf/2 + Emax/(dS)`이다.
beta=.2이면 현재 합이 이전 projection 합의 대략 1/10 이하로 줄어야 하는 강한 제약이다.
S나 d만 바꾸어도 모델 단위 period `M/(dS)`는 이 policy에서는 바뀌지 않는다.

더 강하게, 이전 라운드도 같은 `nmax,B_u` 안에 있다면
`M<=beta*d*nmax*B_u`인데 uniform envelope는 `M>2(d*nmax*B_u+Emax)`를 요구한다.
**B_u>0, beta<1에서는 이 두 worst-case 조건을 동시에 만족할 수 없다.**
이는 현재 SUM profile·균일 범위 보장·이 decoder를 함께 요구한 조건부 결과다.
모든 실제 샘플이 실패한다거나 논문 전체가 불가능하다는 주장은 아니다.

따라서 안전한 큰 fixed M을 택하는 실험은 decoder 검증에는 유효하지만,
기존 적응형 마스크 크기 policy까지 그대로 유지하는 통합의 증거는 아니다.

## 11. FedAvg 적용 방식

현재 기본 경로는 client 동일 가중치 평균이다.

\[
\bar x_r=U_r/(Sn_r),\qquad w_r=w_{r-1}+\bar x_r.
\]

평균은 ring 밖에서 계산한다. 양자화 오차는 nearest rounding 기준 각 client 좌표
최대 1/(2S)이고 동일 가중치 평균의 오차도 최대 1/(2S)다. float baseline과 완전히 같은
학습 trajectory라는 뜻은 아니다.

`Y_i=d*w_i*u_i+m_i`로 바꾸면 arithmetic weighted sum 복원식은 맞지만,
같은 Y의 MGF 입력도 `w_i*u_i/S+m_i/(dS)`로 바뀐다.
이를 w_i로 나누면 mask scale이 client별로 달라진다. 따라서 weighted FedAvg를
**MGF 의미를 그대로 유지하는 단순 확장**이라고 할 수 없다.
toy d3,S1,u1,m3,w3에서는 원래 norm2가 bound3을 통과하고 weighted norm4는 탈락한다.
weight로 나눈 4/3도 원래 norm2와 다르다. 첫 통합 제안은 unweighted로 제한한다.

## 12. 코드와 설계가 일치하는 부분

- scalar HPRF 수식·p/q·inclusive endpoint·q-periodicity.
- 서로 다른 HPRF/VSS domain, 정수 키 합의 무넘침 전제.
- single Y를 MGF와 선택 합산에 공통 사용하고 uncentered mask를 유지하는 점.
- 정수 M에 대한 scale translation, generalized residual bound, center/round 복원.
- 복원 후 실제 mask 합 계산과 SUM history profile이라는 **현재 구현 설명**.
- unweighted mean과 초기 3라운드 bootstrap/이후 inclusive 판정의 구분.

마지막 두 항목이 논문 전체와 동치라는 뜻은 아니다. 기존 manifest에는 legacy profile도 있다.

## 13. Runtime에 미적용된 부분

| 역할 | 현재 Flower runtime | 검증된 실험 / 필요한 구분 |
|---|---|---|
| key sampling | `aion_source_asr.source_request`: 1..100000 | `full_domain_keys.sample_full_domain`: full q |
| key 정책 | sharing `recover_key_opening`, aggregate `validate`, server `key_profile`의 작은 키 한계 | profile별 aggregate domain 검사가 필요 |
| spacing | `PaperDMC`: 후보 20명·decimals6에서 d100 | 실험 d21 등은 독립 parameter |
| mask 계수 | `paper_codec`: 이전 projection norm 기반 유리수 a | 정수 M/p profile은 일부 상태와만 동일 |
| 복원 | `source_paper_numeric.recover → remove_quantized_lift` | `TransmissionParameters.recover`: `%M → center → round` |
| wire 검사 | `aion_source_selection.check_vectors`가 기존 codec 단위를 사용 | d,S,M descriptor에 맞춘 검사 필요 |
| committee 재검증 | `aion_source_aggregate.validate`가 legacy 복원을 replay | 동일 새 복원/history replay가 필요 |
| offline 검증 | `experiments/verify_source_learning.py` | 새 profile 인식 필요 |

`client_app.records`는 canonical JSON **bytes**를 ConfigRecord에 넣는다. Python 왕복은
큰 int를 보존한다. 이를 JavaScript Number/int64/float 필드로 바꾸면 안 된다.
`numeric.py`의 별도 raw-ring backend가 존재한다고 source paper path가 새 방식이라는
뜻도 아니다. 경로 이름을 구분해야 한다.

## 14. 발견한 반례 및 설명 수정

1. **기존 적응형 period의 range 실패:** 실제 p/q, keys4/16, round4, M32000,d100,S1e6.
   양수 좌표 U700,E0은 |dU+E|70000>16000이고 단순 center decode는 60을 준다.
   음수 좌표 U−700,E−1은 절댓값70001>16000이고 −60을 준다.
   이는 현재 synthetic 환경의 공개 최소 fixture이며 옛 private 선택 키를 읽은 것이 아니다.
   안전하지 않은 설정을 새 decoder가 자동으로 고친다는 주장은 반증된다.
2. **초기 M이 비정수:** archived FMNIST initial_linf=9894833/16777216에서
   `a*p=773033828125/65536`이다. 정수 ring M helper에 그대로 넣을 수 없다.
   M=3/2 toy도 translation 항이 정수 M일 때와 다르다. M을 정수로 반올림하면 alpha가
   변경되므로 별도 명시 정책이어야 한다.
3. **history 통계량 불일치:** 6절의 35/3 대 444/101. ratio 형식만 같다고 동치가 아니다.
4. **큰 M에서 E10 고정 불가:** 9절 E12 반례. 일반식을 매 parameter에 적용한다.
5. **runtime max_integer의 floor/round 불일치:** C=.00015,S10000에서 encoder는
   ±2를 만들지만 `FixedPoint.max_integer`는 1이다. 현재 기본 C100은 영향 없다.
   임의 C로 통합할 때 metadata/validator를 맞춰야 한다. 이번에는 runtime을 수정하지 않았다.
6. **범위 사후검사 한계:** feasible n2,C.000079,M32000,d100에서 input total32000,
   aggregate mask0은 0으로 decode되어 residual 검사도 통과한다. 실제 sum320은 입력
   전제를 어긴 값이다. range 위반을 전부 탐지하는 장치라고 표현하면 안 된다.
7. **projection 한계:** J 밖에 큰 값을 둔 predicate-only fixture는 선택된다.
   signed protocol의 모든 사전검사를 통과하는 공격을 입증한 것은 아니다.
8. **입력 overlap:** 실제 full-domain fixture에서 H(k,1,1024)의 뒤 512개는
   H(k,2,512)와 정확히 같다. r+block 인코딩은 비충돌 입력 인코딩이 아니다.
9. **weighted wire의 MGF 의미 변화:** 11절 반례. weighted 식은 집계 대수만 보장한다.

## 15. Correctness 결론

정수 M, 올바른 mask/key 관계, 선언된 입력 envelope 아래 복원식을 승인할 수 있다.
이번에 full-domain 키로 FMNIST frozen update와 synthetic을 다시 계산한
**752,772좌표가 모두 평문 정수 합과 동일**했다. S는 10^4/10^5/10^6,
synthetic selected count는 2/20/100, rounds는 1/4/17/451을 포함한다.

별도 MGF 3설정 replay의 진행 가능한 라운드에서도 617,060개의 좌표 비교가 일치했다.
이는 반복된 비교 건수이며 서로 다른 모델 좌표의 개수나 closed-loop 학습 증거가 아니다.
MGF에서 중단된 라운드는 성공으로 세지 않았다.

**기존 작은 적응형 period의 실패는 여전히 실패다.** feasible period를 새로 정한
성공과 원래 parameter 그대로의 성공을 혼동하지 않는다.

## 16. MGF 실용성 결론

기존 데이터 hash를 확인하고 4라운드 frozen updates, 공개 small keys, 기존 MR attack
4명으로 아래 세 설정을 다시 실행했다. S10000,d21,nmax20이고 predicate/history는
현재 실험 구현 그대로다. benign update는 명시적으로 C로 clip했다. 악성 MR 입력은
성능을 좋게 보이게 하려고 clipping하지 않았다.

| C | M | r4 attack TPR | r4 benign FPR (정상 16명 기준) | 정상 replay r4 |
|---|---:|---:|---:|---|
| .001 | 8421 | 4/4 = 100% | 13/16 = 81.25% | 진행 |
| .01 | 84021 | 4/4 = 100% | 16/16 = 100% | insufficient-valid |
| 100 | 840000021 | 3/4 = 75% | 16/16 = 100% | insufficient-valid |

마지막 행은 attack predicate가 악성 한 명만 통과시켰다는 통계이며, 프로토콜이 그
한 명을 집계했다는 뜻이 아니다. 최소 2명 정책 때문에 진행할 수 없다.
전체가 정상인 20명 replay의 r4 거부율은 각각 80%,100%,95%다. 위 공격 혼합 FPR와 구분한다.

같은 데이터·키의 original adaptive-scale control도 MR TPR100%, benign FPR87.5%다.
따라서 높은 거부율이 전부 modular 변경 때문에 새로 생겼다고 단정하지 않는다.
.001 설정에서 threshold 1.25배의 사후 민감도 검사는 TPR100%,FPR0%이지만,
.01에서는 같은 배수가 TPR0%,FPR0%였다. 이를 일반적인 해결된 threshold로 채택하지 않았다.

.001 설정의 frozen replay test accuracy는 0.884556, validation은 .893이다.
이는 원래 저장된 trajectory의 local updates를 재사용한 수치로, 새로운 MGF 선택이
다음 local training까지 반영되는 closed-loop 수렴 실험이 아니다. 이번 검토에서
장기 학습·새 full-domain-key MGF 실용성·모바일 비용은 검증하지 않았다.
마스크는 계속 uncentered이고, scalar 출력의 상관 때문에 iid uniform norm 공식을
privacy 증거나 정확한 분포 정리로 해석하지 않는다.

## 17. HPRF/키 privacy 결론

새 공개 fixture 실행에서도 작은-key search **20/20**이 유일 키 및 개별 quantized
update를 복원했다(약 9.345초). 전체 q key로 바꾸면 이 작은 사전 공격의 범위는 늘어난다.
그러나 raw HPRF 출력 두 좌표를 입력으로 하는 별도 역산도 **33/33** 성공했다.
후자는 full-domain **masked Y만으로** 키를 복원한 실험이 아니다.

현재 scalar column-sum 구성은 BLMR의 공개 행렬 곱과 vector key 구성과 다르다.
BLMR §5의 보안 정리를 이 scalar artifact에 그대로 적용할 수 없다.
[BLMR 원문 §5](https://crypto.stanford.edu/~dabo/pubs/papers/homprf.pdf).
raw 출력 역산, r+block 충돌, 작은 키 문제가 확인된 상태에서 full-domain sampling을
privacy 완성으로 부를 수 없다. 66-bit entropy를 66-bit protocol security로 부르지도 않는다.
ASR 다중라운드 키 합 누출 및 share-mask inconsistency는 여전히 이번 검토 범위 밖이다.

## 18. 가장 작은 integration plan — 제안만, 구현하지 않음

먼저 **유지하려는 MGF scale/history 정책**을 명확히 해야 한다. 적응형 alpha와 균일
centered 범위 보장이 충돌하면 자동으로 M을 키워 해결했다고 보고하지 않는다.
실험용 fixed-M 변형을 허용할지, 원래 scale을 유지하고 infeasible을 보고할지 구분한다.
history도 현재 actual-mask-sum과 literal Algorithm 6 중 무엇을 재현하는지 명시한다.

그 다음 최소 순서는 다음과 같다.

1. task manifest에 profile을 고정한다. 제안 flag는 `recovery=legacy-quantized-lift |
   transmission-centered-v1`, `key_domain=author-small | author-full-q`,
   `period_policy=adaptive-rational | fixed-integer`, `history=actual-mask-sum | paper-hprf`다.
   기존 task의 default/의미는 유지한다. 새 값은 제안 이름이며 현재 지원되는 옵션이 아니다.
2. S,d,M,nmax,C,J,unweighted 및 rounding convention을 setup에서 검증하고 서명/hash에
   묶는다. integer M, 전체 좌표 bound, d/error/capacity, VSS 용량을 확인한다.
   floor-vs-round bound, zero norm/history denominator 처리도 명시한다.
3. client는 같은 Y만 만들고 mod하지 않는다. `mask_integer_wire`, descriptor 및
   `check_vectors`를 새 L=dS에 일관되게 맞춘다. MGF의 norm/threshold 정책은 명시된
   profile대로 유지하며, mean/sum 단위를 바꾸지 않는다.
4. BFT①가 선택 집합·parameter·vectors를 고정한 다음 기존 ASR을 수행한다.
   full-key 옵션을 쓸 때 생성 위치, manifest, 두 aggregate-key 상한 검사를 함께 바꾼다.
   기존 task 키를 중간에 재추첨하거나 VSS를 재설계하지 않는다.
5. 새 복원은 `%M → center → round`, raw Y 합은 history용으로 보존한다.
   infeasible이면 명확히 거부하며 candidate fallback으로 조용히 다른 가정을 쓰지 않는다.
6. committee의 `aion_source_aggregate.validate`, selection history replay,
   `verify_source_learning`에도 같은 profile을 적용한 뒤 BFT②가 모델을 확정한다.
7. 그 이후에만 별도 task에서 실제 Flower smoke/regression 및 MGF 재선택을 포함한
   closed-loop 실험을 한다. 민감한 데이터를 보호하는 production profile로 승격하지 않는다.

첫 실험 통합은 unweighted에 한정한다. full-domain sampling 옵션은 연구 비교에는
의미가 있지만, 현재 primitive privacy 문제를 해결한 profile로 표시하지 않는다.

## 19. 실행한 테스트와 결과

기존 관련 17개 모듈을 이번 검토에서 다시 실행했다: **966 passed**, 114.90초,
외부 Typer/Click deprecation warning 2개. 새 검토 테스트는 최종 ledger 생성 후
**16 passed**, 0.18초. 합계 **982개 테스트 통과**이며 한 번의 pytest 실행 결과를
982개라고 주장하는 것은 아니다.

```bash
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 -m pytest -q tests/test_full_domain_keys.py tests/test_transmission_numeric.py \
  tests/test_modular_recovery.py tests/test_modular_mgf_recovery.py \
  tests/test_aion_hprf_carry.py tests/test_scaled_ring.py tests/test_source_paper_numeric.py \
  tests/test_source_aggregate_validation.py tests/test_source_filtered_bft.py \
  tests/test_source_selection_authorization.py tests/test_source_encrypted_sharing.py \
  tests/test_source_asr_official.py tests/test_split_wire_amr_audit.py \
  tests/test_aion_original_hprf.py tests/test_paper_dmc.py tests/test_paper_mapping.py \
  tests/test_transmission_audit.py

env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 experiments/audit_design_review.py --output .cache/design-independent-review-20261009-v3

env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 -m pytest -q tests/test_design_review.py
```

audit는 이미 있는 output을 덮어쓰지 않는다. 재실행에는 새 output 이름을 사용한다.
unit test의 ledger 검사 기본 경로는 위 v3이며 캐시가 없으면 해당 검사만 skip한다.
작은 q 전수 계산은 `Fraction` 기준으로 기존 helper와 독립적으로 했고, real-HPRF
recovery/security/MGF fixture는 기존 실험 함수를 새로 호출해 재현했다.
저자 setup 및 staged FMNIST/cache가 없는 환경에서는 전체 offline audit를 실행할 수 없다.

새 파일은 다음 세 개뿐이다.

- `experiments/audit_design_review.py`: 기준식, 반례, fresh replay, 입력 및 runtime 해시.
- `tests/test_design_review.py`: endpoint/center/general bound/history/weight/capacity 등 회귀.
- 이 보고서. 기존 runtime 파일 및 이전 보고서는 수정하지 않았다.

## 20. 최종 판단

| 항목 | 판단 |
|---|---|
| 수치 복원 correctness | **조건부 승인.** 정수 M 및 범위/오차 전제에서 증명과 재현이 일치 |
| MGF 실용성 | **미해결.** 높은 정상 거부율 재현, history/적응형 scale 정책 차이 명시 필요 |
| HPRF/키 privacy | **승인 불가.** small-key 복원, raw-output 역산, 입력 overlap; full-domain만으로 수리 안 됨 |
| Flower 통합 준비 | **즉시 통합 불가.** 코드의 작은-key/legacy 경로가 그대로이며 scale/history 결정을 먼저 해야 함 |

결론은 “캐리 복원식이 틀렸다”도, “보안 문제만 빼면 즉시 통합 가능”도 아니다.
**복원 가능한 ring을 구성하는 방법은 확인했지만, 원래 MGF scale/history 의미까지
유지하는지와 그 필터의 실용성은 따로 검증하고 결정해야 한다.**
