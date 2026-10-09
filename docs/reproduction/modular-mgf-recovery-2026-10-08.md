# 현재 단일 MGF wire의 modular-centered 복원 감사

2026-10-08. 결론은 **C: 현재 mask scaling 그대로 HPRF 출력 mod p 복원을 적용할 수 없다.**
정수 배율 대조군에서는 구현·검증에 성공했지만, 현재 Flower MGF runtime은 교체하지 않았다.
아래의 synthetic 숫자는 공개 fixture 키로 재현한 최소 사례다. 기존 실제 실패 run의
비공개 키를 알아낸 결과가 아니다. MPC, 추가 share, 별도 aggregation vector는 없다.

## 1. 실제 masked-vector 식과 현재 코드 구조

코드 기준으로 다음 변수를 구분한다.

- `S=10^decimals`: 업데이트 양자화 스케일. `u_i=round_even(S*x_i)`.
- `L=PaperDMC.denominator`: wire 소수점 스케일, `10^(decimals+ceil(log10(2*N)))`.
- `d=L/S`: wire 정수에서 업데이트 양자화 단위 사이 간격. 이번 요청의 update spacing `D`에 해당.
- `a=PaperDMC.coefficient`: exact Fraction mask 배율. 실수 단위 mask 배율은 `alpha=a/L`.

실제 client 송신값은 **`Y_i=d*u_i+round_even(a*h_i)`**이다.
`h_i=OriginalAionHPRF.hprf(k_i,r,dimension)`.
논문의 float 수식을 추측해서 정한 것이 아니라 `source_paper_numeric.mask_integer_wire`의 구현이다.

경로:

| 역할 | 파일·함수 |
| --- | --- |
| 원본 HPRF 읽기·동일 계산 | `trustlessfl/aion_original_hprf.py`, `OriginalAionHPRF.hprf` |
| client 양자화·마스킹 | `numeric.FixedPoint.encode`, `aion_source_asr.source_request`, `source_paper_numeric.mask_integer_wire` |
| MGF·selected total | `source_paper_numeric.select_masked` |
| BFT①·share release gate | `aion_source_server.SourceServer.run`, `aion_source_selection`, `aion_source_asr.source_request` |
| 초기 공유·선택집합 ASR | `aion_source_sharing.share_seed`, `sum_keys`, `recover_key_opening` |
| aggregate HPRF·기존 복원 | `source_paper_numeric.recover`, `PaperDMC.remove_quantized_lift` |
| model 평균·BFT② | `aion_source_asr.source_request`, `aion_source_server.SourceServer.run` |
| DMC/DMR 숫자 기준 구현 | `paper_dmc.PaperDMC` |

ASR은 선택된 client 키 share를 더하고 Pedersen commitment를 검증한 뒤 합계 키를 복원한다.
`len(A)<=K_A<=100000*len(A)` 검사를 유지한다. 이 감사는 VSS 또는 BFT를 바꾸지 않는다.

## 2. HPRF modulus

현재 읽은 저자 setup:

```
p = 14760426300877770769       # 출력 modulus
q = 73802131504388853845 = 5*p # 내부 산술 modulus
n = 128, m = 512
```

VSS의 군 위수 `ORDER`는 별도 값이다. 출력 p, 내부 q, VSS ORDER를 혼동하면 안 된다.
원본의 초기 키 범위는 1..100000이다. 이 감사는 원본의 암호학적 보안성을 인증하지 않는다.

## 3. Representative와 dtype

원본과 adapter는 `t=((k*(r+block))%q)*column_sum%q`,
`h=(t*p+q//2)//q`로 계산한다. 반환값은 일반 Python int이며 **0..p inclusive**다.
반올림 때문에 endpoint p가 가능하고, 마지막 `%p`가 없다. 음수 representative는 사용하지 않는다.

현재 학습 wire는 signed Python int 리스트이다. Flower JSON/ConfigRecord로 운반하고,
집계 actor에서는 `numpy dtype=object`로 유지한다. 정수 합·모듈러 계산 중 float를 사용하지 않는다.
현재 paper-scale 경로의 client는 Y를 mod p로 줄이지 않는다.

## 4. Update quantization

`FixedPoint.encode`는 유한 값과 `max_abs`를 검사한 뒤
`Decimal(str(float(x)))*S`를 ties-to-even으로 정수화한다.
`max_abs` 초과 입력은 자동 clipping이 아니라 거부다.
현재 두 공식 run의 `S=10^6`, `max_abs=100`, `C=10^8`.
정수 합을 복원했다면 평균은 field division이 아니라 `sum_u/(S*selected_count)`로 한다.
현재 unweighted mean을 유지하며 sample-count weighting은 추가하지 않았다.

## 5. Mask scaling

normalized profile의 `alpha=a/L=beta*previous_linf/p`.
따라서 실제 실수 단위 mask period는 `P=alpha*p=beta*previous_linf`,
wire 단위 period는 `T=a*p=L*P`이다.

synthetic r4: `N=20`, `L=10^8`, `d=100`, `beta=0.2`, `previous_linf=0.0016`.

```
a = 32000/p
P = 0.00032
T = 32000
```

원래 h의 carry p가 전송 wire에서는 **32000**이 된다.
`round_even(a*(h+p))-round_even(a*h)=32000`, p의 배수가 아니다.
이 사례에서는 T가 짝수 정수라 ties-to-even의 이동도 정확하지만, 일반 profile에서
T가 정수가 아닌 경우에는 그 이동 자체에 추가 rounding 의존성이 있다.

## 6. MGF와 집계의 동일성

현재 두 곳은 동일한 Y를 사용한다. MGF는 지정 projection에서 `sum(Y_j^2)/L^2`를
bound의 제곱과 비교한다. 첫 세 라운드는 선언된 percentile bootstrap이고 r4부터
두 공개 history term으로 갱신한 inclusive bound를 적용한다.
선택된 Y들의 정수 합이 pending total이다. 새로운 wire나 다른 mask scale을 추가하지 않았다.

## 7. 기존 ambiguity 원인

raw HPRF에서는 `sum(h_i)-H(K_A,r)=c*p+e`.
현재 wire에서 aggregate mask를 빼면 `d*sum(u_i)+c*T+wire_error`가 된다.
T/d가 모델 정수 grid와 맞으면 여러 c에서 서로 다른 update sum 후보가 모두 정상 grid에 있다.
현재 legacy는 grid·오차·가능한 mask total 범위를 모두 검사해도 여러 후보가 남으면 중단한다.
새 modular helper에는 carry 후보 열거 또는 legacy fallback이 없다.

## 8. Synthetic r4 재현 및 원래 로그의 한계

기존 `.cache/same-scale-synthetic-official-20261008/failure.json`:
`category=ambiguous`, request `reconstruct, round=4`, 3 committed rounds.
SHA256: `aa91302036a9b5ffab987233968eb9f520d4ae7cb8e1d9174300b5042fc1f799`.
그 run은 r4 비공개 HPRF 키/개별 평문 ground truth를 저장하지 않았으므로 그 실행의
실제 coordinate별 c/e/U는 복원했다고 주장하지 않는다.

대신 **동일한 committed r4 scale·MGF history bound**에서 공개 키 `[4,16]`, 8좌표,
첫 client update quanta `[0,700,-700,5,-5,800,-800,0]`, 두 번째는 0으로 최소 재현했다.
나머지 18 client는 실제 HPRF와 허용 범위 내 update 1.0으로 wire를 만들고 MGF에서 탈락한다.
실제 `select_masked`는 두 공개 fixture client `[1,0]`만 선택하며, 동일한 Y를 집계한다.

| 좌표 | raw mask sum | aggregate HPRF | c | e | 참 update sum | legacy update 후보 | 단순 mod p 복원 | scaled mod T 복원 |
| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: |
| 0 | 26877942862611229325 | 12117516561733458556 | 1 | 0 | 0 | 320, 0 | 320 (오류) | 0 |
| 1 | 13172242274757522414 | 13172242274757522414 | 0 | 0 | 700 | 700, 380 | 700 | 60 (오류) |
| 2 | 18384504091616703277 | 3624077790738932508 | 1 | 0 | -700 | -380, -700 | -380 (오류) | -60 (오류) |

좌표 0의 차이는 정확히 p이고 raw residual e=0이다. `Y_sum=58270`,
`round(a*H_A)=26270`, mod p 차감은 32000을 남겨 update 320으로 잘못 복원한다.
좌표 2의 wire rounding error는 -1이다. 이는 raw HPRF e와 다른 오차다.

scaled T로 바꾸면 mask carry는 지워지지만 좌표 1의 `|d*U|=70000>16000=T/2`라
700이 60으로 접힌다. **MGF 통과가 centered decoding의 SUM bound를 보장하지 않는다.**
legacy의 8개 좌표 모두 두 update 후보가 남는다.

## 9. 원본 Aion과 포팅 차이

`Aion/agent/Aion/SA_Aggregator.py:451-452`에서 원본은 매 vector addition 후 `%p`,
`:549-551`에서 HPRF aggregate subtraction 후 다시 `%p`를 한다.
다만 `SA_ClientAgent.py:316-320`의 SA benchmark는 h를 float64로 바꿔 ones에 더한다.
이 benchmark에는 현재 학습 wire의 rational MGF scaling·정수 DMC가 없다.
float64 때문에 64-bit 정수 mask의 하위 비트/작은 update가 손실될 수 있으며,
원본 코드를 그대로 실행한 결과를 exact signed FedAvg reference로 간주하지 않는다.

포팅의 non-MGF `FixedPoint.mask/unmask`는 이미 modulo/centered decoding을 한다.
그 경로는 이번에 바꾸지 않았다. paper-scale MGF 학습 경로만 integer-lift+후보 검사를 한다.
`PaperDMC.remove`의 literal subtract/round는 작은 e를 흡수하지만 c*p 또는 scaled c*T를
일반적으로 제거하지 않는다. modular arithmetic과 decimal rounding은 별개의 단계다.

## 10. mod p 적용 판정과 수학적 근거

정수 mask 배율 A일 때 동일 wire `Y_i=d*u_i+A*h_i`에 대해

```
(sum(Y_i)-A*H(K_A,r)) mod p = (d*sum(u_i)+A*e) mod p
```

`A*c*p`는 0이므로 carry 복원 없이 정확한 centered lift가 가능하다.
단 `|d*sum(u_i)+A*e|<p/2`, `|A*e|<d/2`가 필요하다.
이 조건을 만족하는 별도 helper를 구현·테스트했다.

**현재 rational-rounded wire에는 위 식을 그대로 적용할 수 없다.** `%p`로 실제 실패했다.
분모를 서버에서 곱해 정수화하는 우회도 synthetic에서 분모가 p라
`cleared_spacing=p*100`이고 update term 자체가 mod p에서 0이 된다.
따라서 이 방법 역시 현재 wire에 대한 해법이 아니다.

## 11. Centered lift 및 새 함수

`modular_recovery.center_p`는 먼저 Python `%p`로 0..p-1을 만들고
`residue>p//2`이면 p를 뺀다. 기존 FixedPoint convention과 같다.
홀수 p의 범위는 `[-floor(p/2),floor(p/2)]`, 짝수 p는 `(-p/2,p/2]`다.
엄격한 half-range 조건을 사용하므로 짝수 midpoint의 부호 모호함을 허용하지 않는다.

추가 파일/함수:

- `trustlessfl/modular_recovery.py`: `center_p`, `hprf_error_bound`, `spacing_limits`,
  `modular_sum`, `ModularRecovery.recover`, `maximum_clients`.
- `paper_dmc.PaperDMC.remove_modular_integer_wire`: 정수 배율만 허용하는 별도 함수.
  current fractional profile은 decode 전에 명시적으로 거부한다.
- `experiments/audit_modular_mgf_recovery.py`: 공개 fixture와 public run history 진단.
- `tests/test_modular_recovery.py`, `tests/test_modular_mgf_recovery.py`: 새로운 회귀 테스트.

legacy는 그대로 보존했다. **runtime feature flag/default 전환은 하지 않았다**:
현재 profile이 preflight에서 실패하기 때문이다. compatible helper는 별도 함수로 비교한다.

## 12. Raw HPRF error bound

nearest rounding의 일반 보수적 bound는 `ceil((n+1)/2)`.
하지만 이 실제 setup은 q=5p, p 홀수이므로 `h=(t+2)//5`이고 각 rounding residual은
최대 2/5이다. aggregate e가 정수이므로 **`E_H=floor(2*(n+1)/5)`**가 성립한다.
단 n=1은 정확히 0이다. n=2:1, n=20:8, n=100:40.
이 bound는 supplied rounding map에서 유도한 것으로 다른 HPRF에 무조건 적용하지 않는다.

독립적으로 내부 q-wrap과 rounding으로 e를 계산했다. 공개 Random 키 20개,
각 513좌표의 실제 HPRF에서:

| r | c!=0 좌표 | 관측 max |e| |
| --- | ---: | ---: |
| 1 | 513 | 0 |
| 4 | 513 | 0 |
| 17 | 513 | 2 |
| 450 | 513 | 1 |

조기 라운드의 e=0도 그대로 기록한다. 원래 실제 키 3개/r450의 별도 기존 ASR 테스트는
e!=0을 명시적으로 재현한다. 관측 최대값을 이론 bound 대신 사용하지 않는다.

정수 배율 A에서는 `E=A*E_H`. 현재 rounded rational mask의 scaled-ring 오차는
rounded aggregate mask를 뺄 때 `a*E_H+(n+1)/2` wire units 이하이다.
synthetic n=2에서 안전하게 올림한 E_wire=2, N=20에서 E_wire=11.

## 13. Update spacing

현재 d=100을 그대로 분석했다. 정수 A=1 대조군도 동일 S,L,d를 사용한다.
현재 배율 a를 몰래 1로 바꾸거나 client vector를 바꾸지 않았다.

## 14. Error correction feasibility

정수 A=1, N=20이면 E_H=8, `100>16`으로 통과한다.
현재 scaled-ring n=2라면 E_wire=2, `100>4`도 통과한다.
**작은 residual error는 문제의 주원인이 아니다. mask period와 SUM capacity가 문제다.**

## 15. Centered capacity feasibility

정수 A=1 대조군 p에서 `d*N*C+E=200000000008<p/2`.
가능한 spacing은 `[17,3690106575]`이다. 이것은 current MGF wire가 아니라 대조군이다.

현재 synthetic scaled T에서 `d*N*C+E_wire=200000000011`, `T/2=16000`:
조건 불충족. 가능한 spacing 하한은 23이고 상한은 0이다. 현재 C,N에서 feasible d가 없다.
selected n=2만 보아도 보수적 bound는 `20000000002>16000`이다.

## 16. 허용 participant / bound envelope

정수 A=1 대조군, d=100,C=10^8에서는 error와 capacity를 함께 계산하면 N_max=123.
N=20,d=100일 때 최대 C는 `3690106575219442`이다.
큰 p를 갖는 이 대조군 수치를 현재 작은 MGF mask에 적용하면 안 된다.

현재 scaled T=32000에서는 d=100,

- selected n=2에서 C_max=79 quanta, 즉 client coordinate bound 0.000079.
- N=20이면 C_max=7 quanta, 즉 0.000007.
- 현재 C=10^8에서는 한 명도 보수적 SUM capacity 조건을 보장할 수 없다.

이 bound를 강제로 도입하면 현재 정상 학습 업데이트를 제한한다. 이번에는 적용하지 않았다.

## 17. Legacy ambiguity의 새 방식 복원 결과

동일한 current wire에서는 **성공했다고 주장할 수 없다**.
mod p는 scaled carry를 남기고, scaled mod T는 out-of-range SUM을 접는다.
새 helper는 current profile을 거부한다. legacy 최소 실패가 새 방식에서 성공한 것처럼
scale을 바꾸거나 ground truth로 후보를 고르지 않았다.

FMNIST의 이미 성공한 4-round public history를 별도 확인했다:

| r | 공개 SUM Linf | P/2 | centered 조건 | centered로 바뀌는 좌표 수 |
| --- | ---: | ---: | --- | ---: |
| 1 | 0.007802 | 약 0.0589778 | 만족 | 0 |
| 2 | 0.002106 | 0.0007802 | 불만족 | 151 |
| 3 | 0.002348 | 0.0002106 | 불만족 | 4520 |
| 4 | 0.001908 | 0.0002348 | 불만족 | 2955 |

네 라운드 모두 a는 정수가 아니다. 이 표는 기존 공개 결과의 read-only range check이지
새로운 Flower training 실행 또는 private key 재현이 아니다. 성공한 legacy run조차
단순 scaled centering으로 교체하면 깨질 수 있음을 보여준다.

## 18. Tests와 재현 명령

새 모듈: odd/even midpoint, 음수·양수, c=0/1/multiple, 좌표별 다른 carry,
e=0/!=0, 너무 작은 spacing, residual rejection, range rejection, 불가능 parameter,
전체합 후 mod와 매 addition mod 동일성, 원본 HPRF multi-round/random-key exact sum,
current synthetic ambiguity, archived bound replay, FMNIST public-history regression을 검사한다.
기존 actual Pedersen ASR·MGF·두 BFT/authorization 회귀도 함께 검사한다.

최종 실행 결과: 아래 9개 파일 **245 passed, 72.75초**.
추가 `tests/test_source_asr_official.py`의 Flower Context·공식 staging 검증은
**18 passed, 1.26초**. 합계 **263 passed**, skipped/failed 없음.
외부 typer/click deprecation warning만 발생했다.
새 Flower 학습 run은 실행하지 않았다. current profile은 preflight에서 불가능하므로
기존 공개 FMNIST/synthetic 기록을 비교하고 runtime 회귀 테스트로 보존 여부를 검증했다.

엄격한 범위 밖 true SUM이 residue 0으로 alias되면 postcheck만으로는 검출할 수 없다는
실패 테스트도 포함한다. 범위 가정은 사전 조건이지 residual/range postcheck가 만드는 증명이 아니다.

```
env PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 -m experiments.audit_modular_mgf_recovery \
    --synthetic-run .cache/same-scale-synthetic-official-20261008 \
    --fmnist-run .cache/same-scale-fmnist-official-20261008

env PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 -m pytest -q tests/test_modular_recovery.py \
    tests/test_modular_mgf_recovery.py tests/test_aion_hprf_carry.py \
    tests/test_scaled_ring.py tests/test_source_paper_numeric.py \
    tests/test_source_aggregate_validation.py tests/test_source_filtered_bft.py \
    tests/test_source_selection_authorization.py tests/test_source_encrypted_sharing.py

env PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 -m pytest -q tests/test_source_asr_official.py
```

## 19. Exact equality와 quantization error

호환성·capacity 조건을 만족하는 A=1 대조군은 모든 정수 좌표에서 recovered SUM = plaintext SUM이다.
float tolerance 비교가 아니라 정확한 정수 equality다. 현재 fractional profile에서는 equality가
성립하지 않으며 위 실패를 기록한다. 실제 Flower server로 plaintext/key를 보내는 변경은 없다.

S=10^6의 nearest 양자화 오차는 각 client coordinate 최대 0.5e-6이고 평균에도 같은 상한을 적용한다.
시험 입력 `[0.12345649,-0.01234549,0.00000049]`의 양자화 전 decimal mean과의 차이는
`49/300000000 = 약1.63333333e-7`이다. binary float FedAvg와의 차이도 이 상한 이내다.
integer sum의 exactness와 원래 float 업데이트에 대한 양자화 오차는 구분한다.

## 20. MGF bound에 미치는 영향

실제 predicate, client Y, threshold, history 갱신은 변경하지 않았다.
정수 A=1로 자동 변경하면 real mask 최대값이 `p/L≈1.476e11`로 현재 .00032보다
압도적으로 커져 현행 bound의 의미가 유지되지 않는다. 따라서 채택하지 않았다.
반대로 scaled-ring의 작은 SUM bound를 도입하는 것도 정상 학습 업데이트를 제한한다.
mod를 MGF의 **뒤에서만** 수행하면 norm 판정은 유지되지만 SUM 정보의 alias는 막지 못한다.

## 21. 남은 한계·최종 결론

**결론 C. 현재 동일 vector·동일 rational scaling에서는 단순 mod p로 전환할 수 없다.**
modular-centered recovery 자체는 정수 호환 mask와 독립적인 SUM bound가 있으면 구현 가능하다.
하지만 현재 MGF의 작은 mask period는 실제 정상 SUM의 centered 범위를 보장하지 않는다.
현행 parameter 그대로 carry ambiguity를 완전히 해결했다고 말할 수 없다.

legacy와 runtime을 보존하고 exact helper·실패 회귀·진단을 추가했다.
ZKP, MPC, 추가 share, 별도 vector, VSS 변경, ASR leakage, poisoning 방어는 추가하지 않았다.
원본 HPRF 보안성 증명이나 private MGF 구현 완료도 이 작업에서 주장하지 않는다.
