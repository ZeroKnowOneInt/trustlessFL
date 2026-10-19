# Aion no-wrap 확장 프로토콜: MPC 비공개 검사와 정적 threshold

날짜: 2026-10-10  
브랜치: `work/aion-private-bound-no-wrap`  
현재 FMNIST 정책: `S=10000`, `B=20000`, `T=25*S²=2500000000`.

이 문서는 기존 Aion을 확장한 **개별 비밀 unmask → 정수 범위 검사 → 정적 norm 검사 → 선택 집계** 프로토콜을 정의한다. 기존 Aion 논문 전체의 보안 증명이나 기존 wire와 호환되는 교체 방식이라는 뜻은 아니다.

**핵심:** 입력 masked 값을 `%M`으로 줄이지 않는다. MPC 안에서 각 클라이언트의 마스크를 정확히 제거한다. 검사에 통과한 정수 업데이트를 충분한 폭으로 더한다. 따라서 집계 HPRF의 rounding carry와 M에 따른 업데이트 SUM wrap를 사용하지도, 추정해 보정하지도 않는다. MPC backend 유한체의 overflow는 별도의 정수 범위 조건으로 배제한다.

구현 상태는 두 가지다. 소규모 native MASCOT MPC fixture에 아래 정수 회로가 구현되어 있다. 전체 FMNIST 모델의 Flower 학습은 같은 함수의 **평문 reference 검증**이며 아직 native MPC와 연결되지 않았다. 등록 키 바인딩·영속 재질의 방지·합의·dropout은 추가 구현이 필요하다.

**최신 추가 후보:** [일반 PRG + seed MPC 상세 설계](aion-seed-mpc-protocol.md)는 public modular single mask와 등록 키 재사용을 유지하고, 개별 비밀 복원 후 큰 필드에서 합산한다. 이 문서의 raw-offset HPRF 회로와 다른 설계이며 아직 native 구현하지 않았다.

**후속 재검토:** HPRF 유지형보다 직접 비밀 입력형을 다음 후보로 권장한다. 현재 선택 SUM의 출력 프라이버시 및 전체 모델 비용은 별도 해결 조건이다. [새 비교·반례·채택 판단](reproduction/mpc-candidate-review-2026-10-10.md). 이 문서의 본 회로는 기존 mask 유지형 명세로 보존한다.

**검사 범위:** norm 이내의 악성 업데이트 탐지는 목표에서 제외한다. 입력 공유·공개 출력의 프라이버시, 정확한 좌표/norm 판정, carry/wrap 없는 집계를 다룬다. 경계를 준수한 입력은 통과시킨다.

## 0. 목표와 설계 선택 기준

목표는 기존 Aion 구현에서 발견한 modular 복원·wrap 문제를 해결하는 안전한 연합학습 프로토콜이다. Aion 논문의 구조를 그대로 재현하거나 HPRF/VSS를 반드시 유지하는 것 자체가 목표는 아니다. 처음 검토한 RS-MGF 보고서는 이 문제를 해결하려는 transmission-centered 후보이며, 현재 MPC 프로토콜은 다른 복원·검사 후보다.

유지하려는 이점은 여러 aggregator의 분산 검증, 개별 업데이트를 aggregator에게 평문으로 공개하지 않는 입력 프라이버시, 악성 클라이언트를 신뢰하지 않는 검사, 검사를 통과한 업데이트의 정확한 집계다. Aion의 효율상 이점인 키 share 재사용·적은 추가 통신도 평가 대상이지만 현재 전체 모델 MPC에서 유지되었다고 입증하지 않았다.

반드시 만족해야 할 산술 조건과 선택 가능한 메커니즘을 분리한다.

- **산술 조건:** 악성 입력에도 안전한 정수 범위, 정확한 복원, 정확한 좌표·norm 검사, 충분한 SUM 용량. mask carry와 MPC 유한체 overflow를 각각 설명해야 한다.
- **보안 조건:** aggregator/클라이언트 공모 범위, 등록된 입력과 계산의 일치, 허용 출력에서의 누출, 재질의·모델 바인딩, 실패 처리. 기존 Aion의 공모 범위가 그대로 유지된다고 가정하지 않는다.
- **선택 가능한 메커니즘:** HPRF, 별도 VSS, 직접 MPC 비밀 입력, key share의 MPC 변환, 합의 및 출력 인증 방식. 기능을 안전하게 대체할 수 있으면 기존 메커니즘을 바꿀 수 있다.

현재 문서의 mask 유지형 MPC 후보는 기존 encoding과 연결하기 위해 HPRF를 유지한다. 소규모 fixture에서는 key를 MPC에 직접 비밀 입력하며 기존 VSS 등록을 연결하지 않았다. 이는 기능 검증의 단순화이며, VSS 제거가 기존 Aion의 키 등록·일관성·재사용·복구 기능을 모두 대체한다는 증거가 아니다.

대안으로 업데이트 u 자체를 악성 보안 MPC에 비밀 입력하고 같은 범위·norm·집계 함수를 실행할 수 있다. 이 구조에서는 별도 HPRF 마스크와 마스크 키 VSS가 필수는 아니다. 대신 안전한 MPC 입력 공유·일관성·인증 및 출력 계약이 필요하다. 두 후보의 전체 모델 비용과 공모 가정을 비교한 뒤 채택한다.

정적 threshold는 현재 학습 정책으로 고정한다. 어떤 메커니즘을 선택하든 기존의 선택 합계 누출 문제는 별도로 해결해야 한다. 안전한 내부 계산만으로 필터링 결과의 프라이버시가 자동 보장되지 않는다.

## 1. 참여자와 계산·공개 경계

| 참여자 | 역할 | 알아도 되는 정보 |
|---|---|---|
| 클라이언트 C_i | 로컬 학습, 양자화, 마스크·offset 생성, 비밀 입력 | 자기 데이터·업데이트·키, 공개 정책·글로벌 모델, 허용 최종 출력 |
| Committee의 MPC 참여자 P_k | 비밀 공유 상태에서 복원·검사·집계 | 자기 share, 공개 정책, 공개 상태·최종 출력 |
| Flower coordinator/server | 학습 요청, 허용 출력으로 모델 갱신 | 공개 모델·정책, 성공 시 SUM/count, 실패 상태 |

Committee는 MPC를 공동 실행하는 여러 aggregator다. coordinator 한 대가 개별 업데이트를 평문 복원해서 검사하는 구조가 아니다. 한 물리 장비에서 여러 프로세스를 실행한 로컬 fixture는 동작 시험이며 독립 운영 주체의 공모 보안을 검증하지 않는다.

표기의 `[v]`는 MPC의 비밀 공유 값이다. 각 P_k는 자기 share를 갖고, `[v]`에 대한 덧셈·곱셈·비교를 공동 수행한다. 개별 업데이트, 키, 마스크, norm, 통과 비트는 open하지 않는다.

native fixture는 MP-SPDZ 0.4.3의 active MASCOT와 ExternalIO를 사용한다. 허용 부정행위 범위와 보장은 해당 backend·입력 채널 가정을 따른다. 악성 참여자가 있어도 항상 다음 라운드를 완료한다는 가용성 보장은 없다. `N>=3f+1` 같은 Committee 배치 조건만으로 MPC 입력 인증·정확성·프라이버시·BFT가 자동 완성되지 않는다.

## 2. 기호와 고정 정책

| 기호 | 의미 | 현재 학습 설정 |
|---|---|---|
| D | 업데이트 좌표 수 | LeNet5 61706 |
| n_max | 한 라운드 최대 클라이언트 수 | 4 |
| S | 실수→정수 scale | 10000 |
| B | 정수 좌표 절댓값 상한 | 20000, 실수 좌표 cap 2 |
| T | 정수 squared L2 threshold | 2500000000, 실수 L2 반경 약 5 |
| d | 정수 encoding spacing | 양의 정수; 학습 기본 1 |
| M | scaled mask 대표값 상한 | 양의 정수; 산술 검증은 1/15/840000021/2^128 |
| p, q | 원본 HPRF 내부 modulus | HPRF 설정값 |
| P | MPC backend의 소수 유한체 modulus | p/q/M과 별개 |
| a_min | 출력에 필요한 최소 통과 인원 | 현 reference/fixture 기본 2 |

공개 정책은 `D,n_max,S,B,d,M,T,a_min,output-policy,HPRF-setup,backend-P`를 포함한다. `0<=T<=D*B²`, `1<=a_min<=n_max`를 검증한다.

**B와 T의 역할은 다르다.** B는 악성 입력까지 포함한 제곱·합계의 안전 폭을 정한다. T는 그 안전 범위 안에서 어떤 업데이트를 통과시킬지 정한다. T가 작아져도 산술 폭을 T만 보고 줄이면 안 된다. 클라이언트가 T를 넘는 입력을 제출할 수 있기 때문이다.

현재 정책은 학습 시작 전에 T를 고정한다. 공개 평균 norm, 이전 통과 인원, 성공/abort history로 T를 갱신하지 않는다. 다른 모델·학습률의 T를 보정하려면 새 학습 세션 시작 전에 정한다. 반경 5는 현재 FMNIST 설정의 초기값이며 보편적인 공격 탐지 기준은 아니다.

양자화된 norm이 실제 검사 대상이다. 경계에서 실수 delta의 norm과 판정이 다를 수 있다. RoundEven의 좌표 오차는 최대 `1/(2S)`이고, D차원 벡터 오차의 L2 상한은 `sqrt(D)/(2S)`다.

## 3. 세션·라운드 바인딩

공개 context는 적어도 다음을 포함해야 한다.

```text
session_id, epoch, round_id,
hash(actual_global_model), ordered_client_cohort,
hash(frozen_policy), hash(HPRF_setup), output_policy
```

context의 canonical hash에서 라운드 HPRF seed x_r를 유도한다. 입력 수신 전에 Committee와 클라이언트가 같은 context를 확인한다. 키 등록·입력 수신·출력 인증서도 그 context에 연결해야 한다.

하나의 `(session,round,cohort,policy,model)`에 입력을 한 번 확정한 뒤 한 번만 평가한다. 동일 frozen 업데이트를 다른 threshold/다른 cohort로 반복 질의하는 것은 허용하지 않는 계약이 필요하다. abort 후 재시도도 같은 입력의 추가 관측을 만들지 않도록 정의해야 한다.

현재 소규모 fixture는 context와 seed를 만들지만, 위의 전체 합의·등록·영속 ledger를 구현한 것은 아니다. 공개 offset 표현을 쓰는 학습에서는 실제 모델이 `reference+offset`이므로 offset hash만으로 actual model을 바인딩하면 부족하다. Flower 메타데이터 비교를 암호학적 모델 인증으로 취급하지 않는다.

## 4. 클라이언트의 입력 생성

### 4.1 로컬 학습과 양자화

클라이언트는 동일한 글로벌 모델 w_r에서 로컬 학습한다.

\[
\Delta_i=w_i^{local}-w_r,\qquad
u_{i,j}=\operatorname{RoundEven}(S\Delta_{i,j}).
\]

정상 클라이언트는 `|u_i,j|<=B`를 확인한다. 범위 밖 값의 silent clipping, 정수 축소 또는 modular reduction을 하지 않는다. 이 로컬 확인은 편의 검사일 뿐이다. 악성 클라이언트의 준수를 믿지 않고 MPC에서도 다시 검사한다.

범위·norm 검사는 업데이트가 실제 SGD로 생성되었는지, 데이터가 정상인지, backdoor가 없는지 증명하지 않는다.

### 4.2 정확한 마스크 대표값

클라이언트의 비밀 키는 `0<=k_i<q`다. 라운드 seed에 대한 HPRF의 정수 출력 h를 얻고 endpoint를 canonicalize한다.

\[
h_{i,j}=\operatorname{HPRF}(k_i,x_r)_j\bmod p,
\quad 0\le h_{i,j}<p.
\]

scaled mask는 float 연산 없이 다음 정수식으로 만든다.

\[
m_{i,j}=\left\lfloor\frac{2Mh_{i,j}+p}{2p}\right\rfloor,
\qquad 0\le m_{i,j}\le M.
\]

여기의 rounding 규칙은 RoundEven 양자화와 구별된다. mask scaling 식은 nearest rounding의 이 정수식을 그대로 사용한다. 원본 HPRF가 h=p endpoint를 반환하면 h=0으로 canonicalize하는 새 profile이다. 기존 profile과 혼합하지 않는다.

### 4.3 modulo를 적용하지 않는 offset encoding

\[
Y_{i,j}=d u_{i,j}+m_{i,j},\qquad
v_{i,j}=Y_{i,j}+dB=d(u_{i,j}+B)+m_{i,j}.
\]

정상 입력은

\[
0\le v_{i,j}\le R:=M+2dB
\]

를 만족한다. **Y나 v에 `%M`, `%p`, `%q`를 적용하지 않는다.** v는 `W_v=bit_length(R)` 비트의 unsigned 정수로 표현한다. 키는 `W_k=bit_length(q-1)` 비트로 표현한다.

키와 offset 비트는 coordinator의 평문 메시지로 보내지 않고 MPC의 인증된 비밀 입력 채널로 제출해야 한다. 특히 M=1처럼 작은 마스크로 공개 Y를 숨길 수 있다는 주장은 하지 않는다.

같은 private key에서 client와 MPC가 같은 마스크를 계산하는 것은 현재 fixture에 구현되어 있다. 그 key가 **사전 등록된 key**인지 검증하는 VSS/commitment 연결은 별도 완료 조건이다.

## 5. MPC 바운더리 체크 과정

전체 입력을 먼저 확정한다. 이후 아래 과정을 비밀 공유 상태에서 실행한다.

### 5.1 입력 형식: bit의 Boolean 여부

private field input을 받았다는 사실만으로 각 입력이 0/1 bit라고 믿지 않는다. 각 비트 b에 대해 `b(b-1)=0`을 검사한다.

현재 회로는 모든 입력을 받은 뒤, 제약마다 독립적인 fresh secret field challenge rho를 생성해

\[
C=\sum_\ell\rho_\ell b_\ell(b_\ell-1)
\]

를 open한다. C가 0이 아니면 프로토콜 전체를 input-abort한다. 잘못된 Boolean 입력이 이 검사를 통과할 확률은 이상적인 독립 균등 challenge 가정에서 `1/P`다. 기존 구현은 열린 C를 짧은 application 폭으로 잘라 검사하지 않고 canonical field 전체 비트를 검사한다.

모든 입력이 정상 bit이면 열린 C는 항상 0이다. 이 확인은 개별 업데이트 공개와 다르지만 공개 실패 상태는 transcript에 남는다.

### 5.2 키 범위와 동일 마스크 재계산

키 bits에서 `[k_i]`를 복원하고 `[key_ok_i]=[k_i<q]`를 계산한다. 잘못된 key는 내부 계산 전에 0으로 sanitize하고 client 전체 validity를 false로 남긴다.

비밀 key와 공개 seed/setup으로 HPRF와 위 scaling 식을 MPC에서 재계산해 `[m_i,j]`를 얻는다. 클라이언트가 제출한 임의 mask 값을 신뢰하는 방식이 아니다.

HPRF 내부의 `%q`와 canonicalization `%p`는 의도된 함수 계산이다. 업데이트 SUM을 줄이는 modulo 연산과 구별한다. 현재 회로의 공개 상수 나눗셈은 bounded binary long division이고, 정수 quotient가 필요한 자리에 유한체 inverse를 사용하지 않는다.

### 5.3 wire 상한 확인과 안전한 residual

offset bits를 unsigned `[v_i,j]`로 복원한다. 비트 폭 안에도 사용하지 않는 값 `R<v<2^W_v`가 있으므로 별도 검사한다.

\[
[wire\_ok_{i,j}]=[v_{i,j}\le R].
\]

잘못된 값은 제곱·signed 해석 전에 sanitize한다.

\[
[\widetilde v_{i,j}]=\operatorname{Select}([wire\_ok], [v_{i,j}], dB),
\qquad
[r_{i,j}]=[\widetilde v_{i,j}]-dB-[m_{i,j}].
\]

정상·비정상 입력 모두

\[
|r_{i,j}|\le A:=M+dB
\]

안에서 처리된다. 모든 wire가 정상이고 mask가 일치하면 정확히 `r_i,j=d*u_i,j`다.

### 5.4 격자와 좌표 바운더리

residual의 부호를 비밀 비교로 얻는다. 절댓값을 **충분한 폭 그대로** 정수 나눗셈한다.

\[
|r_{i,j}|=d q_{i,j}+t_{i,j},\quad
q_{i,j}=\lfloor|r_{i,j}|/d\rfloor,\quad 0\le t_{i,j}<d.
\]

\[
[coord\_ok_{i,j}]=[wire\_ok_{i,j}]\,[t_{i,j}=0]\,[q_{i,j}\le B].
\]

나눗셈 결과를 작은 signed update 폭으로 먼저 잘라 검사하지 않는다. 큰 악성 quotient가 축소 과정에서 작은 값으로 alias될 수 있기 때문이다.

\[
[z_{i,j}]=\operatorname{Select}([coord\_ok_{i,j}],
\operatorname{sign}(r_{i,j})q_{i,j},0).
\]

이후에는 항상 `|z_i,j|<=B`다. `d=1`이면 격자 remainder 검사는 자동 만족하지만 wire/좌표/norm 검사는 그대로 필요하다. 한 좌표라도 실패하면 client 전체는 탈락한다.

### 5.5 전체 squared norm과 정적 threshold

\[
[valid_i]=[key\_ok_i]\prod_{j=1}^{D}[coord\_ok_{i,j}],
\qquad [Q_i]=\sum_{j=1}^{D}[z_{i,j}]^2.
\]

sanitization 덕분에 악성 입력도

\[
0\le Q_i\le D B^2
\]

안에서 계산된다. 이 범위에 충분한 폭을 확보한 뒤 비밀 비교한다.

\[
[e_i]=[valid_i]\,[Q_i\le T].
\]

검사하는 norm은 **unmask된 실제 정수 업데이트**의 norm이다. masked vector norm, mask norm 추정값, 공개 평균 norm을 쓰지 않는다. Q_i와 e_i는 공개하지 않는다. T는 모든 라운드 동일하다.

### 5.6 선택 집계와 출력

\[
[U_j]=\sum_i[e_i][z_{i,j}],\qquad [a]=\sum_i[e_i].
\]

\[
|U_j|\le n_{max}B,\qquad 0\le a\le n_{max}.
\]

`[ok]=[a>=a_min]`을 계산한다. 성공 시 허용 결과는 `status=ok, U, a`다. 실패 시 의미상 결과는 `status=abort`뿐이다. native 회로의 고정 길이 wire는 `(ok, ok*a, ok*U)`이므로 실패 시 count와 SUM slot은 전부 0이다. 최종 MPC MAC 검사가 모두 완료되기 전 출력을 적용하지 않는다.

개별 z_i, mask, key, Q_i, e_i, mask SUM, 추가 signed SUM은 open하지 않는다. 현 native fixture는 동일 최종 결과를 ExternalIO 클라이언트 모두에 반환한다. 실제 Flower 연결에서는 허용 결과의 수신자와 Committee 인증서를 정해야 한다.

성공한 서버 모델 갱신은 현재 동일 크기 shard의 equal-client average다.

\[
w_{r+1}=w_r+\frac{U}{S a}.
\]

실패 시 w_r를 유지한다. 총 참여 인원 대신 통과 인원 a로 나눈다. 데이터 크기 가중 FedAvg로 바꾸려면 weighted SUM·분모와 안전 폭을 다시 정의해야 한다.

## 6. 왜 carry가 없는가

기존 집계 복원에서 문제가 되는 구조는, 각각 rounding한 mask의 합과 집계 key에서 다시 생성·rounding한 mask가 같다고 가정하는 것이다.

\[
\sum_i\operatorname{round}(f(k_i))
\quad\text{와}\quad
\operatorname{round}\bigl(f(\sum_i k_i)\bigr)
\]

는 rounded/modular HPRF에서 일반적으로 같은 ordinary integer가 아니다. 합산 시 modulus를 넘는 carry와 rounding 차이를 별도로 다루어야 한다.

새 구조는 그 등식을 요구하지 않는다. 각 client의 동일한 정수 mask를 먼저 제거한다.

\[
v_{i,j}-dB-m_{i,j}
=d u_{i,j}.
\]

격자를 확인한 뒤 d로 정확히 나누면 u_i,j다. 따라서

\[
U_j=\sum_i e_i u_{i,j}
\]

를 직접 계산한다. 집계 key로 mask를 생성하거나 mask SUM을 근사하지 않는다. 각 mask를 생성할 때 rounding은 있지만 **동일한 정수 값을 빼므로 추가 residual error가 없다.** RoundEven 양자화 오차는 남지만 이는 mask carry와 다른 문제다.

이 때문에 집계 rounding error를 흡수하기 위한 `d>2*error_bound` 조건을 요구하지 않는다. 새 함수의 d는 정확한 격자 spacing이며 d=1도 허용한다. 기존 Aion의 복원 증명에 d=1을 그대로 대입해도 된다는 뜻은 아니다.

## 7. 왜 업데이트 SUM wrap가 없는가

### 7.1 M에 따른 wrap 제거

`%M`을 적용하면 서로 다른 정수 SUM U와 U+M이 같은 대표값이 될 수 있다. 새 입력 offset·복원·SUM에는 `%M`이 없다. M은 mask의 값 범위와 encoding 폭에만 영향을 준다.

예를 들어 D=1, B=2, d=1, M=1이고 업데이트가 `(2,2,2,0)`이면 T>=4 조건에서 모두 통과한다. 각 `v_i=(u_i+2)+m_i`에서 자기 mask와 2를 빼면 업데이트가 정확히 복원된다. 출력은 `U=6, a=4`다. `6>M`이어도 문제가 없다. 음수 `(-2,-2,-2,0)`도 출력은 `U=-6`이다.

이때 필수 조건은 공개 modulo decoder의 `|U|<M/2`가 아니라 **입력을 손실 없이 보존하고 새 SUM 폭을 n_max*B로 확보하는 것**이다.

### 7.2 MPC 유한체 P에 따른 wrap 배제

MPC는 내부적으로 F_P에서 계산한다. 따라서 “일반 정수 합”이라는 설명만으로 overflow가 없어지지 않는다. 비교·bit decomposition·signed 해석까지 모든 intermediate가 backend의 정수 처리 범위를 지켜야 한다.

application 폭의 기준은 다음과 같다. `bit_length(K)`는 0..K를 포함할 unsigned 폭이다.

| 값 | 정수 범위 | 구현의 application 폭 |
|---|---|---|
| offset v | 0..M+2dB | bit_length(M+2dB) |
| residual r | -(M+dB)..M+dB | 1+bit_length(M+dB) |
| sanitized update z | -B..B | 1+bit_length(B) |
| squared norm Q | 0..DB² | bit_length(DB²) |
| SUM U | -n_max*B..n_max*B | 1+bit_length(n_max*B) |
| count a | 0..n_max | bit_length(n_max) |

위 application 폭 외에도 key/modular multiply, mask numerator `2M(p-1)+p`, 나눗셈의 remainder와 비교 여유를 포함해야 한다. 현 fixture runner는

```text
L = max(
    max(application_widths) + 2,
    bit_length(3*q) + 2,
    bit_length(2*M*(p-1) + p) + 2,
    필요할 경우 bit_length(q*p + floor(q/2)) + 2
)
```

를 산정한다. 마지막 항은 일반 HPRF rounding 경로이고, q=5p·홀수 p의 특수 경로는 큰 q*p 곱 대신 정확한 상수 나눗셈을 사용한다. 공개 상수 modular multiply도 큰 key*coefficient를 한 번에 만들지 않고 bounded 반복 계산한다.

현재 선택지는 `P=2^127-1` 또는 `P=2^255-19`이며,

```text
L + 40 + 2 <= bit_length(P)
```

를 요구한다. 40은 fixture backend의 statistical security 여유이고 2는 추가 margin이다. 들어맞는 P가 없으면 실행을 거부한다. 이 조건은 현재 회로와 backend의 설정 규칙이며 다른 backend의 보편적 theorem으로 쓰지 않는다. backend 변경 시 그 backend의 비교·정수 변환 보안 조건을 재검증해야 한다.

출력의 signed 정수 해석도 같은 범위를 따른다. 양의 U와 음의 U의 field 대표값을 구별하려면 `|U|<P/2`가 필요하며, 위 안전 폭은 그 범위를 포함한다. `%M`을 사용해서 음수 부호를 추측하지 않는다.

악성 입력에 대해서도 Boolean 검사 → wire 상한 → 안전 residual → **full quotient 검사** → sanitize → 제곱·SUM 순서를 지켜야 이 범위 증명이 성립한다. 순서를 바꾸거나 좁은 폭으로 먼저 truncate하면 no-wrap 보장은 성립하지 않는다.

## 8. Large M의 영향

norm 검사에서 mask를 먼저 제거하므로 큰 M의 norm이 점수를 지배하지 않는다. UPDATE SUM의 용량도 M이 아닌 n_max*B로 정한다. 그러나 큰 M은 offset 폭·mask scaling numerator 폭·MPC 입력 및 비교 비용을 키운다. 큰 M의 계산 비용까지 사라지는 것은 아니다.

작은 M도 산술적으로 허용하는 이유는 **전체 offset을 안전한 MPC 입력 채널로 숨기기 때문**이다. 공개 masked vector를 작은 mask로 보호하는 기존 공개 구조에 M=1을 적용하면 안 된다. p/q를 줄여도 암호 보안이 그대로라는 결론도 아니다.

MPC로 업데이트 자체를 비밀 입력할 수도 있다. 현재 mask/HPRF를 유지하는 설계는 기존 client encoding과의 연결을 검토하기 위한 선택이다. 안전한 입력의 프라이버시는 단일 마스크의 크기만으로 주장하지 않는다.

## 9. 보안 계약과 남은 문제

“개별 값은 MPC에서 open하지 않는다”와 “허용 출력에서 개인 값이 추론되지 않는다”는 별개다. 현 결과는 다음 조건을 별도로 해결해야 한다.

- **선택된 합계 누출:** 통과 집합에 honest가 한 명뿐이면 공모자 기여를 뺀 U에서 그 honest 값이 복원될 수 있다. a_min=2만으로 해결되지 않는다. 악성 클라이언트 최대 t_C명이면 `a_min>=t_C+2`는 성공 시 최소 두 honest가 남기 위한 필요조건이다. 이것만으로 전체 프라이버시 증명이 완성되지는 않는다. Aion의 q-2 공모 범위를 유지하려면 이 조건은 a_min=q가 되어 일부 제외 후 계속 집계하는 정책과 충돌한다.
- **출력 정보:** count, 성공/abort, 선택된 SUM은 허용 누출로 정의해야 한다. per-client selection을 숨겨도 위 누출이나 입력 의존 abort가 사라지지 않는다.
- **재질의:** 같은 입력의 다른 cohort/T 평가와 재시도는 출력 차분 공격을 만들 수 있다. 영속 one-shot ledger가 필요하다. 정적 T만으로 cohort 재질의를 막지는 못한다.
- **키·모델·정책 바인딩:** private key와 사전 등록 key의 일치, actual model/context 인증, 모든 Committee의 동일 회로 실행, 최종 출력 인증을 연결해야 한다.
- **검사 범위:** norm 안의 방향 공격·backdoor 탐지는 목표에서 제외한다.
- **운영:** Sybil, dropout, 실패 후 라운드 진행 정책은 별도 범위다. 현재 고정 cohort 앱은 누락 reply를 거부하며 가용성 프로토콜을 구현하지 않았다.

따라서 현재 보장은 **조건부 산술 정확성과 비공개 계산 함수의 명세**다. 기존 Aion과 동일한 공모 프라이버시를 달성한 완성 프로토콜이라고 주장하지 않는다. [보안 감사](reproduction/private-bound-security-2026-10-10.md)를 함께 읽는다.

## 10. 구현 대응과 검증 근거

| 기능 | 파일 |
|---|---|
| 정책·폭·정확한 encoding/decoding·출력 함수 reference | [private_bound.py](../trustlessfl/private_bound.py) |
| 고정 학습 threshold 및 동적 설정 혼용 거부 | [static_bound.py](../trustlessfl/static_bound.py) |
| 비밀 입력·HPRF·Boolean/좌표/norm 검사·집계 회로 | [aion_private_bound.mpc](../mpc/Programs/Source/aion_private_bound.mpc) |
| client-side key/offset bits 및 ExternalIO | [mpc_external_client.py](../trustlessfl/mpc_external_client.py) |
| field 폭 선택·소규모 native fixture | [run_private_bound_mpc.py](../experiments/run_private_bound_mpc.py) |
| 공식 Flower 평문 학습 reference | [fmnist_no_wrap_app.py](../trustlessfl/fmnist_no_wrap_app.py) |
| 고정 정책·abort 이후 threshold 유지 회귀 | [test_static_bound.py](../tests/test_static_bound.py) |

산술 감사는 M=1/15/840000021/2^128, d=1/21의 8 profile에서 64000좌표 SUM 일치를 확인했다. 소규모 native MPC에서는 양수·음수 wrap 예제, norm 초과, off-grid, 좌표 초과, non-Boolean, 통과 인원 부족 fixture를 확인했다. 전체 모델이나 악성 MPC party의 fault injection 결과로 확대하지 않는다.

정적 정책의 학습 검증 결과는 공식 Flower IID 5라운드 86.37%·정상 제외 0/20, 로컬 non-IID 10라운드 62.68%·정상 제외 0/40이다. 두 경로 모두 필터 없는 양자화 baseline 모델과 모든 라운드 일치했다. 이는 평문 reference·단일 seed·공격자 없는 조건이다.

- [정적 threshold 변경·학습 재현](reproduction/static-threshold-2026-10-10.md)
- [초기 산술·native MPC 구현과 fixture](reproduction/private-bound-no-wrap-2026-10-10.md)
- [동적 정책의 non-IID 문제 기록](reproduction/mpc-aion-learning-2026-10-10.md)

## 11. 한 라운드 요약

```text
공개 정책/context 확정 (T 고정, B 기반 안전 폭, backend P)
  ↓
동일 글로벌 모델에서 클라이언트 로컬 학습
  ↓
u = RoundEven(S*delta), m = exact_scale(HPRF(key, seed))
v = d*u + m + d*B                 # modulo 없음
  ↓
key/offset bits를 MPC에 비밀 입력, 전체 입력 확정
  ↓
Boolean bit 검사 → key 범위 검사 → 비밀 mask 재계산
  ↓
wire 범위 검사 → 안전 residual → 부호/정수 나눗셈
  ↓
full quotient/격자/좌표 검사 → invalid 좌표 0
  ↓
전체 client validity + secret squared norm <= 고정 T
  ↓
secret accepted bit로 integer SUM/count
  ↓
인원 부족: abort / 충분: 인증 완료 후 SUM/count 공개
  ↓
w_next = w + SUM/(S*count)        # T 갱신 없음
```
