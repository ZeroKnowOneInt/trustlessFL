# 범용 정수 인코딩을 통한 캐리 복원 후보

상태: **현재 형태 채택 제외 — 악성 wire 변조 반례 확인**.
Flower 실행 경로에 적용하지 않았다. 아래의 정직한 입력에 대한 수치 복원
논증은 유지되지만, MGF가 다루는 악성 클라이언트까지 포함한 해결책으로
추천하지 않는다. 후속 반례는 이 문서 마지막 절과 재현 스크립트에 있다.
원본 HPRF, 초기 key sharing, 합계 키 복원은 유지하고, MGF의 실수 마스크
스케일을 보존하면서 업데이트의 양자화 간격과 wire 정수 표현을 바꾸는 제안이다.
저자가 확인한 구현이나 논문 Algorithm 7/8 그대로의 재현이라고 부르지 않는다.
정확성 조건과 프라이버시 보장은 별개다.

## 목적과 선택 이유

현재 fixed decimal wire의 주기가 model quantum의 정수배이면 서로 다른
carry가 같은 격자에 놓여 합계 복원이 모호해질 수 있다. 단순 centered lift의
`2 * SUM_bound < period` 조건은 MGF의 작은 마스크 범위와 잘 맞지 않는다.

앞서 검토한 scale perturbation은 이를 피하지만 alpha를 변경한다. 이번 후보는
alpha를 유지하고 model quantum을 요청 정밀도보다 같거나 더 세밀하게 정한다.
데이터셋, 모델 차원, update의 실제 크기를 보고 carry를 추측하지 않는다.
다만 저장 가능한 정수 크기와 아래의 오차 조건은 검증해야 한다.

## 표기와 전제

- `N`: 해당 라운드에 허용할 최대 기여 수. 실제 선택 수는 `2 <= n <= N`.
- `p`: 원본 HPRF 출력 모듈러스. VSS 필드나 HPRF 내부 q와 다르다.
- `h_i`, `h_*`: 개별 HPRF 출력과 합계 키의 HPRF 출력.
- `sum(h_i) = h_* + c*p + e`, `|e| <= n-1`인 좌표별 정수 관계를 전제로 한다.
- `c`의 보수적인 범위는 `[-1,n]`이다. 원본의 p endpoint도 포함한다.
- `P = alpha*p > 0`: 논문의 스케일을 적용한 실수 마스크 주기.
- `delta_requested > 0`: 요청한 model quantum. 예: `10^-6`.
- 모든 클라이언트가 동일한 codec과 적법한 HPRF 마스크를 사용한다.

근사 준동형 관계의 모듈러 성격은
[BLMR Definition 3.2](https://crypto.stanford.edu/~klewi/papers/homprf-proc.pdf)에
명시돼 있다. 아래 인코딩과 조건부 정확성 논증은 이번 제안이며 해당 논문에서
가져온 프로토콜이 아니다.

## 파라미터와 인코딩

이 문서의 `A`, `B`, `g`, `K`는 수치 codec의 정수이며 HPRF의 공개 행렬이나
VSS generator를 뜻하지 않는다.

```text
K = N + 2
g = 4 * (N + 1)
A = K * g
a = max(64, ceil(P / delta_requested - 1/K))
B = g * (K*a + 1)
delta = A*P/B
u = P/B
```

그러면 `B mod A = g`, `delta <= delta_requested`, `A*u = delta`다.
`a >= 64`는 아주 작은 P에서 마스크 범위가 model quantum보다 작아지는
퇴화 사례를 피하려고 사용한 연구용 선택이다. 64는 암호학적 보안 파라미터나
프라이버시 보장으로 검증된 값이 아니다.

각 좌표에 대해 클라이언트는 exact rational/integer round-to-nearest로:

```text
z_i = round(x_i / delta)
v_i = round(B*h_i / p)
t_i = A*z_i + v_i
```

정수 `t_i` 하나만 전송한다. MGF가 보는 값은 `u*t_i`이며:

```text
u*t_i = delta*z_i + alpha*h_i + epsilon_i
|epsilon_i| <= u/2
```

원본 x_i와 비교하면 추가로 model quantization error `<= delta/2`가 있다.
따라서 차원 d의 MGF 입력 벡터 오차는 L2에서 `<= sqrt(d)*(delta+u)/2`다.
이 오차 때문에 threshold 근처의 판정은 기존과 달라질 수 있다.

## 복원과 조건부 정확성

선택된 합산 wire와 ASR로 복원한 합계 키의 HPRF 출력으로:

```text
R = sum(t_i) - round(B*h_* / p)
  = A*Z + c*B + eta
Z = sum(z_i)
|eta| <= E_n = (B/p)*(n-1) + (n+1)/2
```

설정 단계에서 **`E_N < g/2`**인지 검사한다. 만족하지 않는 경우 정밀도를
조용히 낮추거나 다른 업데이트 합을 선택하지 않고 설정을 거부한다.

`A/g = K`, `B/g = K*a+1`이므로:

```text
round(R/g) mod K = c mod K
```

`[-1,n]`에는 최대 `N+2 = K`개의 원소가 있으므로 carry를 유일하게 해석한다.
residue `K-1`은 -1로, 나머지는 0..n으로 해석한다. 범위 밖은 거부한다.

```text
Z = round((R - c*B)/A)
selected_update_sum = delta*Z
```

이는 임의 크기의 **적법하게 양자화된 정수 Z**에 대한 조건부 복원이다.
실수 x_i 자체를 양자화 오차 없이 복원한다는 주장이 아니다. 또 부정직한
클라이언트가 임의 wire를 보냈을 때 HPRF 사용의 적법성을 입증하는 장치는 아니다.
decoder는 carry 범위, 잔여 오차, implied mask sum `0..n*B`도 확인해야 한다.

실제 wire mask SUM은 `sum(t_i)-A*Z`, 실수 표현은 그 값에 u를 곱하면 된다.
추가 mask share 없이 얻지만, MGF history에 이 값을 사용할지 논문의
`alpha*HPRF(M,r)` 대표값을 사용할지는 명시적 프로필로 구분해야 한다.

## 독립 수치 검사 결과

2026-10-02의 읽기 전용 Python 진단으로 확인했다. 원본 setup/matrix만 읽고,
실제 학습의 private Context나 키는 읽지 않았다. 키는 공개 결정적 fixture다.
기존 PaperDMC decoder는 호출하지 않고 위 식을 별도 Fraction 정수 연산으로
작성했다. 이 결과는 pytest suite나 Flower 학습 실행의 통과 개수가 아니다.

- 참여자 상한 2, 20, 100, 4096; 선택 수 2, 최대 7, 상한 전체.
- HPRF round 1, 4, 60; 각 8좌표.
- P: `10^-9`, `0.02`, `3.7`, `10^6`.
- 요청 quantum: `10^-3`, `10^-6`, `10^-9`.
- 입력 좌표는 공개 결정식으로 약 -1000..1000 범위에서 생성했다.
- 48개 파라미터 조합 중 45개 유효, 3개는 E_N 조건 위반으로 입력 전에 거부.
- 원본 HPRF 2,664좌표 복원 일치. 그중 carry가 0이 아닌 좌표 2,124개,
  작은 HPRF rounding error가 0이 아닌 좌표 888개.
- 별도 정수 검사 14,049건 통과: N=2..16의 모든 허용 carry와 정수 오차 범위,
  Z가 `-10^30`, -100, -1, 0, 1, 100, `10^30`인 경우.
- fixture wire의 최대 정수 크기는 72비트. int64에 무검사 캐스팅하면 안 된다.

P=0.02, 요청 quantum=10^-6일 때:

| N | A | B | delta | E_N (근사) | g/2 |
|---:|---:|---:|---|---:|---:|
| 20 | 1848 | 36960084 | 11/11000025 | 10.50000000005 | 42 |
| 100 | 41208 | 824160404 | 51/51000025 | 50.50000000553 | 202 |
| 4096 | 67158024 | 1343160496388 | 2049/2049000025 | 2048.50037263 | 8194 |

## 범용 구현에 필요한 계약

codec은 flatten된 tensor와 레이아웃, N, p, P, 요청 정밀도만 받도록 분리한다.
MNIST/FMNIST, classifier 크기 840, 특정 optimizer를 수치 codec에 넣지 않는다.
실제 MGF projection과 학습률, 공격 방어 효과는 별도 모델/실험 설정이다.

라운드별 codec 버전·N·A·B·P·레이아웃은 공통 manifest/서명·BFT 검증에 묶는다.
동적 참여는 선택된 n이 공통 N 이하일 때 같은 codec으로 처리한다. 같은
라운드에서 클라이언트별로 다른 양자화 간격이나 alpha를 쓰면 안 된다.
exact integer wire로 전송하고 MGF norm 계산과 최종 모델 적용 시의 단위를
명시해야 한다. P=0과 표현 가능한 정수 한계는 명시적으로 처리해야 한다.

가중 평균은 이 진단의 범위 밖이다. 정수 가중치가 있는 경우 weighted key/share와
가중치 총합에 따른 carry·오차 상한이 필요하다. 참여자 수만 N으로 쓰면 안 된다.

다음 확인은 per-client 정보 노출, 잘못된 mask/quantization 입력, dropout,
실제 Flower의 metadata/wire 검증, 서로 다른 학습 workload에서의 양자화·MGF
영향이다. 원본 scalar HPRF의 작은 키 도메인 등 기존 보안 문제도 그대로 남는다.
이 문서의 조건부 수치 논증은 HPRF 또는 전체 프로토콜의 보안 증명이 아니다.

## 재검토: 작은 wire 변조가 큰 복원 변경으로 증폭되는 반례

`B = A*a + g`이므로 악성 클라이언트 하나가 한 좌표에 g를 더하면:

```text
R' = R + g
c' = c + 1
Z' = Z - a
R' - c'*B - A*Z' = R - c*B - A*Z
```

즉, carry와 implied mask SUM의 범위에 여유가 있으면 잔여 오차 검사가
변조를 구분하지 못한다. MGF가 보는 실수 변화는 `u*g`, 복원된 합의 변화는
`-a*delta`여서 증폭 비율은 `a*K`다. 정직한 입력의 정확성 논증에 있던
"동일한 codec 및 적법한 HPRF 마스크" 전제는 이 악성 입력에 성립하지 않지만,
현재 제안에는 그 전제를 검증하는 절차가 없다.

원본 HPRF의 공개 키 1..20, round 4, 8좌표, 원래 업데이트 모두 0,
N=20, P=0.02, a=20000, 공통 masked-norm bound 0.1인 수치 fixture에서
한 송신자의 각 좌표에 `5*g`를 더했다.

- MGF가 보는 좌표당 변화: 약 `2.2727221e-7`.
- 복원 업데이트 SUM의 좌표당 변화: 약 `-0.09999977`.
- 증폭 비율: 440,000배.
- 변조 전 모든 벡터와 변조 후 해당 벡터가 같은 norm bound를 통과했다.
- decoder의 carry 범위, 잔여 오차, implied mask SUM 범위 검사도 통과했다.
- 합계 키와 초기 share를 변경할 필요가 없다.
- 복원된 변경 벡터의 L2 norm은 이 fixture의 MGF bound보다 크다.

이는 현재 수치 제안의 반례이며 실제 공격 학습이나 인증된 과거 BFT history를
실행한 결과가 아니다. 서명은 악성 송신자가 자신의 메시지를 서명하는 것을
막지 않으며, BFT의 동일 계산 재실행도 mask 정합성 증명을 대신하지 않는다.

```bash
PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m experiments.audit_integer_carry_attack
```

## 후속 판단

범용성과 악성 입력까지 고려하면 이 인코딩은 추가 정합성 검증 없이 채택하면
안 된다. 정합성 증명은 새로운 프로토콜 작업이며 기존 원본 VSS commitment가
모델·마스크·wire의 관계까지 자동으로 증명하지 않는다.

다른 설계 후보는 초기 key shares로 위원회가 각 선택 클라이언트의 HPRF와
정확한 wire rounding을 비공개 공동 계산하고, **선택된 전체 mask SUM 또는
ASR 마스크에 대한 보정값만** 공개하는 것이다. 이때 작은 wire 변조는 그만큼의
작은 실제 집계 변화로 남고 carry 선택을 조작해 증폭시키는 단계가 필요 없다.
초기 share를 악성 보안 MPC의 입력에 올바르게 결합하는 과정, 선택 명단·round·
scale 인증, 중간값 비공개, aggregate-only 공개 정책이 필요하다.

클라이언트가 매 라운드 mask share를 새로 보내지 않는 형태를 목표로 할 수
있지만, 위원회 내부의 추가 통신·계산·중간 share 처리는 발생한다. 개별 키와
좌표별 마스크 계산을 포함하므로 ASR의 합계 키 한 번 평가보다 비싸다.
[MP-SPDZ 공식 문서](https://mp-spdz.readthedocs.io/en/latest/readme.html)는
악성 참여자를 고려한 Shamir/replicated MPC 구현을 제공하지만, 그 존재가
현재 VSS·Flower 전송과의 호환성이나 이 구체 프로토콜의 안전성을 보장하지는
않는다. 이 대안도 아직 구현하지 않았으며 원본 Aion-ASR의 단순 포팅을 넘는
확장이다. 원본 HPRF의 알려진 작은 키 도메인 문제도 별도로 남는다.
