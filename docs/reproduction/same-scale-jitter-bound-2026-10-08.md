# 동일 스케일 미세 조정 후보와 MGF bound 반례

상태: **채택 제외 — 정상 복원과 fixture MGF 판정 보존에도 wire 변조가 증폭됨**.
원본 HPRF를 쓰는 공개 수치 감사이며 Flower 런타임에 적용하지 않았다.

사용자는 수식 변경을 허용하되 MGF의 원래 목적인 bound 검증을 유지하도록
요청했다. 이에 마스크를 크게 늘리지 않고 양자화 격자의 모호성을 없애는
작은 downward scale 변경을 시험했다. 개인 실험 키/Context는 읽지 않았다.

## 후보 수식과 정상 입력의 정확성

원래 period를 P=a_r*p, 양자화 scale을 S, 최대 참여자를 N이라 한다.
K=N+2를 잡고, `P*S*K`보다 크지 않은 정수 j 중 `gcd(j,K)=1`인 값을 고른다.

```
P' = j/(S*K),     a'_r=P'/p
y_i = round_D(z_i/S + a'_r*h_i)
```

모델 precision S는 그대로이고 MGF와 집계 모두 동일한 a'_r를 쓴다.
전송 rounding denominator D는 total error가 `1/(2*S*K)`보다 작도록 정한다.
실제 sum residue에 대한 carry 후보는 `[-1,n]`이며 폭 N+1<K이다.
`P'*S=j/K`의 분모가 K라서 서로 다른 carry가 서로 다른 model-grid phase에
놓인다. 정직한 mask와 quantum에 대해서는 phase 간격보다 오차가 작으면
합계가 유일하게 복원된다.

이번 공개 원본 HPRF fixture: N=20, 8좌표, round=4, keys=1..20,
L=0.1, beta=0.2, model decimals=6, MGF bound=0.1.

- 원래 P=0.02.
- 후보 P'=439999/22000000 ≈ 0.01999995454545.
- 변경량 1/22000000 ≈ 4.54545e-8, 상대 변경 약 2.27e-6.
- model S=10^6 유지, wire D는 10^8에서 10^9로 늘림.
- phase 간격=1/22000000, aggregate error 상한 약 1e-8로 반간격보다 작음.
- 양/음수를 포함한 3개 모델 fixture에서 24좌표 정확 복원.
- 관측한 MGF 통과 명단 변화 0, 좌표별 MGF 입력의 최대 변화 4.7e-8.

판정 변화 0은 검사한 fixture에 관한 결과이지 모든 threshold 경계에서의
판정 동일성 증명이 아니다. P'가 줄어 mask noise 상한 자체는 커지지 않았다.

## 단일 송신자 변조

정상 클라이언트 update는 모두 0이고 초기 키/공유/합계 키는 그대로 둔다.
한 sender가 자신의 8좌표 wire를 각각 `-136/10^9`만큼 바꾼다.
그 송신자는 자신의 변조된 VECTOR에도 서명할 수 있으므로 서명/BFT만으로
이 메시지의 HPRF 관계를 입증할 수는 없다. 이 시험은 실제 서명/BFT 실행이
아니며 모든 숫자가 공개된 산술 반례다.

| 항목 | 결과 |
|---|---:|
| 좌표당 visible wire 변화 | -1.36e-7 |
| 원래/변조 후 MGF 통과 수 | 20 / 20 |
| 복원된 SUM 좌표 변화 | -0.06 |
| 증폭 비율 | 약 441,176배 |
| 복원 변화 벡터의 L2 제곱 | 0.0288 |
| 초기 키/합계 키 변경 | 없음 |
| 추가 mask share | 0 |

원래 true wire-mask SUM을 public fixture에서 그대로 빼면 변화는
`-1.36e-7`뿐이며, 6자리 모델 quantum으로 반올림하면 0이다. candidate decoder는
이를 다른 carry phase로 해석해 -0.06을 반환한다. 실제 구현에 개별 키나
true mask SUM을 전달하는 fallback을 추가한 것은 아니다.

## 왜 MGF bound 기능 위반인가

한 sender만 변하고 다른 sender의 실제 update가 0인 이 fixture에서, mask가
등록된 키와 일치하고 ||y||_2<=b이면 triangle inequality에 의해 그 sender의
실제 update norm은 `b+sqrt(d)*P'+sqrt(d)/(2D)` 이하다.

sqrt(8)<3을 써서 더 느슨한 합리적 상한
`b+3*P'+3/(2D) ≈ 0.159999865`를 적용해도, candidate의 decoded 변화 norm은
`sqrt(0.0288) ≈ 0.169705627`로 이를 넘는다. 따라서 작은 scale 변경으로
mask-size budget을 지켰다는 사실이 decoder까지 bound 의미를 유지하는
근거가 되지 않는다. 이 decoder는 sender의 실제 mask를 확인하지 않고
grid phase를 믿어 carry를 선택했기 때문이다.

## 검증과 다음 단계

신규 도구 `experiments/audit_same_scale_jitter.py`, 신규 회귀
`tests/test_same_scale_jitter.py`. 10/20/100명 fixture에서 정상 복원과 변조
반례를 함께 검증한다. phase 분리, 부족한 precision/period 처리도 검사한다.
기존 same-scale feasibility/scaled-ring/collision과 묶어 **59 passed**.

이 결과는 모든 수식 변경의 불가능성 증명이 아니다. 다음 후보에는 bound를
정확히 검증한 송신 벡터가 복원 때 어떻게 해석되는지를 입증할 조건이 필요하다.
격자 위상을 조정해 carry를 선택하는 수치 방법은 정상 입력의 liveness만으로
채택하지 않는다. 기존 quantized-lift 경로를 이 후보로 교체하지 않았다.

```bash
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. python3 experiments/audit_same_scale_jitter.py
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. python3 -m pytest -q tests/test_same_scale_jitter.py tests/test_same_scale_feasibility.py tests/test_scaled_ring.py tests/test_scaled_sum_collision.py
```
