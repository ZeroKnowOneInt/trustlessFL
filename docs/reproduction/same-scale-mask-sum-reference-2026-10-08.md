# 동일 스케일 보정에 필요한 정보의 수치 검증 — 2026-10-08

최신 사용자 지시는 **MPC 미도입**이다. 이 문서의 MPC 비용/계산 항목은 과거
후보의 한계를 기록한 것이며 구현 계획이나 승인 대기 항목이 아니다.

## 범위와 결론

원본 HPRF, 기존 decimal wire, 기존 MGF를 그대로 두고 **실제 전송 정밀도로
반올림한 개별 마스크들의 합**을 알면 정수 업데이트 합을 정확히 복원할 수 있다.
합계 키만으로 결정되지 않았던 기존 collision도 이 값으로 구분된다.

그러나 아래 코드는 공개 fixture 키를 사용하는 **수치 기준 구현**이다.
비공개 마스크 합 계산, MPC, Flower 연결을 구현한 것이 아니다. 서버에 개별
키를 읽게 하거나 이 oracle을 런타임에 연결하는 것은 해법으로 채택하지 않는다.
이 oracle은 MPC 미도입 지시 이후에도 실험 전용이며 런타임 해결책으로 사용하지 않는다.

## 정확히 빼야 하는 값

기존 `source_paper_numeric.mask_integer_wire`는 다음 값을 보낸다.

```
S = 10^decimals
D = codec.denominator
extra = D/S                       # 현재 정수
b_i[j] = round_even(coefficient * H(k_i,r)[j])
Y_i[j] = extra*z_i[j] + b_i[j]    # MGF 검사와 집계에 같은 벡터
```

필요한 보정값은 `B[j] = sum_i b_i[j]`다. `H(sum_i k_i,r)`를 스케일링한
값이나 `round_even(coefficient*sum_i H(k_i,r))`로 대체하지 않는다.
각 sender의 반올림도 합에 포함해야 한다.

```
Q[j] = sum_i Y_i[j] - B[j]
Q[j] % extra == 0                 # 아니면 off-grid 거부
Z[j] = Q[j] // extra              # 정확한 sum_i z_i[j]
```

이는 모듈러 대표값을 선택하지 않는다. carry를 추측하지 않으며 HPRF의 작은
동형 오차도 남지 않는다. **같은 키의 개별 실제 마스크를 모두 평가했다는
전제**가 핵심이다. 기존 합계 키 기반 ASR의 저비용 평가와는 다르다.

MGF는 기존 `sum_j Y_i[j]^2 <= (D*bound)^2`를 그대로 사용한다.
검사한 좌표 집합에서 유효 업데이트는 `x_i=(Y_i-b_i)/D`이므로 삼각부등식으로
`||x_i|| <= bound + ||b_i/D||`다. 보정이 선형이어서 wire 차이를 큰 업데이트로
증폭시키지 않는다. 이것은 원래 작은 마스크가 허용하는 여유를 없애는 강한
평문 norm 증명이 아니며, projection 밖 좌표나 모든 poisoning 공격을 막는
보장도 아니다. 사용자가 요구한 MGF의 목적을 유지하는 보정 대상이다.

## 실행과 수치

실행 환경은 저장소 내 기존 dependency cache를 사용했다.

```
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 -m experiments.audit_same_scale_mask_sum_reference --full-dimension 61706

env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 -m pytest -q tests/test_same_scale_mask_sum_reference.py tests/test_same_scale_jitter.py \
  tests/test_same_scale_feasibility.py tests/test_scaled_ring.py tests/test_scaled_sum_collision.py
```

관련 검사 **78 passed**. 신규 검사는 공개 oracle의 한계도 확인한다.

- `S=1,000,000`, beta=0.2, 이전 공개 크기 0.001, period=0.0002.
- 최대 후보 2/20/100명, 실제 선택 2/10/50명, round 1/4/9, 각 288좌표.
- 별도로 20명 전원, round 4, **61,706좌표**.
- 양수/음수 및 양자화 경계에 걸린 입력에서 정수 합 불일치 **0**.
- full-dimension fixture는 MGF bound=1에서 20/20 통과. 이 bound는 공개 수치
  입력 조건이지 실제 학습 이력에서 유도됐다는 주장이 아니다.
- 그 fixture의 58,465좌표는 실제 합이 centered period 범위 밖인데도 정확히 복원.
- 개인 및 평균 양자화 오차 최댓값 `1/2,000,000 = 5e-7`.
- 기존 aggregate collision의 세 번째 좌표 `60000`과 `80000`을 각각 올바르게 복원.
- 기존 jitter의 약 441,176배 증폭 wire는 정수 격자 위반으로 거부.
- 격자에 맞춘 wire 변화는 같은 크기의 정수 변화로 복원; 증폭 없음.

새 Flower 실행, FMNIST 학습 정확도 검증, weighted FedAvg 검증은 이 검사에
포함되지 않는다. 이전 Flower 성공/실패 기록을 이 oracle의 실행 증거로 사용하지 않는다.

## 중요한 누출 조건: 추가 메시지가 없어도 결과에서 추론 가능

`Y_sum`과 **정확한** `Z`를 같은 관찰자가 알면 다음 항등식이 성립한다.

```
B = Y_sum - extra*Z
```

따라서 보정값을 MPC 내부에만 보관해도, 정확한 결과를 공개하면 해당 관찰자는
그 값을 다시 계산할 수 있다. 이는 별도의 carry 메시지 전송 여부와 다른 문제다.

합계 키에서 계산한 `h_A=H(K_A,r)`도 알 때,

```
c = round_even((B/D)/period - h_A/p)
```

로 carry를 추론할 수 있다. 충분조건은
`(n+1)/(2p) + n/(2D*period) < 1/2`다. 실제 평가한 10개 fixture 모두 이 조건을
만족했고, 추론한 carry와 실제 `round_even((sum h_i-h_A)/p)`가 모든 좌표에서
같았다. full-dimension의 61,706좌표 모두 nonzero carry였다.

즉 **MPC 계산의 transcript 비공개성만으로 이 결과 기반 누출이 제거되지 않는다.**
원본 scalar 키의 작은 범위에서는 특히 주의해야 한다. 이 실험은 실제 공격자가
모든 키를 복원했다는 실험이 아니지만 추가 키 제약이 드러난다는 점은 항등식과
수치로 확인했다. 최종 모델/평균을 어떤 정밀도로 공개하는지에 따라 추론 가능한
정보도 검토해야 한다. 모든 공개 Flower transcript가 위의 정확한 Z를 직접
포함한다는 주장은 하지 않는다.

## 제외된 위원회 비공개 계산 후보의 비용과 한계

추가 클라이언트 share 대신 초기 키 share를 입력으로 사용하려던 **확장 후보**다.
프로토콜의 정확성·비공개성·성능을 검증하지 않았으며 사용자 지시에 따라 제외했다.

실제 원본 setup은 `p=14760426300877770769`, `q=5p`이고 p는 홀수다.
`t=(k*((r+block)*column_sum mod q)) mod q`로 공개 곱을 미리 계산하면
HPRF 반올림은 정확히 `h=(t+2)//5`로 단순화된다. endpoint를 포함한 동치 검사를
추가했다. 비밀값에 대한 mod q, 정수 나눗셈, decimal-wire 반올림은 여전히 필요하다.

직접 평가 방식의 대상 좌표 수는 20명에서 1,234,120개, 100명에서 6,170,600개다.
현재 aggregate HPRF는 61,706개다. 이것은 직접 평가의 산술 대상 수이지 MPC의
실행시간, 통신량, 제약 수 또는 최적 알고리즘 하한을 측정한 결과가 아니다.

VSS 입력은 2047-bit ORDER 위의 share다. ORDER는 q의 배수가 아니므로 각 share를
개별적으로 `%q`한 뒤 보간하는 변환은 원래 비밀값의 mod q를 보존하지 않는다.
기존 share와 commitment를 안전하게 받아들여 비공개 계산 입력에 연결해야 한다.
악성 위원회가 다른 입력 share를 주입하는 경우의 검사도 필요하다.

MPC 후보를 실제로 도입하려면 적어도 다음을 확정해야 한다.

1. 초기 VSS share/commitment와 MPC 입력의 결속, 부패 임계값 및 입력 검증.
2. BFT①의 선택 집합, round, scale, model context를 입력에 결속.
3. 개별 키/마스크를 복원하지 않는 계산 및 위원회 중간 메시지의 비공개성.
4. Flower 전달 방식과 실패 처리; 별도 네트워크를 자동으로 추가하지 않음.
5. 공개 출력 자체가 드러내는 mask/carry 정보의 허용 정책과 키 공격 검증.
6. 실제 차원과 선택 인원에서 비용 측정 후 BFT② 모델 경로 연결.

[MP-SPDZ 공식 문서](https://mp-spdz.readthedocs.io/en/latest/non-linear.html)는
비밀 비교 등 비선형 연산이 단순 share 덧셈과 다른 연산임을 설명한다.
[지원 프로토콜 문서](https://mp-spdz.readthedocs.io/en/latest/readme.html)는 여러
부패 모델을 지원하며 네트워크 보안 설정도 요구한다. 이것만으로 기존 VSS나
Flower 통신과의 호환성 또는 본 프로젝트의 보안성이 입증되는 것은 아니다.

## 수정 범위

- 추가: `experiments/audit_same_scale_mask_sum_reference.py`.
- 추가: `tests/test_same_scale_mask_sum_reference.py`.
- 현재 목표 문서에 수치 결과/필요한 확장 승인/누출 경계를 연결.
- HPRF, VSS, ASR, MGF, Flower 런타임은 **변경 없음**.
