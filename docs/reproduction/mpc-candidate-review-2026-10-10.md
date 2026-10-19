# MPC 후보 재검토: Aion의 이점과 no-wrap 목표

2026-10-10. 브랜치 `work/aion-private-bound-no-wrap`.

**판정: MPC로 정수 복원·범위 검사를 하는 방향은 유효하다. 다만 현재 HPRF 유지형을 그대로 전체 Flower 학습에 연결하는 것은 권장하지 않는다. 직접 비밀 입력형으로 회로를 단순화하고, 선택 합계의 출력 계약·정상 입력 정책·실패 처리부터 확정해야 한다.**

검토 목표는 기존 Aion 구조 보존이 아니다. 여러 aggregator의 분산 검사, 개별 입력 프라이버시, 악성 입력의 정확한 검사, wrap 없는 집계 및 현실적인 비용을 평가한다. HPRF/VSS는 이 기능을 구현하는 선택지다.

이번에는 기존 native 소규모 결과를 읽고 새 직접 비밀 입력 함수에 대한 산술·출력 반례 검사 및 두 회로의 컴파일 자원 비교를 실행했다. 새 native runtime, 전체 모델 MPC 학습, poisoning 실험 또는 TLS 실험은 실행하지 않았다.

**검토 범위 확정:** norm 이내의 악성 업데이트 탐지는 사용자 요청에 따라 목표에서 제외한다. 경계를 준수한 입력은 통과시키며, 입력 공유의 일관성·프라이버시·정확한 범위/norm 판정·no-wrap 집계가 검증 대상이다. 아래 norm defense 한계는 기능의 경계 설명이며 채택 차단 사유가 아니다.

## 1. 유지되는 부분과 다시 설계할 부분

| 항목 | 재검토 결과 |
|---|---|
| no-wrap 복원 | 개별 정확 복원 후 bounded integer 집계는 유지할 가치가 있음 |
| norm 검사 | unmask된 업데이트 또는 직접 비밀 입력한 업데이트를 검사; mask domination 제거 |
| 정적 threshold | T=25*S² 유지. 평균 기반 동적 갱신은 재도입하지 않음 |
| 분산 검사 | 악성 보안 MPC backend와 허용 공모 가정을 명시하면 가능 |
| HPRF+키 입력 | 현재 전체 offset/key를 비밀 입력하므로 HPRF 계산의 필수성이 낮음 |
| 별도 VSS | 직접 입력형에서 마스크 키 VSS는 필수가 아님. 인증된 일관된 입력 공유 기능은 필수 |
| 최종 출력 프라이버시 | 현재 선택 SUM/count는 기존 unfiltered SUM 프라이버시와 다름 |
| 검사 범위 | norm 이내 악성 업데이트의 탐지는 목표 밖; 경계 준수 입력은 통과 |
| 비용·운영 | Aion의 one-time key sharing·저비용 집계·비동기 지원이 현재 MPC에 이전됐다는 증거 없음 |

Aion은 one-time key sharing, single mask, 집계 mask 복원 및 BFT/비동기 처리를 주요 이점으로 제시한다. 이것들은 완전한 MPC norm 회로를 사용하면 그대로 유지되지 않는다. [Aion 원문 §1.1–1.2](https://www.usenix.org/system/files/usenixsecurity25-liu-yizhong.pdf).

## 2. HPRF를 제거할 수 있는 이유

현재 mask 유지형의 MPC는 key와 전체 offset을 비밀 입력받고, 각 HPRF mask를 비밀 재계산한 뒤 제거한다. coordinator나 한 aggregator는 offset 원문도 보지 못한다. 그 안전한 입력 채널을 업데이트 u 자체에 사용하면 아래 함수가 동일하게 실행된다.

```text
u 비밀 입력 → 좌표 범위 검사 → squared norm <= T → 선택 SUM/count
```

따라서 이 후보에서는 HPRF·mask scaling·spacing division·mask key 입력·VSS→MPC key 변환을 제거할 수 있다. 마스킹을 없애는 대신 **업데이트가 평문으로 가는 것이 아니라 MPC용으로 비밀 공유된다.** 단일 aggregator에게 평문을 전달한 뒤 내부적으로 sharing하는 trusted-client 방식과 구별한다.

MP-SPDZ의 ExternalIO는 모든 계산 서버에 연결해 private input을 넣는 인터페이스를 제공한다. 이를 사용하는 것만으로 시스템 전체의 등록·인증·모델 바인딩이 완성되지는 않는다. [공식 I/O 문서](https://mp-spdz.readthedocs.io/en/latest/io.html).

별도 마스크 키 VSS는 필요 없어지지만, 악성 client가 서로 다른 share/input을 보내는 문제는 MPC의 인증된 입력 프로토콜로 처리해야 한다. 기존 key 재사용의 장점 대신 전체 업데이트를 라운드마다 공유하는 비용이 발생한다. identity·라운드·정책 바인딩도 새 방식으로 명시해야 한다.

## 3. 직접 비밀 입력형의 no-wrap 규칙

정수 업데이트 u를 unsigned offset v=u+B의 W=bit_length(2B) 비트로 입력한다. 모든 입력을 확정한 뒤 기존과 같은 randomized Boolean bit 검사를 수행한다.

각 좌표에서 v<=2B를 비밀 비교하고, 실패 좌표는 0으로 sanitize한다. 정상 좌표는 z=v-B다. client validity는 모든 좌표 검사 결과의 곱이다. 이후 Q=sum(z_j²)를 계산하고 `e=valid*[Q<=T]`로 선택한다.

- 입력 대표값: `0<=v<=2B`.
- 제곱 전에: `|z_j|<=B`.
- squared norm: `0<=Q<=D*B²`.
- SUM: `|U_j|<=n_max*B`.

masked transmission modulus M, HPRF p/q 및 집계 rounding residual은 없다. backend 유한체 P는 여전히 존재하므로 안전 폭이 필수다. 너무 작은 P에서는 `u=(10,1)`, Q=101이 P=101에서 0으로 alias되어 threshold 검사를 우회할 수 있다. 직접 입력 자체가 overflow를 자동 제거하지 않는다.

현재 full FMNIST 설정 D=61706, B=20000, n_max=4에서:

```text
Q_max = 24682400000000
norm unsigned bits = 45
direct input coordinate bits = 16
application L (여유 포함) = 47
fixture P = 2^127-1  # L + 40 + 2 <= bit_length(P)
```

이는 정수 범위 계산이며 전체 모델의 compile/runtime 측정이 아니다. Boolean check 및 backend의 비교 soundness를 전제로 하는 조건부 보장이다.

## 4. 직접 입력형 산술 검증

새 [audit_mpc_candidate.py](../../experiments/audit_mpc_candidate.py)로 다음을 실행했다.

- **708개**의 작은 B·D에 대한 모든 bit-width wire 대표값 검사. 사용하지 않는 offset code의 거부와 제곱 전 sanitize를 포함한다.
- **800개**의 mask 유지형/직접 입력형 비교. M=1/15/840000021/2^128, d=1/21에서 판정·SUM/count가 같았다.
- non-Boolean input-abort, 작은 field의 norm alias, 선택된 honest 한 명의 누출, all-pass guard의 abort 누출을 검증했다.
- 정상 두 명이 항상 범위·norm 조건을 만족한다는 가정에서 **3025개**의 조건부 함수 사례를 비교했다. 출력이 정상 둘의 합과 통과한 악성 입력 기여로만 정해짐을 확인했다. clipping 구현·전체 프라이버시 증명은 아니다.
- 기존 관련 회귀 **89 passed**. 기존 보안 반례 테스트 통과는 반례 재현을 뜻한다.

[기계 판독 결과](mpc-candidate-review-results-2026-10-10-v2.json).

## 5. 회로 자원과 전체 모델 비용

공식 pinned MP-SPDZ 0.4.3 compiler로 같은 공개 조건의 두 회로를 새로 compile했다. 클라이언트 4명, 좌표 2개, B=2, T=8, P=2^127-1, application L=14, seed=42다. masked 후보는 p=101/q=505/M=15/d=5를 추가로 사용한다.

| 컴파일러 요구 상한 | mask 유지형 | 직접 입력형 |
|---|---:|---:|
| integer triples | 100273 | 3313 |
| integer simple multiplications | 100189 | 3289 |
| integer bits | 43815 | 1651 |
| integer opens | 351 | 19 |
| virtual machine rounds | 3947 | 40 |
| private input field elements | 84 | 24 |

triple 상한은 약 30.3분의 1이다. 이는 toy 조건의 **컴파일 자원** 차이다. 실제 실행 시간·통신량·전체 모델 속도가 그 비율로 줄었다고 주장하지 않는다. `integer opens`는 마스크된 프로토콜 내부 open도 포함하며 개별 업데이트의 공개 횟수가 아니다. VM rounds도 네트워크 왕복 시간과 같지 않다.

[masked 회로·로그](mpc-candidate-review-2026-10-10/masked/compile.log), [직접 입력 회로·로그](mpc-candidate-review-2026-10-10/direct/compile.log), [직접 입력 검토용 소스](mpc-candidate-review-2026-10-10/direct/review.mpc).

기존 mask 유지형 native D=2·4-client wrap fixture의 시간은 52.724초, `Global data sent`는 35108.8 MB였다. 이는 기존 stock MASCOT·특정 회로·전처리·로컬 실행의 실제 기록이다. 전체 모델 값을 단순 비례 계산하거나 모든 MPC의 성능으로 일반화하지 않는다. [기존 native 결과](private-bound-mpc-results.json).

직접 입력형도 현 bit-per-field encoding에서는 client당 D*16=**987296개의 private field input**을 요구한다. 네 client의 3949184개 input bit에 Boolean 검사를 하면 현 식은 각 bit에 두 secret multiplication을 사용한다. norm과 선택 SUM을 하기 전부터 큰 비용이 생긴다. 이는 회로 수준 비용 설명이며 최적 compiler/runtime 자원 측정값은 아니다. 배치, range encoding, mixed circuit, active honest-majority backend 등을 검토해야 한다.

MASCOT는 malicious dishonest-majority backend다. Aion처럼 aggregator honest majority를 가정해도 된다면 그 가정에 맞는 active honest-majority backend가 다른 비용을 가질 수 있다. semi-honest backend로 바꾸고 악성 보안을 유지했다고 주장해서는 안 된다. [공식 backend/security 분류](https://mp-spdz.readthedocs.io/en/latest/readme.html).

## 5.1 공모 범위: backend와 시스템 계약 구분

현재 MASCOT의 원 논문은 실행 시작 전 결정된 static malicious adversary가 n-1 MPC party를 부패시킬 수 있는 모델이다. n명 중 한 명이 honest이고 프로토콜·인증된 채널·보안 가정이 성립하면, 허용 출력 외 추가 정보를 숨기는 MPC 내부 보장을 목표로 한다. 악성 party가 실행을 abort하는 것은 막지 못한다. [MASCOT 원문 Security model](https://eprint.iacr.org/2016/505.pdf).

따라서 MPC party가 4명이면 backend의 이론적 privacy/correctness-with-abort 범위는 최대 3명 공모다. 현재 fixture에 적힌 committee_fault_budget=1은 Aion형 시스템 배치 가정이며 MASCOT 자체의 최대 공모 상한이 아니다. 기존 native fixture는 악성 MPC party를 주입하지 않았으므로, 우리의 전체 구현이 3명 공모를 검증 완료했다는 뜻은 아니다.

BFT에 부분 동기 n>=3f+1을 채택하면 4명 배치의 합의 fault budget은 1명이다. MPC의 내부 비밀 계산이 3명 공모에 안전할 수 있어도 이 BFT 계약의 3명 악성 진행성/합의가 보장되는 것은 아니다. 전체 시스템의 보장은 구성요소의 계약과 가정을 모두 만족해야 한다.

클라이언트 공모는 별개다. 공개 SUM에서 공모자 자기 기여를 뺀 뒤 무엇이 남는지 평가한다. 가장 단순한 개인 고립을 피하려면 성공 SUM에 최소 두 honest 기여자가 있어야 한다. 공모 상한 t_C와 통과 인원 a만 사용하는 worst-case guard는 a>=t_C+2이며, 이것은 전체 프라이버시 충분조건이 아니다. 현재 a_min=2만으로 client 공모에 대한 이 조건을 보장하지 않는다.

## 6. 핵심 보안 문제는 선택 SUM의 의미

이 문제는 HPRF 제거 여부와 관계없다. 완벽한 MPC도 공개 함수의 출력에서 나오는 정보는 숨기지 않는다.

q=4, T=25, 공격자 둘의 입력이 0,0이고 정상 둘이 3,6이면 선택 SUM은 3, count는 3이다. 통과한 정상 한 명의 값이 노출된다. 정상 입력을 1,8로 바꿔도 unfiltered honest SUM은 9지만 선택 SUM은 1이다. 같은 원래 SUM을 가진 두 세계를 구별한다.

Aion은 q명 중 q-2 클라이언트 공모를 명시한다. [원문 §3.2](https://www.usenix.org/system/files/usenixsecurity25-liu-yizhong.pdf). **현재 정상 업데이트도 임의로 탈락할 수 있는 정확한 선택 집계 정책에 그 보장을 그대로 붙일 수 없다.** 이것은 MPC backend의 내부 비밀 공유가 깨졌다는 반례가 아니라, 목표한 출력 프라이버시와 새 함수의 불일치다.

`a>=t_C+2`는 최대 공모 클라이언트 수 t_C를 안다고 가정할 때 성공 집계에 최소 두 honest를 남기기 위한 최악의 경우 count 조건이다. t_C=q-2면 a=q가 필요하다. 이 계산은 정상 input의 통과를 따로 보장하지 않는 현재 함수에 관한 것이다. 전체 프라이버시 충분조건은 아니다.

all-pass에서만 출력해도 같은 원래 SUM에 대해 abort/ok가 달라질 수 있다. count를 숨기거나 mean만 출력해도 원래 SUM만의 공개 계약이 자동 복구되지 않는다. 동일 frozen input의 명단 차분도 one-shot 계약 없이 남는다.

## 7. 출력 정책을 수정하는 두 가지 방향

### 방향 A: 정상 탈락을 허용하는 filtered-sum 기능

개별 norm 초과를 탈락시키는 현재 동작을 유지한다. 공개 정보는 선택 SUM/count/status임을 명시하고, client 공모 상한 t_C를 별도로 정한다. 성공 시 최소 honest 기여자 수를 위한 guard, 고정 roster/입력 확정, one-shot 실행을 구현한다.

Aion의 q-2 공모 보장을 유지하면서 정상 탈락 이후에도 계속 출력한다고 주장하지 않는다. 등록 identity/Sybil 가정도 필요하다. 낮은 t_C를 임의로 기본값으로 정하는 것은 보안 목표 변경이므로 현재 실행 설정을 변경하지 않았다.

### 방향 B: 정상 client 입력을 항상 통과하도록 정의

정상 client가 정해진 clipping/정수 정규화로 **이미 B/T 안의 입력**을 만들고, MPC는 그 경계를 강제한다. 완전한 고정 cohort에서 honest 둘이 입력을 완료한다는 가정이면 둘 다 통과하므로, 악성 입력을 제외해도 위의 정상 한 명 고립 반례는 성립하지 않는다.

중요한 차이는 **공개 목표가 원래 raw update의 합이 아니라 제출된 bounded/clipped update의 합**이라는 점이다. 같은 raw SUM의 세계가 다른 clipped SUM을 낼 수 있으므로, raw SUM만의 프라이버시와 동등하다고 주장하지 않는다. clipping에 따른 학습 영향과 양자화 후 norm의 정확한 범위도 검증해야 한다.

이 방향은 단순히 T를 크게 설정하는 것과 다르다. 정상 입력 생성 규칙이 범위·norm 준수를 보장하고, 공통 model/context와 완전한 roster를 강제해야 한다. honest dropout 뒤 임의로 roster를 줄이면 다시 조건을 확인해야 한다. count/abort·보조 transcript·반복 라운드까지 포함한 formal functionality와 증명도 필요하다.

현재 로컬 학습 코드는 clipping하지 않고 cap 초과를 거부한다. 이 방향의 실제 clipping 정책·학습 연결은 **아직 구현하지 않았다.** 기존 정적 threshold를 이번 검토에서 바꾸지 않았다.

## 8. 한 라운드의 권장 계산 골격

직접 입력형을 다음 비교·개발 후보로 권장한다. 아래는 계산 골격이며 완료된 production protocol이 아니다.

1. Committee가 `session, round, actual_model_hash, roster, policy, circuit, backend-P, output-policy`를 확정·인증한다.
2. 모든 정상 client가 같은 모델에서 학습한다. 방향 A/B에 맞는 입력 규칙으로 정수 u를 만든다.
3. client별 distinct identity에 연결된 일관된 private input을 수신한다. coordinator에 평문 u를 전달하지 않는다.
4. 모든 입력 확정 후 Boolean/range 검사, 안전 sanitize, 정확한 norm 검사, 선택 integer SUM/count를 실행한다.
5. 정해진 output-policy의 guard를 평가한다. 개별 값·norm·selection을 open하지 않는다.
6. MAC 검사와 Committee 출력 인증 완료 후 허용 SUM/count 또는 abort만 공개한다. 서버는 SUM/(S*count)를 적용한다.
7. 성공·abort·입력 소비 상태를 영속 기록한다. 같은 frozen input을 새 session/cohort/정책으로 재질의하지 않는다.

단순 task UUID, client가 주장하는 model hash, `N>=3f+1` 설정만으로 위 계약이 충족되지 않는다. 악성 보안 MPC의 correctness/privacy-with-abort와 BFT의 결과 합의·진행성·dropout 처리는 구별한다.

## 9. 채택 판단

- **유지:** 고정 T, 고정 B 기반 안전 폭, 제곱 전 sanitize, 정확한 정수 norm/SUM, 개별 값 미공개.
- **다음 후보:** HPRF 없는 직접 비밀 입력형. HPRF가 필요한 별도 기능이 없다면 key/HPRF MPC 계산을 추가하는 이점이 작다.
- **우선 확정:** 정상 입력의 clipping 여부, 허용 client 공모 범위, 정확한 출력 의미 및 one-shot/dropout 계약.
- **후속 검증:** 실제 직접 입력 native 실행, 입력/검사/집계의 단계별 통신·전처리·wall time, 중간 D에서의 확장 측정, active backend 비교, 악성 입력/share·출력 불일치 검사 및 non-IID 학습.

이번 검토만으로 direct 후보를 Flower production backend로 전환하지 않는다. 현재 default app, native fixture, T, Hub 설정 및 root pyproject/uv.lock은 유지했다. 비교용 함수·compile script·증거와 문서만 추가했다.

## 10. 재현

```bash
cd /home/hacho/@WSL-Projects/trustlessFL
# 이미 존재하는 output 대신 새 경로 사용. 컴파일만 하며 native 실행하지 않음.
.venv/bin/python -m experiments.audit_mpc_candidate \
  --output .cache/mpc-candidate-review/review-new.json
.venv/bin/python -m pytest -q tests/test_static_bound.py tests/test_private_bound.py \
  tests/test_mpc_private_input.py tests/test_fmnist_no_wrap_math.py tests/test_private_bound_security.py
```

[기존 프로토콜 명세](../aion-no-wrap-mpc-protocol.md), [정적 threshold 학습 검증](static-threshold-2026-10-10.md), [기존 함수 보안 반례](private-bound-security-2026-10-10.md).
