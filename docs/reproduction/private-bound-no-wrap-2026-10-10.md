# 비공개 bound 검사와 no-wrap 확장: WSL 로컬 검증

**후속 변경: 새 no-wrap 학습 경로는 정적 `T=25*S²`로 전환했다. 아래 동적 경계 절은 초기 구현 기록이며 현재 학습 정책이 아니다. 공식 Flower 평문 학습 검증은 완료했으나 native MPC 학습 연결은 미완료다.** [현재 정적 정책과 검증](static-threshold-2026-10-10.md).

날짜: 2026-10-10. 브랜치: `work/aion-private-bound-no-wrap`.
기준 commit: `69844a2` (`work/aion-flower-port-snapshot-20261001`).

상태: **정수 산술·동적 boundary 및 별도 로컬 active MPC 경로 구현. Flower 새 경로는 미연결.**

**후속 보안 검토:** 아래 산술·native fixture 성공은 현재 출력 정책의 프라이버시나
동적 경계의 poisoning 방어 보장이 아닙니다. 선택 후 개인 업데이트 누출과
경계 상쇄 반례를 재현했으므로 [보안 재검토](private-bound-security-2026-10-10.md)의
출력 계약·재질의 방지·경계 교체 조건을 먼저 해결해야 합니다.

현재 대화에서 제안한 Committee MPC 설계를 구현할 새 분기다. 기존 문서의
MPC 제외 지시는 이전 동일 스케일·ASR 목표에 관한 기록으로 보존한다.
이 분기는 기존 원본 재현 설정의 실행 의미를 변경하지 않는다.

## 구현한 부분

`trustlessfl/private_bound.py`:

- epoch 고정 좌표 상한 B_cap과 라운드별 squared L2 boundary T를 분리한다.
- client raw integer encoding: `Y=d*u+m`, `v=Y+d*B_cap`.
- offset/residual/update/norm/sum/count의 application bit width를 산정한다.
- 마스크는 canonical HPRF h를 `floor((2*M*h+p)/(2*p))`로 정확히 scaling한다.
- plaintext specification에서 각 mask를 개별 제거하고 full quotient의
  격자·좌표 상한을 검사한 뒤 invalid coordinate를 0으로 sanitize한다.
- 전체 norm이 boundary를 넘거나 한 좌표라도 invalid면 client 전체를 제외한다.
- 최종 ordinary integer SUM에 `%M`, aggregate key 또는 aggregate HPRF를 쓰지 않는다.
- 허용 출력은 sum/count 또는 RoundEven된 mean뿐이며, 인원이 부족하면 abort다.
- 기본 `aggregate(..., mode="mpc")`는 PrivateBackendUnavailable로 차단한다.
  plaintext model은 `mode="plaintext-reference"`를 명시해야 한다.

여기의 Python 함수는 **분산 비밀 계산이 아니다**. 함수 인자에 개별 mask를
넘기는 것은 시험 fixture에서만 허용된다. coordinator에게 개별 키/mask나 raw Y를
전달하고 이 함수를 호출하는 방법을 보안 구현으로 사용하면 안 된다.

## 동적 boundary

공개 결과에서 얻은 정수 평균 g의 squared norm Q를 쓴다. 첫 두 성공 라운드는
T_boot로 시작하고 이후:

```
eta = clip((Q_new+epsilon2)/(Q_old+epsilon2), eta_min, eta_max)
T_next = clip(RoundEven(T_previous*eta), T_min, T_max)
0 < T_min <= T_boot <= T_max <= D*B_cap^2
```

공개 계산은 Python arbitrary-precision integer/Fraction이다. mask 보정 항은
넣지 않는다. abort는 성공 history에 들어가지 않는다. 동적 T를 줄여도 회로의
안전 폭은 B_cap 기준으로 유지한다. Committee의 이전 결과 인증서 검증과
입력 전 policy 합의/영속화는 실제 backend 연결에서 구현해야 한다.
현재 PublicRound 타입이 인증서 검증을 대신하지 않는다.

이 갱신 정책은 Aion evolving bound 발상의 확장이며 원래 masked norm 식의
동일한 판정이나 poisoning 방어 성능을 보장하지 않는다. 정상 방향 상쇄 및
악성 평균 조작이 Q를 바꿀 수 있다. 초기값/floor/최댓값은 실제 학습으로 보정한다.

## Large M

mask norm은 검사 점수에 들어가지 않는다. SUM 용량은 n_max*B_cap으로 결정되므로
M보다 큰 SUM도 정확히 복원한다. 작은 M=1도 산술적으로 허용한다. 이는 raw Y까지
인증된 비밀 입력으로 받는 새 프로토콜을 전제로 하며, 공개 Y를 작은 mask로
숨길 수 있다는 뜻이 아니다. HPRF의 p/q를 작게 바꿔도 된다는 결론도 아니다.
큰 M의 encoding/scaling 비용은 기존 값을 유지하면 남는다.

기존 OriginalAionHPRF는 h=p endpoint를 반환할 수 있다. 새 profile은 명시적으로
h%p를 canonicalize한다. 기존 profile wire와 호환되지 않으며 섞어 실행하지 않는다.
column scalar 원본 HPRF의 cryptographic privacy 한계도 이 산술 변경으로 해결되지 않는다.

## WSL 검증

```
cd /home/hacho/@WSL-Projects/trustlessFL
.venv/bin/python -m pytest -q tests/test_private_bound.py
.venv/bin/python -m experiments.audit_private_bound --output docs/reproduction/private-bound-arithmetic-results.json
```

테스트는 old modular SUM alias, norm alias, 음수, M=1/큰 M, unused wire code,
off-grid 및 큰 quotient 검사, mean rounding, dynamic threshold, backend 차단을 다룬다.
감사는 실제 저장소의 OriginalAionHPRF adapter와 공개 통제 행렬로 여러 profile의
정확한 정수 합을 대조한다. 실제 학습 데이터, 원본 artifact 행렬 전체 실행,
MPC 통신 및 암호 보안 시험으로 확대 해석하지 않는다.

## 이번 실행 결과

- 새 산술 테스트: **51 passed**; private-input/field-boundary 테스트 포함 **61 passed**.
- 새 테스트 및 source profile/modular recovery/MGF selection 회귀:
  **180 passed, 23 skipped**. 원본 저자 setup/matrix가 필요한 테스트는
  저장소 상위 Aion artifact가 없어 skip되었다. Flower 새 비공개 경로를
  실행한 결과가 아니다.
- 공개 통제 행렬의 원본 HPRF adapter 감사: **64,000 좌표 합 일치**.
  M=1/15/840000021/2^128, d=1/21의 8개 profile을 검사했다.
- `git diff --check` 통과.
- WSL 가상환경에 누락된 기존 선택 의존성 gmpy2 2.3.2,
  pycryptodomex 3.24.0, dill 0.4.1을 설치했다. pyproject/uv.lock은 변경하지 않았다.

전체 회귀 명령:

```
.venv/bin/python -m pytest -q tests/test_private_bound.py tests/test_mpc_private_input.py tests/test_source_profiles.py tests/test_modular_recovery.py tests/test_mgf_selection.py
```

## 로컬 active MPC 구현

`mpc/Programs/Source/aion_private_bound.mpc`, `trustlessfl/mpc_external_client.py`,
`experiments/run_private_bound_mpc.py`는 별도 실제 MPC 실행 경로다.
Python reference 함수의 기본 차단은 유지한다. 로컬 하네스는 테스트 입력을
알지만, native aggregator 프로세스에는 개별 key/offset의 clear input 파일을
주지 않는다. 각 client가 공식 ExternalIO 프로토콜과 TLS로 비밀 입력한다.

고정 backend는 공식 MP-SPDZ 0.4.3 Linux 배포본의 MASCOT이다. 실제 active
preprocessing을 사용하며 fake preprocessing 또는 plaintext fallback은 없다.
공개 입력 범위와 통계 보안 여유 40+2 bits를 계산하여 P=2^127-1 또는
2^255-19를 선택한다. HPRF p/q와 이 backend field는 다른 파라미터다.
key와 offset을 bitstring으로 비밀 입력하고, 모든 입력 수신 후 독립
random field challenge로 Booleanity를 검사한다. 위반 시 1/P의 soundness
error를 제외하고 전체 입력 batch를 abort한다. 전체 field bit로 공개
zero를 확인하며 짧은 application width의 clear equality를 사용하지 않는다.

등록 key는 각 실행에서 새로 비밀 입력된다. 기존 VSS share import는 아직
없다. 원본 HPRF의 secret 계산, endpoint canonicalization, exact mask scaling,
full quotient 검사, sanitize, norm, secret selection, integer SUM을 회로 안에서
수행한다. output은 status/count/SUM이며 인원이 부족하면 status 외에는 0이다.
개별 통과 여부는 공개하지 않는다. 순수 공개 boundary의 동적 갱신은 Python
모델에 구현되어 있고, native fixture는 단일 round의 고정 T를 검사한다.

각 actor에는 자신의 TLS private key만 저장하고 서로의 public certificate를
배포한다. 로컬 같은 Unix 사용자로 실행하는 시험이므로 hostile OS/host 격리
검증은 아니다. 인증된 pending output을 수신한 뒤 모든 native party가
MAC 검사 후 exit 0으로 끝났는지 확인해야 결과를 성공으로 기록한다.
이는 분산 BFT 최종 인증서/영속 ledger를 대신하지 않는다.

재현 명령(WSL, 저장소 루트):

```
.venv/bin/python -m experiments.prepare_private_bound_mpc
.venv/bin/python -m experiments.run_private_bound_mpc --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 --case wrap
.venv/bin/python -m experiments.run_private_bound_mpc --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 --case nonboolean
```

설치 스크립트는 공식 release archive의 SHA-256을 고정값과 검증한다.
아카이브 약 141 MB, 추출된 배포본은 훨씬 크다. fixture private 입력/key는
ignored `.cache` 아래에 두며 tracked 결과에는 허용된 aggregate만 기록한다.
Hub 게시/계정/publisher 설정을 변경하지 않는다.

실제 fixture **8건이 모두 통과**했다. 결과는
[`private-bound-mpc-results.json`](private-bound-mpc-results.json)에 기록한다.

| 사례 | M | 확인된 결과 |
|---|---:|---|
| wrap | 15 | count=4, SUM=[6,6] |
| negative-wrap | 15 | count=4, SUM=[-6,-6] |
| norm 초과 | 15 | count=3, SUM=[1,1] |
| off-grid | 15 | 잘못된 client 전체 제외, count=2, SUM=[0,0] |
| coordinate-large | 15 | 잘못된 client 전체 제외, count=2, SUM=[0,0] |
| nonboolean | 15 | 전체 input-abort, pending output 없음 |
| small-M wrap | 1 | count=4, SUM=[6,6], SUM>M |
| insufficient | 1 | 통과 인원 1명, 합/count 공개 없이 abort |

잘못된 client 입력을 주입한 시험과 악성 committee party deviation 시험은
구분한다. 이번 실행에는 악성 party fault를 주입하지 않았다. 통과한 정상
완료 fixture는 약 38~57초, 전체 native 송신량 약 24,189~35,806 MB였다.
비트 위조 fixture는 예상된 runtime abort로 native benchmark footer가 없어
통신량을 null로 기록한다. 해당 시험에서 프로세스 동시 종료를 일반 실패로
잘못 분류하던 하네스 문제를 수정한 뒤 재실행했다.

최초 성공
wrap 사례는 4 party/4 client/2 coordinate, d=5, M=15에서 [6,6] 복원이다.
이 경우 d*SUM=30은 기존 mod 15 복원에서 0과 alias되지만 native MPC는
ordinary integer SUM을 반환했다. 전처리를 포함해 약 53초, 총 송신량
약 35,109 MB였다. 이는 실제 FL 크기에 바로 사용할 성능이 아니다.
현재 bytecode의 exact secret HPRF/정수 나눗셈 회로 비용을 먼저 줄여야 한다.

초기 255-bit field pilot는 180초 deadline을 초과하여 중단했다. application
width에 40+2-bit 여유를 유지하면서 127-bit field를 선택한 재실행이
성공했다. 실패한 pilot를 성공 결과에 포함하지 않는다.

MASCOT은 악성 참여자의 privacy/correctness 또는 abort를 지원하는 backend이며,
N=4/f=1의 guaranteed availability나 BFT 진행성을 이 시험이 증명하지 않는다.
악성 party 프로세스의 임의 deviation 시험도 별도다. 입력 오류 시험은 악성
client 입력에 관한 것이다. 원본 HPRF의 실제 p/q 전체 native 실행 및 저자
artifact matrix는 이번 toy fixture 성공과 구분한다.

최종 선택 합/count 자체에서 유추되는 정보는 허용 출력 누출이다. 선택된
honest client가 한 명뿐이면 공모자의 알려진 기여를 빼서 그 업데이트를
유추할 수 있다. minimum_accepted=2는 honest 2명을 보장하지 않으며, 이
확장을 원본 Aion의 모든 프라이버시 정리와 동일하다고 주장하지 않는다.

## 전체 구현에 남은 것

1. 실제 배치 크기에 맞춘 회로 최적화, backend와 N>=3f+1/BFT/abort 모델 매핑.
2. 로컬 TLS authenticated input을 Flower client의 실제 다중 호스트 수명주기에 연결.
3. 기존 VSS key의 비공개 authenticated import 또는 직접 update sharing 새 backend.
4. 현재 secret HPRF 회로를 원본 p/q 및 artifact matrix 전체에서 실행/평가.
5. 현재 secret norm/selection/SUM 회로의 대규모 성능과 malicious-party deviation 검증.
6. 공개 roster BFT와 비밀 selection을 분리하고 aggregate key release를 제거한다.
   비밀 통과 비트를 기존 공개 selected roster로 돌려보내면 설계 목표에 어긋난다.
7. frozen-input-root/model/policy/circuit/epoch/round 바인딩, 동일 입력 재질의 방지,
   MAC 검증 후 output 인증, dropout/abort/재시작 경로.
8. Flower multi-party 실행과 실제 학습의 정확도/탐지 성능/시간/통신 비용 측정.

기존 Flower 기본 실행에는 아직 이 backend를 연결하지 않았다. 위 미완성 단계를
실행 완료로 주장하지 않으며 Hub 배포는 로컬 프로토콜 검증 이후로 보류한다.
