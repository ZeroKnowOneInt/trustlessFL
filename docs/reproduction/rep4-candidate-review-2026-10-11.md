# Rep4와 비트 기반 마스크 제거·범위 검사 검토

작성일: 2026-10-11. WSL의 `work/aion-private-bound-no-wrap` 브랜치에서 MP-SPDZ 0.4.3으로 실행했다.

후속 단계의 [chunk 처리·runtime 입력·컴파일 재사용 검토](rep4-chunked-review-2026-10-11.md)에서 64좌표 compile 병목을 개선하고 1024좌표까지 실행했다. 아래 수치는 그 이전 후보 비교의 기록이다.

**Rep4와 비트 회로를 실제 구현해 검증했으며, 현재 4 aggregator·최대 1개 악성이라는 계약에 맞는 유망한 후보다.** 동일한 작은 입력에서 Rep4 비트 회로의 내부 통신은 0.350628 MB였고, Rep4 산술 회로보다 19.32% 적었다. 이전 MASCOT 구현의 11.74 GB가 MPC 방식 자체의 불가능성을 뜻하지는 않는다. 다만 전체 FMNIST 모델 실행과 제품 프로토콜의 보안 합성 검증은 아직 완료하지 않았다.

## 1. 구현한 구조와 신뢰 모델

클라이언트는 AES-128 키를 등록할 때 한 번 비밀 입력한다. 네 aggregator는 키의 replicated shares를 보유하며, 같은 세션의 세 라운드에서 재사용한다. 매 라운드 단일 AES-CTR 마스크를 MPC 내부에서 생성하고, 비공개 업데이트 복원·좌표 검사·정적 norm 검사·선택 집계를 수행한다. 클라이언트가 별도 ZKP를 작성하지 않는다.

Rep4는 네 계산 참여자 중 최대 한 명의 static 악성을 대상으로 한다. 악성 참여자가 실행을 중단시킬 수 있는 보안으로 사용했다. `--semi-honest`나 가짜 전처리를 사용하지 않았다. MASCOT 계산 엔진 자체의 dishonest-majority 허용 범위보다 좁지만, 우리가 정한 전체 시스템의 N=4, f=1 계약에는 맞는다. 두 aggregator 공모나 여러 시점의 shares를 모으는 공격까지 보장하지 않는다. [Fantastic Four 원논문](https://www.usenix.org/conference/usenixsecurity21/presentation/dalskov), [MP-SPDZ 공식 문서](https://mp-spdz.readthedocs.io/en/stable/readme.html).

공개 결과는 성공 여부, 최종 선택 SUM과 통과 인원이다. 개별 키·마스크·업데이트·norm·통과 비트는 열지 않는다. 통과 인원 부족 시 공개 배열은 실패 표시와 0으로 채워 실제 SUM/count를 숨긴다. 시험 도구는 네 native process가 정상 종료하고 출력이 일치한 뒤 성공으로 기록한다. 이것은 제품의 BFT 결과 인증서를 구현했다는 뜻이 아니다.

최종 SUM/count에서 가능한 역추론은 그대로 남는다. 공모 클라이언트 기여를 제외했을 때 honest 입력 하나만 남으면 그 값이 드러난다. 최소 통과 인원 2는 honest 입력 2개를 보장하지 않는다. Aion의 원래 클라이언트 공모 프라이버시와 동일하다고 주장하지 않는다.

## 2. 실제 통신 비교

비교 입력은 클라이언트 4명, 좌표 2개, 등록 1회, 라운드 3회다. `Q=65536`, `B=20000`, squared norm threshold는 400000000인 산술 검증용 fixture다. 이는 FMNIST 정책의 threshold 2500000000과 구분한다. 모든 집계 회로의 SUM/count/실패 결과는 동일했다.

| 계산 엔진 | 좌표 복원·검사 | 내부 전체 통신 | 실행 시간 관측값 |
|---|---|---:|---:|
| MASCOT | 산술 | 11743.5 MB | 31.173초 |
| MASCOT | 비트 | 4097.54 MB | 14.276초 |
| Rep4 | 산술 | 0.434604 MB | 1.566초 |
| Rep4 | 비트 | **0.350628 MB** | 1.557초 |

MB는 10진 단위이며, native 프로그램의 전송 카운터를 합산했다. TLS/TCP/IP와 실제 네트워크 인터페이스 트래픽, 클라이언트 등록 통신, 매 라운드 masked upload는 포함하지 않는다. 시간은 한 장비에서 한 번 관측했으며 접속 재시도 시간을 포함하므로 정밀 속도 비교에 사용하지 않는다.

Rep4 산술/비트 비교는 동일한 등록 방식과 키 표현, 출력 정책을 사용했다. 따라서 **19.32% 절감은 좌표 회로 변경의 효과로 비교할 수 있다.** MASCOT과 Rep4 사이에는 계산 엔진뿐 아니라 소수 필드/정수 링, 키 입력 표현과 외부 등록 adapter가 다르다. 수만 배 차이를 비트 회로 하나의 효과로 해석하면 안 된다. Rep4는 honest-majority 구조를 활용하며 이전 MASCOT의 큰 전처리 부담을 피했다.

Rep4 비트 회로의 측정값은 online 0.330132 MB와 전처리 0.020496 MB다. compiler의 triple/daBit 요구량은 실행 엔진별 의미가 다르므로 서로 그대로 곱해 통신량을 예측하지 않는다. 원시 로그와 해시는 [비교 JSON](rep4-candidate-comparison-2026-10-11.json)에 보존했다. 이전 측정은 [MASCOT 통신 분석](seed-mpc-communication-2026-10-11.md)에 남겨 두었다.

## 3. 비트 기반 마스크 제거와 wrap 방지

마스크/전송 공간은 `Q=2^w`, 내부 정수 계산은 Rep4의 `Z_(2^K)`이며 현재 `K=64`다. 둘을 같은 폭으로 쓰지 않는다.

클라이언트는 `y=(u+m) mod Q`를 보낸다. MPC는 비밀 AES 출력에서 w-bit 마스크를 얻고 다음을 계산한다.

\[
r=(y-m)\bmod 2^w,\qquad x=r-2^w\operatorname{MSB}(r).
\]

w-bit 뺄셈은 carry/borrow를 정확히 모듈러 연산으로 처리한다. 복원된 x는 `[-Q/2,Q/2-1]`의 정수다. 정상 제출 정수가 `|u|<=B<Q/2`이면 x=u이고, 그 구간에서 표현이 유일하다. **carry 자체가 발생하지 않는다는 뜻이 아니라 carry 때문에 복원 결과가 달라지지 않는다는 뜻이다.**

각 좌표의 비밀 비트는 `b_ij=[-B<=x_ij<=B]`다. 범위를 벗어난 좌표는 비트 단계에서 0으로 만든다. 이 과정은 큰 악성 residue를 제곱하기 전에 수행한다. unsigned 비트 벡터를 산술 shares로 변환한 다음 `Q*sign`을 명시적으로 빼므로 음수의 부호 해석을 변환 함수에 맡기지 않는다.

\[
\tilde x_{ij}=b_{ij}x_{ij},\quad v_i=\bigwedge_j b_{ij},\quad
t_i=\sum_j\tilde x_{ij}^{\,2},\quad
e_i=v_i\land[t_i\le\tau].
\]

좌표 하나라도 invalid면 전체 클라이언트가 제외된다. norm은 모든 좌표의 제곱합으로 검사하고, 최종 `U_j=sum_i e_i*tilde x_ij`와 `a=sum_i e_i`를 넓은 내부 링에서 계산한다. SUM을 Q로 다시 줄이지 않는다. 실제로 Q=65536인데도 SUM=80000 및 -80000을 정확히 출력했다.

악성 클라이언트가 어떤 원래 정수에 Q를 더한 뒤 동일 residue를 제출했는지는 알아낼 수 없다. 프로토콜 입력은 canonical 복원 정수 x로 정의한다. 실제 SGD를 수행했거나 원래 실수 업데이트가 바운더리 안이었다는 증명은 제공하지 않는다. 이는 우리가 정한 제출 입력 검증 범위와 일치한다.

### 내부 계산 링도 충분히 커야 한다

외부 wire wrap을 처리해도 norm/SUM 자체의 내부 wrap은 별도 방지해야 한다. 정책 validator는 좌표 상한, norm 최대값, threshold, SUM 최대값 및 비교 폭을 검사한다. 64/128-bit 링만 허용하고 부족한 폭은 실행 전에 거부한다.

FMNIST의 D=61706, B=20000, n=4에서는 다음과 같다.

\[
DB^2=24682400000000<2^{45}<2^{63},\qquad nB=80000<2^{63}.
\]

현재 정책의 norm 비교 폭은 47bit이며 64bit 내부 링의 폭보다 작다. 제곱합은 invalid 좌표를 제거한 뒤 계산하므로 위 상한이 악성 제출에도 적용된다. 이 회로는 근사적인 확률적 truncation을 사용하지 않는다. 이러한 **응용 산술의 폭 증명**은 모든 backend primitive와 외부 입력 등록의 보안 증명을 대신하지 않는다. 전송 modulus를 최종 전체 합보다 크게 잡는 Large M 요구는 없어지지만, 내부 계산 공간을 충분히 크게 잡는 요구는 남는다.

## 4. 링 전환에서 발견하고 수정한 등록 문제

소수 필드용 검사를 그대로 `Z_(2^64)`로 옮기면 안전하지 않다. 두 가지를 찾아 수정했다.

1. 무작위 가중 Boolean 검사 `rho*b*(b-1)=0`를 링에서 쓰면 b=2^63 같은 입력이 짝수 rho에서 통과한다. 필드에서 기대하던 작은 실패 확률을 그대로 주장할 수 없다. 기본 키 입력을 두 개의 완전한 64bit word로 바꿨다. 두 word는 전체 128bit 키를 보존하며 모든 word 값이 유효해서 Boolean 증명이 필요 없다. 선택적인 128개 비트 입력 경로에서는 전체 64bit를 분해해 상위 비트가 모두 0인지 검사한다.
2. 외부 등록에서 복원한 random triple이 `c=a*b`라는 검사만으로 일관된 Rep4 shares를 인증하지 않는다. a에 2^63을 더한 변조는 b가 짝수일 때 검사에 걸리지 않을 수 있다. Rep4의 전체 replicated components를 클라이언트에 전달하고, 각 component를 가진 세 서버의 사본이 모두 일치하는지 확인하도록 바꿨다. 최대 한 서버 악성이라면 적어도 두 사본은 honest다. 불일치 시 중단한다. 복원된 triple의 곱 관계도 검사한다.

등록 응답도 모든 aggregator가 받은 blinded word를 MPC 내부에 입력한 후 **전체 64bit 일치**를 확인한다. 한 서버에만 다른 값을 보내면 중단한다. 기본 경로는 입력당 두 word이며 마스크는 등록용 random triple에서 얻는다. 실제 키나 사용자 업데이트를 열지 않는다. AES known-answer 프로그램은 공개 synthetic 키만 쓰는 시험 전용 프로그램이다.

이 adapter는 pinned Rep4의 share 배치·pack 형식과 인증된 네 서버 identity를 전제로 한다. 소수 필드용 ExternalIO 출력 검사를 링에 그대로 적용하지 않고 최종 공개 결과는 native MPC 경로로 출력한다. **위 수정과 시험만으로 악성 외부 클라이언트와 악성 aggregator의 모든 공동 공격에 대한 합성 보안 증명이 끝났다고 말할 수는 없다.**

등록 통신은 클라이언트당 입력 전송 80byte, triple 수신 592byte, 합계 **672byte**다. 접속/설정 메시지 84byte는 별도이며 TLS/TCP 비용은 제외했다. 이전 128개 필드 비트 입력은 32800byte였다. 키는 한 세션에서 재사용하므로 이 등록 비용은 매 라운드 반복되지 않는다. 새 random triple을 포함한 MPC 실행 통신은 별도다.

## 5. 검증 결과와 확인 범위

| 검증 | 결과 |
|---|---|
| 비밀 키 AES의 전체 128bit ciphertext | 독립 Python AES 결과와 일치 |
| 등록 1회, 3라운드 재사용 | SUM/count/실패 결과가 정수 oracle와 일치 |
| 16bit signed 최솟값·최댓값, ±B, ±(B+1) | 범위 검사 결과 일치 |
| norm 정확한 threshold와 1 초과, zero | 선택 결과 일치 |
| Q를 넘는 +80000/-80000 합계 | 정확히 복원 |
| 32bit wire 경계 | 6라운드 결과 일치 |
| 64좌표, 4클라이언트, 3라운드 | native 결과 일치; 내부 통신 3.45064 MB |
| 비트 입력 2 및 2^63 | 두 경우 모두 등록 중단, 최종 출력 없음 |
| 한 aggregator에 다른 등록 응답 | 중단, 최종 출력 없음 |
| replicated triple component 하나 변조 | 중단, 최종 출력 없음 |
| 16bit residue 전체 × 3종 좌표 상한 | 독립 signed 해석과 196608개 결과 일치 |
| Python 정책·wire·등록 adapter 및 기존 관련 회귀 | 116개 통과 |

component 변조는 시험 클라이언트의 수신 지점에서 서버 한 개의 frame을 변조한 모의 공격이다. native 악성 aggregator 구현을 직접 주입한 시험과 구분한다. 네 party 모두 변조한 종합 공격 시험을 했다는 뜻도 아니다.

산술/비트 최종 비교와 악성 등록 시험은 등록 SIMD 최적화를 포함한 v3를 사용했다. [기능 검증 기록](rep4-candidate-2026-10-11/summary.json)의 첫 네 실행은 동일 좌표 회로와 강화된 adapter를 가진 v2이며, 최적화는 등록 변환의 벡터화만 바꿨다. v3 AES와 정상 세션은 별도로 다시 통과했다. [악성 등록 기록](rep4-candidate-security-2026-10-11/summary.json)은 네 경우 모두 완료했다. 초기 미강화 실험 JSON은 과거 비교 자료이며 권장 구현이 아니다.

## 6. 전체 모델 이전에 남은 일

- 현재 public Y는 compile 시 고정한 fixture다. 실제 Flower 라운드 업로드와 인증된 context/input 확정은 연결하지 않았다.
- 등록 identity/handle, 재실행 방지 ledger, 결과 인증서와 BFT 연결이 필요하다. native 종료 전 출력 문자열을 제품이 확정 결과로 적용하면 안 된다.
- 새 외부 입력 adapter의 악성 클라이언트·aggregator 공동 공격에 대한 합성 검토가 필요하다. 실제 native party 변조와 독립 장비 시험도 아직 수행하지 않았다.
- 키 shares는 한 프로세스 세션의 메모리에서 재사용했다. 안전한 저장, 재시작, committee 교체와 refresh는 별도다. 동일 키에서 round/block counter를 재사용하면 안 된다.
- 64좌표 회로의 compile 시간은 84.487초였다. 현재 Python 전개 방식은 전체 61706좌표에 적합하다고 검증되지 않았다. 회로 벡터화·chunk 처리가 먼저 필요하다. chunk별 검사를 전체 norm 검사로 대체하거나 판정 전 중간 합을 공개해서는 안 된다.
- 전체 모델의 통신·메모리·WAN 지연·학습 정확도는 아직 측정하지 않았다. 2좌표 수치를 61706좌표까지 단순 비례 확장해 실용성을 확정하지 않는다. 기존 평문 Flower FMNIST 결과를 Rep4 실행 결과로 표시하지 않는다.

**다음 구현 후보는 Rep4 + 비트 좌표 검사로 정한다.** 먼저 등록 합성 검토와 vectorized/chunk 회로를 진행하고, 실제 signed input/context 확정 및 인증 결과 경로를 연결한 뒤 전체 FMNIST로 확대한다. Flower Hub 게시 설정은 하지 않았다.

## 7. 코드와 재현

- 회로: [seed_mpc_candidate_session.mpc](../../mpc/Programs/Source/seed_mpc_candidate_session.mpc), [비트·등록 helpers](../../mpc/Programs/Source/seed_mpc_candidate_primitives.py).
- 입력 adapter: [rep4_external.py](../../trustlessfl/rep4_external.py), [외부 등록 클라이언트](../../trustlessfl/seed_mpc_external_client.py).
- 폭 검증: [seed_mpc_policy.py](../../trustlessfl/seed_mpc_policy.py).
- 시험: [test_rep4_candidate.py](../../tests/test_rep4_candidate.py), [native 검증 runner](../../experiments/review_rep4_candidate.py).
- [최종 Rep4 비트 결과](seed-mpc-rep4-binary-2026-10-11-v3.json), [최종 Rep4 산술 결과](seed-mpc-rep4-arithmetic-2026-10-11-v3.json), [통신 비교와 로그 해시](rep4-candidate-comparison-2026-10-11.json).

WSL 저장소 루트에서 실행한다. 결과 경로는 새 이름을 지정한다.

```sh
.venv/bin/python -m experiments.run_seed_mpc_probe --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 --backend rep4 --coordinate-circuit binary --case multi-round --communication-stats
.venv/bin/python -m experiments.run_seed_mpc_probe --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 --backend rep4 --coordinate-circuit arithmetic --case multi-round --communication-stats
.venv/bin/python -m experiments.review_rep4_candidate --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 --output-directory docs/reproduction/rep4-new-review --suite all
```

MP-SPDZ 설치·native runner는 시험용 키와 인증서, bytecode를 ignored `.cache`에 둔다. 공개 보고서는 결과·로그·source hash를 보존하며 사용자 키를 포함하지 않는다.
