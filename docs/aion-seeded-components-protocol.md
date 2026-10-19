# Seed 기반 마스크 component의 로컬 확장과 비공개 바운더리 검사

작성일: 2026-10-11. WSL `trustlessFL`, `work/aion-private-bound-no-wrap`.

현재 Flower staging의 기본 `mask_mode`는 `rep4-seeded-components-v1`이다.
선택형 `holder-checked-direct-v1` native 입력은 [직접 share 연결 문서](aion-direct-rep4-import-protocol.md)를 따른다.
이 문서의 component 재입력 설명은 기본 `stock-private-v1` 경로에 해당한다.
이 문서는 [기존 통합 프로토콜](aion-seed-mpc-current-protocol.md)의 **마스크 생성·등록 경로를 대체**한다.
기존 snapshot, client dropout, 정적 threshold, Rep4 악성 보안, 영속 lock, CHECK 이후 결과 인증과 모델 갱신 계약은 그대로 적용한다.
기존 방식은 `--mask-mode secret-aes-v1`로 재현한다. 과거 측정 결과와 공개 재현 파일은 변경하지 않는다.

## 1. 구현 범위와 신뢰 모델

고정 aggregator 네 명 중 최대 한 명이 악성인 Rep4의 가정을 유지한다.
클라이언트는 프로토콜 형식과 등록 절차를 준수하면서 임의의 업데이트 입력을 선택할 수 있다.
SGD 수행, 학습 품질, 클라이언트의 마스크 생성 의도는 증명하지 않는다.
MPC에서 복원한 canonical 정수 벡터에 좌표·global norm 제한을 적용한다.
클라이언트의 프로토콜 중단 공격을 허용하지 않는 모델이며, 최소 통과 인원 미달이나 aggregator 중단에도 항상 진행한다는 보장은 없다.

**이번 구현은 검증되지 않은 share를 native 레지스터에 직접 주입하는 방식이 아니다.**
각 holder가 로컬에서 확장한 component를 MP-SPDZ 0.4.3의 기존 악성 보안 binary input으로 넣고,
동일 component를 가진 세 holder의 값이 일치하는지 MPC에서 검사한다.
따라서 비밀 AES 회로는 제거되지만, aggregator 간 component 입력·일치 검사 통신은 남는다.
검사 없이 native share를 직접 읽는 최적화는 구현하지 않았다. 전체 FL 구성에 대한 형식적 프라이버시 증명도 별도 과제다.

## 2. 최초 등록

클라이언트 \(i\)는 서로 독립이고 균등한 128-bit seed 네 개를 생성한다.

\[
s_{i,0},s_{i,1},s_{i,2},s_{i,3}\leftarrow\{0,1\}^{128}.
\]

Aggregator \(P_p\)는 \(s_{i,p}\)를 제외한 세 seed만 전달받는다.
실제 local 순서는 Rep4와 같이 \((p+1,p+2,p+3)\bmod4\)다.
클라이언트가 적용하는 최종 마스크는 하나이며, client 간 pairwise mask를 도입하지 않는다.

로컬 bootstrap에서 클라이언트 subprocess가 수신자별 seed 세 개를 384-bit 정수로 묶고,
기존 Identity의 X25519 + HKDF + AES-GCM으로 암호화한 뒤 Ed25519로 서명한다.
Associated data는 protocol, 등록 본문 digest, sender, recipient, component 순서를 포함한다.
등록 digest에는 session, epoch, client, key handle, policy, execution hash가 포함된다.
로컬 PRG 구현 두 파일의 SHA-256을 native config와 execution hash에 포함하고, client/aggregator에서 실행 파일과 대조한다.
서버·bootstrap이 운반하는 파일은 ciphertext다. 각 aggregator는 자신의 packet만 복호화하며
서명·수신자·등록 binding·세 seed 길이를 검사한다. 한 수신자의 복호화 결과에 네 seed를 담지 않는다.

Aggregator는 실제로 복호화한 세 seed를 각각 두 64-bit word로 분할해 자기 native private-input FIFO에 전달한다.
MPC는 component별 세 holder의 등록 사본을 비밀 입력하고 full-width 64-bit 차이를 검사해 일치 여부만 연다.
기존 native TLS client 채널은 등록 digest binding에 사용하며 seed를 중복 전달하지 않는다. CHECK도 유지한다. seed 또는 전체 mask는 공개하지 않는다.
등록 데이터는 D와 무관하다. seed 본문은 client당 64 bytes, recipient당 48 bytes이며
ciphertext·signature·context framing과 native 등록 tag 채널의 비용은 별도로 계측한다.

## 3. 각 라운드의 로컬 마스크 확장

등록 본문을 \(R_i\), component 번호를 \(j\)라 할 때 domain을 분리한 키를 도출한다.

\[
k_{i,j}=\operatorname{HKDF}_{128}(s_{i,j};
\mathrm{salt}=\operatorname{SHA256}(\operatorname{Canonical}(R_i)),
\mathrm{info}=\texttt{component-v1}\Vert j).
\]

실제 info 상수는 `trustlessfl/seeded-mask-component/v1/`와 component 번호 byte다.
\(r\)는 양의 64-bit round counter, \(b\)는 64-bit block index다.

\[
z_{i,j,r,b}=\operatorname{AES}_{k_{i,j}}(\operatorname{BE64}(r)\Vert\operatorname{BE64}(b)).
\]

AES 출력은 big-endian \(W\)-bit word로 분할한다. component word를 \(r_{i,j,r,t}\)라 하면,

\[
m_{i,r,t}=r_{i,0,r,t}\oplus r_{i,1,r,t}\oplus r_{i,2,r,t}\oplus r_{i,3,r,t}.
\]

클라이언트는 네 component를 로컬 계산해 **하나의 additive masked 벡터**를 전송한다.

\[
y_{i,r,t}=(x_{i,r,t}+m_{i,r,t})\bmod Q,\qquad Q=2^W.
\]

Aggregator는 자신이 알고 있는 세 component만 로컬 계산한다. 전체 mask는 평문으로 생성하지 않는다.
세션·클라이언트·등록 handle·policy·실행 artifact는 HKDF namespace에, round/block은 AES counter에 연결된다.
model hash는 서명된 wire 및 입력 인증서에 연결하며 PRG counter에 별도로 넣지 않는다.
같은 등록/round를 다른 모델에 재사용하지 않는 기존 durable client lock과 인증 체인이 계속 필요하다.

## 4. 악성 holder를 고려한 component 입력

각 component는 해당 seed를 가진 세 holder가 각각 비밀 binary input으로 제출한다.
좌표 \(t\)에 대해 세 값 \([v^{(0)}],[v^{(1)}],[v^{(2)}]\)의 차이를 XOR로 계산하고,
전체 component·좌표 bit에 OR를 적용한다.

\[
\mathrm{bad}=\bigvee_{j,t,\ell}\left(
(v^{(0)}_{j,t,\ell}\oplus v^{(1)}_{j,t,\ell})
\lor(v^{(0)}_{j,t,\ell}\oplus v^{(2)}_{j,t,\ell})\right).
\]

`bad=0`이면 한 사본씩 선택해 component들을 XOR한다. 하나라도 다르면 집계 공개 전 native abort한다.
공개하는 것은 일치 여부뿐이다. 각 component나 개인 업데이트를 공개 비교하지 않는다.
최대 한 holder가 악성이므로, 세 사본이 일치하면 나머지 두 honest holder의 로컬 값과 일치한다.
등록 seed와 클라이언트가 의도한 마스크를 별도로 ZKP로 증명하지 않는다.
전체 프로토콜을 따르는 honest adapter는 고정된 등록 packet에서 로컬 확장하며,
malicious holder가 바꾼 component 입력은 다른 honest holder의 사본과 비교해 검출한다.

로컬 입력은 aggregator 자신의 mode 0600 FIFO로 native에 전달한다.
이는 같은 aggregator 내부 IPC이며 client가 D차원 mask를 업로드하는 통신이 아니다.
native binary input으로 component를 재공유하는 aggregator 간 비용은 송신 counter에 포함된다.

## 4.1 공개 입력의 인증된 비교

`checked-open-v1`은 이미 공개로 지정된 wire, snapshot header, presence,
등록 digest tag에만 적용한다. Aggregator별 사본을 기존 Rep4 private input으로 넣고,
네 사본을 열어 **CHECK를 완료한 후** 전체 64-bit word를 공개 비교한다.

\[
(v^{(0)},v^{(1)},v^{(2)},v^{(3)})\leftarrow
\operatorname{OpenCheck}([v^{(0)}],[v^{(1)}],[v^{(2)}],[v^{(3)}]),
\qquad \bigwedge_{p=1}^3(v^{(p)}=v^{(0)}).
\]

하나라도 다르면 값 사용과 집계 공개 전에 중단한다. 최상위 bit도 비교 대상이다.
등록 TLS tag는 네 수신 사본의 일치뿐 아니라 확정된 등록 digest와도 비교한다.
Seed, component, unmasked update, norm, acceptance bit에는 이 공개 helper를 사용하지 않는다.
이미 공개인 자료를 비교하는 비밀 64-bit 변환/OR 회로를 제거하며,
입력/공개 일관성 검사, 기존 CHECK 및 결과 인증을 유지한다.
`--public-agreement secret-bit-compare-v1`은 이전 비용을 비교하는 실행용이다.

SIMD lane 수는 `--chunk-blocks`로 설정할 수 있다(1..64). 기본은 D>=512에서 64,
소형 모델에서 4다. 한 chunk는
`chunk_blocks * (128 / word_bits)`개 좌표다. Client의 서명된 제출 chunk 32좌표와
MPC의 처리 chunk 크기는 별개다. Aggregator는 확정된 전체 wire를 합쳐 처리 chunk에 맞게
패딩하며, private component FIFO에도 같은 크기와 순서를 적용한다.
검사는 전체 좌표 및 global norm에 적용하고, 마지막 chunk의 패딩은 0이어야 한다.

## 5. Carry·wrap 복원과 바운더리 검사

각 좌표를 binary 회로에서 정확히 \(W\)-bit subtraction해 다음을 복원한다.

\[
[q_{i,t}]=(y_{i,t}-[m_{i,t}])\bmod Q,
\qquad
[x_{i,t}]=\operatorname{Signed}_Q([q_{i,t}]).
\]

마스크가 커서 wire 생성 중 carry/borrow가 발생해도 위 식은 동일한 canonical signed 값으로 복원된다.
허용 좌표는 \(|x_{i,t}|\le B\), \(2B<Q\)이므로 accepted residue의 signed 해석이 유일하다.
원래 무제한 정수를 증명하는 계약이 아니라 이 canonical 입력을 검사하는 계약이다.

각 부적합 좌표는 norm 계산용으로 0으로 치환하되, whole-client invalid flag를 유지한다.

\[
e_i=p_i\cdot\bigwedge_t(|x_{i,t}|\le B)
\cdot\mathbf1\{\sum_t x_{i,t}^2\le T\}.
\]

Presence \(p_i\)는 snapshot에서 확정한다. absent slot의 wire/padding은 기존대로 0이어야 하며,
출력에는 들어가지 않는다. norm은 chunk마다 따로 통과시키지 않고 전체 좌표의 합으로 검사한다.

\[
a=\sum_i e_i,\qquad U_t=\sum_i e_i x_{i,t}.
\]

`a < minimum_accepted`이면 abort만 공개한다. 성공이면 기존 count와 SUM을 공개하고
\(\theta_{r+1}=\theta_r+U/(Sa)\)로 갱신한다.
SUM은 Q에서 계산하지 않고 기존 넓은 arithmetic ring에서 계산한다.
현재 D=61706, B=20000, N=4에서 최대 좌표 합 80000과 norm 누적 상한
24682400000000을 기존 폭·ring 용량 검사로 수용한다.

## 6. 프라이버시와 남은 비용

Honest client의 seed는 네 개가 독립이며 균등하다. 한 aggregator의 관측에는 항상 하나가 빠져 있다.
그 component가 PRG로 안전하면 전체 XOR mask도 해당 aggregator에게 pseudorandom하다.
동일한 MPC의 transcript 보안·허용된 출력 누출 가정을 추가로 적용한다.
두 aggregator의 seed 집합 합집합은 네 seed 모두이므로 **두 aggregator 공모는 허용하지 않는다**.
클라이언트마다 seed를 별도로 생성하므로 다른 client의 seed 공개가 honest client의 seed를 제공하지 않는다.

기존 결과 SUM/count/abort로 추론되는 정보는 여전히 허용된 누출이다.
DP, 전체 악성 protocol 조합 증명, 무조건적인 liveness는 추가하지 않았다.

제거한 비용은 MPC 내부 AES다. 남는 비용은 component private input 및 일치 검사,
공개 wire 사본 일치, binary subtraction/좌표 검사, binary-arithmetic 변환,
global norm, acceptance, 최종 SUM과 악성 보안 preprocessing/CHECK다.
공개 wire의 비밀 비트 비교는 인증된 공개 비교로 대체했다. SIMD chunk 크기도 조절할 수 있다.
Component의 세 사본 입력·비밀 일치 검사는 계속 유지한다. Native share 직접 주입은 구현하지 않았다.

## 7. 구현 및 재현

- `trustlessfl/seed_mpc_prss.py`: component domain 분리, XOR mask, 수신자별 암호화 packet, private input 순서.
- `mpc/Programs/Source/seed_mpc_candidate_primitives.py`: 등록 사본·round component 일치 검사.
- `mpc/Programs/Source/seed_mpc_chunked_session.mpc`: mask mode 분기와 기존 바운더리·wide SUM.
- `trustlessfl/seed_mpc_client_app.py`, `seed_mpc_external_client.py`, `seed_mpc_service.py`: 실제 Flower client 및 aggregator 연결.
- `experiments/run_seeded_components_security.py`: 등록 seed/round component equivocation을 명시적으로 주입하는 로컬 검증.

```bash
PATH="$PWD/.venv/bin:/usr/local/bin:/usr/bin:/bin" .venv/bin/python -m experiments.run_seed_mpc_flower \
  --output .cache/seeded-components-example \
  --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3-telemetry \
  --mode fixture --dimension 65 --rounds 3 --snapshot-version 2 --communication-meter
```

기본 mode가 seeded component다. 이전 AES 경로는 `--mask-mode secret-aes-v1`을 추가한다.
실행은 WSL에서 하며 Flower Hub 게시 설정을 만들지 않는다.
최초 seed 개선 실측은 [적용·검증 기록](reproduction/seeded-components-2026-10-11.md)에 정리한다.
후속 공개 비교·packing 개선 실측은 [최적화 검증 기록](reproduction/public-packed-2026-10-11.md)에 정리한다.
