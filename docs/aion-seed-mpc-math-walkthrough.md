# Single-mask Seed-MPC: 전체 과정과 프라이버시를 수식으로 이해하기

> 2026-10-11 마스크 경로 갱신: 현재 기본 구현은 [seed 기반 component 로컬 확장](aion-seeded-components-protocol.md)이다. 아래의 비밀 키 AES 생성식은 `secret-aes-v1` 이전 경로를 설명한다. 바운더리 검사·wrap 복원·wide SUM·인증·dropout 계약은 새 경로에도 적용된다.

작성일: 2026-10-11. [현재 프로토콜 명세](aion-seed-mpc-current-protocol.md)의 수식 설명이다. 고정 aggregator 4개, static 최대 1개 악성 aggregator, 정적 바운더리를 사용한다. 참여 비트·가변 snapshot은 v2 하부 회로에서 구현·검증했으며, 현재 Flower orchestration은 전원 참여를 요구한다. 제출 수집·dropout·복귀 연결은 미구현이다.

## 1. 목표 함수와 표기

Client \(C_i\)는 모델 \(\theta_r\)에서 계산한 업데이트 \(\Delta_{i,r}\in\mathbb R^D\)를 갖는다. 원하는 함수는 바운더리를 통과한 양자화 업데이트의 평균이다.

\[
u_{i,r}=\operatorname{RoundEven}(S\Delta_{i,r}),\quad
U_r=\sum_i e_{i,r}u_{i,r},\quad
a_r=\sum_i e_{i,r},\quad
ok_r=\mathbf1\{a_r\ge a_{\min}\}.
\]

\[
\theta_{r+1}=\begin{cases}
\theta_r+U_r/(Sa_r),&ok_r=1,\\
\theta_r,&ok_r=0.
\end{cases}
\]

여기서 \(e_i\in\{0,1\}\)는 MPC 안에서 계산하는 비밀 통과 비트다. 충분한 통과 인원이 없으면 합계·인원을 공개하지 않고 abort하며 모델을 유지한다.

\([z]\)는 secret shares로 표현된 비밀값이다. MPC가 \([z]\)를 계산했다는 것은 aggregator가 평문 \(z\)를 읽었다는 뜻이 아니다. \(\operatorname{Open}([z])\)는 지정한 값을 공개하는 연산이다. \(\mathbf1\{P\}\)는 조건 \(P\)가 참이면 1, 거짓이면 0인 지시함수다. \([u_i],[e_i]\)는 공개하지 않고 허용된 \(U,a\)만 연다. 첫 목표 식의 \(u_i\)는 범위 내 정당한 입력이며, 악성 제출까지 포함하는 실제 함수는 아래의 canonical 복원값 \(x_i\)를 대상으로 정의한다.

| 기호 | 의미 | 현재 값 |
|---|---|---:|
| \(D\) | 좌표 수 | 61706 |
| \(n_{\max}\) | 등록 client slot 수 | 4 |
| \(S\) | 양자화 scale | 10000 |
| \(Q=2^w\) | mask·wire modulus | 65536 |
| \(B\) | 좌표 절댓값 상한 | 20000 |
| \(\tau\) | 정적 제곱 norm 상한 | 2500000000 |
| \(a_{\min}\) | 최소 통과 인원 | 2 |
| \(2^{64}\) | MPC 산술 링 modulus | 전송 modulus와 별개 |

## 2. 최초 등록: 작은 key를 비밀 공유

각 client는 세션 전용 독립 AES-128 key \(k_i\)를 생성한다. 현재 입력은 2개의 64비트 word \(k_i^{(0)},k_i^{(1)}\)다. 공유의 원리를 설명하기 위해 각 word를

\[
k_i^{(h)}=\sum_{\ell=0}^{3}s_{i,h,\ell}\pmod {2^{64}}
\]

로 표현한다. 설명상 component를 재배열해 \(A_\ell\)이 자신의 인덱스 component를 제외한 3개를 보유한다고 하자. 이는 4-party Rep4의 복제 공유 구조를 나타낸다. 실제 배열 인덱스와 인증·private input 절차 전체를 대신하는 식은 아니다.

확률적 비밀성을 설명하려면 무작위 생성 전제가 필요하다. 이상적인 공유에서는 \(s_0,s_1,s_2\)를 \(\mathbb Z_{2^{64}}\)에서 독립 균등하게 뽑고 \(s_3=k^{(h)}-s_0-s_1-s_2\)로 정한다. 어느 component 하나를 제외한 세 component의 관측 \(V_\ell\)도 모든 key word \(z\)에 대해

\[
\Pr(V_\ell=v\mid k^{(h)}=z)=(2^{64})^{-3}
\]

이다. 고정된 key와 관측 세 component가 남은 component를 유일하게 정하므로, 무작위 선택에서 관측으로의 대응이 전단사다. 따라서 단일 aggregator의 이상적 share 관측 분포는 key와 독립이다. 실제 PRNG 기반 무작위 생성과 등록·실행 transcript 전체의 보안은 별도 전제이며 이 공유식만으로 증명되지 않는다.

한 aggregator에게는 한 component가 빠져 있다. 자신의 view를 고정해도 모든 가능한 key word \(z\)에 대해 빠진 component를

\[
s_{i,h,\ell}=z-\sum_{t\ne\ell}s_{i,h,t}\pmod {2^{64}}
\]

로 선택할 수 있다. 따라서 한 aggregator의 share만으로 key를 결정할 수 없다. 반면 서로 다른 aggregator 2명의 view를 합치면 4개 component를 모두 모아 key를 복원할 수 있다. 이것이 최대 1개 악성 aggregator라는 계약의 중요성이다.

실제 등록은 client를 통해 받은 input triples의 component 일치·곱 관계, full-width blinded 응답 일치, 등록 descriptor hash와 native CHECK를 검증한다. 키 일관성은 별도 Aion Feldman VSS를 그대로 붙인 방식이 아니라 Rep4 private-input 경로에서 구성한다. 서버에는 \(k_i\)가 전달되지 않는다. 동일하게 실행 중인 native 세션에서 \([k_i]\)를 재사용한다.

## 3. 라운드별 single mask 생성

Round \(r\), AES block 번호 \(b\)에 대해

\[
t_{r,b}=\operatorname{uint64}_{BE}(r)\parallel\operatorname{uint64}_{BE}(b),\qquad
z_{i,r,b}=\operatorname{AES128}_{k_i}(t_{r,b}).
\]

AES 출력 128비트를 big-endian 16비트 word 8개로 나누어 좌표 mask \(m_{i,r,j}\)를 얻는다. Client는 평문 key로 계산하고 MPC는 secret key로 같은 함수를 계산한다.

\[
[m_{i,r}]=\operatorname{MPC\text{-}PRG}([k_i],r).
\]

MPC가 AES를 secret 상태로 평가하는 식이지, 각 aggregator의 AES 출력들을 단순히 더하는 식이 아니다. 일반 AES에는 HPRF 같은 key-homomorphic 선형성을 요구하지 않는다.

주소 `(key, round, block)`는 서로 다른 업데이트에 재사용하지 않는다. 같은 서명된 메시지의 재전송은 가능하지만, 동일 주소로 다른 업데이트를 다시 마스킹하면 안 된다. 현재 native 계약은 \(1\le r<2^{63}\)이며 fresh 세션은 fresh key를 사용한다.

## 4. Client가 보내는 값

\[
Y_{i,r,j}=(u_{i,r,j}+m_{i,r,j})\bmod Q.
\]

서버는 \(Y_i\)를 받는다. \(u_i\)와 \(m_i\)는 받지 않는다. 각 32좌표 청크의 메시지 \(M\)에 context, identity/handle, offset, word 폭과 값들을 넣고

\[
\sigma_i=\operatorname{Sign}_{sk_i}(\operatorname{Canonical}(M))
\]

로 서명한다. Context는 세션·고정 epoch·round·실제 모델 hash·정책 hash에 결합된다. Snapshot에는 이전 결정 hash도 포함한다.

이상적으로 균등한 독립 mask \(m\) 하나라면 모든 \(u,y\)에 대해

\[
\Pr(Y=y\mid u)=\Pr(m=(y-u)\bmod Q)=1/Q.
\]

즉 작은 업데이트도 mask를 모르면 residue에서 직접 읽을 수 없다. 실제 구현은 짧은 AES seed에서 긴 stream을 결정적으로 생성한다. 따라서 이 식을 전체 stream에 대한 정보이론적 완전 비밀성 주장으로 확대하지 않는다. 실제 mask 보안은 AES/PRG의 계산적 보안에 의존한다.

## 5. 참여집합과 실제 입력을 함께 확정

V1 Flower는 모든 등록 client의 완전한 입력을 요구한다. V2 Flower·snapshot·회로와 수신증명·마감·확정 API는 부분집합을 지원한다. 전체 signed 입력과 그 입력에 대한 3-of-4 수신증명을 확보해 확정한 집합을 \(P_r\)라 하고

\[
p_{i,r}=\mathbf1[i\in P_r]
\]

를 공개 제출 비트로 둔다. \(p_i\)는 바운더리 통과 비트 \(e_i\)와 다르다. 현재 기본 Flower 실행은 모든 \(p_i=1\)인 경우다.

Snapshot은 개념적으로

\[
\mathcal M_r=(\text{contract},\text{context},\text{parent},
\{p_i,\text{handle}_i,\text{signed }Y_i\}_{i\in R})
\]

다. 실제 입력 전체를 확보·검증하고 \(d_r=H(\operatorname{Canonical}(\mathcal M_r))\)를 입력 인증서에 묶는다. 참여자 명단이나 hash만 있고 데이터가 없는 상태로 확정하지 않는다. 입력은 모든 실행 party에 전달돼야 하며, native가 각 party의 snapshot digest와 값 사본을 비교한다.

Aggregator 3개의 동일 body 서명이 quorum다. 서로 다른 두 quorum은

\[
|Q_1\cap Q_2|\ge3+3-4=2
\]

를 만족한다. 최대 1개 악성이면 공통 정직 party가 존재하며 durable lock으로 같은 round의 상충 snapshot 투표를 거부한다. 이는 고정 proposal의 안전성 설명이며 BFT 진행 보장이나 전체 보안 증명을 대신하지 않는다.

완전한 입력을 \(T_i\), 공개 collection context를 \(C_r\)라 하면 receipt의 서명 body는 개념적으로

\[
R_{i,r}=(\text{contract},H(C_r),\text{context},\text{parent},i,\text{handle}_i,H(T_i))
\]

다. 정직한 party는 \(T_i\)와 서명을 영속 commit하고 로컬 마감 전·close 전인 경우에만 새 receipt를 반환한다. Snapshot의 각 \(p_i=1\)에는 \(R_{i,r}\)에 대한 3-of-4 QC가 필요하며 실제 payload와 hash도 대조한다.

Receipt signer 집합 \(Q_R\)와 입력 vote 집합 \(Q_M\)에 대해

\[
|Q_R\cap Q_M|\ge3+3-4=2>f_{agg}=1.
\]

정직한 공통 party는 receipt를 먼저 commit했다면 그 입력의 누락·교체 투표를 거부한다. Snapshot close를 먼저 commit했다면 새 receipt를 거부한다. 두 전이는 같은 SQLite transaction lock으로 직렬화하므로 순서와 무관하게 상충하는 두 QC가 만들어질 수 없다. 동일 payload의 이미 commit된 receipt 재조회는 새 발행이 아니다.

Subset close는 party별 영속 마감 뒤에만 가능하고, 전체 roster가 receipt QC를 갖춘 경우 조기 close할 수 있다. 다른 party에서 payload와 QC를 가져와 마감 후 투표하는 것은 허용하지만 새 receipt를 발행하지 않는다. 이는 로컬 clock·durable storage/rollback 방지를 전제로 한 조건부 안전성이다. 서버만 받은 입력의 포함, 글로벌 부재 증명과 BFT liveness는 보장하지 않는다. 3명 미만 receipt 상태에서는 명시적인 확정 실패가 가능하다.

미제출 slot을 `Y=0`인 실제 client 업데이트로 취급하지 않는다. Absence와 canonical \(p_i=0\)을 snapshot에 묶고 contribution/count를 0으로 한다. V2 Flower는 reply 도착 시 즉시 완전성을 검증하고 receipt를 받아 partial/timeout client를 미제출로 처리한다. 입력 확정 후 dropout이면 이미 확보한 \(Y_i\)와 \([k_i]\)로 계산을 계속할 수 있다.

Client의 head를 \(h_i\), 현재 공개 round를 \(r\)라 하면 새 학습 전에 누락 결정 suffix

\[
\mathcal D_i=(\mathcal D_{h_i+1},\ldots,\mathcal D_{r-1})
\]

의 계약·input/result QC·연속 parent·모델 hash를 검증한다. Coordinator가 ACK를 못 받았으면 이미 적용한 결정도 재전송할 수 있으므로 client는 저장된 동일 결정을 검증하고 재적용하지 않는다. 전체 suffix를 검증한 뒤 유효한 새 결정을 순서대로 저장하며, 늦은 과거 commit으로 head를 되돌리지 않는다. Abort도 모델을 유지하면서 round/decision head를 전진한다. 동기화 뒤 \(h_i=r-1\)와 인증 모델 \(\theta_r\)를 요구하므로 과거 모델에서 학습한 입력을 새 round로 받지 않는다.

V2의 commit ACK는 다음 suffix 길이를 줄이기 위한 동기화 확인이며 집계 성공 조건이 아니다. 결과는 한 번 push하고 ACK를 polling한다. Client가 끝까지 offline이면 상태가 인증 체인의 prefix에 머물 수 있으나 coordinator의 인증 모델은 유지한다. 이는 보존된 client seed/ledger·동일 node mapping·계속 실행 중인 native 세션에서의 복귀이며 native/coordinator 재시작 복구와 구분한다.

## 6. 정확한 마스크 제거와 signed 복원

MPC에서

\[
[\rho_{i,j}]=\operatorname{MPC\text{-}Mod}_Q(Y_{i,j}-[m_{i,j}])
\]

를 계산한다. 후보 signed 정수는

\[
x_{i,j}=\rho_{i,j}-Q\mathbf1\{\rho_{i,j}\ge Q/2\}.
\]

현재 회로는 w비트 binary 뺄셈으로 이 modular 계산을 정확히 수행한다. Signed 값을 arithmetic으로 옮길 때 unsigned 값에서 \(Q\cdot sign\)을 뺀다. 복원된 \([x_i]\)는 aggregator나 서버에 공개하지 않는다.

## 7. 비공개 좌표·global norm 검사

\[
[q_{i,j}]=[\mathbf1\{-B\le x_{i,j}\le B\}],\quad
[v_i]=\bigwedge_{j=1}^{D}[q_{i,j}],\quad
[s_{i,j}]=p_i[q_{i,j}][x_{i,j}].
\]

위 식의 \(q,v\)는 비교 결과 비트이며 대괄호는 secret 상태를 표시한다. 부적합 좌표는 제곱하기 전에 0으로 만든다. 전체 valid 비트 \(v_i\)에는 한 좌표라도 잘못된 사실을 남긴다.

\[
[h_i]=\sum_{j=1}^{D}[s_{i,j}]^2,\qquad
[e_i]=p_i[v_i][\mathbf1\{h_i\le\tau\}].
\]

V1은 모든 \(p_i=1\), v2는 가변 \(p_i\)를 구현한다. Invalid 좌표를 0으로 만든 덕분에 norm 계산이 안전하지만, 그것만으로 잘못된 client가 통과하지는 않는다. \(v_i=0\)이면 전체 client의 \(e_i=0\)이다.

Norm은 전체 D좌표에 대해 계산한다. 예를 들어 7개 좌표가 20000이면 각 좌표는 범위 안이지만

\[
h_i=7\cdot20000^2=2800000000>2500000000
\]

이어서 탈락한다. 여러 chunk에 나누어 각 chunk norm이 작더라도 전체 norm 조건으로 판정한다. \(e_i\)는 client의 모든 좌표에 동일하게 적용한다.

## 8. 비밀 선택 집계와 공개

\[
[U_j]=\sum_i[e_i][s_{i,j}],\quad
[a]=\sum_i[e_i],\quad
[ok]=[\mathbf1\{a\ge a_{\min}\}].
\]

Native가 공개하는 값은

\[
\operatorname{Open}([ok]),\quad
\operatorname{Open}([ok][a]),\quad
\operatorname{Open}([ok][U]).
\]

성공하면 실제 SUM/count, 부족하면 ok=0과 masked-zero count/SUM이다. Adapter는 후자를 `abort`로 바꾼다. 개별 update, norm, valid/accept 비트와 mask/key는 직접 열지 않는다. **허용된 count/ok로부터 추론되는 정보는 누출 범위에 포함한다.** 현재 제출자 4명에서 count=4이면 모든 \(e_i=1\)을 알 수 있고, abort이면 \(a<2\)임을 알 수 있다. 따라서 개별 비트의 직접 비공개가 그 비트의 추론 불가능성을 뜻하지 않는다.

Native 결과는 사후 CHECK 전까지 pending이다. 정직 aggregator는 자신의 native CHECK 및 round/input digest를 확인한 뒤에만 결과 투표를 한다. 결과 body는 입력 hash, 현재/다음 모델 hash, 이전 결정 및 공개 결과에 결합한다. 3개 distinct 서명을 확인한 coordinator만 모델을 적용한다. 인증 전 pending 값이 aggregator에 출력되는 순서만으로 모든 abort의 프라이버시 증명이 완료되는 것은 아니다.

## 9. 모델 갱신과 client 동기화

\[
\theta_{r+1}=
\begin{cases}
\theta_r+U_r/(Sa_r),&ok_r=1,\\
\theta_r,&ok_r=0.
\end{cases}
\]

현재는 같은 샘플 수의 client를 사용하는 단순 평균이다. 결정·모델은 한 번만 적용하며 재전송은 재적용하지 않는다. 정상 인증 abort도 결정 head를 전진시킨다.

Dropout 확장에서는 client commit ACK를 집계 완료 조건으로 요구하지 않는다. 복귀 client는 누락된 인증서·모델 체인을 순서대로 검증하고 최신 round로 따라잡는다. 현재 앱은 전원 ACK를 요구하며 이 복귀 경로도 미구현이다.

## 10. Carry·wrap 정확성

Wire에서 wrap이 발생해도

\[
((u+m)\bmod Q-m)\bmod Q=u\bmod Q.
\]

예를 들어 \(u=20000,m=60000\)이면 \(Y=14464\)이지만 제거 residue는 20000이다. \(u=-20000,m=10000\)이면 \(Y=55536\), 제거 residue 45536을 signed 복원하면 -20000이다.

또 \(2B<Q\)이면 \([-B,B]\)의 정수 표현은 유일하다. \(u,v\)가 같은 residue이면 \(u-v=tQ\)인데 \(|u-v|\le2B<Q\)이므로 \(t=0\), 즉 \(u=v\)다.

최종 SUM은 Q로 줄이지 않는다. 4개 client의 한 좌표가 각각 20000이면

\[
U=80000,\quad U\bmod65536=14464.
\]

현재는 80000을 출력한다. 전송 modulus와 집계 계산 공간을 분리했기 때문이다.

MPC 내부 정수 폭도 안전해야 한다.

\[
0\le h_i\le DB^2=24682400000000<2^{45},\qquad
|U_j|\le n_{\max}B=80000.
\]

현재 wire/norm/SUM/count 비교폭 18/47/19/5비트와 64비트 링을 validator로 확인한다. Input sanitize와 비교·변환 primitive 전제가 필요하며, arbitrary 값에 대한 무조건 무overflow 보장이 아니다.

이 정확성은 승인된 canonical 정수 입력에 대한 명제다. 같은 residue를 만드는 \(u+Q\) 같은 무제한 정수나 client가 주장하는 실제 SGD 결과를 증명하지 않는다. 바운더리는 프로토콜이 복원한 canonical 입력을 검사한다.

## 11. 서버가 알 수 있는 값과 누출 조건

정상 분리 운영에서 서버의 관측은 개념적으로

\[
V_S=(\text{공개 계약·모델·context},\{Y_i\},
\text{snapshot/인증서},\{U_r,a_r,ok_r\})
\]

다. \(k_i,m_i,x_i,h_i,e_i\)는 API에서 직접 공개하지 않는다. count/ok/SUM으로부터 추론되는 정보도 허용된 출력의 누출에 포함한다. 실제 실행 권한은 별도로 평가해야 한다.

### 11.1 알려진 기여를 빼면 남은 개인값이 드러난다

선택 client 집합 \(E=\{i:e_i=1\}\)에 대해, 공격자가 기여를 아는 집합 \(K\subseteq E\)가 있으면

\[
U-\sum_{i\in K}u_i=\sum_{i\in E\setminus K}u_i.
\]

남은 집합이 \(\{t\}\)이면 이 값은 \(u_t\)다. 현재 4명이 모두 통과한 라운드에서 서버가 3개 client의 입력을 알고 있다면

\[
u_1=U-u_2-u_3-u_4
\]

로 복원한다. 합계가 공개되는 한 MPC가 이 추론을 제거하지 않는다. \(a\ge2\)는 선택된 client 수 조건이며 공격자가 모르는 honest 기여 2명 조건이 아니다.

SUM을 서버에 직접 전달하지 않고 평균 모델만 전달해도 현재 정책에서 count와 scale을 알면

\[
U=Sa(\theta_{r+1}-\theta_r)
\]

라는 정보 관계가 남는다. 구현의 finite-precision 모델에서는 이 관계의 정수 복원이 반올림에 영향을 받을 수 있지만, 평균 공개를 독립적인 합계 은닉 대책으로 볼 수는 없다.

### 11.2 동일 입력의 부분집합 재집계도 금지한다

같은 입력에 대해 \(E\)와 \(E\setminus\{t\}\)의 합을 둘 다 얻으면

\[
U_E-U_{E\setminus\{t\}}=u_t.
\]

따라서 같은 세션·라운드에서 snapshot을 한 번 확정하고 다른 부분집합·모델·threshold로 입력을 다시 검사하지 않는다. Durable lock과 counter/context binding은 해당 세션·라운드의 충돌 입력·재실행을 통제한다. **새 세션에서 같은 업데이트를 다시 생성·제출하는 것까지 자동 방지하지 않는다.** 새 세션의 fresh key도 이런 출력 차분을 막지 못한다. 세션을 넘는 재질의를 막으려면 client의 세션 간 참여 정책과 지속 상태 등 별도 설계가 필요하다. 서로 다른 정상 라운드의 업데이트는 일반적으로 서로 다르므로 이 식을 임의의 두 라운드 차이에 그대로 적용하지 않는다.

### 11.3 Key를 얻으면 masked 입력을 풀 수 있다

2개 aggregator가 공모해 key를 복원하거나 서버가 client key 파일을 읽으면

\[
m_i=\operatorname{PRG}(k_i,r),\qquad
x_{i,j}=\operatorname{Signed}_Q((Y_{i,j}-m_{i,j})\bmod Q)
\]

로 개별 canonical 업데이트를 복원할 수 있다. 현재 로컬 시험에서는 server/client가 같은 OS UID이며 mode 0600의 seed와 시험용 raw audit도 같은 UID가 읽을 수 있다. API를 통한 비밀 전달이 없다는 것이 OS 격리를 의미하지 않는다.

## 12. 검증 결과와 보장 범위

현재 backend는 **MP-SPDZ 0.4.3의 malicious Rep4**다. 공식 문서는 지연된 consistency check를 이용한 selective-failure 취약점을 설명하며, [0.4.3 릴리스](https://github.com/data61/MP-SPDZ/releases/tag/v0.4.3)는 해당 Rep4 수정 포함을 명시한다. [공식 보안 설명](https://mp-spdz.readthedocs.io/en/latest/security-fixes.html#insufficient-checks-in-rep4)을 함께 보안 전제로 둔다. 2026-10-11에 로컬 `Protocols/Rep4.hpp`와 `Protocols/Rep4MC.hpp`가 공식 v0.4.3 태그와 주석·공백을 제외한 소스 내용이 일치함을 확인했고, `Rep4::exchange()`에서 결과 finalize 후 consistency hash를 검사하는 경로를 확인했다. 이 두 파일 비교는 전체 소스·실행 binary의 provenance 증명이나 전체 합성 보안 증명을 대신하지 않는다. 마지막 CHECK 뒤 결과에 서명하는 application 규칙만으로 수정되지 않은 backend의 취약점을 보완할 수 있다고 주장하지 않는다.

문서 보완 시 전체 65536개 residue의 signed 범위 판정과 범위 내 40001개 정수 각각에 대한 6개 대표 mask(0, 1, 32767, 32768, 65534, 65535), 총 240006개 제거 사례를 별도 Python 산술로 확인했다. 이는 정수 항등식 검사이며 악성 MPC 실행 검증은 아니다.

전체 FMNIST/LeNet5 실제 IID 5라운드에서 정상 제외 0/20회, 최종 정확도 86.24%였다. 모든 양자화 업데이트·정수 SUM/count·모델이 독립 재학습과 정확히 일치했다. 이는 산술·학습 경로의 검증이며 전체 프라이버시의 합성 증명은 아니다.

이후 [v2 구현 기록](reproduction/seed-mpc-v2-presence-2026-10-11.md)에서 공식 배포 소스 616개·native binary의 archive 일치를 고정하고, 가변 제출 snapshot과 native gating을 실제 16개 패턴·21라운드 및 7개 변조 거부 사례로 검증했다. 이는 전체 악성 native party에 대한 보안 증명이 아니다.

이어서 [수신증명·확정 구현 기록](reproduction/seed-mpc-v2-collection-2026-10-11.md)에서 atomic receipt/close, 영속 마감, 각 present 입력의 receipt QC를 검증했다. 실제 Rep4 21라운드와 공식 Flower v2 전원 제출 3라운드·12개 QC가 통과했다. 이후 [Dropout 구현 기록](reproduction/seed-mpc-v2-dropout-2026-10-11.md)에서 공식 Flower/Ray·Rep4 10라운드의 timeout·partial·전원 ACK 누락·정상/abort 후 복귀를 검증했다. 정수 SUM/모델·28개 receipt QC가 독립 검증과 일치했고 관련 회귀 322개가 통과했다.

조건부 목표는 **고정 4-party/max 1 corrupt aggregator와 보호된 client 실행 환경에서 허용한 출력 이외의 개별값을 열지 않는 것**이다. 전체 공동 공모 증명, 독립 운영자 격리, safe share 복구, BFT 진행 보장은 미완료다. Flower dropout·복귀는 작은 fixture에서 구현·검증했으며 전체 FMNIST dropout 재학습과 실제 독립 운영자/네트워크 배치 검증은 남아 있다. Norm 이내 악성 업데이트 탐지는 목표 밖이다.

[프로토콜 상태와 코드 연결](aion-seed-mpc-current-protocol.md), [실제 5라운드 검증](reproduction/seed-mpc-lenet5-iid-5r-2026-10-11.md)에 상세 기록이 있다.
