# Seed-MPC AION 실험계획: wrap 정확성·입력 검증·poisoning 영향

작성일: 2026-10-11  
작업 환경: WSL Ubuntu-24.04 `/home/hacho/@WSL-Projects/trustlessFL`  
브랜치: `work/aion-private-bound-no-wrap`

사용자가 추가로 설정하거나 자료를 준비할 필요 없이 현재 로컬 환경에서 수행한다. 이 문서는 실행 계획이며, 아래에 완료 기록으로 표시한 항목 이외의 결과는 아직 측정하지 않았다. Flower Hub 게시 설정은 하지 않는다.

## 1. 확인할 질문

1. Wire에서 모듈러 wrap이 발생해도 MPC가 유효한 signed 정수를 복원하고 정확히 합산하는가?
2. 악성 클라이언트가 좌표·global norm 제한을 위반하면 aggregator의 MPC가 그 클라이언트 전체를 제외하는가?
3. 악성 aggregator 1명 또는 서버의 입력·출력 변조가 잘못된 인증 결과와 모델 갱신으로 이어지는가?
4. 정적 threshold 안에 들어오는 악성 업데이트는 FMNIST 정확도를 얼마나 떨어뜨리는가?
5. 위 조건에서 초기 셋업 비용과 라운드별 통신·실행 비용은 각각 얼마인가?

1~3은 프로토콜의 정확성·무결성 평가다. 4는 학습의 poisoning 취약성 평가다. 현재 필터는 방향이나 학습 데이터의 진실성을 검증하지 않으므로, 범위 내 공격이 통과하고 정확도를 떨어뜨릴 수 있다. 이는 그대로 측정해 보고한다. 정적 threshold를 실험 도중 동적 바운더리로 바꾸거나 다른 robust aggregation으로 교체하지 않는다.

## 2. 현재 기준선과 남은 작업

| 항목 | 현재 상태 |
|---|---|
| 비밀 seed 기반 AES 마스크 제거·signed 복원·정적 범위 검사·인증 집계 | 구현 및 기존 실제 Rep4 실행 기록 있음 |
| Full LeNet5, FMNIST IID, 정상 4클라이언트, 5라운드 | 기존 실행 완료. 마지막 정확도 86.24%, 매 라운드 정수 SUM과 모델 대조 일치 |
| Dropout·receipt·마감·복귀·통신 계측 | 단계 4까지 완료 기록 있음 |
| 역할별 파일 접근 격리 | 예비 실행에서 9개 역할의 자기 파일 접근 허용, 교차 접근 72건 거부 확인 |
| 격리된 공식 Flower Deployment | 작은 D=65 fixture 3라운드 예비 실행 완료. 최종 검증·기록 정리 남음 |
| 실제 악성 native aggregator 변조 | 테스트 빌드 준비 중. 아직 실행·검증 완료 아님 |
| 아래 poisoning 비교 행렬 | 새로 구현하고 실행할 대상 |

기존 결과: [정상 학습 5라운드](reproduction/seed-mpc-lenet5-iid-5r-2026-10-11.md), [통신 계측](reproduction/seed-mpc-meter-2026-10-11.md). 프로토콜 기준: [현재 프로토콜](aion-seed-mpc-current-protocol.md), [수식과 보안 한계](aion-seed-mpc-math-walkthrough.md).

## 3. 고정하는 학습·정책 조건

| 설정 | 값 |
|---|---|
| 모델 | Full LeNet5, D=61,706 |
| 데이터 | Fashion-MNIST train 60,000 / test 10,000 |
| 클라이언트 | 4명, IID 분할, 각 train 15,000 |
| 학습 | 5라운드, 라운드당 local epoch 1, batch 64 |
| Optimizer | SGD, lr 0.01, momentum 0.9, weight decay 0.0005; 현재 코드와 동일한 optimizer 생성 방식 |
| 실행 | CPU, 현재 deterministic 학습 경로 |
| 반복 seed | 42, 43, 44; 실제 MPC 첫 비교는 seed 42 |
| 양자화 | S=10,000, `np.rint(S * delta)` |
| Wire modulus | Q=65,536 |
| 좌표 상한 | B=20,000: 학습 단위로 절댓값 2 이하 |
| Norm threshold | τ=2,500,000,000: 학습 단위로 L2 norm 5 이하 |
| 최소 통과 인원 | 2 |
| Committee | 고정 aggregator 4명, Rep4, static 악성 aggregator 최대 1명 |

Threshold는 모든 조건·seed·라운드에서 위 값으로 고정한다. 반복 seed에 따른 모델 초기화와 데이터 분할의 실제 사용 값을 기록하고, 같은 seed의 비교군에는 동일한 값을 적용한다. 전처리와 batch RNG도 기존 학습 코드를 따른다.

악성 클라이언트 수와 악성 aggregator 수는 구분한다. 학습 공격은 우선 클라이언트 1/4명, 이후 선택 조건에서 2/4명으로 확대한다. Aggregator 무결성 시험은 1/4명만 변조한다.

## 4. 정확성의 판정식

공개 제출 비트 p_i와 유효 signed 정수 x_i에 대해 독립 reference가 다음을 계산한다.

\[
e_i=p_i\mathbf1[\forall j,\ |x_{i,j}|\le B]\mathbf1[\sum_jx_{i,j}^2\le\tau],\qquad
a=\sum_i e_i,\quad U_j=\sum_i e_ix_{i,j}.
\]

Reference는 Python의 충분한 정수 폭으로 계산한다. MPC 결과는 모든 좌표에서 정수 그대로 같아야 하며, 근사 오차 허용값을 두지 않는다. `a >= 2`인 인증된 성공 라운드에만 `theta_next = theta + U / (S*a)`를 적용한다. 실패 라운드는 모델을 갱신하지 않는다.

클라이언트의 마스크된 wire는 Q에서 wrap할 수 있다. 검사 대상은 `(wire - mask) mod Q`를 signed 복원한 canonical 정수다. `2B < Q`와 충분한 내부 정수 폭을 확인한다. 최종 U는 Q로 다시 줄이지 않는다. 현 정책에서 `D*B^2=24,682,400,000,000`, `N*B=80,000`이므로 norm 누적과 합계를 해당 값보다 넓은 회로 폭으로 계산해야 한다.

이 검사는 임의 정수의 모듈러 인코딩 이전 의도나 실제 SGD 수행을 증명하지 않는다. 공격 벡터도 실제 wire에서 복원되는 유효 정수를 기준으로 분류한다.

## 5. 프로토콜 실험

### A. 산술·바운더리

우선 작은 D=65 fixture에서 실제 Rep4로 실행하고, 선택한 마지막 좌표·global norm 사례를 D=61,706에서도 확인한다.

| 입력 사례 | 기대 결과 |
|---|---|
| 0, 양수·음수, ±B, mask+update의 Q 경계 통과 | 정확한 signed 복원과 합계 |
| ±(B+1), 마지막 실제 좌표만 범위 밖 | 해당 클라이언트 전체 제외 |
| Norm 제곱 τ 바로 아래·동일·바로 위 | ≤τ 통과, >τ 제외 |
| 각 청크 norm은 작지만 전체 norm이 τ 초과 | global norm으로 전체 제외 |
| 정상 좌표와 부적합 좌표 혼합 | 일부 좌표만 넣지 않고 전체 제외 |
| Padding·partial·중복·겹친 청크·잘못된 길이 | 해당 단계의 framing/입력 검증 거부 |
| 모든 제출 패턴과 통과 인원 0/1/2/3/4 | 제출 gate·count·abort가 reference와 일치 |
| 합계가 Q/2 또는 Q를 넘는 유효 업데이트 | 충분한 폭의 U와 정확히 일치 |
| 재사용 seed의 여러 라운드 및 dropout 후 복귀 | 라운드 counter에 맞는 마스크, 과거 입력 재사용 거부 |

작은 차원 사례와 전체 차원 사례는 서로 다른 정책임을 기록한다. Norm 경계 벡터는 먼저 독립 정수 reference로 정확한 norm을 검증해 생성한다.

### B. 입력 확정·결과 적용

기존 회귀를 재사용하면서 다음 경로의 거부 위치·영속 상태·모델 불변을 확인한다: quorum receipt가 있는 입력 누락/교체, 상충 snapshot, 마감 이후 입력, 잘못된 session/model/policy/counter, 불완전 제출, 재실행·중복 commit, 인증서 변조. Dropout은 악성 입력 제외와 별도로 기록한다.

### C. 역할 격리·악성 aggregator

Server, C0~C3, P0~P3의 별도 실행 뷰를 사용한다. 자기 비밀 파일 접근은 성공하고 다른 역할의 seed·share·private 설정 접근은 실패해야 한다. 일반 실행에서는 평문 업데이트 감사 파일을 생성하지 않는다. 코드·binary 읽기 전용, symlink 우회, 다른 역할 process 접근도 확인한다. 같은 호스트의 관리자 권한은 신뢰 전제이며, 이 파일 격리 시험으로 독립 호스트 전체 보안을 증명하지 않는다.

악성 native 시험은 P0만 테스트 전용 변조 binary로 실행하고 P1~P3은 승인된 build를 유지한다. 산술 곱셈 share 변조, binary 곱셈 share 변조, opening 송신 데이터 변조, 라운드 중 종료를 각각 실행한다. 변조 지점에 도달한 공개 marker와 binary/source hash를 보존한다. Python adapter가 입력을 거부한 결과를 native MPC 공격 시험으로 세지 않는다.

완료 기준은 잘못된 인증 집계·모델 갱신이 없고, 검사 실패 또는 명시적 중단으로 끝나는 것이다. Opening 변조가 공개 header 단계에서 발생했다면 그 단계의 시험으로 기록하며 최종 비밀 SUM opening까지 검증했다고 표현하지 않는다. 네 native party가 모두 필요한 현 구조에서 한 party의 종료로 진행이 멈추는 것은 예상되는 가용성 한계다.

## 6. Poisoning 실험 행렬

공격은 악성 클라이언트의 자체 입력 생성 경로에 넣는다. 최종 wire는 정상 마스킹·서명·수신증명 경로를 따른다. 범위 밖 공격은 테스트 전용 client에서 정직한 클라이언트의 사전 bound 확인을 우회하여 **MPC가 실제로 제외하는지** 확인한다. 제품의 검사나 threshold는 변경하지 않는다.

| 조건 | 공격 입력 | 목적·예상 필터 동작 |
|---|---|---|
| Clean | 모든 클라이언트 정상 학습 | 정상 수렴·불필요한 제외·기존 기준선 재확인 |
| Out-of-bound | 악성 클라이언트 업데이트를 확대하여 정확한 norm 또는 좌표 상한 초과 | 제외되어야 하는 양성 대조군 |
| Sign-flip | 악성 클라이언트의 자체 업데이트 부호 반전 | 원 입력이 범위 내라면 통과; 정확도 영향 측정 |
| Bounded-scale | 자체 업데이트 부호를 반전하고 확대하되 좌표와 global norm 안에 투영 | 강한 범위 내 방향 공격; 통과와 정확도 하락 측정 |
| Label-flip | 악성 클라이언트 자체 train의 0↔6 라벨을 바꿔 학습 | 데이터 poisoning; norm 판정 및 클래스별 영향 측정 |

Bounded-scale의 기본 공격 강도는 허용 L2 norm의 50%, 100% 두 가지다. 좌표 clipping 후 norm 조절을 하고 양자화한 **최종 정수 벡터**에 독립 bound 검사를 다시 적용한다. 반올림 때문에 초과하면 크기를 줄여 재검사한다. 0 벡터는 별도 처리한다. Sign-flip과 Label-flip은 실제 입력의 pass/fail을 기록하며 예상과 다르게 범위를 초과한 경우를 숨기지 않는다.

공격자는 자신의 데이터·업데이트와 공개 글로벌 모델을 사용한다. 정직한 클라이언트의 평문 업데이트나 전체 honest 합을 공격 생성에 제공하지 않는다. 라벨 변조는 train에만 적용하고 공통 test 라벨은 유지한다. 공격은 기본적으로 매 라운드 수행하며 첫 라운드만 공격하는 조건은 후속 실험으로 분리한다.

## 7. 비교군과 실행 순서

동일한 공격 조건마다 다음 세 경로를 비교한다.

| 경로 | 역할 |
|---|---|
| 평문 양자화 평균 | 바운더리 검사 없는 공격 영향 대조군 |
| 평문 동일 정적 필터 | 현재 정책의 학습 효과와 정확한 정수 reference |
| 실제 Flower + Rep4 동일 정적 필터 | 프라이버시 구현이 같은 판정·합계·모델을 계산하는지 검증 |

각 경로는 같은 seed·초기 모델·분할에서 시작한다. 필터 유무로 모델이 달라진 이후에는 **각 경로의 현재 모델에서 다시 로컬 학습**한다. 정상 기준선의 미리 계산한 업데이트를 다른 모델의 후속 라운드에 재사용하지 않는다. MPC와 평문 동일 필터는 같은 입력에 대해 모든 좌표의 U/count와 매 라운드 모델이 일치해야 한다.

1. 프로토콜 A~C의 작은 fixture와 기존 회귀를 먼저 정리한다.
2. 평문 경로로 seed 42/43/44, 악성 클라이언트 1명, 위 6개 조건(Clean/Out-of-bound/Sign-flip/Bounded-scale 2개/Label-flip), 각 5라운드를 실행한다. Seed별 paired 정확도 차이를 계산한다.
3. 실제 MPC는 우선 seed 42의 Clean, Out-of-bound, 평문 실험에서 가장 큰 정확도 하락을 보인 범위 내 조건을 각각 5라운드 실행한다. 선택 기준과 모든 예비 결과를 공개하여 선택된 조건만의 결과를 일반화하지 않는다.
4. 정수·모델 일치와 계측이 맞으면 선택 조건의 seed 43/44 및 악성 클라이언트 2명 조건으로 확대한다. 2명 조건은 정상 기여 2명이 남는 경우지만 norm이 정직성을 보장하지 않음을 명시한다.
5. 후속으로 non-IID, 공격 시점, threshold별 tradeoff를 별도 실험한다. Threshold sweep은 새 정책의 비교이며 이번 고정 정책 결과와 섞지 않는다.

과거 전체 5라운드 실행은 약 21분이었다. 새 계측·격리 경로의 소요 시간은 다시 측정하며 과거 값을 일정 보장으로 쓰지 않는다. 작은 170-parameter 모델은 실행 경로 확인에만 사용하고 LeNet5의 poisoning 성능을 대신하지 않는다.

## 8. 기록할 지표와 산출물

- 학습: 라운드별 test accuracy/loss, clean 대비 정확도 하락(%p), 0/6 클래스별 정확도와 상호 오분류율. 3 seeds의 개별 값·paired 차이·평균/표준편차를 함께 제시한다.
- 필터: 제출/통과/abort count, 테스트 reference에서의 정상·악성 그룹별 제외 수. 개별 norm/통과 비트를 제품 출력에 새로 추가하지 않는다.
- 정확성: 모든 좌표의 정수 SUM/count 일치, 매 라운드 모델 일치, 실패 라운드의 모델 불변, 인증서와 CHECK 경계.
- 비용: 컴파일 1회, seed 등록 셋업, 라운드별 native 송신 합, Flower 객체 크기, RPC JSON, external seed socket을 별도 기록한다. 중복 관측 지표를 무조건 더하지 않고 각 계측 범위와 TCP/TLS 미포함 항목을 표시한다.
- 재현성: 정책·공격 설정·seed·분할·학습 설정, 소스/bytecode/binary hash, 실행 명령, 종료 상태, public 결과 및 모델 hash.

예정 구현 파일은 `experiments/run_seed_mpc_poisoning.py`(평문 실험·조건 행렬), 공격 생성용 테스트 모듈, 실제 Flower 연결, 결과 export/검증기다. 이 이름의 poisoning runner는 아직 구현된 실행 명령이 아니다. 기존 `run_seed_mpc_isolated.py`와 native 테스트 runner를 기반으로 확장한다.

실행 원본은 조건별 새 `.cache/seed-mpc-experiments/<run-id>/`에, 공개 요약은 `docs/reproduction/seed-mpc-security-experiments/` 및 Markdown 보고서에 둔다. 결과 JSON에는 실제 실행한 조건만 `completed`로 표시한다. 키·share·평문 업데이트는 공개 산출물에 넣지 않는다.

평문 대조는 연구용 trusted reference이며 프로토콜 서버의 권한이 아니다. 실제 실행과 비교하기 위한 입력 oracle이 필요하면 역할별 테스트 입력을 별도의 명시적 trusted audit에서만 사용한다. 일반 격리 실행의 서버가 클라이언트 비밀 파일을 읽도록 권한을 넓히지 않는다.

## 9. 결론을 내리는 기준

Wrap/바운더리 구현은 정수 reference와 완전히 일치하고 범위 밖 입력 전체를 제외해야 한다. 무결성 시험에서 잘못된 결과가 인증되거나 모델에 적용되면 구현 실패로 판정한다. 관측한 악성 경로에서 실패하지 않았다는 결과는 해당 경로의 증거이며 전체 암호학적 보안 증명으로 확대하지 않는다.

Poisoning은 목표 정확도를 미리 성공 조건으로 정하지 않는다. **범위 내 공격이 통과한 상태에서 clean 대비 얼마나 떨어졌는지**가 결과다. Norm 제한이 대형 업데이트를 차단해도 범위 내 poisoning을 막았다고 주장하지 않는다. 정상 입력도 많이 제외되면 정책의 학습 적합성 문제로 보고한다.

개별 업데이트 프라이버시는 Rep4의 aggregator 공모 전제와 허용 출력에 의존한다. Aggregator 2명 공모, 알려진 입력을 최종 합에서 빼는 역추론, 반복 공개 모델로부터의 추론까지 이 실험이 제거했다고 주장하지 않는다. 최소 통과 인원 2명은 정직한 입력 2명을 보장하지 않는다. DP나 실제 SGD 수행 증명은 이번 프로토콜에 추가하지 않는다.
