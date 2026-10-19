# Seed-MPC single-mask FL 구현 계획

작성일: 2026-10-11  
작업 위치: WSL `/home/hacho/@WSL-Projects/trustlessFL`  
브랜치: `work/aion-private-bound-no-wrap`  
기준: [현재 통합 프로토콜](aion-seed-mpc-current-protocol.md), [설계 변천](aion-seed-mpc-protocol.md), [선행연구 비교](seed-mpc-related-work.md).

완료된 5라운드 기준선 이후의 구현 순서와 완료 조건은 [다음 구현 계획](seed-mpc-next-implementation-plan.md)을 따른다. 아래 단계 A–G는 기존 구현 이력과 원래 계획을 보존한 기록이다.

## 목표와 완료 조건

일반 AES-CTR PRG의 seed를 한 번 인증 공유하고, 여러 aggregator가 MPC 안에서 마스크를 제거한 뒤 정적 바운더리를 검사한다. 개별 업데이트를 열지 않고 선택 SUM과 인원만 Flower coordinator에 전달한다. 정상 양자화 정수 입력의 carry/wrap 때문에 집계 결과가 달라지지 않아야 한다.

완료 조건은 **실제 secret-key AES MPC → 키 재사용 다중 라운드 → 정확한 비공개 검사 → 인증된 결과 확정 → 공식 Flower의 전체 FMNIST 모델 실행**이다. 평문 oracle, compile 성공, 공개 키 AES demo 또는 작은 좌표 fixture만으로 완료 처리하지 않는다.

이 문서는 계획 작성 당시의 단계와 완료 조건을 기록한다. 현재(2026-10-11)는 실제 Rep4·메모리 key reuse·공개 영속 ledger·입력/결과 인증과 공식 Flower 연결, [전체 LeNet5/FMNIST IID 5라운드](reproduction/seed-mpc-lenet5-iid-5r-2026-10-11.md)까지 구현·검증했다. 독립 운영자 격리, 전체 BFT liveness·구성 보안 증명 및 안전한 secret share 복구는 남아 있다. **Committee는 변경하지 않는 것으로 범위를 고정한다.** 가변 client 참여집합과 dropout/복귀 처리는 현재 통합 프로토콜에 명세했고 아직 미구현이다. Flower Hub 게시와 publisher 설정은 작업 범위에 포함하지 않는다.

같은 날 **Rep4 + 비트 좌표 회로**를 추가 검증했다. 기본 키 입력은 128bit 전체를 두 개의 64bit word로 보존하며, 링에서 안전하지 않은 기존 필드식 등록 검사를 전체 component/응답 일치와 full-width 검증으로 대체했다. 2좌표 3라운드 내부 통신 0.350628 MB, 64좌표 fixture와 악성 등록 중단을 확인했다. [Rep4 검토와 결과](reproduction/rep4-candidate-review-2026-10-11.md).

다음 후보는 Rep4로 두되, 단계 E/F로 확대하기 전에 외부 등록의 악성 클라이언트·aggregator 합성 검토 및 vectorized/chunk 회로를 우선 수행한다. 64좌표 compile에 84.487초가 걸려 현재 전개 방식으로 전체 61706좌표를 확장했다고 볼 수 없다. Chunk를 사용해도 동일 입력의 전체 norm과 단일 비밀 선택 비트를 유지한다. 위 완료 조건은 그대로 남는다.

이후 **병렬 AES·runtime chunk 회로와 컴파일 재사용**을 구현했다. 64좌표 compile 6.727초, 1024좌표 compile 6.409초 및 실제 native 결과 일치를 확인했다. 다른 공개 입력에 같은 bytecode를 사용한 실행은 compile 0회였다. Whole norm/partial chunk 반례와 입력 불일치·counter 재사용을 검사했다. [확장 결과와 조건부 등록 보안 검토](reproduction/rep4-chunked-review-2026-10-11.md). 위 84.487초는 이전 전개형 회로의 기록이다. 새 입력 경로는 runtime 파일이며 등록의 완전한 합성 증명과 실제 악성 native party 시험은 남아 있다. 다음 구현은 단계 E의 signed input/context 확정·durable ledger·사후 결과 인증 연결이다.

## 1. 신뢰 모델과 실행 계약을 먼저 고정

단계 F의 작은 **공식 Flower masked 연결**을 구현했다. 네 client는 서명된 masked chunk만 보내고 네 aggregator service가 별도 process에서 실행·서명한다. Client도 결과 인증서와 공개 모델 hash를 검증한다. 65좌표 반례와 170파라미터 FMNIST 3라운드의 실제 정수 SUM/모델 일치, 인증되지 않은 모델의 학습 전 거부를 확인했고 Python 관련 검사 196개가 통과했다. [구현·통신·남은 범위](reproduction/seed-mpc-flower-review-2026-10-11.md). 같은 WSL UID의 기능 검증이며 전체 61706좌표, 운영자 격리, dropout·share 복구·BFT liveness는 남아 있다. 다음은 단계 G의 고정 fixture 규모 확대와 전체 모델 비용 확인이다.

단계 E에서는 **서명된 입력·영속 lock·실행 예약·native 사후 CHECK·결과 인증·모델 한 번 적용**을 작은 고정 committee에 연결했다. 등록 descriptor를 실제 비밀 입력 socket에도 묶었다. 2/65좌표 3라운드와 변조 중단을 실제 Rep4로 검증했으며 당시 Python 관련 검사 169개가 통과했다. [검증 기록](reproduction/seed-mpc-certified-review-2026-10-11.md). 이후 위 단계 F의 Flower masked 업로드와 인증된 모델 경로를 연결했다. 일반 BFT view change/liveness와 외부 입력 전체 합성 증명은 남아 있다.

- Aggregator N=4, static 악성 f<=1. Coordinator는 신뢰하지 않는다. BFT 안전성은 부분 동기 N>=3f+1 조건을 따른다.
- 클라이언트의 제출 값은 믿지 않는다. 좌표 및 norm 조건을 만족한 effective input만 집계한다. 실제 SGD 수행 증명과 norm 이내 공격 탐지는 범위 밖이다.
- 구현 목표로 aggregator–client 공동 공모도 포함하는 모델을 권고한다. Aion 비교 한도는 라운드 q명 중 악성 client 최대 q-2명이다. 이는 아직 완성된 보안 보장이 아니며 입력 등록·변환·출력 합성 검토의 목표다.
- 공개 출력 함수는 선택 SUM/count/abort이다. q-2 한도라도 정상 입력 하나만 선택 SUM에 남으면 그 값이 드러날 수 있다. 참여자 수와 통과 인원만으로 두 honest 기여를 보장하지 않는다. 허용 출력의 추론과 추가 정보 누출을 구분한다.
- 초기 MVP는 고정 committee와 계속 실행되는 MPC 세션을 사용한다. 상태가 불확실한 프로세스 재시작에는 새 세션/새 키를 등록한다. 기존 인증 share를 새 MAC key에서 읽지 않는다.
- Safety와 liveness를 구분한다. 악성 MPC party 때문에 라운드가 abort할 수 있다. BFT 연결만으로 학습 지속을 보장하지 않는다.

기본 공개 정책은 D=61706, n_max=4, S=10000, B=20000, tau=2500000000, a_min=2, w=16, Q=65536이다. 처음에는 작은 D fixture를 사용하고 동일한 산술 계약으로 확장한다. 무가중 평균 U/(S*a)을 구현한다. 가중 FedAvg는 별도 정책/폭 검토 후 확장한다.

정수 계약: Q>2B, norm 최대 DB², SUM 좌표 최대 n_max*B. Backend field와 모든 비교/변환 폭은 이 최대값 및 primitive의 통계적 여유로 계산한다. P=2^127-1은 검토 후보이고 pinned backend의 실제 조건 확인 전 자동 승인하지 않는다.

통과 조건: policy/context/output 명세와 공모 범위가 코드 설정으로 표현되고, 폭이 부족한 설정을 학습 시작 전에 거부한다.

## 2. 기존 코드의 재사용 범위

| 현재 자산 | 재사용할 부분 | 새로 필요한 부분 |
|---|---|---|
| `experiments/audit_seed_mpc_protocol.py` | AES byte-order, signed 복원과 SUM의 평문 oracle | 제품 encoder/policy 모듈과 실제 MPC 비교 |
| `trustlessfl/static_bound.py`, `fmnist_no_wrap_math.py` | 정적 threshold 결정, 양자화 및 정수 집계 reference | HPRF/spacing 가정이 없는 seed 전용 정책 |
| `mpc/Programs/Source/aion_private_bound.mpc` | sanitize, norm/선택 함수와 인증 출력의 설계 참고 | secret AES, public Y, persistent key; 기존 HPRF 회로를 그대로 사용하지 않음 |
| `trustlessfl/mpc_external_client.py` | ExternalIO 접속과 필드 확인 | seed-only 등록, 등록 ID와 인증 handle 연결 |
| `experiments/run_private_bound_mpc.py` | pinned MP-SPDZ 설치, 격리 실행과 결과 수집 | 여러 라운드의 계속 실행 세션, 일반 서비스 경로 |
| `trustlessfl/hotstuff.py`, `peer_transport.py` | 서명·인증서·peer 통신과 투표 상태 | 새 context/input/output 바인딩; 상태 영속화 연결 검토 |
| `trustlessfl/fmnist_no_wrap_app.py` | 로컬 trainer, partition, 평가와 deterministic baseline | 새 ClientApp/ServerApp: raw delta를 coordinator에 보내지 않는 경로 |

기존 fixture harness는 입력을 아는 신뢰된 테스트 도구다. 이를 실제 서비스의 private input 수집기로 사용하지 않는다. 기존 BFT adapter는 normal path 또는 bounded driver 범위를 가지므로 완전한 부분 동기 liveness 구현으로 표시하지 않는다.

## 3. 단계 A — seed 전용 정책·wire encoder

예정 파일: `trustlessfl/seed_mpc_policy.py`, `seed_mpc_wire.py`, `tests/test_seed_mpc_math.py`.

구현: 128-bit 전용 key, round/block의 64-bit big-endian counter, AES output의 uint16 big-endian 분할, `Y=(u+mask) mod Q`, canonical 길이/범위 검증. Session과 key handle, actual model hash, 고정 policy hash 및 chunk 위치를 서명 payload에 포함한다.

Chunk가 있어도 counter의 block index는 전체 벡터에서 연속이다. Chunk마다 index 0으로 돌아가지 않는다. 양자화/학습 모델 순서·dtype·rounding 계약도 고정한다.

통과 조건: NIST AES known-answer, 현재 exhaustive oracle와 randomized 검사, ±B 및 wire 경계, 길이/round/handle 오류를 재현한다. 범위 밖 정상 encoder 입력은 거부한다. 실제 PRG 출력은 평문 구현과 byte-for-byte 일치한다.

## 4. 단계 B — 실제 secret-key AES와 변환 검증

예정 파일: `mpc/Programs/Source/seed_aes_probe.mpc`, `experiments/run_seed_mpc_probe.py`, `docs/reproduction/seed-mpc-backend.md`.

MP-SPDZ 0.4.3의 pinned 소스를 기준으로 active binary AES와 arithmetic/binary 변환을 선택한다. 기존 `aes_circuit.mpc`는 공개 상수 키 demo이므로 그 성공을 비밀 키 검증으로 사용하지 않는다. AES 회로 파일 출처/해시, key 입력 비밀성, bit order, preprocessing 설정을 기록한다.

첫 비교는 fixture용 1~2 AES block이다. Test-only 출력으로 known-answer를 확인하는 회로와, mask를 열지 않고 최종 합만 출력하는 제품 회로를 별도 파일로 둔다. 알려진 fixture key만 test-only 회로에 사용한다.

필수 확인: binary input의 Boolean 제약, authenticated A2B/B2A 연결, 동일 보안 모델과 MAC domain, 4party active 실행 지원. MASCOT 산술 성공만으로 arbitrary AES 혼합 회로를 지원한다고 가정하지 않는다. 필요하면 같은 보안 모델의 backend 조합을 비교하되 semi-honest로 낮추지 않는다.

통과 조건: 실제 외부 비밀 key 입력과 public counter로 oracle와 일치하고, key/mask를 열지 않는 경로까지 실행한다. Native 시간·triple/daBit/AND 사용량·통신량을 기록한다. 단순 compile 지표는 runtime과 분리한다.

## 5. 단계 C — 등록 한 번과 계속 실행되는 키 상태

예정 파일: `trustlessfl/seed_mpc_registration.py`, `seed_mpc_session.py`, `mpc/Programs/Source/seed_mpc_session.mpc`.

Client가 128-bit seed만 aggregator들의 authenticated input으로 등록한다. Coordinator나 어느 한 aggregator가 raw seed를 받지 않는다. 모든 bit를 검증하고 인증 check 완료 후 공개 key handle을 활성화한다. Client identity/등록 handle/epoch를 묶고 중복 등록과 무단 handle 교체를 거부한다.

외부 악성 client와 f=1 aggregator 공동 공모에 대한 입력 프로토콜의 전제를 확인한다. AlphaFL 입력 인증 설계와 현재 ExternalIO API를 대조한다. 기존 API가 목표 모델을 충족하지 않으면 검증 가능한 인증 입력 adapter를 구현한 뒤 진행한다. 논문 proof를 다른 필드/party 수에 그대로 적용했다고 주장하지 않는다.

초기 구현은 한 세션이 registration과 여러 round를 순차 처리하며 인증 key shares를 메모리에 유지한다. 실패/재시작 시 새 session/key가 기본이다. Disk share 복구, proactive refresh, committee 교체는 후속 범위다. 소비된 preprocessing은 재사용하지 않는다.

통과 조건: 같은 handle로 3회 이상 native MPC 라운드를 실행하며 private seed 입력은 최초 한 번만 발생한다. 키 교체·client 사칭·nonboolean seed·다른 MAC epoch 사용 시 성공 결과가 확정되지 않는다.

## 6. 단계 D — 비공개 unmask·좌표 검사·norm·SUM

제품 회로는 등록된 secret seed와 합의된 public Y를 입력받는다.

1. Secret AES로 mask word m 생성.
2. 넓은 산술 공간에서 z=Y-m, r=z+Q*[z<0] 계산.
3. `r<=B` 또는 `r>=Q-B` 판정; signed v=r-Q*[r>=Q-B] 복원.
4. Invalid 좌표는 0으로 sanitize하되 전체 client invalid 비트를 유지.
5. 전체 D좌표의 제곱합을 충분한 폭에서 계산하고 `<=tau` 판정.
6. e_i를 비밀 상태로 유지하여 큰 계산 공간에서 U=sum(e_i*u_i), a=sum(e_i) 계산.
7. a<a_min이면 U/count를 공개하지 않고 abort. 성공 시 output policy에 정한 값만 공개.

Wire, norm, SUM, count 비교폭을 각각 산정한다. SUM을 uint16으로 줄이지 않는다. Chunk별 norm이나 선택 판정으로 전체 norm 검사를 대체하지 않는다. 여러 pass로 계산할 때도 input/context를 바꾸지 않고 동일 global e_i를 사용한다. Chunk SUM을 최종 검사 전에 공개하지 않는다.

통과 조건: positive/negative mask wrap, ±B, B+1, exact norm threshold/threshold 초과, invalid coordinate가 있는 client 전체 제외, count 부족을 native 실행으로 확인한다. 4개 20000 입력의 SUM 80000이 wire modulus 65536을 넘더라도 정확히 출력된다. 작은 필드/잘못된 comparison width는 실행 전에 거부한다.

평문 oracle와 native 결과의 SUM/count/abort는 정수 단위로 완전히 일치해야 한다. 정상 학습 정확도만으로 이 검증을 대체하지 않는다.

## 7. 단계 E — 입력 확정과 출력 확정

예정 파일: `trustlessfl/seed_mpc_committee.py`, `seed_mpc_ledger.py`, `tests/test_seed_mpc_committee.py`.

각 aggregator는 서명된 public Y의 canonical 내용과 context를 확인한다. 동일한 receipt roster, ordered input digest와 모델/정책을 확정한 뒤 MPC를 실행한다. 여기서 roster는 받은 입력 명단이며 비밀 필터 통과 명단이 아니다.

Context와 round counter를 durable ledger에 기록한 뒤 응답/서명한다. 동일 round/context의 중복 요청은 한 논리적 실행으로 처리한다. Threshold/cohort/model을 바꿔 같은 입력을 다시 검사하는 요청은 거부한다. 불확실한 실행 상태는 새 세션으로 복구한다.

MPC 출력은 인증/MAC check 전까지 pending이다. 정직 aggregator는 check 완료 후에만 결과 hash에 서명한다. N=4의 3개 distinct 서명이 있는 output certificate를 검증한 coordinator만 모델을 한 번 갱신한다. 인증서 수집 전에 MPC가 모든 party를 기다리거나 abort할 수 있다는 제한은 남는다.

통과 조건: coordinator가 서로 다른 Y/context를 전달하거나 결과를 조작할 때 성공 certificate가 생기지 않는다. Duplicated vote, 잘못된 parent, round 재실행, pending output, crash 시점별 rollback을 검사한다. 1개 악성 vote만으로 잘못된 모델을 적용할 수 없어야 한다. 일반 BFT pacemaker/liveness는 별도 완료 항목이다.

## 8. 단계 F — Flower 연결

예정 파일: `trustlessfl/seed_mpc_client_app.py`, `seed_mpc_server_app.py`, `seed_mpc_service.py`, `experiments/run_seed_mpc_flower.py`.

로컬 배치는 4개의 학습 client, 4개의 aggregator service/native party, 1개의 coordinator 역할로 분리한다. 같은 WSL에서의 process 분리는 기능 검증이며 실제 독립 운영자 보안 실험은 아니다.

ClientApp은 학습·양자화·마스킹 후 Y/context/서명만 보내고 seed는 등록 private 채널에서만 입력한다. Coordinator는 전달/학습 orchestration과 인증된 결과 적용을 수행한다. 기존 앱의 raw delta 응답과 delta hash/meta를 새 앱에 복사하지 않는다. 공개값에 없는 개별 norm/accept bit도 로그로 수집하지 않는다.

Aggregator service가 받은 payload를 확정하고 계속 실행되는 MPC 세션에 연결한다. Flower ClientApp 수명과 coordinator 프로세스 재시작이 key 상태를 암묵적으로 reset하지 않도록 서비스 경계를 둔다. MVP에서는 client가 등록 후 일시적으로 offline이어도 aggregator들에 남은 shares로 계산할 수 있게 한다.

통과 조건: 공식 Flower 실행에서 등록 1회/여러 round, client별 seed 비공개 경로, 인증된 U/(S*a) 모델 갱신을 확인한다. Native MPC unavailable/MAC 실패 시 평문 집계로 자동 fallback하지 않는다. Chunk 누락/중복/재정렬과 output certificate replay를 거부한다.

## 9. 단계 G — 전체 FMNIST와 비용·보안 검토

2026-10-11 진행: 1024→4096→전체 61706좌표의 dense 고정 입력을 공식 Flower와 Rep4로 검증했다. 전체 D/3라운드는 compile 6.870초/1회, ServerApp 733.502초, native 통신 2476.15MB, native 프로세스 1개 최대 RSS 145.82MiB였다. 마지막 좌표 범위 위반·여러 청크의 전체 norm 위반·abort 모델 유지까지 정확히 비교했다. Python 202개와 묶음 출력 native 회귀 9개가 통과했다. [비용 분석 및 공개 기록](reproduction/seed-mpc-scale-review-2026-10-11.md). 이는 G의 전체 차원 고정 입력 단계 완료이며 전체 FMNIST 학습 단계 완료가 아니다.

추가 완료: 기존 reference와 같은 초기 LeNet5/partition/SGD 설정으로 실제 IID 1라운드를 실행했다. 학습 60000장·테스트 10000장, client당 15000장/235 SGD step이며 정확도 74.84%, 통과 4/4, 독립 재학습의 양자화 업데이트·정수 SUM·모델이 정확히 일치했다. ServerApp 256.587초, native 통신 825.968MB, native 최대 RSS 71.52MiB, compile 6.300초/1회와 seed 등록 1회를 확인했다. 관련 Python 204개가 통과했다. [1라운드 실제 학습](reproduction/seed-mpc-lenet5-learning-2026-10-11.md).

IID 5라운드도 완료했다. 정확도 74.84%→80.54%→83.72%→84.99%→86.24%, 정상 업데이트 제외 0/20회였다. 20회 독립 재학습의 양자화 업데이트와 5개 정수 SUM/count·전체 모델이 정확히 일치했다. ServerApp 1253.902초, native 통신 4126.98MB, native 최대 RSS 204.61MiB, compile 6.520초/1회 및 seed 등록 1회를 확인했다. [5라운드 결과·비용·재현](reproduction/seed-mpc-lenet5-iid-5r-2026-10-11.md). Non-IID 실제 MPC 10라운드는 아직 실행하지 않았다.

비용 개선 후보는 AES/변환 SIMD 폭 확대와 native 청크·서명 업로드 청크 분리다. 개선은 전체 norm/선택·입력 binding·출력 정책을 유지하고 별도의 범위·padding·active 입력 오류 회귀를 통과해야 반영한다. 현재 backend의 근사 통신 횟수는 약 301만 회/3라운드이므로 bytes뿐 아니라 반복 왕복도 평가한다.

D를 1block → 수백 좌표 → 수천 좌표 → 전체 61706으로 올린다. 전체 모델에 진입하기 전에 실측 자원량을 확인하고 timeout/batching을 조정한다. 기준 FMNIST의 threshold와 데이터 partition은 유지한다. 비용 때문에 보안 모델·검사 정확도·output policy를 조용히 바꾸지 않는다.

실행 순서: 고정 synthetic fixture → 전체 D의 고정 fixture → FMNIST IID 1round → IID 5round → non-IID 10round. 학습은 모든 client에서 기존 양자화 reference와 동일한 train seed/모델/partition을 사용한다.

각 단계 기록: backend/circuit/config hash, 최대 메모리, compile 비용, 실제 preprocessing/online 시간, client↔aggregator와 aggregator↔aggregator 통신, 등록 통신/round payload, abort 조건과 결과 certificate. FullD AES는 client당 7714block, 4client당 30856block이므로 수천 좌표 probe로 규모를 확인한다.

학습 검증은 integer SUM/count/abort 동일성, dequantization 후 모델 동일성 및 accuracy를 각각 보고한다. Acceptance 결과를 필요한 synthetic/reference harness가 아는 것과 실제 서비스가 공개하는 것을 구분한다. 제품 경로는 per-client norm/selection을 열지 않는다.

비교 기준: 현재 plaintext quantized/static reference, 인증된 직접 업데이트 공유형 MPC, 새 seed-MPC. 동일 입력/보안/출력 조건에서 비교하며 직접 공유형은 평가 기준선이다. 사용자 요구의 single-mask 구현을 평가 중에 몰래 대체하지 않는다.

악성 case는 malformed seed/wire, 바운더리 초과, 한 aggregator의 입력 변조·잘못된 share/MAC·equivocation, 재시도/출력 조작을 포함한다. Fault injection의 탐지 성공은 보안 증명과 구분한다. 입력 등록→AES/변환→norm/선택→결과 공개의 합성 검토와 로그/side-channel review를 문서화한다.

통과 조건: 전체 모델의 공식 Flower native MPC 결과가 정수 reference와 동일하고, 재사용되는 seed를 매번 다시 보내지 않으며, 검사가 실패한 라운드에서 모델 갱신이 없다. 실행 비용이 지나치게 크면 원인과 가능한 active-secure 최적화를 기록하고 진행 여부를 검토한다. 평문 결과를 실제 MPC 완료 결과로 표시하지 않는다.

## 의존 순서와 첫 구현 단위

`계약 고정 → encoder/oracle → secret AES·변환 probe → 등록/세션 → 전체 검사 회로 → committee/ledger → Flower → 전체 FMNIST`

초기 구현 단위는 **4party, 2~8좌표, 등록 1회, 실제 비밀 seed AES, 3round, 정적 norm, 정수 oracle 비교**다. 이 단위가 통과해야 전체 모델 서비스 코드를 확장한다. 보안 입력 인증 전제의 공백이 발견되면 작은 probe 수준에서 먼저 수정한다.

MVP 이후 후보: 안전한 disk persistence/resharing, quorum 장애에도 계속 계산하는 MPC, BFT pacemaker와 일반 liveness, 가중 FedAvg, 다른 모델, Hub 배포. Committee 교체는 현재 작업 범위에서 제외한다. Client dropout/복귀는 고정 committee 안의 참여집합 확정 확장으로 별도 구현한다.

참조: [MP-SPDZ 입력·출력/인증 share 저장](https://mp-spdz.readthedocs.io/en/latest/io.html). 실제 지원 여부는 최신 문서와 함께 pinned 0.4.3 소스/실행 결과를 기준으로 확인한다.
