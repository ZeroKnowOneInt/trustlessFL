# Seed-MPC 다음 구현 계획: 제출 집합·dropout·계측·보안 검증

> 최신 구현 상태와 남은 작업은 [packing 이후 구현 계획](seed-mpc-roadmap-after-packing.md)을 따른다. 아래는 이전 secret-AES 단계 계획과 당시 진행 기록이다.


작성일: 2026-10-11  
작업 위치: WSL Ubuntu-24.04 `/home/hacho/@WSL-Projects/trustlessFL`  
브랜치: `work/aion-private-bound-no-wrap`  
기준: [현재 프로토콜](aion-seed-mpc-current-protocol.md), [수식·보안 한계](aion-seed-mpc-math-walkthrough.md).

이 계획은 기존 [구현 계획](seed-mpc-implementation-plan.md)의 구현 이후 작업을 정한다. 각 단계의 완료 범위는 아래 진행 갱신과 검증 기록에 표시한다. 실제 Rep4의 비밀 AES·signed 복원·정적 바운더리·인증 집계·Flower FMNIST 5라운드는 완료된 기준선으로 유지한다.

**구현 진행 갱신:** 단계 0/1의 backend pin·고정 실행 argv·v2 가변 snapshot/native gating을 구현했다. [단계 0/1 증거](reproduction/seed-mpc-v2-presence-2026-10-11.md). 이어 단계 2의 receipt·영속 마감·atomic close를 완료했다. [단계 2 증거](reproduction/seed-mpc-v2-collection-2026-10-11.md). 단계 3의 reply 스트리밍·timeout/partial 미제출 처리·비차단 commit·인증 suffix 동기화도 구현했다. 관련 회귀 322개, 공식 Flower/Ray·Rep4 dropout 10라운드·28개 QC, v1/v2 정상 3라운드 회귀를 통과했다. [단계 3 증거](reproduction/seed-mpc-v2-dropout-2026-10-11.md). **단계 4도 완료했다:** 별도 승인 observer build의 native 정수 counter, Flower 객체 그래프·RPC JSON 양 endpoint·external seed socket을 분리했다. 회귀 351개와 정상/10라운드 dropout/D170 FMNIST/v1 정상 실행을 통과했다. [단계 4 증거](reproduction/seed-mpc-meter-2026-10-11.md). 다음은 단계 5의 역할 격리·악성 경로 검증이며 단계 6의 전체 FMNIST dropout/규모 계측은 남아 있다.

## 1. 유지할 계약과 다음 완료 목표

Committee 4명, static 악성 aggregator 최대 1명, single mask, 최초 AES seed 등록과 동일 native 세션의 키 재사용을 유지한다. 좌표 상한과 norm threshold는 정적이다. 정책은 D=61706, S=10000, Q=65536, B=20000, tau=2500000000, n_max=4, a_min=2다.

다음 완료 목표는 **등록 후 client가 빠지거나 복귀해도, 고정 committee가 인증된 입력으로 정확히 집계하고 client 전원 ACK 없이 학습을 진행하는 것**이다. Aggregator 장애를 견디는 MPC, committee 교체, secret share 재시작 복구와 완전한 BFT liveness는 이 목표에 포함하지 않는다. 실제 등록 도중 client가 사라지면 이번 범위에서는 초기 세션을 실패시키며, 등록 roster의 자동 재구성은 뒤로 미룬다.

공개 출력 함수는

\[
L_r=(\text{공개 context·제출집합·인증자료},ok_r,ok_r a_r,ok_r U_r)
\]

로 명시한다. Count/ok/SUM 및 공격자가 아는 입력에서 추론되는 정보도 허용 출력의 누출 범위에 포함한다. 정상 기여가 하나만 남으면 합계가 그 입력을 드러낼 수 있으며 a_min=2가 정직한 기여 2명을 보장하지 않는다. Norm 이내 poisoning과 실제 SGD 수행 증명은 범위 밖이다.

## 2. 단계 0 — 기준선과 backend를 고정

현재 5라운드 검증 기록은 보존한다. 새 실험은 새 디렉터리·새 세션·fresh key를 사용한다. 진행 중인 v1 native 세션의 회로나 등록 계약을 바꾸지 않는다.

- MP-SPDZ 0.4.3 소스 배포물 hash, 적용 패치, compiler·native binary hash, 빌드 옵션과 실제 실행 옵션을 기록한다. 관련 두 파일 확인을 전체 binary provenance 검증으로 확대한다.
- Backend와 application의 CHECK 경계를 검토하고 semi-honest 또는 검사 생략 옵션이 실행 경로에 들어가지 않도록 계약·launcher에서 거부한다. 수정된 Rep4라는 전제와 최종 결과 서명 규칙을 각각 확인한다.
- 새 snapshot/runtime/circuit에는 v2 계약을 부여하고 execution hash에 반영한다. 다른 버전·다른 bytecode로 실행하는 party를 거부한다. 기존 v1 검증 자료는 그대로 읽을 수 있게 보존한다.
- 바이트코드·비밀 입력과 native 로그 경로, 실제 public 출력/abort 내용을 목록화한다. 중간 norm·선택 비트·seed가 실수로 공개되는 경로를 확인한다.

수정 대상: `experiments/prepare_private_bound_mpc.py`, `seed_mpc_resources.py`, `seed_mpc_session.py`, launcher/검증 기록.

완료 조건: 빌드·실행 artifact와 보안 옵션을 재현할 수 있고 v1/v2 혼용·검사 생략 실행이 시작 전에 거부된다. 이 계측·pinning은 전체 보안 증명을 대신하지 않는다.

## 3. 단계 1 — 공개 제출 비트와 가변 snapshot을 MPC까지 연결

등록 slot 수 N은 고정한다. 각 라운드에 공개 제출 비트 p_i를 추가한다. p_i는 반드시 full-width 정수 0 또는 1이며 네 party의 사본이 일치해야 한다. p_i=1인 slot은 정확히 D개의 유효한 signed wire 좌표가 필요하다. p_i=0인 slot은 명시적 absence marker와 canonical dummy framing을 사용하고 signed 업데이트를 포함하지 않는다.

Native 계산은 다음을 따른다. 모든 비밀 판정은 끝까지 비밀 상태다.

\[
q_{i,j}=\mathbf1\{-B\le x_{i,j}\le B\},\quad
v_i=\prod_jq_{i,j},\quad
s_{i,j}=p_iq_{i,j}x_{i,j},
\]

\[
h_i=\sum_js_{i,j}^2,\quad
e_i=p_i v_i\mathbf1\{h_i\le\tau\},\quad
U_j=\sum_ie_i s_{i,j},\quad a=\sum_ie_i.
\]

Absent slot의 dummy Y=0을 실제 0 업데이트로 복원·집계하지 않는다. p_i=0이면 contribution/count는 반드시 0이다. p_i=1인데 바운더리에 실패하는 경우는 제출자로 남고 비밀 e_i=0이 된다. 이 둘을 혼동하지 않는다.

초기 구현은 slot과 청크 길이를 고정하고 p로 gate하여 스트림 정렬을 단순하게 유지한다. 미제출 slot의 AES 생략 등 최적화는 정확성 검증 이후 수행한다. 비밀 e_i에 따라 공개 실행 흐름이나 로그 길이가 바뀌지 않도록 한다. 모든 native round에서 공개 counter를 소비하며, 미제출 round의 업데이트를 나중에 제출하거나 재집계하지 않는다.

수정 대상: `seed_mpc_committee.py`의 manifest/검증/runtime 생성, `seed_mpc_chunked_session.mpc`, native reference/fixture와 결과 검증기.

검증:

- N=4의 16개 제출 패턴 전부, 전원 미제출과 제출자 수가 a_min 미만인 경우 포함.
- p=-1, 2, 2^32, 2^63 등 비정상 비트 및 party별 p/hash/Y 불일치 거부.
- 부재 표시와 signed payload의 충돌, partial·overlap·중복 청크·미등록 slot 거부.
- 정상 signed 끝값, 음수, wire wrap, 마지막 실제 좌표, padding, global norm 초과, 범위 밖 좌표와 abort.
- 통과한 전체 client에 동일 e_i를 적용하며 정상 정수 SUM/count가 독립 reference와 일치.
- 미제출 client의 복귀 후 새 round mask가 정확하고 소비한 round의 늦은 입력이 거부됨.

완료 조건: 작은 실제 Rep4 fixture에서 가변 snapshot과 native 결과가 일치한다. 이 단계의 수동 snapshot 검증만으로 서버가 제출자를 부당 제외하지 못한다고 주장하지 않는다.

## 4. 단계 2 — 제출 수신증명·마감·입력 확정

Client transport timeout이나 잘못된 서명·불완전 업로드는 해당 client의 미제출 처리 후보가 된다. 완전하고 서명이 유효한 범위 밖 업데이트는 삭제하지 않고 MPC 검사로 보낸다. 서버 단독으로 raw 업데이트나 norm을 검사하지 않는다.

서버가 완전한 입력을 aggregator 수집 경로에 전달한다. Aggregator는 전체 입력을 검증·durable 저장한 다음 receipt에 서명한다. Receipt는 session/round/model/policy/client/handle/full-input hash에 결합하고 동일 client·context의 상충 입력에는 다시 서명하지 않는다. Client가 확인할 수 있도록 receipt를 반환하거나 질의하는 경로도 제공한다.

마감 후 snapshot 확정 규칙은 다음과 같이 구현·검토한다.

1. Aggregator는 자신이 receipt를 발행한 입력을 누락하거나 다른 값으로 바꾼 snapshot에 투표하지 않는다.
2. Receipt 발행과 collection close/snapshot vote는 동일 영속 상태기계에서 상호 배타적으로 처리한다. Close 뒤에는 해당 round의 새 receipt를 발행하지 않는다.
3. Receipt나 snapshot hash만으로 충분하다고 보지 않는다. 투표·실행 party가 전체 payload를 확보해야 한다. 필요한 peer 조회·재전송은 마감/close 절차에 포함한다.
4. 동일 digest에 3명의 receipt가 있는 입력은 3-of-4 snapshot quorum의 교집합에 정직한 receipt 발행자가 존재하므로 이를 누락한 입력 인증서와 양립할 수 없게 만든다.
5. 서버만 받은 입력이나 한 party만 받은 입력에는 동일한 포함 보장을 주장하지 않는다. 불완전 receipt의 재전파·확정 실패·타임아웃 정책을 명시한다. 수신증명은 모든 client에 대한 무조건 참여 공정성 또는 BFT liveness를 제공하지 않는다.

위 교집합 논리가 성립하려면 receipt 서명·payload 보존·상충 투표 거부·close 뒤 receipt 금지가 모두 필요하다. 로컬 wall-clock timeout을 글로벌 부재 증명으로 취급하지 않는다. Collection window와 close proposal을 context에 묶고, 실제 배포의 통신·시간 가정을 기록한다.

**구현 결과:** `collect-open`/`collect`/`submission`/`receipt` RPC, SQLite `collections`/`submissions`/`collection_proofs`, atomic `prepare`를 구현했다. 모든 present 입력에 receipt QC를 요구해 마감 후 증명 없는 payload를 끼워 넣는 경로도 거부한다. 부분집합은 각 party의 영속 마감 이후, 전원 입력은 조기 close 가능하다. Clock은 DB lock 획득 뒤 읽으며 API timestamp override는 허용하지 않는다. 저장된 receipt 재조회는 마감 후에도 가능하다. 정확한 구현·한계·검증은 단계 2 보고서에 기록했다.

완료 조건: quorum receipt가 있는 입력의 누락/교체, receipt 발행과 close의 경쟁, close 이후 늦은 업로드, 상충 snapshot이 거부된다. 서버의 응답 누락이 다른 정상 client의 산술을 바꾸지 않고, 진행 실패는 명시적으로 보고된다.

## 5. 단계 3 — Flower timeout·비차단 commit·복귀 동기화

`seed_mpc_server_app.py`의 모든 요청을 일괄 `len(replies)==4`로 검사하는 경로를 단계별로 분리한다. 초기 등록은 이번 범위에서 전원 필요, 학습 제출은 마감까지 완전한 입력 수집, aggregator native 실행은 여전히 전원 필요다.

인증 결과 적용 후 client commit ACK는 다음 라운드의 필수 조건으로 삼지 않는다. ACK가 없어도 확정 모델을 rollback하지 않는다. 제품 경로의 중복 commit 전송을 제거하고 재전송의 exactly-once 검증은 fault fixture에서 수행한다.

복귀 client에게 마지막으로 인증한 head 이후 결정 체인을 제공한다. 각 결정의 입력/결과 인증서, parent, 정책·모델 hash를 순서대로 검증하고 현재 모델로 동기화한 뒤 다음 round 학습을 허용한다. Snapshot에 자기 입력이 없었던 결정도 검증할 수 있어야 한다. 인증 abort도 head를 전진시키고 모델을 유지한다. 적용 완료한 결정의 재전송은 안전하며, chain gap·다른 parent·변조 모델·상충 결정은 거부한다.

기존 native 세션과 client seed/ledger가 유지되는 등록 후 dropout/복귀에는 키 재등록을 요구하지 않는다. Native secret state가 사라진 재시작은 별도 문제이며 자동 share 복구로 처리하지 않는다. 새 세션에서 같은 raw 업데이트를 재사용하는 것에 대한 전역 방지는 이 작업만으로 제공되지 않는다.

**구현 결과:** V2에서 도착한 reply를 즉시 검증·receipt 저장하고 마감 뒤 subset을 확정한다. Commit은 `push_messages`로 한 번 보내며 ACK를 기다리지 않는다. 누락·변조 ACK는 동기화 확인에만 영향을 준다. 다음 train 요청에 필요한 결정 suffix를 전달하고 client는 전체 suffix 검증 후 영속 적용·모델 확인을 수행한다. 완료 결정 replay·늦은 과거 commit은 rollback하지 않는다. 같은 Flower node mapping과 보존된 client/native 세션 범위의 논리적 dropout을 실제 Flower/Ray에서 주입 검증했다. 새 node ID 재매핑·coordinator/native 재시작 복구는 미구현이다. V1 역사적 경로는 보존한다.

수정 대상: `seed_mpc_server_app.py`, `seed_mpc_client_app.py`, `seed_mpc_ledger.py`, `seed_mpc_service.py`, 실험 runner.

완료 조건: 업로드 전 dropout, 전체 업로드 후 dropout, ACK 누락, 여러 round 후 복귀가 공식 Flower 경로에서 작동한다. Client 전원 ACK 부재가 인증된 결과 적용을 막지 않으며, 오래된 모델로 생성한 입력은 새 round로 전용되지 않는다.

## 6. 단계 4 — 초기 비용·라운드 비용을 구분해서 계측

현재 5라운드의 native Global 4126.98 MB는 전체 누적이며 초기 setup을 빼고 측정한 round별 비용이 아니다. 기존 값의 단순 나눗셈 또는 offline 전체 차감으로 새 계측을 대체하지 않는다.

각 party의 누적 byte counter를 동일 실행의 다음 경계에서 수집한다.

- native 시작/연결 완료, 등록 CHECK 완료: 최초 setup 및 등록 비용.
- 각 round 실행 직전과 결과 CHECK 직후: 해당 round native 통신량 delta.
- 세션 종료: shutdown delta와 전체 누적의 일치.

사용 가능한 MP-SPDZ counter API를 확인하고, 필요한 경우 공개 byte counter만 노출하는 최소 관측 hook을 작성한다. secret-dependent state나 입력값은 계측에 포함하지 않는다. 송신/수신 및 합산 규칙을 기록해 같은 링크를 두 번 센 값인지 명시한다. Online/offline은 계산 단계 분류로 유지하며 one-time/per-round 분류와 섞지 않는다.

Flower와 aggregator RPC는 실제 직렬화 message 길이를 별도 기록한다. Application bytes와 transport wire bytes를 구별하고 framing/TLS 등 미측정 overhead를 숨기지 않는다. Native 내부 비용과 별도 외부 입력 socket·Flower/RPC 비용도 구분한다. Compile 1회 시간, 학습 시간, 전체 wall time과 native 시간을 각각 기록한다.

완료 조건: setup + round별 delta + shutdown이 동일 정의의 전체 native counter와 일치한다. 계측만으로 성능 향상을 주장하지 않는다.

**구현 결과:** 원본 공식 설치를 보존하고 `BaseMachine.cpp` 출력만 추가한 별도 승인 build를 만들었다. 패치는 archive에서 다시 유도하고 build/config/binary/shared library/실제 loader 경로를 hash 고정한다. 등록 CHECK와 각 결과 CHECK의 timer 경계, 종료의 정수 Global counter로 정확히 분할하며 live preprocessing을 해당 발생 구간에 포함한다. D65 정상 3라운드 총 4,144,988 bytes, D65 dropout 10라운드 13,641,144 bytes, D170 FMNIST 3라운드 8,127,948 bytes가 setup/round/shutdown 합과 일치했다. Flower는 각 메시지의 실제 deflate 객체 그래프 크기이며 cross-message cache 할인은 적용하지 않는다. RPC JSON은 client/service 양쪽에서 일치했고 최초 external 입력은 별도 기록했다. Compile·ServerApp·service/native·harness wall 및 trusted test client work 시간을 구분했다. TCP/TLS 전체 overhead와 native 수신 counter는 미측정이다. 이것을 전체 wire 계측이나 full LeNet5 새 측정으로 표시하지 않는다.

## 7. 단계 5 — 역할 격리와 실제 악성 경로 검증

로컬 단일 UID 학습은 기능 기준선이다. 프라이버시 검증용 배치는 server/client/aggregator별 독립 OS 사용자 또는 충분히 분리된 runtime을 사용하고, 다른 역할의 secret 디렉터리를 읽을 수 없도록 한다. 공유 호스트 관리자까지 방어한다고 주장하지 않는다.

Client는 자신의 권한 안에서 seed를 생성·보관하고 일반 모드에서는 raw audit을 기록하지 않는다. Trusted test audit은 별도 명시 모드에서만 활성화하며 제품 경로로 전달·archive하지 않는다. 신뢰된 테스트 bootstrap이 키를 다루는 경우에도 이를 실제 독립 client 보장으로 제시하지 않는다.

공격 시험은 계층별로 구분한다.

- Coordinator: 입력/receipt 누락·교체, 상충 snapshot, stale model, 이전 결과 재생, threshold 교체, ACK 누락과 잘못된 복귀 chain.
- Client: malformed 등록, 상충 signed 입력, 범위 밖 좌표, 분산된 global norm 초과, partial upload, counter 재사용.
- 실제 악성 native party: custom/변조 party 실행으로 등록·공개 사본·곱셈/변환/출력 경계의 불일치와 selective abort를 시험한다. Python adapter의 public input 거부만으로 악성 native 시험을 대체하지 않는다.
- 보안 계약 밖의 대조: 두 aggregator로 seed 복원이 가능한 공유 구조와, 최종 합에서 알려진 기여를 빼 개인 입력을 얻는 경우를 명시적으로 확인한다.

등록 private-input → arithmetic/binary 변환 → secret AES → 비교·sanitization → 선택·공개·abort의 합성 가정/누출 목록을 작성한다. backend patch와 최종 CHECK만으로 합성 프라이버시를 증명했다고 표시하지 않는다. 테스트 통과와 formal proof를 구분한다.

완료 조건: API 전달 비공개와 OS 권한 격리를 각각 검증하고, 실제 악성 native 시험의 성공/거부/남은 범위를 공개 자료로 남긴다. 해결되지 않은 등록·변환·abort 누출 문제가 발견되면 전체 모델 재학습보다 먼저 해당 경로를 수정한다.

## 8. 단계 6 — 전체 FMNIST 최종 통합 검증

작은 실제 Rep4 fixture와 Flower fault regression을 먼저 통과시킨다. 이후 D=61706 LeNet5에서 다음 두 실행을 별도로 수행한다.

- 전원 정상 IID 5라운드: 기존 seed42/학습 설정을 유지해 독립 양자화·SUM/count·모델·평가 기준선과 대조.
- 사전에 고정한 dropout/복귀 일정의 5라운드: r1 전원, r2 C3 업로드 전 부재, r3 C2/C3 부재, r4 C3 복귀 및 C1의 전체 업로드 후 ACK 부재, r5 전원 복귀. 각 client의 참가·체인 동기화·정수 기여를 독립 reference로 검증.

통과 수가 부족한 abort와 악성 norm fixture는 작은 회로에서도 별도 검증한다. Dropout 실행의 최종 정확도가 기존 86.24%와 같아야 한다고 요구하지 않는다. 참여와 학습 데이터 기여가 다르므로 **각 일정에 해당하는 독립 산술·모델 결과**가 기준이다.

최종 기록에는 제출자 수, 공개 통과 인원/status, input/result 인증서, 모델 hash, 초기 setup 및 각 round 통신량·시간을 남긴다. 개별 비밀 판정이나 raw 업데이트를 일반 공개 로그에 추가하지 않는다.

## 9. 실행 순서와 보류 항목

순서는 **단계 0 → 단계 1 → 단계 2 → 단계 3 → 단계 4 → 단계 5 → 단계 6**이다. 단계 0~4는 위 진행 갱신의 범위에서 완료했다. 단계 5의 역할 격리와 실제 악성 native 경로 검증은 진행 중이다. 사용자의 요청에 따라 [실험계획](seed-mpc-security-experiment-plan.md)을 추가했으며, wrap·무결성 검증과 범위 내 poisoning의 학습 영향을 별도 결과로 평가한다. 다음 실행은 해당 계획의 작은 프로토콜 fixture 및 평문 poisoning 대조군부터 진행한다.

Flower Hub 게시·publisher 설정, committee 교체, full BFT view change, safe secret-share 복구, 가중 FedAvg, DP 출력, 새로운 threshold 탐지법, 세션을 넘는 전역 재질의 방지는 별도 작업으로 남긴다. 비용 계측 뒤 실제 병목을 기준으로 최적화를 선택하며, 바이트코드는 매 round 다시 컴파일하지 않는다.

