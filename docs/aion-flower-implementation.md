# AION Flower 구현 현황

## 구현 범위

2026-09-12에 승인된 구성은 Flower 서버 1개와 여러 독립 aggregator이다. 기본값은 **고정 cohort의 AION-ASR 연구용 실행 경로**다. 선택적으로 사전 확정된 서로 겹치지 않는 privacy group 단위의 참여와 1라운드 지연 업데이트를 지원하지만, 원 논문 전체나 production 수준의 악의적 참여자 보안을 구현했다고 주장하지 않는다.

| 구성요소 | 상태 | 논문과의 관계 및 제한 |
|---|---|---|
| Flower 연동 | 구현·검증 | `ServerApp`, `ClientApp`, `Message`, `Grid`; Flower 1.36.0 고정 |
| 일회성 VSS | 구현·검증 | Algorithm 1, RFC 3526 group 14의 prime-order subgroup 기반 Feldman 검증 |
| share 전달 | 구현·검증 | aggregator별 X25519/HKDF/AES-GCM 암호화, client 서명, task/recipient/commitment binding |
| mask 생성 | 연구 대체 구현 3종 | 기본 `artifact` scalar 방식, `lwe-reference`(VSS와 같은 2047비트 모듈러스), `lwe-192-reference`(HPRF와 VSS 모듈러스 분리). 벡터 백엔드는 논문 수식의 기능 경로이나 보안 파라미터 검증·감사 없음 |
| ASR | 구현·검증 | Algorithm 3, aggregate commitment 검증 후 `f+1`개 이상의 유효 share로 합계 key만 복원 |
| DMC/DMR | 구현·검증 | Algorithm 7·8, fixed-point 정수와 modular wrap 처리, 반올림 오차 제거 |
| 참여 집합·결과 certificate | 구현·검증 | `n-f`개 서로 다른 Ed25519 서명 및 영속 vote lock. 결과 모델은 별도 `commit` 정족수 인증서까지 다음 라운드에서 검증 |
| HotStuff BFT | 연구용 부분 구현 | 선택형 `hotstuff=true`는 roster/model에 3단계 투표, 영속 prepare/high-QC·잠금 QC, timeout/new-view 정족수를 적용한다. 기본 및 legacy `leader_views` 모드는 이와 별도이다. threshold signature 압축 및 부분 동기 liveness의 포괄 검증은 미제공 |
| aggregator P2P 전송·복구 | 제한형 별도 프로세스·루프백 검증 | `aion-peer`가 고정 Ed25519 identity, task/recipient binding, 암호화, 서명된 수신 확인, 프레임 크기 제한 및 프로세스 내 replay 검사를 제공. 고정 cohort에서는 client update 이중 전달·peer 간 결손 조회·roster/model 정족수와 결정 증거 복구에 사용한다. `hotstuff=true`의 peer 투표와 leader 장애 후 다음 view 전환, MGF 동적 roster 복구도 통합 시험을 통과했다. 실제 SuperNode 병행 배포와 임의 부분 동기 스케줄 검증은 별도 |
| CCS/VRF | 미구현 | 논문의 비공개 추첨 및 적응형 공격 방어 없음. 대신 사전 확정된 서로 겹치지 않는 privacy group 전체만 선택적으로 집계 |
| AMR | 미구현 | 집계 key를 공개하지 않는 reconstruction 및 HPRF share decoding 필요 |
| MGF | masked classifier 공식 Flower 실행 완료; 전체 차원 비용·보안 한계 남음 | classifier 840좌표 검사와 전체 61,706좌표 ASR 집계, 수신자 share 입장 정족수, fresh per-round 키, Pedersen mask 합 복원을 구현. 원본식 percentile 및 전체 후보 mask norm 기반 threshold를 연결했다. N=500/q=100 1라운드와 N=100/q=20 공격·회복 4라운드 및 무방어 대조군 완료. 개별 probe/update 일치 증명·bounded-mask privacy·60라운드 재현은 미완료 |
| EMA | 제한형 구현·검증 | 선택된 privacy group 전원이 다음 라운드에 도착할 때만 별도 ASR로 이전 라운드 delta 평균을 복원하고 `ema_weight`로 반영. 임의의 부분집합·장기 지연은 미지원 |
| FL workload | 구현·검증 | 합성 non-IID NumPy least-squares, MNIST softmax, 공식 checkpoint 기반 FMNIST/LeNet5 정상·model-replacement 학습. 공식 Flower Runtime의 N=500/q=100 10라운드 공격·네 경로 비교와 별도 oracle MGF→AION 집계 비교 완료; 논문 60라운드와 보안 MGF 곡선은 미완료 |
| 악의적 입력의 학습 정당성 | 미보장 | 형식·서명·round는 검증하지만 올바른 mask·local training·poisoning 무해성은 증명하지 않음 |
| 네트워크 배포 | 앱·설정 경로 제공 | 로컬 프로세스 Grid와 FAB 빌드 검증 완료. 실제 SuperLink/TLS 배포 검증은 별도 |

공개 FMNIST 입력 검증 artifact의 `server.py`/`aggregation_rules.py`도 서버가
client별 평문 update를 모아 SHPRG mask를 생성하고 MGF를 계산한다. 따라서
`aion_mgf_oracle`은 해당 **ML 실험 선택 규칙**과 비교할 수 있지만 논문에서
의도한 비공개 분산 MGF의 보안 성질을 구현한 것은 아니다.

테스트 통과는 구현한 연산·상태 전이의 검증이며 privacy 증명이나 암호 감사를 대신하지 않는다.

HotStuff의 AION application 검증은 각 집계자가 한 번 검증한 정확한
`(slot, value, command)`를 자기 서명 증거로 재사용한다. 다른 집계자의 증거,
바뀐 명령·값·slot 또는 서명이 어긋난 증거는 재사용하지 않는다. 증거가
없는 이전 상태는 처음에 다시 검증한다. 이 최적화는 application 입력이
slot과 명령에 고정된 AION 경로에서만 켜며, 범용 `HotStuffSlot`의 기본값은
매번 검증이다. 재사용 모드의 검증 callback은 입력을 변경할 수 없다.
각 투표 단계의 QC·view·double-vote·lock 규칙은 계속 검사한다. 이는 반복
모델 복원 비용을 줄이는 구현 변경이며 HotStuff 전체 진행 보장의 증명은
아니다. 실행 중인 공식 실험 앱 사본에는 사후에 이 변경을 주입하지 않는다.

FMNIST처럼 큰 모델과 여러 client의 update를 한 `prepare` 메시지에 담으면
16MB payload 한도를 넘는다. 이때 Flower 경로는 각 client의 서명 update를
`stage_update`로 aggregator별 영속 파일에 전달하고, 공통 aggregator 정족수가
모두 수신했음을 확인한 뒤 순서와 digest가 묶인 참조 목록으로 roster를 준비한다.
로컬 q=6 시험과 공식 Flower Runtime의 q=100 10라운드 공격 실험에서
정상 집계를 확인했다. 다만 논문의 collect-aggregate-transfer 통신비용과
같다는 주장은 하지 않는다.

공개 `artifact` 마스크 backend의 행렬 열 캐시는 61,706차원 FMNIST 모델을
한 번에 보관할 수 있게 조정했다. 이는 반복 client 평가에서 동일한 공개
열을 다시 해시하지 않게 하는 계산 최적화이며, 마스크 수식이나 보안 성질을
변경하지 않는다. 로컬 마스크 재평가 측정과 캐시 회귀 시험을 완료했고,
Flower N=500/q=100 [2라운드 재실행](./experiments/fmnist-flower-official-cache-two-round-2026-09-29/report.md)에서
기존 실행과 동일한 모델을 확인했다. 두 별도 실행의 첫 두 `train` 요청
합계는 93.54초와 88.71초였지만, 통제된 성능 벤치마크는 아니다.

## Flower 역할 매핑

```text
Flower ServerApp / SuperLink (coordinator, public registry only)
    ├─ ClientApp / SuperNode → client-0: local training + secret m_0
    ├─ ClientApp / SuperNode → client-1: local training + secret m_1
    ├─ ClientApp / SuperNode → ...
    ├─ ClientApp / SuperNode → aggregator-0: only its own share column
    ├─ ClientApp / SuperNode → aggregator-1: only its own share column
    └─ ClientApp / SuperNode → ...
```

Flower의 `ClientApp`는 메시지 수신 앱이라는 transport 역할이다. 이 앱을 실행하는 aggregator는 AION에서 학습 client가 아니며 로컬 학습에 참여하지 않는다. `Parameters`는 client/aggregator identity의 중복을 거부한다.

정상적인 학습·집계 워크플로의 요청은 Flower 서버를 경유한다. 선택형 `aion-peer-addresses`를 client 노드에 설정하면 Flower `ClientApp`에서 학습한 동일한 서명 update를 aggregator 정족수의 암호화된 inbox에도 전달한다. Flower의 학습, `ServerApp`, `ClientApp`, `Grid` 경로는 유지되지만 P2P 메시지 자체에는 Flower의 전송·운영 기능이 적용되지 않는다. 별도 `PeerTransport`는 aggregator끼리 서명된 합의 메시지를 주고받는 **독립 TCP 경로**이며, pinned X25519 수신자 키·임시 송신자 키·HKDF·AES-GCM으로 요청과 응답을 암호화하고 안쪽 Ed25519 서명도 검증한다. `PeerParty`는 인증된 peer의 영속 roster·모델 제안 투표를 조회하고, 인증된 roster에 대한 aggregate share 요청과 검증 가능한 `finalize`·`commit`·`decide`를 Flower `ClientApp`과 동일한 영속 상태에 적용한다.

Flower 서버가 roster 인증서를 남기기 전에 중단되어도 aggregator 정족수가 동일한 roster를 각자 검증·영속 저장했다면, peer가 서명 투표를 모아 인증서를 재구성할 수 있다. `leader_views=true`에서는 추가 `roster-committed` 정족수도 수집한다. 인증된 roster로 aggregate share 정족수를 모으고, 각 aggregator가 독립적으로 복원한 모델의 제안·commit·decision까지 P2P로 완료한다. leader-view 모드는 첫 모델 리더가 응답하지 않으면 인증된 model view-change 투표를 모아 다음 리더를 시도한다. `aion-peer`는 이 복구를 영속 roster 발견 후 기본 5초 대기한 뒤 자동 재시도한다. 이미 모델 제안만 끝난 경우도 두 모드에서 마지막 합의를 복구한다. 4개 중 3개 aggregator가 있어야 성공하며 2개만 있으면 실패한다. 고정 cohort에서 재시작한 Flower coordinator는 `recover` 질의로 peer 증거 정족수를 검증하고 잃어버린 checkpoint를 재구성해 다음 학습 라운드를 진행한다. 손상된 peer 증거 두 개를 거부하는 시험도 있다.

고정 전체 cohort·비-EMA·비-leader-view 모드에서는 Flower가 roster 준비 전에 중단되어도 peer가 전달받은 서명 update로 roster부터 결정까지 진행할 수 있다. 서로 다른 client가 서로 다른 aggregator 정족수에 전달한 경우 `synchronize_inbox()`가 결손 업데이트를 조회한다. 준비 요청도 원래 client 서명을 포함해 다른 peer에게 중계한다. 모든 batch는 task·설정·round·parent·client 서명·vector 범위·중복 client를 검증하며, 로컬에 이미 저장한 상충 update가 있으면 batch 전체를 거부한다. aggregator 서명만으로 client update를 만들 수 없다. 서로 다른 3/4 전달 정족수, 불완전한 inbox에서의 재시작, 한 aggregator의 지속 장애, 후속 라운드 자동 복구를 통합 시험으로 확인했다. 학습 자체는 계속 Flower ClientApp에서 수행한다.

이 동기화는 정직한 update 보유 peer 사이의 통신이 복구되어야 진행한다. MGF에서 norm-valid 후보 2개 중 깨진 share 때문에 입장 후 2개가 남지 않으면 peer 인벤토리를 유한 timeout까지 모두 다시 조회해 다른 peer의 정상 update를 찾는다. client가 상충 update를 서명한 경우의 Byzantine reliable broadcast는 구현하지 않았다. MGF 동적 roster는 `hotstuff=true`에서만 peer가 합의할 수 있으며, 임의의 유효 client를 배제하지 않는 공정성까지 보장하지 않는다. legacy `leader_views=true` 또는 EMA 모드의 자동 복구는 roster가 이미 검증된 이후에 한정된다. legacy peer view-change는 유한 model view 체인에 한정된다. `hotstuff=true`는 별도의 영속 잠금과 timeout 정족수를 사용하지만 아직 모든 부분 동기 장애 스케줄을 검증하지 않았다. EMA의 미처리 그룹 상태도 peer 증거만으로 복구하지 않는다. 원격 peer의 legacy model `view_vote` 요청은 인증된 roster와 해당 aggregator의 영속 roster 잠금이 일치할 때만 허용된다. aggregate share 요청도 인증된 roster와 영속 pending lock이 일치해야 하며, 개별 share는 공개하지 않는다. Flower 경로의 share 전달은 서버가 모든 개별 share의 평문을 받지 않도록 end-to-end 암호화한다. 서로 다른 프로세스만으로 독립 trust domain이 만들어지는 것은 아니므로 실제 배포에서는 관리 권한과 파일 접근 권한도 분리해야 한다.

Flower 기본 `FedAvg`가 개별 update를 수집하지 않도록 `AionWorkflow`에서 low-level Message API로 단계를 직접 실행한다. Flower 내장 SecAgg+를 AION으로 이름만 바꾸어 사용하지 않는다.

## 실행 및 검증

```bash
uv sync
uv run aion-demo
uv run aion-demo --clients 6 --aggregators 7 --faults 2 --rounds 5 --dimension 8
uv run aion-demo --clients 4 --privacy-group-size 2 --ema-weight 0.25
uv run aion-demo --clients 4 --mask-backend lwe-reference --hprf-width 8 --rounds 2
uv run aion-demo --clients 4 --mask-backend lwe-192-reference --hprf-width 8 --rounds 2
uv run aion-demo --clients 4 --mask-backend lwe-reference --hprf-width 8 --hprf-input-bits 128 --rounds 2
uv run aion-demo --clients 3 --dimension 2 --rounds 2 --mgf-beta 0.2 --mgf-initial-alpha 0.2 --mgf-initial-bound 5 --mgf-initial-term 1
uv run aion-demo --leader-views --rounds 2
uv run pytest -q
uv run flwr build
```

기본 실행은 server 1개, client 4개, aggregator 4개, `f=1`, `t=f+1=2`, certificate quorum `n-f=3`, 3 rounds이다. `--aggregators 1 --faults 1`은 오류로 거부한다.

`ProcessGrid`는 각 노드의 실제 Flower ClientApp을 별도 프로세스에서 실행하고, Flower protobuf로 직렬화한 요청과 응답을 pipe로 운반한다. 서버는 실제 ServerApp 진입점을 실행한다. 이 테스트 transport는 Flower SuperLink나 Ray simulation runtime을 실행하는 것은 아니다.

기본 데모의 합성 데이터 loss 예:

```text
round 0: 0.9383557396
round 1: 0.7578176379
round 2: 0.6121430808
round 3: 0.4945502898
```

합성 데모의 모든 client는 32개 sample을 사용한다. 각 round에서 delta를 동일 가중 평균해 이전 model에 더한다. sample 수가 다른 실제 학습에 맞게 바꿀 경우 공개/비공개 weighting 정책을 먼저 정의해야 한다.

MNIST 실험은 client당 15,000개의 실제 학습 이미지를 사용한다.
[실험 실행 방법](../experiments/README.md#mnist-전체-데이터-실험)을 참고한다.
node-local 설정으로 선택한 trainer를 `Party`에 주입하며, 서명·마스킹·집계 경로는 같다.

## 코드 구성

| 파일 | 책임 |
|---|---|
| `trustlessfl/crypto.py` | Feldman VSS, commitment 합산, 검증·보간, identity 서명, share 암호화 |
| `trustlessfl/numeric.py` | 연구용 mask backend, fixed-point DMC/DMR, 별도 MGF 수치 모듈 |
| `trustlessfl/lwe_parameters.py` | 인용된 LWE-HPRF 정리의 키 폭·잡음 상한 및 Regev 환원 조건의 공통 구간 존재 여부를 정수 연산으로 검사; 보안성 증명은 아님 |
| `trustlessfl/protocol.py` | 독립 Party 상태 기계, 초기화·학습·roster 합의·ASR·결과 인증 |
| `trustlessfl/client_app.py` | Flower 메시지 처리, local manifest/identity, 영속 상태와 lock |
| `trustlessfl/workflow.py` | discovery, Message 전송, certificate 수집, round 실행 |
| `trustlessfl/server_app.py` | Flower ServerApp, 최종 ArrayRecord 및 certificate history |
| `trustlessfl/local_grid.py` | 독립 프로세스용 local Grid, protobuf round-trip |
| `trustlessfl/demo.py` | 합성 데이터 데모와 연구용 identity provisioning |
| `trustlessfl/task.py` | 교체 가능한 local dataset와 trainer |
| `trustlessfl/mnist.py` | MNIST softmax local SGD, shard 분할과 평가 |
| `experiments/run_mnist.py` | 전체 MNIST IID/non-IID 실험 및 일반 집계와 비교 |
| `tests/test_aion.py` | 암호 연산·변조·재시도·집합 변경·multi-round·Flower 앱 테스트 |

## 메시지 순서

```text
hello → enroll → initialize → model certificate (round 0)

매 round:
train(previous model certificate)
  → signed masked updates from the fixed cohort or complete privacy groups
prepare(updates, previous model certificate)
  → roster certificate (n-f matching votes)
share(roster certificate)
  → signed aggregate shares
finalize(roster certificate, aggregate shares)
  → independent reconstruction and model certificate
commit(model certificate)
  → n-f commit acknowledgments → commit certificate
  → next-round client/aggregator verifies both model and commit certificates
```

각 aggregator는 client 서명, model parent hash, vector 차원과 field 범위, 사전 확정된 privacy group의 완전성을 확인하고서만 roster vote를 발급한다. 해당 roster의 정족수 certificate를 받아야 집계 share를 공개한다. 결과는 각 aggregator가 독립적으로 계산하고 서명한다.

client는 같은 round에 대한 요청을 cache하고 재시도 시 동일한 signed update를 반환한다. 다른 model parent를 사용한 재요청은 거부하며, 다음 round의 인증 model은 자신이 직전에 학습한 model을 parent로 가리켜야 한다. aggregator는 `(task, phase, round)`별 값을 lock하여 상충 proposal에 두 번 서명하지 않는다. state 파일을 `0600`으로 저장하고 atomic replace와 fsync를 완료한 뒤 응답한다.

라운드 0의 모델은 초기화 정족수 서명으로 확인한다. 이후 모델은 결과 정족수 서명만으로는 다음 라운드에 사용하지 않고, 동일 모델 해시를 가리키는 별도 `commit` 정족수 서명을 요구한다. 모든 모드의 aggregator는 자신의 commit *투표*만으로 `last_model`을 전진시키지 않는다. commit 정족수 인증서가 붙은 모델을 `decide`로 받은 뒤에만 영속 상태를 갱신하고, coordinator는 `n-f`개의 decision 확인을 수집한 뒤 다음 라운드를 시작한다. 체크포인트도 decision 정족수 증거를 요구한다. 이는 coordinator가 아직 commit되지 않은 결과를 다음 라운드에 배포하는 일을 막지만, 부분 동기 네트워크에서의 진행 보장을 제공하는 HotStuff 전체 구현은 아니다.

집계 및 commit 정족수 수집은 기본 3회까지 동일한 signed 요청을 재시도한다. 각 노드는 재시도 시 기존 vote lock과 signed 결과를 재사용하므로 일시적 응답 손실은 복구할 수 있다. 이는 **view-change가 아니며**, Flower coordinator 또는 다수 노드가 응답하지 않으면 라운드는 중단된다.

`leader_views=true` 모드에서는 roster/model 단계에 대해 aggregator 순서의 leader가 먼저 signed proposal을 만든다. 다른 aggregator는 leader 서명과 자신이 독립 계산한 값을 비교한 뒤 투표한다. leader가 응답하지 않거나 제안이 거부되면 각 aggregator가 `(task, phase, round, view, 직전 인증값)`에 묶인 view-change vote를 서명하고, `n-f`개 증거를 모아 다음 leader에게 제안 기회를 준다. 두 번째 이상 교체에서는 이전 view들의 연속된 정족수 인증서를 요구한다. roster/model certificate에 leader proposal과 전체 view-change 증거를 포함하여 소비 노드도 이를 검증한다. 이 모드에서는 roster 투표 정족수에 더해 별도 `roster-committed` 정족수를 요구하며, 이 증거 없이는 share를 방출하지 않는다. 기존 영속 vote lock은 view가 바뀌어도 동일 슬롯의 상충 결과에 서명하지 못하게 한다. 이는 **HotStuff 전체 구현이 아니다**. P2P가 없는 실행은 Flower coordinator 중단 시 멈추며, P2P를 켠 경우에도 model 단계의 유한 view 체인만 복구한다. 부분 동기 조건에서 모든 정상 노드의 view를 동기화하는 전체 pacemaker는 아직 없다.

`hotstuff=true`는 legacy `leader_views`와 별도로 roster·모델에 Basic HotStuff의 prepare, pre-commit, commit 투표를 적용한다. 각 노드는 `(phase, round, 인증된 이전 값)` 슬롯별로 현재 view, prepare-QC, 잠금 QC, 서명한 값과 결정 QC를 같은 영속 파일에 기록한 뒤 응답한다. 새 리더는 `n-f`개의 서명된 new-view 보고서 중 가장 높은 prepare-QC의 값을 이어받고, 서명된 timeout 정족수가 있어야 다음 view에 진입할 수 있다. 인증된 commit-QC가 붙기 전에는 AION roster·모델 투표를 발행하지 않는다. Flower `Grid` 조정과 aggregator P2P sidecar가 이 동일한 상태 전이를 사용한다. 리더가 없는 상태에서 Flower 중단 후 P2P의 나머지 3개 aggregator가 다음 view로 확정하는 TCP 시험을 통과했다. 첫 상태 조회 직후 peer가 인증된 높은 view로 진입해 현재 view의 timeout 정족수가 모이지 않으면 상태를 재조회해 높은 view에 합류한다. 높은 view의 드라이버 대기는 노드의 지수형 timeout과 일치시키고, 대기 중에도 인증된 더 높은 view나 결정을 확인한다. 해당 응답 순서를 단위 시험으로 검증했다. 이는 AION 논문 §2.3의 안정된 리더용 두 투표 라운드보다 한 단계를 더 사용하는 안전 우선 경로다. 메시지에 개별 Ed25519 정족수 서명을 담으므로 논문의 상수 크기 threshold signature 통신량은 달성하지 않는다. 부분 동기 네트워크의 일반적 진행 보장, 임의의 Byzantine 스케줄과 프로세스 재시작 조합에 대한 검증은 아직 끝나지 않았다.

영속 타이머는 Linux boot ID로 `monotonic` 시계의 epoch를 확인한다. Flower/P2P 프로세스만 재시작하면 같은 view의 만료 시간을 유지하고, OS 재부팅 뒤에는 타이머를 새로 시작한다. boot ID를 읽을 수 없는 플랫폼에서는 `hotstuff=true`를 거부한다.

Flower `ServerApp`은 확정된 라운드마다 `Context.state["aion-checkpoint"]`에 인증서 history와 EMA 지연 그룹 상태를 저장한다. 재시작 시 task·연속 모델 체인·commit·decision 정족수와 지연 업데이트 서명을 검증한 뒤 다음 라운드부터 이어간다. 고정 cohort에서는 이 체크포인트가 없더라도 peer 정족수가 영속 저장한 decision 증거가 있으면 Flower `recover` 질의로 잃어버린 history를 재구성한다. EMA의 미처리 그룹 상태는 이 peer 증거에 포함되지 않으므로 이 경로로 복구하지 않는다. P2P가 전달된 업데이트나 영속 제안의 합의를 마칠 수 있는 범위는 위 역할 매핑을 따른다. 서버 중단 중 새로운 client 학습을 자동 시작하는 기능과 전체 pacemaker는 아직 없다.

state는 task ID별로 분리한다. 완료된 task를 `workflow.run`으로 처음부터 재실행하면 정상적인 새 학습으로 진행하지 않는다. 새 실험에는 새 provisioning과 task ID를 사용한다. 복구 중 투표 lock을 삭제하거나 과거 backup으로 되돌리면 안전성 전제가 깨진다. 일반적인 crash recovery 및 서버 측 resume orchestration은 아직 제공하지 않는다.

현재 wire claim은 `aion-asr-research-v2`이며 모든 서명과 certificate에 전체 공개 프로토콜 파라미터의 해시를 포함한다. 서로 다른 mask backend, privacy group 또는 EMA 설정을 가진 노드가 같은 task ID에서 투표를 혼합할 수 없다. 이전 `v1` task의 state/certificate와 호환되지 않으므로 새 task ID와 provisioning이 필요하다.

## ASR, privacy group 및 EMA

ASR은 `M = sum(m_i) mod ORDER`를 공개한다. 서로 다른 참여 집합의 key 합을 공개하면 차분으로 개인 key가 드러날 수 있다. 기본값은 모든 round에 **동일하게 초기화된 client 전원**이 참가해야 한다. `privacy_groups`를 설정한 경우에는 그룹 전체가 응답했을 때만 포함하고, 일부만 응답한 그룹의 key 합은 공개하지 않는다. 각 라운드의 참여 집합은 사전 확정된 그룹들의 합집합이어야 한다.

기본 고정 cohort에서는 정확히 같은 집합만 반복 사용한다. 그룹 모드에서는 공개되는 각 key 합이 사전 확정된 그룹 key 합의 선형 결합이므로, 그룹을 쪼개는 key 합의 차분은 만들지 않는다. **이는 그룹 내부의 충분한 비공모 client가 존재한다는 가정에 의존하며 논문의 CCS/VRF 대안이나 연구 HPRF의 안전성 증명이 아니다.** 적대자가 한 그룹의 다른 client 전부와 공모하면 남은 client key를 추론할 수 있다. 다른 task에서 기존 client secret을 재사용하면 안 된다.

`ema_weight > 0`이면 직전 라운드에서 누락된 그룹 전원의 signed update가 다음 라운드에 모였을 때만 `late-roster → late-aggregate-share → late-delta` 인증 경로를 실행한다. 이미 직전 집계에 포함된 client는 late roster에 다시 들어갈 수 없다. 복원한 이전 라운드 delta의 평균에 `ema_weight`를 곱해 현재 delta 평균에 더한다. 그룹이 끝내 완성되지 않으면 늦은 update를 버린다. 클라이언트가 라운드를 건너뛴 뒤 돌아오면 인증된 모델 전체 경로와 이전 학습 해시의 연속성을 검증한다. 이는 논문 Algorithm 9의 임의 지연 client 집합보다 제한적이다.

## HPRF 및 수치 처리의 차이

확인한 공식 artifact 경로는 `Aion/agent/Aion/HPRF/hprf.py`이다. 그 코드는 matrix column sum에 scalar key/round를 곱하고 modulus conversion으로 반올림한다. 기본 `artifact` 백엔드에서는 해당 연산 형태를 독립적으로 작성하고 다음을 변경했다.

- pickle로 공개 matrix를 읽지 않고 task별 SHAKE-256으로 공개 column coefficient를 생성
- VSS scalar field와 mask key field를 같은 `ORDER`로 통일
- 출력 modulus를 `2^128`로 명세
- NumPy int64 대신 Python arbitrary-precision integer 사용
- task와 round를 명시적으로 결속
- masked value의 합·차는 output modulus에서 계산하고 signed 값으로 decode

이는 논문 §2.2의 안전한 LWE-HPRF를 검증하여 구현한 것이 아니다. 반올림 key homomorphism과 집계 mechanics만 재현한다. 일반 PRG/HMAC을 homomorphic PRF라고 주장하지 않으며, `research-mode=true` 없이는 실행을 거부한다. mask 수치 연산이 맞는다는 테스트만으로 privacy가 입증되지는 않는다.

선택형 `lwe-reference` 백엔드는 논문이 인용한 Boneh–Lewi–Montgomery–Raghunathan 구성의 `F(k,x)=round((A_{x_1}⋯A_{x_l})k mod q)` 형태를 구현한다. 벡터 키의 각 좌표를 한 번씩 Feldman VSS로 공유하고, aggregator는 해당 좌표별 aggregate share와 commitment를 검증·복원한다. 공개 이진 행렬 2개는 task별 SHAKE에서 결정적으로 도출한다. 기존 32비트 입력은 SHA-256을 잘라 만들므로 서로 다른 round/block이 충돌할 수 있다. 새 LWE task는 기본적으로 64비트 round와 64비트 block을 연결한 128비트 입력을 사용한다. 기존 인증서를 재현할 때만 `--hprf-input-bits 32`를 명시한다. 이 입력 길이는 설정 해시에 결속돼 32비트와 128비트 task의 인증서를 섞을 수 없다. `lwe-192-reference`는 같은 경로에서 HPRF 모듈러스만 별도의 P-192 소수로 사용한다. 집계 키를 VSS 필드에서 복원한 뒤 P-192로 환원하며, 클라이언트 키 합이 VSS 필드를 넘지 않는 범위에서 정확성을 시험한다. 기본 width 8은 두 백엔드 모두 **기능 테스트용이며** 논문의 `m=n⌈log q⌉` 관계와 LWE hardness parameter, 행렬 분포의 보안 증명 조건을 충족한다고 주장하지 않는다. 128비트 입력도 이 결함을 해결하지 않으며 순수 Python 연산은 constant-time도 아니다. 따라서 이 모드 역시 사적인 실데이터에 사용하면 안 된다.

각 local delta는 기본 소수 4자리로 양자화된다. `padding = 10^ceil(log10(2q))`를 곱한 정수에 mask를 더한다. 집계 후 signed modular 차를 padding으로 나누어 최근접 정수로 반올림한다. q개 mask의 작은 반올림 오차를 제거한 뒤 scale과 client 수로 나누어 mean delta를 얻는다.

MGF는 bounded real-valued masked gradient의 norm을 검사하는 알고리즘이다. 기본 modular residue에는 적용하지 않는다. 별도의 선택형 `mgf_beta` 모드에서는 client가 매 라운드 새 HPRF 키와 실제 bounded mask의 검증 가능한 비밀 share를 aggregator별로 암호화한다. signed fixed-point vector를 Flower가 먼저 norm으로 거르고, aggregator는 각 update의 자기 share를 독립 검증한다. `mgf_admit` 정족수를 얻지 못한 update는 roster 잠금 전에 배제해, 한 client의 깨진 암호문이 정상 업데이트의 집계를 막지 않도록 한다. 인증된 roster의 mask 합만 복원해 정확히 제거하며, 그 합은 ASR 키 합에서 계산한 HPRF 출력과 출력 링의 carry·반올림 허용 범위 안에서 일치해야 한다. ASR 키 합은 동적 bound의 mask 항에도 사용한다. 모델 인증서에 다음 alpha, bound 및 이전 항을 포함한다. 초기 값은 manifest에서 명시한다. `hotstuff=true`에서는 Flower 중단 뒤 peer inbox의 유효한 update로 동적 roster부터 집계를 복구할 수 있다. `MaskedGradientFilter` 단위 모듈은 이 wire 모드와 별개다.

기본 출력 ring의 마스크가 거의 균등하면 `y = x + h (mod 2^128)`의 분포는 정상 `x`와 중독된 `x`를 거의 구별하지 못한다. `y`를 unsigned 정수로 읽으면 `-1`에 해당하는 잔여값 `2^128-1`의 norm이 거대해지는 등 실수형 norm과도 다르다. MGF 모드는 별도의 signed wire여서 이 오류를 피한다. 그러나 작은 bounded mask는 가능한 입력 범위를 드러낼 수 있다. 집계 일치성 검사는 상쇄되는 client별 오류를 찾지 못하므로, 악성 client가 제출한 mask share와 자기 HPRF 키의 관계는 아직 증명하지 않는다. 라운드별 새 키는 과거 key 합 차분을 막지만 CCS/VRF의 전체 적응형 공격 분석을 대체하지 않는다. per-coordinate VSS/암호문 통신량도 논문보다 크다. 이 모드를 사적인 실데이터 보안으로 취급하면 안 된다.

FMNIST 전용 `aion_mgf_oracle`은 위 `mgf_beta`와 **다른, 프라이버시 비보장 연결 시험**이다. client가 classifier 층 840개 평문 delta를 서명된 update에 추가하고 Flower coordinator가 원본 artifact MGF의 선택 규칙을 적용한다. 선택된 client의 전체 모델 delta는 매 라운드 새로 공유한 ASR 키로 마스킹·집계하고, aggregator는 수신자별 암호화 키 share를 검증한다. 이로써 좌표별 Pedersen mask share 비용 없이 MGF 선택 다음의 AION roster·집계·결과 인증 경로를 시험할 수 있다. 다만 coordinator가 개별 classifier delta를 알며, 공개 delta가 masked 전체 update의 해당 좌표와 같다는 영지식 증명도 없다. 공격 client가 거짓 classifier를 서명해 필터를 우회할 수 있으므로 이를 안전한 AION-MGF 구현이나 논문의 프라이버시 달성으로 표시하지 않는다.

공식 FMNIST 실행기에 추가한 실험 옵션 `--modes aion_mgf_beta`는 위의
전체 차원 bounded-mask wire를 사용한다. **전체 차원 MGF**로 완료된 FMNIST 결과는 없다.
2-client 실행은 10분 넘게 첫 업데이트를 계산해 종료했고, 기존 표현의
기존 share 재료는 client당 약 693MiB로 추정됐다. 수신자별 벡터 암호화로
64좌표에서 재료 크기를 65.7% 줄였지만, 전체 차원은 약 233MiB로 추정돼
여전히 16MiB payload 한도를 넘는다. 기존 좌표별 packet도 읽을 수 있다.
계산에는 선택형 `fast-crypto` extra의 GMP 가속을 추가했으며, 메시지 분할
전달은 Flower 경로에서 4MiB 조각으로 구현했고, 큰 요청·응답·staging 후 roster를
ProcessGrid에서 검증했다. 전체 차원 MGF의 계산·메모리 비용은 여전히 남아 있다.
classifier projection 경로는 [q=100 1라운드](./experiments/fmnist-flower-masked-percentile-paper-scale-one-round-2026-09-30/report.md)와
[원본식 threshold 4라운드](./experiments/fmnist-flower-masked-artifact-bound-four-round-2026-09-30/report.md)를 완료했다.
[전체 차원 측정 및 실행 기록](./experiments/fmnist-mgf-wire-feasibility-2026-09-30/report.md)은
이 projection 실행과 구분한다.

MGF 최종 집계는 signed envelope를 로컬 복사한 뒤 roster·두 VSS 계열의
모든 share를 검증하고, 같은 함수 범위에서 승인된 mask 값만 보간한다.
기존처럼 동일 Pedersen share를 복원 직전에 다시 검증하지 않는다.
공개 집계자 인덱스의 보간 계수만 bounded cache에 저장하며, 비밀 share나
검증 verdict를 전역 캐시하지 않는다. 840좌표·4집계자의 로컬 합성 입력에서
기존 검증+복원 32.03초, 통합 경로 15.77초를 측정했고 복원 정수는 완전히
같았다. 이는 P2P 회귀 시험과 동시 실행한 단일 microbenchmark로, Flower
전체 라운드 속도나 논문 대비 성능을 나타내지 않는다. 공식 실험의 기존
시간 기록을 이 값으로 교체하거나 재측정 결과처럼 표시하지 않는다.

MGF 입장 검사와 prepare 사이에는 수신자 자신의 검증한 share를 로컬
상태에서 재사용한다. 캐시 증거는 해당 집계자가 서명하며 task·설정·round·
parent·정확한 signed update hash·share 값의 hash에 결속된다. 다른 집계자의
입장 표를 캐시 증거로 취급하지 않으며, client 서명·norm·alpha·probe 검사는
매 요청에서 유지한다. 로컬 캐시는 최대 32개, 항목당 직렬화 2MiB 이하이고
결정 후 삭제한다. ClientApp 재생성 시에도 자기 VSS share와 동일한 0600
권한의 로컬 상태 파일에서 읽는다. 이는 집계자 자신의 비밀 share를 임시로
추가 보관하는 최적화이며, 파일 접근 권한이 다른 trust domain과 실제로
분리된다는 새로운 보안 보장이나 전체 Flower 실행 속도 측정은 아니다.

## Flower 네트워크 배포 연결 방법

FMNIST 선택형 `aion_mgf_beta --mgf-projection`은 원본 입력 검증처럼
classifier weight 840개 좌표만 bounded mask로 검사하고, 전체 모델은
modular ASR로 집계한다. 검사 벡터의 복원 합과 전체 ASR 결과의 해당
좌표를 비교한다. N=q=2 공식 Flower 1라운드를 약 105초에 완료했고,
개별 classifier 평문 필드 없이 실제 서명 update를 약 5.8MB로 줄였다.
[실행 기록](./experiments/fmnist-flower-masked-classifier-mgf-one-round-2026-09-30/report.md)에
초기 bound와 원본 percentile 규칙의 차이를 명시했다. q=100 공격 실험과
개별 probe/update 일치 증명은 남아 있다.

아래는 합성 데이터 연구 배포를 위한 설정이다. 실제 SuperLink 통신·TLS는 이 변경에서 end-to-end 검증하지 않았으며, 검증한 실행 경로는 위 ProcessGrid이다.

새 키 세트 생성:

```bash
uv run aion-demo --provision-only .aion
```

이 명령은 기존 디렉터리를 덮어쓰지 않는다. 생성되는 공개 `manifest.json`은 각 노드에 고정하고, client/aggregator별 디렉터리는 해당 노드에만 배포한다. server에는 manifest만 제공한다. `.aion`은 git 및 FAB 대상에서 제외된다.

로컬 테스트용 SuperLink:

```bash
uv run flower-superlink --insecure \
  --fleet-api-address 127.0.0.1:9092 \
  --control-api-address 127.0.0.1:9093 \
  --disable-runtime-dependency-installation
```

각 노드에서 자신의 경로로 교체하고 SuperNode를 실행한다. 같은 머신에서 여러 개를 실행하면 Runtime API port를 서로 다르게 지정한다.

```bash
uv run flower-supernode --insecure --superlink 127.0.0.1:9092 \
  --host 127.0.0.1 --port 9094 \
  --node-config 'aion-manifest="/absolute/path/manifest.json" aion-identity="/absolute/path/client-0/identity.json"'
```

client-0부터 client-3, aggregator-0부터 aggregator-3까지 총 8개 SuperNode를 구성한다. aggregator의 경로만 바꾸면 동일 앱이 aggregator 역할로 작동한다. client가 aggregator 역할을 겸하지 않는다.

선택형 aggregator peer handler는 Flower SuperNode와 **별도 프로세스**로 실행하되, 해당 aggregator의 동일한 manifest·identity 경로를 사용한다. 예를 들어 `aggregator-0`의 peer 주소 파일에는 다른 aggregator만 `{"aggregator-1":["127.0.0.1",9191],"aggregator-2":["127.0.0.1",9192],"aggregator-3":["127.0.0.1",9193]}` 형태로 기록한다. 각 peer에도 자신을 제외한 전체 aggregator 주소를 제공한다.

```bash
uv run aion-peer --manifest /absolute/path/manifest.json \
  --identity /absolute/path/aggregator-0/identity.json \
  --peers /absolute/path/aggregator-0/peers.json --port 9190
```

기본 설정은 loopback만 허용한다. `--allow-insecure-network`는 비-loopback 연구망에 한해 별도 명시적 허용을 요구하는 호환성 플래그다. peer 메시지에는 애플리케이션 계층 암호화가 적용되지만 구현이 보안 감사를 받았거나 운영 배포에 적합하다는 뜻은 아니다. 이 handler는 제한된 model view-change와 전달된 update의 합의를 진행하며 새 client 학습은 시작하지 않는다.

선택형 이중 전달을 사용하려면 학습 client의 node-config에 `aion-peer-addresses="/absolute/path/all-aggregators.json"`을 추가한다. 이 파일에는 **모든** aggregator 이름과 `[host, port]`를 넣는다. aggregator용 `--peers` 파일은 자신을 제외하므로 client 주소 파일과 다르다. `train`은 로컬 학습 결과를 먼저 영속 저장한 뒤 이 주소로 동일한 signed update를 보내며, `n-f`개의 서명된 수신 확인을 받아야 Flower에 성공 응답한다. 정족수 실패 시 재시도는 캐시한 동일 업데이트를 사용한다. 옵션을 끄면 Flower-only 전달 경로가 유지된다. P2P 메시지의 인증·암호화·재시도는 이 별도 계층의 책임이며 Flower 전송 설정으로 자동 관리되지 않는다.

Flower 1.36은 SuperLink 접속 설정을 Flower config 파일에서 읽는다. `uv run flwr config list`로 위치를 확인한 뒤 다음 profile을 추가한다.

```toml
[superlink.aion-local]
address = "127.0.0.1:9093"
insecure = true
```

서버에 존재하는 manifest의 절대 경로로 실행한다. `aion-manifest`를 run config로 넘길 수 있도록 pyproject에 기본값을 선언해 두었다.

```bash
uv run flwr run . aion-local \
  --run-config 'aion-manifest="/absolute/path/manifest.json" num-server-rounds=3 research-mode=true' \
  --stream
```

외부망 배포에서는 Flower의 TLS 및 SuperNode authentication을 구성하고 각 SuperNode의 Runtime API는 localhost에 둔다. 서버가 배포하는 앱 코드까지 악의적으로 바꿀 수 있으면 로컬 secret을 읽을 수 있으므로, 독립 운영자는 검토한 앱 bundle만 실행하도록 신뢰하는 publisher/bundle 정책도 설정해야 한다. application signature 검증만으로 원격 코드 배포에 대한 신뢰 문제까지 해결되지는 않는다.

## 후속 구현 항목

1. 실제 보안 parameter가 있는 LWE-HPRF와 VSS field 결합 검증
2. AMR의 HPRF share interpolation·오류 검증 및 반복/변동 cohort 테스트
3. HotStuff의 leader/view-change, 정족수 certificate, partial synchrony liveness
4. VRF/CCS 및 참여 집합을 바꾸어도 안전한 multi-round policy
5. MGF mask 범위와 privacy의 관계를 명세한 통합 backend
6. 올바른 mask 적용과 제출값의 norm 등을 증명하는 검증 계층
7. 임의 부분집합 EMA를 위한 안전한 집합 선택·공모 임계치와 장기 지연 처리
8. 실제 분산 SuperLink 배포, TLS, node identity, 장애 복구·재시작 테스트

## 참고 자료

- [로컬 AION 논문](./AION.pdf): §2–6, Algorithm 1–9
- [Boneh–Lewi–Montgomery–Raghunathan HPRF 논문](https://crypto.stanford.edu/~klewi/papers/homprf-proc.pdf): §5의 이진 행렬 기반 almost key-homomorphic PRF와 보안 파라미터 조건
- [공식 AION artifact](https://zenodo.org/records/15870338): `agent/Aion/HPRF/hprf.py`, ASR 및 BFT 코드 검토
- [Flower secure aggregation](https://flower.ai/docs/framework/explanation-ref-secure-aggregation-protocols.html): 사용자 정의 protocol은 low-level API로 구현 가능
- [Flower ClientApp](https://flower.ai/docs/framework/ref-api/flwr.clientapp.ClientApp.html): custom query handler
- [Flower Grid](https://flower.ai/docs/framework/ref-api/flwr.serverapp.Grid.html): 메시지 전송 인터페이스
- [Flower deployment runtime](https://flower.ai/docs/framework/how-to-run-flower-with-deployment-engine.html): SuperLink/SuperNode 배치
