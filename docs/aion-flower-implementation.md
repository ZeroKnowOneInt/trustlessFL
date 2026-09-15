# AION Flower 구현 현황

## 구현 범위

2026-09-12에 승인된 구성은 Flower 서버 1개와 여러 독립 aggregator이다. 구현은 **고정 cohort의 AION-ASR 연구용 실행 경로**이며, 원 논문 전체나 production 수준의 악의적 참여자 보안을 구현했다고 주장하지 않는다.

| 구성요소 | 상태 | 논문과의 관계 및 제한 |
|---|---|---|
| Flower 연동 | 구현·검증 | `ServerApp`, `ClientApp`, `Message`, `Grid`; Flower 1.36.0 고정 |
| 일회성 VSS | 구현·검증 | Algorithm 1, RFC 3526 group 14의 prime-order subgroup 기반 Feldman 검증 |
| share 전달 | 구현·검증 | aggregator별 X25519/HKDF/AES-GCM 암호화, client 서명, task/recipient/commitment binding |
| mask 생성 | 연구 대체 구현 | artifact의 column-sum/rounded-linear 구조 참고. 논문의 검증된 LWE-HPRF를 구현한 것은 아님 |
| ASR | 구현·검증 | Algorithm 3, aggregate commitment 검증 후 `f+1`개 이상의 유효 share로 합계 key만 복원 |
| DMC/DMR | 구현·검증 | Algorithm 7·8, fixed-point 정수와 modular wrap 처리, 반올림 오차 제거 |
| 참여 집합·결과 certificate | 구현·검증 | `n-f`개 서로 다른 Ed25519 서명 및 영속 vote lock |
| HotStuff BFT | 미구현 | threshold signature 압축, view-change, 부분 동기 liveness 미제공. 정족수 부족 시 abort |
| CCS/VRF | 미구현 | 모든 라운드에서 동일 cohort만 허용; membership 변경과 client dropout 시 abort |
| AMR | 미구현 | 집계 key를 공개하지 않는 reconstruction 및 HPRF share decoding 필요 |
| MGF | 단위 모듈 구현·검증 | Algorithm 6 수치 실험. modular masked vector의 wire 경로에는 적용하지 않음 |
| EMA | 미구현 | 늦은 update는 다음 round에 재사용하지 않음 |
| FL workload | 구현·검증 | 합성 non-IID NumPy least-squares 및 MNIST softmax; 동일 sample 수의 client별 delta 평균 |
| 악의적 입력의 학습 정당성 | 미보장 | 형식·서명·round는 검증하지만 올바른 mask·local training·poisoning 무해성은 증명하지 않음 |
| 네트워크 배포 | 앱·설정 경로 제공 | 로컬 프로세스 Grid와 FAB 빌드 검증 완료. 실제 SuperLink/TLS 배포 검증은 별도 |

테스트 통과는 구현한 연산·상태 전이의 검증이며 privacy 증명이나 암호 감사를 대신하지 않는다.

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

모든 프로토콜 메시지는 Flower 서버를 경유한다. 서버가 모든 개별 share의 평문을 받지 않도록 end-to-end 암호화를 사용한다. coordinator가 중계를 차단하면 진행이 중단될 수 있다. 서로 다른 프로세스만으로 독립 trust domain이 만들어지는 것은 아니며 실제 배포에서는 관리 권한과 파일 접근 권한을 분리해야 한다.

Flower 기본 `FedAvg`가 개별 update를 수집하지 않도록 `AionWorkflow`에서 low-level Message API로 단계를 직접 실행한다. Flower 내장 SecAgg+를 AION으로 이름만 바꾸어 사용하지 않는다.

## 실행 및 검증

```bash
uv sync
uv run aion-demo
uv run aion-demo --clients 6 --aggregators 7 --faults 2 --rounds 5 --dimension 8
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
  → signed masked updates from the fixed cohort
prepare(updates, previous model certificate)
  → roster certificate (n-f matching votes)
share(roster certificate)
  → signed aggregate shares
finalize(roster certificate, aggregate shares)
  → independent reconstruction and model certificate
commit(model certificate)
  → n-f commit acknowledgments
```

각 aggregator는 client 서명, model parent hash, vector 차원과 field 범위, 정확히 동일한 cohort를 확인하고서만 roster vote를 발급한다. 해당 roster의 정족수 certificate를 받아야 집계 share를 공개한다. 결과는 각 aggregator가 독립적으로 계산하고 서명한다.

client는 같은 round에 대한 요청을 cache하고 재시도 시 동일한 signed update를 반환한다. 다른 model parent를 사용한 재요청은 거부한다. aggregator는 `(task, phase, round)`별 값을 lock하여 상충 proposal에 두 번 서명하지 않는다. state 파일을 `0600`으로 저장하고 atomic replace와 fsync를 완료한 뒤 응답한다.

state는 task ID별로 분리한다. 완료된 task를 `workflow.run`으로 처음부터 재실행하면 정상적인 새 학습으로 진행하지 않는다. 새 실험에는 새 provisioning과 task ID를 사용한다. 복구 중 투표 lock을 삭제하거나 과거 backup으로 되돌리면 안전성 전제가 깨진다. 일반적인 crash recovery 및 서버 측 resume orchestration은 아직 제공하지 않는다.

## ASR과 고정 cohort

ASR은 `M = sum(m_i) mod ORDER`를 공개한다. 서로 다른 참여 집합의 key 합을 공개하면 차분으로 개인 key가 드러날 수 있다. 현재는 모든 round에 **동일하게 초기화된 client 전원**이 참가해야 한다. 실패한 client를 제외해 작은 집합을 재집계하거나 MGF로 일부 client를 제거하는 동작은 허용하지 않는다.

정확히 같은 집합을 반복 사용하므로 공개되는 aggregate key도 같으며, 서로 다른 subset 합을 공개하지 않는다. 이것은 subset 차분을 예방하는 제한이지 연구 HPRF 전체의 안전성 증명은 아니다. dropout을 허용하려면 CCS의 실제 참여 집합 보장 또는 AMR을 추가해야 한다. 다른 task에서 기존 client secret을 재사용하면 안 된다.

## HPRF 및 수치 처리의 차이

확인한 공식 artifact 경로는 `Aion/agent/Aion/HPRF/hprf.py`이다. 그 코드는 matrix column sum에 scalar key/round를 곱하고 modulus conversion으로 반올림한다. 이 구현에서는 해당 연산 형태를 독립적으로 작성하고 다음을 변경했다.

- pickle로 공개 matrix를 읽지 않고 task별 SHAKE-256으로 공개 column coefficient를 생성
- VSS scalar field와 mask key field를 같은 `ORDER`로 통일
- 출력 modulus를 `2^128`로 명세
- NumPy int64 대신 Python arbitrary-precision integer 사용
- task와 round를 명시적으로 결속
- masked value의 합·차는 output modulus에서 계산하고 signed 값으로 decode

이는 논문 §2.2의 안전한 LWE-HPRF를 검증하여 구현한 것이 아니다. 반올림 key homomorphism과 집계 mechanics만 재현한다. 일반 PRG/HMAC을 homomorphic PRF라고 주장하지 않으며, `research-mode=true` 없이는 실행을 거부한다. mask 수치 연산이 맞는다는 테스트만으로 privacy가 입증되지는 않는다.

각 local delta는 기본 소수 4자리로 양자화된다. `padding = 10^ceil(log10(2q))`를 곱한 정수에 mask를 더한다. 집계 후 signed modular 차를 padding으로 나누어 최근접 정수로 반올림한다. q개 mask의 작은 반올림 오차를 제거한 뒤 scale과 client 수로 나누어 mean delta를 얻는다.

MGF는 bounded real-valued masked gradient의 norm을 검사하는 알고리즘이다. 현재의 modular residue에 직접 L2 norm을 적용하면 다른 알고리즘이 되므로 wire 경로에는 연결하지 않았다. `MaskedGradientFilter`는 식과 경계 조건을 검증하는 독립 모듈이다.

## Flower 네트워크 배포 연결 방법

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
7. EMA와 지연된 집계 집합의 공모 임계치
8. 실제 분산 SuperLink 배포, TLS, node identity, 장애 복구·재시작 테스트

## 참고 자료

- [로컬 AION 논문](./AION.pdf): §2–6, Algorithm 1–9
- [공식 AION artifact](https://zenodo.org/records/15870338): `agent/Aion/HPRF/hprf.py`, ASR 및 BFT 코드 검토
- [Flower secure aggregation](https://flower.ai/docs/framework/explanation-ref-secure-aggregation-protocols.html): 사용자 정의 protocol은 low-level API로 구현 가능
- [Flower ClientApp](https://flower.ai/docs/framework/ref-api/flwr.clientapp.ClientApp.html): custom query handler
- [Flower Grid](https://flower.ai/docs/framework/ref-api/flwr.serverapp.Grid.html): 메시지 전송 인터페이스
- [Flower deployment runtime](https://flower.ai/docs/framework/how-to-run-flower-with-deployment-engine.html): SuperLink/SuperNode 배치
