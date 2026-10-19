# Seed-MPC 독립 호스트 실행

2026-10-12, `work/aion-private-bound-no-wrap`.

독립 역할 실행 경로를 `trustlessfl-distributed`로 제공한다. 로컬 simulation을 유지하면서
네트워크 실행을 별도 경로로 추가했다. 각 aggregator와 client가 자기 환경에서 키를
생성하고 보관한다. 중앙 bootstrap이 다른 역할의 평문 키·seed·학습 데이터를 만들지 않는다.
Flower Hub 게시나 계정 설정은 수행하지 않는다.

## 역할과 공개 정보

| 환경 | 실행 | 개인 파일 |
|---|---|---|
| A0 | Flower SuperLink / ServerApp, MPC party 0, 집계 제어 | A0 서명·암호화 키, P0 TLS 키, 각 client의 seed 3개 |
| A1 / A2 / A3 | 각자의 MPC party, RPC service | 자기 서명·암호화·TLS 키, 각 client의 seed 3개 |
| 각 client | Flower SuperNode / ClientApp, 로컬 학습·마스킹 | 자기 데이터·서명·암호화·TLS 키, component seed 4개 |

A0는 client가 보낸 **전체 masked update**를 받고 각 aggregator에게 전달한다.
업데이트 조각을 네 aggregator에 나눠 보관하는 방식은 아니다.
각 A(p)는 seed component p를 모르므로 개별 마스크 전체를 계산할 수 없다.
서버가 seed 암호문을 중계하는 것도 가능하지만 수신자가 아닌 역할은 이를 열 수 없다.

Committee는 고정 4명이며, **세션 전체에서 악성·공모 aggregator는 최대 1명**이다.
A0의 Flower 서버와 party 0은 하나의 보안 도메인이다. Aggregator 2명 공모를 허용하지 않는다.
SUM/count/abort, 참여·시간·크기, 그 출력에서 추론되는 정보는 이전과 같이 공개 범위다.
예컨대 합에 honest client가 1명만 남고 나머지 기여를 알면 그 honest update는 추론될 수 있다.
독립 호스트 분리는 이 집계 출력의 역추론을 없애지 않는다.

## 사전 준비

모든 환경은 동일한 TrustlessFL wheel / Flower 1.36.0을 설치한다. 현재 CPU 분류 모델을
지원하며 A0와 client는 PyTorch도 필요하다. 설치 방법은 [backend 자동화](seed-mpc-backend-setup.md).
Client는 패키지에 포함된 TLS 등록 통신을 사용하므로 MP-SPDZ·컴파일러·native backend 설치가 필요 없다.
[역할별 설치와 패키지 실행 안내](seed-mpc-package-guide.md)를 참고한다.

각 aggregator 운영자는 자신의 OS 계정에서 직접 backend를 준비·승인한다.

```bash
trustlessfl-mpc doctor
trustlessfl-mpc setup --directory /home/operator/backend --mode direct
trustlessfl-mpc verify --installation /home/operator/backend/mp-spdz-0.4.3-checked-source-v1
```

다른 운영자의 보호된 native 승인 레코드를 가져와 신뢰 근거로 사용하지 않는다.
실행 파일·라이브러리·경로는 환경마다 달라도 된다. 공식 소스, active Rep4 patch,
compiler 옵션과 보안 모드는 공통이어야 하며 로컬 backend 검증을 우회하지 않는다.
현재 `direct` 입력 모드를 사용한다.

공통 public bundle에는 모델 소스·schema·초기 모델·정적 정책·학습 설정·회로·주소가 들어간다.
client의 학습 데이터나 seed, 개인 키는 넣지 않는다. 모델 plugin은 사용자가 승인한 코드이며
sandbox가 아니다. Client는 자신의 로컬 모델 소스를 별도로 지정하고 공통 모델의 hash와 대조한다.

## 1. 각 aggregator의 로컬 키 생성

각 호스트에서 slot과 실제 DNS / IPv4 주소를 지정한다. 다음은 A0 예다.

```bash
trustlessfl-distributed init-aggregator \
  --directory /home/operator/session-a0 --slot 0 --host a0.example.org
```

A1~A3는 각각 자기 slot / 주소 / 디렉터리를 사용한다.
생성된 `public.json`만 공유한다. `identity.json`, `P*.key`는 이동하지 않는다.
TLS 인증서는 CA 발급 권한이 없고 자기 프로토콜 역할만 주장한다.
한 aggregator가 다른 party 인증서를 발급해 사칭하는 경로를 허용하지 않는다.

**공개 키와 계약 fingerprint는 실제 운영자의 인증된 채널로 확인해야 한다.**
자기 서명만으로 독립 운영자라는 사실이 증명되지 않는다. A0가 보내온 네 개의 키와
hash를 같은 채널에서 그대로 신뢰하면 A0가 네 역할을 가장할 수 있다.

## 2. 공개 모델·정책·회로 계획

`model.json` 예시다. `train_data`와 `test_data`는 이 파일에 넣지 않는다.

```json
{
  "plugin": "classifier.py",
  "kwargs": {"hidden": 5},
  "training": {"epochs": 1, "batch_size": 16, "learning_rate": 0.05},
  "policy": {
    "coordinate_cap": 20000,
    "squared_threshold": 2500000000,
    "scale": 10000,
    "minimum_accepted": 2
  }
}
```

A0에서 공개 enrollment 파일 네 개를 받아 계획을 작성한다.

```bash
trustlessfl-distributed plan --output /home/operator/public-bundle \
  --mp-spdz-dir /home/operator/backend/mp-spdz-0.4.3-checked-source-v1 \
  --model-config /home/operator/model.json \
  --peers A0-public.json A1-public.json A2-public.json A3-public.json \
  --clients 4 --rounds 3 --collection-window-ms 60000
```

출력 `contract_hash`를 모델·정책·주소·운영자 키와 함께 확인한다. 각 aggregator에게
public bundle을 전달하고 각자의 환경에서 다음을 수행한다.

```bash
trustlessfl-distributed approve --directory /home/operator/session-a0 \
  --bundle /home/operator/public-bundle \
  --expected-contract-hash REVIEWED_CONTRACT_HASH \
  --mp-spdz-dir /home/operator/backend/mp-spdz-0.4.3-checked-source-v1
```

단순히 A0의 bytecode hash를 믿지 않는다. 각 aggregator가 승인된 소스·도구로
독립 컴파일하고 결과를 비교한다. source / artifact가 맞지 않으면 서명하지 않는다.
동일한 TrustlessFL 앱 코드도 공통 계약에 포함한다. 승인 결과 `approval.json`만 공유한다.
컴파일은 등록·승인 시 수행하며 라운드마다 수행하지 않는다.

## 3. Client의 로컬 등록

각 client가 공통 계약을 확인한 뒤 자신의 환경에서 수행한다.

```bash
trustlessfl-distributed client-prepare --directory /home/operator/session-c0 \
  --slot 0 --bundle /home/operator/public-bundle \
  --expected-contract-hash REVIEWED_CONTRACT_HASH \
  --train-data /home/operator/my-private-train.npz \
  --model-plugin /home/operator/my-approved-classifier.py
```

공유할 것은 `enrollment.json`과 수신자별 `component-packets/A*.json`이다.
후자는 서명된 암호문이다. `client.json`, `seed-input.json`, `C*.key`, 데이터는 공유하지 않는다.
개별 업데이트 audit은 생성하지 않는다. Client에 ZKP를 요구하지 않는다.
일회성 native TLS 연결은 공개 client slot과 등록 digest만 보내며 seed를 평문으로 보내지 않는다.
현재 전송은 고정 4-party / 64-bit ring / seeded-component / native-public 경로 전용이다.
이전 secret-AES private-input 실험의 ExternalIO 전송은 별도 경로로 유지한다.

## 4. 공개 등록 확정과 각 환경의 로컬 binding

A0는 네 운영자 서명과 모든 client의 공개 enrollment를 수집한다.

```bash
trustlessfl-distributed finalize --bundle /home/operator/public-bundle \
  --expected-contract-hash REVIEWED_CONTRACT_HASH \
  --approvals A0-approval.json A1-approval.json A2-approval.json A3-approval.json \
  --enrollments C0-enrollment.json C1-enrollment.json C2-enrollment.json C3-enrollment.json
```

생성한 `deployment-public.json`과 `public_deployment_hash`를 모두에게 전달·확인한다.
각 aggregator는 자기 수신자용 seed 암호문만 지정해 binding한다. A0 예다.

```bash
trustlessfl-distributed bind --directory /home/operator/session-a0 \
  --bundle /home/operator/public-bundle \
  --expected-contract-hash REVIEWED_CONTRACT_HASH \
  --expected-deployment-hash REVIEWED_DEPLOYMENT_HASH \
  --seed-packets C0-A0.json C1-A0.json C2-A0.json C3-A0.json \
  --test-data /home/operator/public-test.npz
```

평가 데이터는 선택이며 A0에만 둔다. A1~A3는 자신의 암호문을 지정하고 `--test-data`를 생략한다.
각 client는 같은 명령에서 `--seed-packets`와 `--test-data`를 생략한다.
로컬 projection은 public 계약의 모델·정책·등록·주소를 바꿀 수 없다.
공개 bundle 복사는 허용된 파일 목록만 사용하며 다른 개인 파일을 자동 복사하지 않는다.

## 5. 실행

각 aggregator에서 다음을 실행한다.

```bash
trustlessfl-distributed aggregator --directory /home/operator/session-a0
```

A0에서 별도로 Flower SuperLink를 실행한다.

```bash
trustlessfl-distributed superlink --directory /home/operator/session-a0
```

각 client에서 자기 디렉터리로 SuperNode를 실행한다.

```bash
trustlessfl-distributed client --directory /home/operator/session-c0
```

클라이언트가 모두 접속한 뒤 A0에서 학습을 시작한다.

```bash
trustlessfl-distributed flower-run --directory /home/operator/session-a0
```

MPC는 각 호스트 주소 목록으로 연결한다. RPC는 mTLS 및 실제 peer fingerprint를 확인하며
제어 요청은 A0 인증서 소유자에게만 허용한다. Flower Fleet API는 TLS를 사용한다.
Control / AppIO는 각 호스트 loopback에만 바인딩한다. HTTP 평문 fallback은 없다.

Flower TLS만으로 A0의 임의 실행 코드를 신뢰하지 않는다. Client가 소유한 시작 guard가
FAB를 설치하기 전에 패키지 bytes와 entrypoint를 로컬 승인 코드와 대조한다.
추가 실행 파일·경로 탈출·변경된 ClientApp을 거부하고 runtime dependency 설치를 막는다.
실제 실행은 이미 로컬에서 가져온 ClientApp을 사용한다. 이 gate를 생략한 직접
`flower-supernode` 실행은 이 배포 경로와 같은 보안 설정이 아니다.

## 네트워크와 재시작

| 연결 | 기본 포트 | 범위 |
|---|---|---|
| Aggregator 간 native MPC | 15000 + party slot | 네 aggregator 사이 |
| Client의 일회성 native 등록 tag | 16000 + party slot | client → 각 aggregator |
| Aggregator 제어 RPC | 17000 | A0 → 각 aggregator |
| Flower Fleet | A0의 18000 | client → A0 |
| Flower client AppIO | 각 client의 19000 | loopback |
| Flower Control / Server AppIO | A0의 19001 / 19002 | loopback |

포트는 `plan`의 `--party-port / --client-port / --rpc-port / --fleet-port`로 변경할 수 있다.
주소·포트는 모두가 승인한 계약에 들어간다. 고정 committee 호스트 간 연결을 방화벽에서
허용해야 하고 collection deadline을 사용하는 운영자 시계는 동기화해야 한다.
DNS / IPv4를 지원하며 IPv6 전용 주소 형식은 현재 지원하지 않는다.

등록 후 client가 중단돼도 수신된 complete submission만 확정하고 남은 client로 검사·집계한다.
Flower가 복귀 client에게 새 node ID를 주면 등록된 client 키로 fresh challenge에 서명해
논리 client ID를 다시 연결한다. 복귀 시 인증된 결과 체인을 확인하고 모델 상태를 따라잡는다.
마지막 commit ACK는 성공 조건이 아니고, 공개 기록에 늦게 도착한 것으로 나타날 수 있다.

Native MPC / 학습 실행은 영속 시작 marker로 one-shot이다. 불확실하게 중단된 MPC를
동일 seed로 다시 실행하지 않는다. Aggregator/native 장애 후에는 새 세션이 필요하다.
Client 프로세스 재접속은 자기 영속 상태를 보존해야 한다. 이미 시작했으나 답을 확정하지
못한 training round는 재계산하지 않는다. 초기 등록이 끝나기 전 roster 미접속과 네트워크
DoS, 악성 aggregator의 MPC 중단을 무조건 견디는 BFT liveness는 제공하지 않는다.

## 검증 범위

검증 runner는 `experiments/validate_seed_mpc_distributed.py`다. 각 역할마다 별도 Docker
filesystem / network namespace를 사용하고, 공개 exchange만 읽을 수 있게 한다.
데이터·키·seed는 각 컨테이너 안에서 생성한다. 재학습 oracle은 알려진 합성 데이터 seed로
별도 생성한 데이터를 사용하며 client의 비밀 파일을 읽지 않는다.

연구용 image는 [Dockerfile.distributed-validation](../deployment/seed-mpc/Dockerfile.distributed-validation)을
사용해 만든다. Context에는 wheel과 Dockerfile만 둔다. Base는 이전 backend 검증 이미지다.
이미지는 client / aggregator의 FL 개인 키나 데이터를 포함하지 않는다.
한 Docker 관리자가 관리하는 시험으로 **실제 네 독립 기관을 운영한 실험은 아니다**.
실제 운영자는 각자 backend 승인과 파일 권한·네트워크·키 교환을 적용해야 한다.
전체 FL 프라이버시의 composition 증명이나 poisoning 방어 성능 증명을 대신하지 않는다.

실제 검증 결과와 재현 범위는 [2026-10-12 검증 보고서](reproduction/independent-hosts-2026-10-12.md)에 정리했다.
