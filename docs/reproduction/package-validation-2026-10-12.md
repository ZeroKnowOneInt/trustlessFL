# 클라이언트 설치 경량화와 패키지 검증

2026-10-12. 브랜치 `work/aion-private-bound-no-wrap`.
[사용자 설치·실행 안내](../seed-mpc-package-guide.md),
[독립 역할 실행 절차](../seed-mpc-independent-hosts.md).

단계 5에서 최종 기존 패키지의 이탈·복귀를 재검증하고, client에 필요하던 native backend
설치를 제거했다. 새 wheel을 고정 Ubuntu base의 새 client 환경에 설치한 뒤 MLP/CNN을
실제 Flower·Rep4에 연결했다. Flower Hub 게시·계정 설정은 수행하지 않았다.

## 변경 내용

Client는 MP-SPDZ 전체 설치의 ExternalIO Python 코드를 가져오는 대신 패키지의
`seed_mpc_registration.py`를 사용한다. 최초 등록에서 네 aggregator와 상호 TLS를 연결하고
공개 client slot, 64-bit ring specification, 공개 등록 digest를 확인·전송한다.
Seed는 기존 수신자별 signed encrypted packet으로 전달한다. 이 TLS 등록 연결에
seed나 업데이트를 평문으로 보내지 않는다. Expected party hostname와 실제 certificate
fingerprint도 대조하며, frame 크기·fragmentation·EOF와 socket timeout을 처리한다.

현재 transport는 **4-party / seeded-components / 64-bit ring / native-public** 계약만 지원한다.
Private input triples와 legacy secret-AES 실험의 ExternalIO 경로를 대체하는 범용 구현은 아니다.
독립 `client-prepare` / `bind`는 native binary를 검증·실행하지 않고, 네 운영자가 승인한
public contract와 local app/model bytes를 확인한다. Aggregator는 자기 backend 검증과
독립 회로 컴파일을 계속 수행한다. Legacy local/simulation 경로는 별도로 유지했다.

`client` / `aggregator` 설치 extra를 추가했고 둘 모두 Ray·simulation extra를 요구하지 않는다.
[client Dockerfile](../../deployment/seed-mpc/Dockerfile.client)은 wheel과 일반 Python 의존성,
CPU Torch를 설치하며 compiler·MP-SPDZ·개발 checkout을 복사하지 않는다.
Public MLP/CNN 설정과 역할별 설치, 등록·시작·종료·불확실한 장애·복귀 절차를 문서화했다.

마스크·MPC 회로는 변경하지 않았다. Single mask, holder 사본 검사, 정확한 mod-2^16
제거·signed lift, 정적 좌표/전체 norm, 넓은 ring SUM, 인증된 snapshot/result와 영속 lock을 유지한다.
Client에 새로운 ZKP나 SGD/마스크 생성 의도 증명을 요구하지 않는다.

## 실제 실행

모든 시험은 공식 Flower 1.36.0 SuperLink/SuperNode, MP-SPDZ 0.4.3 active Rep4를 사용했다.
Role별 Docker filesystem/network namespace와 자기 키·데이터를 사용했다.
Aggregator image는 이전에 source build·승인된 backend와 새 wheel을 사용했다.
새 client image는 고정 Ubuntu base에서 설치했으며 해당 backend image를 상속하지 않았다.

| 시험 | 모델 크기 | Client | Round | presence·통과 인원 | 정수 합·모델·인증서 |
|---|---:|---:|---:|---|---|
| 기존 final-v2 wheel 재검증 | MLP 53 | 4 | 3 | `4 → 3 → 4` | 모든 round 정확히 일치·유효 |
| 새 wheel·backend 없는 client | MLP 53 | 4 | 3 | `4 → 3 → 4` | 모든 round 정확히 일치·유효 |
| 새 wheel·다른 adapter | CNN 435 | 2 | 2 | `2 → 2` | 모든 round 정확히 일치·유효 |

각 MLP 이탈 시험은 C3 컨테이너를 round 1 제출 후 종료하고 round 2의 native CHECK 뒤 재시작했다.
새 node ID로 인증·복귀한 C3가 round 3의 인증 모델을 학습하고 제출했다.
별도 참조 계산은 알려진 seed로 합성 데이터를 재생성하고 독립 재학습했다.
Client 실제 seed·키·데이터 파일을 참조 입력으로 읽지 않았다.

MLP 데이터는 client별 64개/6 features/3 classes이며 test 96개다.
CNN은 28×28 합성 stripe 이미지, client별 64개, test 96개, 3 classes다.
CNN 예시 소스의 class 수를 3으로 설정해 435개 파라미터가 됐다.
이는 실제 FMNIST 학습이나 poisoning 방어 성능 평가가 아니다.
기존 패키지 재시험은 363.020초, 새 client MLP 시험은 282.551초, CNN 시험은 196.672초였다.
등록·승인·실행·참조 계산을 포함한 wall time이며, 서로 다른 실행 조건이므로 속도 개선율로 비교하지 않는다.

Raw 업데이트 audit은 모든 시험에서 0개였다. 등록된 A1의 A2 제어 RPC는 거부됐다.
각 역할에 자신의 native 개인 키만 있었으며 다른 역할의 private workspace와 Docker socket이 없었다.
새 client 환경에서는 MP-SPDZ backend, `g++`, Ray가 없는 것을 실제로 검사했다.
Package 경로는 `/opt/venv/lib/python3.12/site-packages/trustlessfl`로 개발 checkout이 아니다.
`pip check`와 `uv lock --check`도 통과했다.

새 client 설치 버전은 Torch **2.8.0+cpu**, Flower **1.36.0**, NumPy **2.5.4**,
cryptography **46.0.7**, tomli-w **1.2.0**이다. Client image의 uncompressed 크기는
**371,559,397 bytes**였다. 이 값은 설치 image 크기이며 FL 라운드 통신량이 아니다.
Native 회로나 라운드 메시지는 이번 변경으로 최적화한 것이 아니다.

## 회귀 검사

```bash
.venv/bin/python -m pytest -q tests/test_seed_mpc_*.py tests/test_rep4_candidate.py
```

**508 passed**, 30.41초, 기존 dependency deprecation warning 82개.
추가 등록 검사는 실제 네 TLS 서버 연결, 잘못된 party 인증서, 다른 ring/specification,
잘못된 digest/slot, oversized frame, fragmented frame와 EOF, client의 native backend
접근 없이 provisioning/binding을 수행하는 경우를 포함한다.
실제 MPC/Flower 시험은 이 Python 회귀와 별도로 수행했다.

## 재현·artifact

```bash
uv build --wheel --out-dir dist
# Dockerfile.client와 wheel만 넣은 context에서 client image를 만든다.
docker build -t trustlessfl-client:local ./client-context
python experiments/validate_seed_mpc_distributed.py \
  --image LOCAL_APPROVED_AGGREGATOR_IMAGE --client-image trustlessfl-client:local \
  --output .cache/new-lite-dropout --clients 4 --dropout
python experiments/validate_seed_mpc_distributed.py \
  --image LOCAL_APPROVED_AGGREGATOR_IMAGE --client-image trustlessfl-client:local \
  --output .cache/new-lite-cnn --clients 2 --model-kind cnn
```

각 실행은 새 output directory를 사용한다. Runner가 자신이 만든 컨테이너·network를 정리한다.
Public 결과는 [기존 final-v2 재시험](package-validation-2026-10-12/previous-final-dropout.json),
[새 client MLP 재참여](package-validation-2026-10-12/lite-mlp-dropout.json),
[새 client CNN](package-validation-2026-10-12/lite-cnn.json),
[wheel·source·image·결과 hash](package-validation-2026-10-12/manifest.json)에 있다.
Wheel과 설치 문서·예제·공개 검증 요약은 로컬 release bundle에 담는다.
개인 키·seed·학습 데이터·approval registry·native input·client SQLite 상태는 bundle에 넣지 않는다.

## 범위와 다음 검증

한 Docker 관리자는 모든 역할을 통제할 수 있다. 이번 시험은 **실제 네 독립 운영자 또는
물리 호스트 검증이 아니다**. 그 환경에서의 키 교환·backend 승인·방화벽·clock·지연/대역폭
조건은 별도 확인이 필요하다. Aggregator 최대 악성·공모 1명의 static 계약은 유지한다.
두 aggregator의 공모와 SUM/count/abort에서 가능한 기여 역추론을 해결한 것이 아니다.
Client 모델 plugin은 승인한 로컬 코드이며 sandbox가 아니다. 전체 FL composition 증명,
일반 DoS/BFT liveness, 임의 학습 hook·buffer, GPU와 FMNIST poisoning 평가는 완료 범위에 없다.
