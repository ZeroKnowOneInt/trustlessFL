# 역할별 설치와 패키지 실행

Linux/WSL, Python 3.12, Flower 1.36.0, CPU PyTorch 2.8.0 기준이다.
Hub 계정 연결이나 게시 없이 로컬 wheel을 사용한다. 독립 실행의 client는 자기 데이터·키를
보유하며 MP-SPDZ, C++ compiler, Ray를 설치하지 않는다. 실제 MPC backend는 네 aggregator에 둔다.

## 패키지 만들기와 설치

개발자는 checkout에서 한 번 build한다. 생성한 같은 wheel을 역할별 환경에 전달한다.

```bash
uv lock --check
uv build --wheel --out-dir dist
sha256sum dist/trustlessfl-0.1.0-py3-none-any.whl
```

각 client는 자기 환경에 다음과 같이 설치한다. CPU Torch를 먼저 설치하므로 일반 PyPI의
GPU runtime dependency를 내려받지 않는다. 모델·데이터 코드는 사용자가 로컬에서 승인한다.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install 'torch==2.8.0' --index-url https://download.pytorch.org/whl/cpu
python -m pip install './trustlessfl-0.1.0-py3-none-any.whl[client]'
python -m pip check
trustlessfl-distributed --help
```

Client에는 인증서 hash directory를 준비하는 `openssl` 명령도 필요하다.
Ubuntu에서는 `python3-venv ca-certificates openssl`을 시스템 패키지로 설치한다.
일반 client 실행에서 `seed-mpc` / `simulation` extra를 설치할 필요가 없다.
동일 패키지에 기존 실험 코드도 들어 있지만 독립 client의 실행 경로는 이를 사용하지 않는다.
검증 환경의 Python 의존성 snapshot은 [client-requirements.txt](../deployment/seed-mpc/client-requirements.txt)다.
CPU Torch 설치 후 `pip install -r client-requirements.txt`로 검증된 버전을 맞출 수 있다.

각 aggregator도 별도 venv에 같은 wheel과 CPU Torch를 설치한다. `[aggregator]` extra를
사용한 뒤 자신의 OS 계정에서 backend를 준비·승인한다.

```bash
python -m pip install './trustlessfl-0.1.0-py3-none-any.whl[aggregator]'
trustlessfl-mpc doctor
trustlessfl-mpc setup --directory /home/operator/backend --mode direct
trustlessfl-mpc verify --installation /home/operator/backend/mp-spdz-0.4.3-checked-source-v1
```

설치 의존성·offline archive·시스템 패키지 옵션은 [backend 설치 안내](seed-mpc-backend-setup.md)에 있다.
A0에는 평가 데이터를 선택적으로 둘 수 있다. A1~A3에는 client 학습 데이터를 전달하지 않는다.
실제 독립 운영 환경의 backend 승인 레코드를 다른 운영자에게 복사해 신뢰 근거로 사용하지 않는다.

## 모델과 정적 정책

[MLP 공개 설정 예시](../examples/seed_mpc_custom/distributed-mlp.json)와
[CNN 공개 설정 예시](../examples/seed_mpc_custom/distributed-cnn.json)를 제공한다.
설정의 `plugin`은 해당 JSON 기준의 로컬 소스 경로다. `make_model(**kwargs)`가 CPU 분류 모델을
생성하고 `prepare_inputs(x)`가 NumPy 데이터에서 Torch 입력을 준비한다.
Client의 private `train.npz`에는 `x`, `y`를 두며 `allow_pickle=False`로 읽는다.
공개 모델 설정에는 학습 데이터 경로를 넣지 않는다.

`coordinate_cap`, `squared_threshold`, `scale`, `minimum_accepted`를 학습 전에 정한다.
예시 값이 모든 모델에 적합하다는 의미는 아니다. 모델을 바꾸면 정상 업데이트의 정수화·norm과
threshold를 사전 확인해야 한다. 실행 중 제출값으로 정책을 동적으로 바꾸지 않는다.
Parameter schema와 D/N/정책은 공개 세션 계약에 고정한다. 회로 조건이 달라지면 새 계획·승인과
필요한 compile을 수행하며, 같은 세션의 라운드마다 compile하지 않는다.

## 세션 준비와 실행 순서

전체 인자와 네트워크 포트는 [독립 호스트 실행 절차](seed-mpc-independent-hosts.md)를 따른다.

1. 각 aggregator가 `init-aggregator`로 자기 개인 키를 만들고 `public.json`만 공유한다.
2. A0가 공개 모델·정책·주소·키로 `plan`을 만든다. 모두가 운영자의 인증된 채널로 fingerprint를 확인한다.
3. 네 aggregator가 `approve`에서 자신의 backend로 회로를 독립 컴파일·대조한 뒤 서명한다.
4. 각 client가 자기 데이터·모델을 지정해 `client-prepare`를 실행한다. **Client에는 `--mp-spdz-dir`가 필요 없다.**
5. A0가 공개 enrollment·운영자 승인으로 `finalize`한다. 각 역할이 같은 public deployment hash를 확인하고 `bind`한다.
6. 각 aggregator service를 실행하고 A0의 SuperLink, 각 client의 SuperNode를 실행한다.
7. A0가 `flower-run`을 실행한다. 클라이언트는 최초 등록 후 인증된 모델만 학습하고 masked update를 제출한다.

Client 등록 예:

```bash
trustlessfl-distributed client-prepare --directory /home/operator/session-c0 \
  --slot 0 --bundle /home/operator/public-bundle \
  --expected-contract-hash REVIEWED_CONTRACT_HASH \
  --train-data /home/operator/private-train.npz \
  --model-plugin /home/operator/approved-model.py
```

`client.json`, `seed-input.json`, `*.key`, `train.npz`, client SQLite 상태를 다른 역할에게 보내지 않는다.
공유 대상은 signed public enrollment와 aggregator별 암호화 seed packet이다.
서버는 전체 masked update를 보지만 각 aggregator는 전체 마스크 seed를 보유하지 않는다.
Client 등록 TLS는 공개 slot·등록 digest를 보내며 seed나 raw update를 평문으로 보내지 않는다.

## 종료·실패·복귀

- 정상 완료: A0의 `flower-run-status.json`과 `runtime-results`의 인증된 결과를 확인하고
  SuperLink/SuperNode/service를 종료한다. Audit 파일을 완료 확인에 사용하지 않는다.
- 등록 전 roster 누락: 학습을 시작하지 않는다. 필요한 client의 공개 등록을 갖춘 새 계획을 준비한다.
- Client 이탈: collection deadline까지 complete submission이 없는 client는 해당 round에서 빠진다.
  복귀 시 같은 private 디렉터리와 SQLite 상태를 보존한 채 `client`를 실행한다.
  Fresh challenge로 새 node ID를 인증하고 놓친 결과 체인을 따라잡는다.
- Client의 training 시작 후 불확실한 실패: 같은 round를 다시 학습해 같은 mask를 재사용하지 않는다.
  확정한 response는 동일하게 반환하고 미확정 training은 실패 처리한다.
- Native MPC / aggregator 중단: 영속 marker 때문에 동일 세션을 재실행하지 않는다.
  마지막 인증 모델과 별도 검토한 정책으로 fresh session·키 등록을 준비한다.
- 모델·정책·회로·앱 코드·cert fingerprint 불일치: 승인 또는 실행 전에 중단한다.
  검사를 끄거나 HTTP / semi-honest 경로로 우회하지 않는다.

Client는 직접 `flower-supernode`를 실행하는 대신 `trustlessfl-distributed client`를 사용한다.
이 명령이 client 소유 FAB 검사와 로컬 승인 ClientApp 실행을 연결한다.
마지막 commit ACK는 비동기이며 종료 시 늦을 수 있다. 공개 결과 인증서와 정수 합을 성공 기준으로 사용한다.

## Docker로 확인하기

[client Dockerfile](../deployment/seed-mpc/Dockerfile.client)은 고정 Ubuntu base에서 일반 Python 의존성과
CPU Torch·wheel을 새로 설치한다. Compiler, MP-SPDZ, Ray, 개발 checkout은 복사하지 않는다.
Build context에는 wheel과 Dockerfile만 넣는다. Aggregator 이미지와 별도로 사용한다.

```bash
docker build -f Dockerfile.client -t trustlessfl-client:local ./client-context
python experiments/validate_seed_mpc_distributed.py \
  --image LOCAL_APPROVED_AGGREGATOR_IMAGE --client-image trustlessfl-client:local \
  --output .cache/new-package-validation --clients 4 --dropout
```

다른 모델 adapter는 `--model-kind cnn --clients 2`로 확인할 수 있다. 이 runner의 데이터는
공개 seed로 재현하는 합성 데이터이며 FMNIST 성능 시험이 아니다. 컨테이너를 분리해도
한 Docker 관리자의 신뢰를 네 독립 운영자의 신뢰로 바꾸지는 않는다.
검증된 범위는 [패키지 검증 보고서](reproduction/package-validation-2026-10-12.md)에 기록한다.
