# Seed-MPC 사용자용 로컬 실행

작성일: 2026-10-11. 세션별 고정 client N명 / aggregator 4명, Rep4의 정적 악성 aggregator 최대 1명.
이번 단계는 실험 harness에서 독립한 사용자 실행 경로다. Flower Hub 계정 설정이나 게시를 수행하지 않는다.

## 역할과 실행 환경

- Client: 자기 모델·데이터로 학습하고 seed를 등록하며 signed masked 업데이트만 반환한다.
- Aggregator A0..A3: 각자의 signing key, encrypted component seed packet, ledger와 native MPC party를 실행한다.
- Coordinator: Flower ServerApp에서 라운드를 진행하고 인증된 aggregate로 모델을 갱신한다. 이 역할은 A0와 같은 호스트에 배치할 수 있으며 다섯 번째 MPC party가 아니다.

`prepare`는 하나의 Linux/WSL 사용자 권한에서 수행하는 **신뢰된 로컬 bootstrap**이다. 각 역할의 설정·파일은 분리되지만 동일 UID와 관리자에게 읽기 권한이 없는 것은 아니다. 현재 RPC/native 주소는 loopback이며 독립 머신 배포는 다음 단계다. Role JSON만으로 운영자 격리가 보장된다고 해석하면 안 된다.

## 설치와 모델 계약

Python 3.12와 Linux/WSL에서 repo root의 `uv sync --extra seed-mpc` 또는 `pip install '.[seed-mpc]'`를 사용한다. MP-SPDZ는 [설치·실행 자동화 도구](seed-mpc-backend-setup.md)로 준비하거나 기존 검증된 설치를 지정한다. 독립 host provisioning은 다음 작업이다. `openssl`과 `/usr/bin/time`도 필요하다.

[모델 adapter 계약](seed-mpc-user-models.md)을 따른다. 자체 `.py` plugin의 `make_model(**kwargs)`와 선택적인 `prepare_inputs(x)`, client별 NPZ N개 및 공개 평가용 NPZ 한 개를 `model.json`으로 지정한다. SGD / cross entropy CPU 분류 학습, 고정 공개 buffer를 지원한다. 모델 plugin은 사용자가 승인한 실행 코드다.

정책 B, T, S는 명시적으로 지정하며 자동 학습 추정은 없다. 평가 파일은 coordinator가 읽으므로 **공개해도 되는 평가 데이터**만 지정한다. Client 학습 데이터는 `clients/Ci/train.npz`에만 복사하고 FAB에 넣지 않는다.

## 사용자 명령

실험 모듈을 호출하지 않는 재현 예제:

```bash
python examples/seed_mpc_custom/create_local_data.py --output .cache/user-model-data --clients 8
python -m trustlessfl.seed_mpc_user prepare \
  --output .cache/user-session \
  --model-config .cache/user-model-data/model.json --clients 8 \
  --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3-direct-rep4-v1 \
  --component-input holder-checked-direct-v1 \
  --rounds 2 --collection-window-ms 30000 --communication-meter
python -m trustlessfl.seed_mpc_user run --output .cache/user-session
python -m trustlessfl.seed_mpc_user status --output .cache/user-session
```

패키지를 설치하면 같은 인자로 `trustlessfl-seed-mpc`를 사용할 수 있다. 기존 실험의 준비·raw audit oracle·독립 재학습 도구를 실행하지 않는다. CLI에는 trusted-test-audit 옵션이 없다.

기본 component input은 stock-private-v1이며 direct를 사용하려면 승인된 importer build가 필요하다. Native backend/source/library pin과 compiled bytecode hash 검사는 유지한다. 회로 공개 source는 패키지 내부 `trustlessfl/mpc_sources`의 Python DSL resource로 포함되며 준비 시 원래 `.mpc` 이름으로 복원한다. 원본과 동일한 bytes인지 회귀 검사한다. Backend binary, raw update, NPZ, seed와 개인키는 앱 패키지에 포함하지 않는다.

## 클라이언트 수 설정

`model.json`의 `train_data` 목록 길이로 N을 정한다. `prepare --clients N`은 선택적인 일치 검사이며 데이터를 자동 분할하거나 파일을 복제하지 않는다. 예제 데이터 생성 도구의 `--clients N`은 N개의 서로 다른 synthetic NPZ를 만든다. 정책의 `max_clients`를 생략하면 N을 사용하고, 지정했다면 N과 같아야 한다. `minimum_accepted <= N`, 정수 폭과 backend ring 용량은 준비 전에 검사한다.

등록 roster는 세션 중 바뀌지 않는다. 등록 후 dropout한 클라이언트는 presence=0으로 제외하며, 복귀 시 인증된 모델 head를 동기화한다. 세션 중 신규 가입은 지원하지 않는다. N이 바뀌면 SUM/count 정수 폭과 회로 cache key가 달라져 새 컴파일이 필요하다. 동일 설정의 새 세션은 cache hit이며 라운드마다 재컴파일하지 않는다. Aggregator 수와 Rep4 공모 허용 범위는 4명 / 최대 1명으로 유지한다.

4·8·16명 실제 Flower/Rep4 기능 검증은 [재현 기록](reproduction/client-counts-2026-10-11.md)을 따른다. 이 검증이 대규모 N의 자원·가용성 보장을 뜻하지 않는다.

### 많은 클라이언트의 로컬 메모리 설정

`prepare --simulation-workers 1`은 로컬 Ray worker 수를 정한다(기본 1, 허용 1~32). 클라이언트나 aggregator 수, 보안 가정을 변경하지 않는다. `--compile-timeout 3600`은 호스트 컴파일 대기 시간이다(기본 180, 허용 1~7200초). MP-SPDZ 내부의 컴파일 제한을 해제하지 않는다.

`--client-loop compact-runtime-v1`은 component-mask 회로의 클라이언트 반복을 runtime loop로 컴파일한다. 기본 `static-unrolled-v1`은 유지한다. 입력 순서·좌표 범위·global L2·통과 비트·출력은 동일하며 이 모드도 회로 cache key에 포함된다. Seed를 공유하고 aggregator가 PRG를 확장하는 구조는 유지한다.

`--rpc-material prepared-reference-v1`은 prepare 단계에 전체 manifest를 보내고, execute/decide에서 round ID·input hash·인증서를 보낸다. 각 aggregator는 자기 durable ledger에 준비된 manifest를 읽고 round/hash 및 내용의 일치를 확인한 뒤 기존 input QC·실행 잠금·result QC 검사 경로를 수행한다. 외부의 검증 완료 플래그를 믿지 않는다. Prepare/decide는 순차 RPC이며 실제 MPC execute는 네 party가 동시에 실행한다. 기본값은 `inline-v1`이다.

RPC request 상한은 고정된 dimension·클라이언트 수에서 계산하고 최대 512MiB로 제한한다. 전송 객체 공유 및 native 입력의 작은 batch 쓰기는 메모리 할당을 줄이며 전송 정보·검사·계측을 생략하지 않는다.

## 생성 파일과 역할별 설정

| 파일 | 소비하는 역할 | 내용 |
|---|---|---|
| `deployment.json` | 모든 역할 | 공개 모델·정책·등록 공개키·인증 계약·backend/circuit hash |
| `coordinator/role.json` | Flower coordinator | 공개 deployment와 app/run config 위치 |
| `clients/Ci/role.json` | 해당 client | slot, 자신의 directory와 deployment 위치 |
| `clients/Ci/client.json`, `seed-input.json`, `train.npz` | 해당 client | 개인 identity·seed·로컬 학습 데이터 |
| `mpc/Pi/role.json` | 해당 aggregator | slot, deployment와 자신의 private config 위치 |
| `mpc/Pi/service-private.json`, `seed-packets/` | 해당 aggregator | 개인 identity와 수신자별 암호화 seed packet |
| `app/` | Flower | Python 앱과 모델 plugin, 공개 실행 설정 |
| `runtime-results/run-*/results.json` | coordinator / 사용자 | 공개 masked transcript, 인증서, aggregate 모델·평가 |
| `summary.json` | 사용자 | 공개 인증서·모델 전이 검증 결과 |

`check-coordinator --config PATH`는 역할 설정과 실제 Flower app/config 연결을 검사한다. 일반 `run`도 실행 전에 이 binding을 확인한다.

`check-client --config PATH`는 client binding과 audit 비활성화를 검사한다. ClientApp은 `context.node_config['client-config']`로 자기 role.json을 받을 수 있다. 로컬 Simulation에서는 기존 partition-id를 역할 directory에 연결한다. Aggregator는 `aggregator --config mpc/Pi/role.json`으로 단독 시작할 수 있다. 일반 `run`이 네 service를 시작하므로 두 방식을 동시에 실행하지 않는다.

## 일반 실행의 프라이버시 경계

- 모든 사용자 client의 `test_audit=false`, deployment의 `trusted_test_audit=false`를 요구한다. 이후 audit 플래그를 켜도 training 전에 거부한다.
- 사용자 경로에서 fixture, legacy mask, poisoning test hook, injected fault/dropout schedule을 거부한다. 기존 실험 harness의 명시적 test 모드는 그대로 유지한다.
- 일반 실행은 `audit/round-*.json`을 생성하지 않는다. Public summary verifier는 client 데이터·seed·개별 업데이트 파일을 읽지 않는다.
- Public verifier는 제출 receipt QC, input/result QC, aggregate에 따른 모델 갱신, 최종 head를 확인한다. 이것은 독립 재학습·개별 업데이트 oracle와 다르며 summary의 `independent_retraining_verified=false`로 명시한다.
- 공개 SUM/count/abort와 masked transcript가 허용된 출력이다. Count와 최종 합에서 가능한 판정·개인 기여 추론, 최소 통과 2명이 반드시 honest 2명이라는 보장이 없다는 한계는 유지한다. DP나 전체 합성 프라이버시 증명을 추가한 것이 아니다.

## 재실행과 실패

준비할 때 기존 디렉터리를 덮어쓰지 않는다. `run-started.json`을 어떤 process launch보다 먼저 0600/O_EXCL로 생성한다. 실행이 완료됐거나 불확실하게 중단됐다면 같은 세션을 다시 `run`하지 않는다. 새 output과 새 seed로 준비한다. Client 호출 ledger와 aggregator durable lock도 유지한다.

`status`는 공개 저장 결과를 읽을 뿐 재학습·재집계를 하지 않는다. `completed=true`는 인증된 라운드 실행 완료를 의미하며, 각 라운드의 `status=abort`는 별도 표시한다. Abort 시 모델 유지와 숨겨진 count 정책을 따른다. TLS bootstrap 인증서의 기존 유효기간은 1일이므로 오래된 준비 세션은 새로 만들어야 한다.

## 남은 작업

독립 host RPC/TLS·role provisioning, 역할 격리 배포 검증, 임의 loss/변동 buffer 지원과 Flower Hub 최종 패키징은 별도 작업이다. 현재 제공 경로는 audit 없는 로컬 기능 실행이며 production 인증 완료를 뜻하지 않는다.
