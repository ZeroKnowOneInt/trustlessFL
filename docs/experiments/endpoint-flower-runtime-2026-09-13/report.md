# Endpoint: 공식 Flower Runtime 연결 테스트

실행일: 2026-09-13. 결과: **통과**.
현재 AION이 아니라, crowdsensing **일반 평균/FedProx 평문 학습**의 Runtime 이전을 검증했다.

## 실제 실행 경로

- `flwr run`으로 FAB를 로컬 SuperLink에 제출하고 공식 Flower Simulation Runtime/RayBackend에서 실행했다.
- Flower 1.36.0, Ray 2.55.1, NumPy 2.5.0, CPU float64.
- ServerApp 1개, 가상 SuperNode 8개, CPU 1개/worker, Runtime 전체 CPU 2개, GPU 0개.
- ClientApp 응답에서 서로 다른 worker PID 2개를 관측했다. 가상 클라이언트 8개 각각을 고정 프로세스 8개로 실행한 것이 아니다.
- Run ID: `5466189459782919444`. Flower CLI 상태: `finished:completed`.
- FAB SHA-256: `d2a7c2fda79af98e78e1a053bba1066036e8f58f92097d8cd9d67a83d6a41559`.
- 이번 테스트 전용 SuperLink를 loopback 주소에 시작했다. 실행 중 의존성 자동 설치는 끄고 사전 설치된 가상환경을 사용했으며, 실행 종료 후 launcher가 자신이 시작한 SuperLink 프로세스 그룹을 종료했다.

다음 로그를 실제로 확인했다.

```text
Successfully started run 5466189459782919444
Starting Flower Simulation
Federation `@none/default` (8 simulated SuperNodes)
```

자체 ProcessGrid 및 `run_simulation`을 흉내 낸 실행 루프는 사용하지 않았다.
ServerApp의 평균 집계 제어 흐름은 직접 구현해 기존 **동일 클라이언트 가중치 1/8**을 유지했다.
Flower 내장 FedAvg/FedProx Strategy의 기본 설정을 그대로 실행했다는 뜻은 아니다.

## 학습 조건

- 기존 V2 CSV 8개와 동일한 중복 그룹 분할: train 102,509 / validation 34,227 / test 34,317.
- MLP 31→128 ReLU→9, 5,257 parameters. 기존 학습기 그대로 사용.
- seed 42, 3 rounds, local 3 epochs, batch 128, SGD learning rate 0.1.
- μ=0(일반 평균), μ=0.1(FedProx)의 정상/25% label-flip, 총 네 조건을 하나의 Flower run에서 순차 실행.
- 각 조건은 같은 seed의 초기 모델에서 새로 시작한다. 공격자는 기존 난수 규칙과 같은 클라이언트 `[1, 2]`.
- ClientApp은 자신의 partition에 해당하는 train/test shard를 읽는다. ServerApp에는 train 데이터를 전달하지 않으며 평가 시 confusion matrix와 손실 합계를 반환한다. 다만 공유 파일시스템의 시뮬레이션이므로 데이터 접근의 보안 격리를 주장하지 않는다.
- 이번에는 하이퍼파라미터를 다시 선택하지 않았다. 이전 validation에서 고정한 learning rate 0.1을 사용했다.

## 결과 및 동등성

| 조건 | 3라운드 test macro-F1 | NumPy 대비 모든 라운드 모델 최대 절대 오차 |
| --- | ---: | ---: |
| 일반 평균, 정상 | 51.3728% | 0 |
| FedProx μ=0.1, 정상 | 47.9720% | 0 |
| 일반 평균, 25% label-flip | 47.8275% | 0 |
| FedProx μ=0.1, 25% label-flip | 47.6862% | 0 |

초기 모델(round 0)부터 round 3까지 각 조건의 모든 모델을 별도 NumPy 순차 대조군과 비교했다.
사전에 정한 **오차 0** 기준을 네 조건 모두 만족했고, 라운드별 test confusion matrix도 정확히 일치했다.
이 표는 1 seed / 3 rounds의 연결 테스트이며 이전 3 seeds / 10 rounds 성능표와 직접 비교하지 않는다.

추가 확인:

- 임의의 Flower node ID와 논리적 partition 0–7의 대응을 발견하고 검증했다.
- 응답 도착 순서와 무관하게 partition 순으로 정렬한 뒤 평균냈다.
- 중복·누락 응답, 잘못된 case/round, 잘못된 모델 차원을 거부하도록 검사했다.
- `Context.state`의 클라이언트별 학습 호출 횟수가 4조건 × 3rounds = 12로 모두 유지되었다. 호출마다 동일 ClientApp 인스턴스가 살아 있다고 가정하지 않았다.
- 전체 단위·회귀 테스트 **67개 통과**. 새 테스트는 메시지 직렬화, FedProx/poisoning 결과, 상태 보존, 응답 순서 및 누락·중복 검사를 포함한다.

## 구현과 재실행

- 앱: [endpoint_flower.py](../../../trustlessfl/endpoint_flower.py)
- 준비·실행·대조 검증: [run_endpoint_flower.py](../../../experiments/run_endpoint_flower.py)
- 별도 앱 설정 템플릿: [flower-pyproject.toml](../../../configs/endpoint/flower-pyproject.toml)

```bash
uv sync --extra simulation --cache-dir .cache/uv
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  .venv/bin/python -m experiments.run_endpoint_flower \
  --output .cache/endpoint/runs/flower-runtime-new --rounds 3
```

이 launcher는 데이터 shard와 최소 소스만 포함한 별도 앱을 준비하고 실제 `flwr run`을 호출한다.
root `pyproject.toml`의 AION entrypoint는 바꾸지 않았다. `flwr run .`만으로 이 테스트가 실행되는 것은 아니다.
새 output 경로가 필요하며 로컬 socket을 사용할 수 있어야 한다. 준비 후 포트 권한으로 실패한 경우에만 같은 output에 `--phase run`으로 재시도할 수 있다.

첫 sandbox 시도는 socket 생성 권한 때문에 실행 전에 실패했고, 권한 승인 후 공식 Runtime 실행에 성공했다. 실행기 대체는 없었다.

원본 증거는 git에서 제외된 `.cache/endpoint/runs/flower-runtime-2026-09-13/`에 보존한다.

- `provenance.json`: 버전·소스 hash·사전 동등성 기준.
- `data-audit.json`, `split.npz`, `shards/manifest.json`: 원본/분할/학습 파일 검증 정보.
- `attempt-552c8c8c/commands.json`, `flwr.log`, `superlink.log`, `run-status.json`: 실제 명령·Runtime 로그·최종 상태.
- `runtime-results/run-5466189459782919444/`: 각 라운드 모델과 지표.
- `verification.json`: 네 조건의 round별 오차 `[0, 0, 0, 0]`.

## 범위와 다음 단계

**공식 Runtime에서 학습·평가·상태·집계의 동등성을 확인했다.** 정확도 개선, GPU 실행, AION 보안집계, 악성 서버 내성 또는 실제 silo 네트워크 검증은 이번 테스트에 포함하지 않았다.
다음 AION 단계에서는 별도 aggregator 역할·신원·내구성 있는 서명 상태를 연결하고 작은 합성 데이터부터 검사한다.
정상 오탐률 등 학습 품질 진단은 별도 과제로 유지한다.
