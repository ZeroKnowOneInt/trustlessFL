# AION 연구 구현 실험

## 공개 코드 MLP·Adam 설정 이식 테스트

31→30→30→9 MLP, Adam lr=0.01, batch 500, 최대 150 epochs/validation 조기 종료를
공식 Flower Runtime의 단일 GPU worker에서 실행한다. 독립 그룹 test와
notebook식 행 분할·validation 재사용을 서로 다른 결과로 기록한다.
원본 Lightning notebook의 완전 재현 또는 AION/FL 실험이 아니다.

```bash
uv sync --extra simulation --extra gpu --cache-dir .cache/uv
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  .venv/bin/python -m experiments.run_endpoint_public \
  --output .cache/endpoint/runs/public-recipe-new --seeds 42 43 44
.venv/bin/python -m experiments.export_endpoint_public \
  --run .cache/endpoint/runs/public-recipe-new --output docs/experiments/public-recipe-new
```

`--profiles group-holdout`으로 독립 test 조건만 실행할 수 있다.
[결과와 원본 코드 대비 차이](../docs/experiments/endpoint-public-recipe-2026-09-13/report.md)를 참고한다.

## 동일 Endpoint MLP의 중앙집중 진단

공개 train 데이터를 합쳐 공식 Flower Runtime의 가상 노드 하나에서 30 epochs 학습한다.
모델·분할·SGD 설정을 보존한 진단이며 AION이나 논문 재현이 아니다.

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  .venv/bin/python -m experiments.run_endpoint_central \
  --output .cache/endpoint/runs/central-new --seeds 42 43 44 --steps 10
.venv/bin/python -m experiments.export_endpoint_central \
  --run .cache/endpoint/runs/central-new --output docs/experiments/central-new
```

[결과](../docs/experiments/endpoint-central-2026-09-13/report.md)와
[논문 코드 감사](../docs/crowdsensing-source-audit.md)를 함께 참고한다.

## Endpoint 공식 Flower Simulation Runtime 테스트

단일 GPU 테스트는 `uv sync --extra simulation --extra gpu --cache-dir .cache/uv` 후
아래 runner에 `--backend torch-cuda`와 새 출력 경로를 지정한다.
가상 클라이언트 8개를 GPU worker 1개가 순차 학습한다. float64 로컬 SGD만 CUDA이고
평가·평균 집계는 CPU다. 이 경로는 AION 보안집계 실험이 아니다.
상세 검증 기준과 자원 정책은 [단일 GPU 실행 지침](../docs/flower-runtime-guidelines.md#단일-gpu-실행)을 따른다.

[실행 지침](../docs/flower-runtime-guidelines.md)에 따라 본 FL 실험은 공식 Runtime을 사용한다.
[첫 연결 테스트](../docs/experiments/endpoint-flower-runtime-2026-09-13/report.md)는 CPU worker 2개/가상 노드 8개로
일반 평균·FedProx의 정상/label-flip 네 조건을 실행하고 NumPy 대조군과 모든 round 모델의 정확한 일치를 확인했다.

```bash
uv sync --extra simulation --cache-dir .cache/uv
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  .venv/bin/python -m experiments.run_endpoint_flower \
  --output .cache/endpoint/runs/flower-runtime-new --rounds 3
```

launcher가 별도 앱을 구성하고 로컬 SuperLink에 실제 `flwr run`으로 제출한다. 포트 사용 권한이 필요하다.
root AION 앱 설정과 과거 결과는 유지한다. 기본 CPU 테스트에는 GPU가 포함되지 않으며,
두 backend 모두 AION 보안집계·실제 네트워크 장애가 포함되지 않는다.

## Crowdsensing: 보안집계 전 평문 학습 비교

`experiments.download_endpoint`는 공식 Science Data Bank V2의 장치별 특징 CSV 8개만
다운로드하고 고정한 크기/MD5를 검사한다(약 88 MB). 원시 로그나 악성코드는 받지 않는다.
실제 배포 파일은 입력 31개 + label이며, 논문의 32개 입력 명세와 차이를 기록한다.

```bash
.venv/bin/python -m experiments.download_endpoint
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  .venv/bin/python -m experiments.run_endpoint \
  --output .cache/endpoint/runs/plaintext-new --seeds 42 43 44 --rounds 10
.venv/bin/python -m experiments.export_endpoint \
  --run .cache/endpoint/runs/plaintext-new \
  --output docs/experiments/endpoint-plaintext-new
```

순수 NumPy 학습 시뮬레이션으로 동일 가중 평균과 FedProx μ=0.01/0.1을 정상/25% label-flip에서
비교한다. Flower/AION, 새로운 방어 알고리즘, 프라이버시 보장은 포함하지 않는다.
정확히 같은 특징 그룹은 split을 공유하고 상충 label은 유지한다. 시간순 평가는 아니다.
Learning rate는 clean validation으로만 선택하며 모든 μ와 공격 조건에서 고정한다.
출력 디렉터리는 새 경로여야 한다. 그룹 인덱스·모델은 cache에, 공개 지표만 문서에 저장한다.

## 공식 artifact 재현 준비

[재현 계획](../docs/aion-reproduction-plan.md)에 따라 공식 archive를 먼저 검사한다.
`experiments.audit_artifact`는 Zenodo record 15870338의 파일 크기·MD5와 ZIP CRC를
검증하고 SHA-256을 기록한다. 코드/설정 등 UTF-8 텍스트만 새 디렉터리에 추출하며,
archive의 Python·shell·pickle·모델을 실행하거나 역직렬화하지 않는다.

```bash
python -m experiments.audit_artifact \
  --archive .cache/aion-artifact/Aion.zip \
  --record .cache/aion-artifact/record-15870338.json \
  --output .cache/aion-artifact/inspection-15870338
```

공식 파일을 별도로 받은 뒤 실행한다. output은 존재하지 않는 새 경로여야 한다.
archive와 추출 원본은 `.cache`에 두고, 검토 결과와 공개 설정만 문서화한다.
`configs/reproduction/paper-targets.csv`는 논문 보고값 목록이며 측정 결과가 아니다.

첫 [공식 artifact 감사와 checkpoint 실행 준비 결과](../docs/reproduction/source-audit.md)를 기록했다.
`experiments.probe_aion_checkpoint`는 별도 PyTorch CPU 환경이 필요하며, 현재 Flower
의존성에 torch를 추가하지 않는다. 원 checkpoint의 제한된 tensor 추출과 임의 입력의
forward/backward만 검사한다. 실제 FMNIST 정확도·공격 방어 검증은 아래 별도 runner를 사용한다.

## 공식 Fashion-MNIST artifact CPU pilot

이 runner는 **중앙 평문 input-validation 실험**이다. Flower/secure aggregation 경로를
실행하지 않는다. [pilot 보고서](../docs/experiments/fmnist-artifact-pilot-2026-09-13/report.md)에
관측 결과와 논문 재현 여부를 기록한다.

별도 `.cache/aion-artifact/iv-cpu-venv`를 사용한다. Python 3.12.12 환경에
torch 2.4.0+cpu / torchvision 0.19.0+cpu를 공식 CPU wheel index에서 설치하고,
[최소 의존성 freeze](../configs/reproduction/artifact-pilot-cpu.lock.txt)의 나머지를 설치한다.
이는 원 artifact의 Python 3.11/CUDA 환경 전체를 재현한 lock이 아니다.

```bash
.cache/aion-artifact/iv-cpu-venv/bin/python -m experiments.prepare_fashion_mnist \
  --download --output docs/reproduction/fashion-mnist-new-data.json

.cache/aion-artifact/iv-cpu-venv/bin/python -m experiments.run_aion_artifact \
  --rule avg --rounds 2 --output .cache/aion-artifact/runs/fmnist-avg-new
.cache/aion-artifact/iv-cpu-venv/bin/python -m experiments.run_aion_artifact \
  --rule aion --rounds 2 --output .cache/aion-artifact/runs/fmnist-aion-new

.cache/aion-artifact/iv-cpu-venv/bin/python -m experiments.export_artifact_pilot \
  --avg .cache/aion-artifact/runs/fmnist-avg-new \
  --aion .cache/aion-artifact/runs/fmnist-aion-new \
  --output docs/experiments/fmnist-new
```

이미 받은 데이터는 다운로드 명령 없이 사용할 수 있다. 학습 runner는 네트워크 다운로드를
하지 않고 압축 파일 MD5 및 IDX header/내용을 검증한다. 각 output은 **새 경로**여야 한다.
원본 SHA 검증 후 별도 사본을 생성하고, CPU device 호출·제한된 checkpoint loader·관측 로그만
추가한다. 모델 생성 때문에 추가로 소모될 torch RNG를 복구해 원 loader의 난수 진행을 보존한다.

공격 클라이언트 20명, boost 20, N=500/q=100, 120 attack steps, benign 2 local epochs,
checkpoint round 300과 원 코드의 자연 난수 일정을 유지한다. poison data는 원 코드대로
테스트셋의 512개 항목(중복 가능)을 학습/평가에 함께 사용한다. 독립 held-out ASR이 아니다.
`rounds.jsonl`, `result.json`, partition 인덱스, source hash, runtime patch, 실행 adapter 사본,
최종 NPZ weights를 저장한다. NPZ만으로 전체 RNG 상태를 포함한 중간 재개는 지원하지 않는다.

두 집계의 첫 라운드 업데이트 일치 여부는 exporter에서 검증한다. 이후 AION의 mask 생성은
Python RNG를 추가 소비하므로 다음 라운드 참여자가 avg와 달라질 수 있다. 원 동작을 보존하며
paired multi-round 시험이라고 부르지 않는다. `--repeat-of <기존 export 경로>`를 주면 시간 외
모든 라운드 관측값과 model hash가 재실행에서도 같은지 검증한다.

60라운드 기준선은 각각 **새 output + `--rounds 60`**으로 checkpoint부터 다시 시작한다.
pilot만으로 60라운드 성능, 여러 seed의 통계적 재현, 분산 MGF 또는 보안성을 판정하지 않는다.

## 합성 데이터 실험

```bash
uv sync
FLWR_TELEMETRY_ENABLED=0 OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  uv run python -m experiments.run_aion \
  --output docs/experiments/aion-new-run --repeats 3
```

출력 디렉터리는 새 경로여야 한다. 기존 결과를 덮어쓰지 않는다. 각 실행마다 임시 identity/share 상태와 task ID를 새로 만들고 종료 시 제거한다. 프로토콜 코드는 변경하지 않는다.

실험은 순차 수행한다. 성능 측정 중 다른 테스트나 벤치마크를 함께 실행하지 않는다. 기본 구성은 정상 조건 7개 × 3회, 장애/공격 조건 8개 × 1회로 총 29회다.

- 정상 조건: client 수 2/4/8, aggregator 수 4/7, 차원 8/128/1024, 30라운드 수렴
- 비교 기준: 동일 데이터와 fixed-point 양자화를 쓰는 clear aggregation, 양자화 없는 float aggregation
- 평가: 학습 MSE와 별도 합성 데이터 MSE, 모든 라운드 model 최대 절대 오차
- 장애/공격: aggregator 1/2개 응답 억제, client 탈락, signed share·결과 변조, 서버 모델 변조, 이전 update 재전송, 정상 서명의 poisoned update

`results.json`에는 개별 실행·단계별 시간, application payload 바이트 수, 완료 상태, 평가 결과, source hash와 환경을 저장한다. `summary.csv`에는 조건별 요약을 저장한다. 개인 key, share, masked update, certificate는 결과 파일에 기록하지 않는다. `final_model`은 이 실험의 공개 합성 데이터 집계 결과다.

`expectation_met`는 예상한 동작을 관찰했는지를 나타낸다. 현재 방어하지 못하는 signed poisoning은 **공격이 받아들여지는 것**이 예상 결과이므로, 이 값이 true라는 사실을 보안 테스트 통과로 해석하면 안 된다.

노드 탈락은 요청을 즉시 억제하는 방식으로 주입하며 실제 TCP 단절이나 timeout 지연을 모사하지 않는다. 공격 harness는 지정한 악의적 노드의 private key만 읽어 정상 서명을 가진 조작 메시지를 만든다. 정상 coordinator의 권한이나 코드가 확장되는 것은 아니다.

이 실험은 로컬 ProcessGrid와 합성 데이터에 대한 구현 검사다. 논문의 성능 배수, real-world poisoning 방어율, cryptographic privacy를 재현하는 실험은 아니다.

## MNIST 전체 데이터 실험

추가 ML 프레임워크 없이 NumPy softmax regression을 사용한다. 학습 60,000장 전체를
4개 client에 15,000장씩 배정하고 테스트 10,000장은 학습에서 제외한다.
784 pixels + bias × 10 classes = 7,850 parameters, 픽셀은 255로 나눈다.
각 round마다 local SGD 1 epoch, batch 256, learning rate 0.1, zero initialization이다.

```bash
mkdir -p .cache/mnist
curl --fail --location --output .cache/mnist/mnist.npz \
  https://storage.googleapis.com/tensorflow/tf-keras-datasets/mnist.npz
FLWR_TELEMETRY_ENABLED=0 OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  uv run python -m experiments.run_mnist \
  --output docs/experiments/mnist-new-run --rounds 20
```

이미 다운로드한 파일은 다시 받을 필요 없다. runner는 [공식 Keras 소스](https://github.com/keras-team/keras/blob/master/keras/src/datasets/mnist.py)의
SHA-256 `731c5ac602752760c8e48fbffcf8c3b850d9dc2a2aedcf2cc48468fc17b673d1`을 검증한다.
데이터는 git에서 제외된 `.cache`에 저장한다.

기본적으로 IID와 label-skew를 각각 1회 실행한다. label-skew는 라벨 정렬 후
7,500개씩 8개 shard를 만들어 client마다 무작위로 2개씩 배정하는 방식이며,
client당 반드시 두 종류의 숫자만 있다는 뜻은 아니다. `--seed`는 분할과 local
minibatch 순서를 고정한다. `--splits iid`로 한 조건만 선택할 수 있다.

일반 fixed-point 집계, 일반 float 집계, 실제 Flower/AION 집계를 각각 독립적으로
학습시킨다. 데이터·초기화·batch 순서·하이퍼파라미터는 같고, fixed-point와
AION은 소수 4자리 delta 양자화를 동일하게 적용한다. 모든 라운드의 model
최대 절대 오차와 test accuracy/cross-entropy를 저장하며 fixed-point 모델과
오차가 0이 아니면 실행 실패로 처리한다.

client별 `mnist-shard`, `mnist-seed`, `mnist-batch-size`는 **node-local 설정**이다.
server 메시지로 trainer나 파일 경로를 지정하지 않는다. aggregator에는 shard
설정을 전달하지 않는다. 평가 harness만 공개 MNIST 전체를 가지고 기준값을
계산한다. 로컬 동일 OS user의 프로세스 분리는 파일 접근을 막는 보안 경계가 아니다.

출력: `results.json`과 split별 JSON(환경·hash·분포·학습곡선·단계별 timing),
`*-models.npz`(공개 데이터로 학습한 모든 round의 집계 model; key/share 없음).
보안 경로 wall time에는 프로세스 시작·shard 로딩·학습·프로토콜·종료가 포함되며,
사전 provisioning과 사후 평가는 제외된다. 일반 집계 시간은 **순차 로컬 계산**이라
암호화만의 오버헤드를 비교하는 공정한 대조군은 아니다. 통신량은 canonical JSON
payload 합계이며 실제 네트워크 트래픽이 아니다.

이 실험은 CNN이나 AION 논문의 MNIST 결과 재현이 아니며, malicious client/server를
주입하지 않는다. 기존 poisoning 방어 부재 및 연구용 masking의 보안 한계는 그대로다.

## Crowdsensing AION / 공식 Flower Runtime

공개 MLP·Adam recipe를 연구용 AION-ASR에 연결한 실행기는 `experiments.run_endpoint_aion`이다.
기존 ProcessGrid 실험과 구분한다. ServerApp1 + client8 + aggregator4 역할을 사용한다.

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  .venv/bin/python -m experiments.run_endpoint_aion \
  --rounds 10 --seeds 42 43 44 --output .cache/endpoint/runs/aion-new
```

새 출력 경로를 지정한다. AION / 평문 양자화 / 평문 float를 별도 FAB에서 실행하고
모든 AION/평문 양자화 round 모델이 정확히 같은지 확인한다. 설정과 한계는
[실행 문서](../docs/endpoint-aion-runtime.md)를 참고한다. 기존 root AION entrypoint는 변경하지 않았다.
