# AION 연구 구현 실험

## 저자 구현 포팅 경로

[원본 HPRF와 SHPRG·MGF의 포팅 기준 및 실행 명령](../docs/aion-author-port-goal.md)을
우선 따릅니다. 원본 ASR은 `--original-hprf-dir`, 학습 실험의 원본 CPU
계산은 `--author-mgf`로 선택합니다. `aion_mgf_oracle` 연결 경로는
classifier 평문을 공개하고 매 라운드 새 ASR 키를 공유하므로, 원본의
one-time sharing 비용이나 비공개 MGF까지 재현한 것으로 해석하지 않습니다.
기존 bounded-mask 경로는 아래처럼 별도로 유지합니다.

[저자 HPRF·SHPRG/MGF·HotStuff의 공식 Flower 10라운드 결과](../docs/experiments/fmnist-flower-author-hprf-shprg-hotstuff-ten-round-2026-09-30/report.md)에
실행 명령·대조군·매 라운드 선택 일치·평균/최종 지표와 남은 차이를
기록했습니다. N=100/q=20의 축소 검증이며 논문 전체 실험의 재현 결과로
확대하지 않습니다.

학습 배치 구성은 `--training-sampling author-loader`로 원본의
DataLoader/SubsetRandomSampler 및 중복 없는 poison 첫 batch를
선택할 수 있습니다. 기본 `legacy`는 기존 결과를 보존합니다.
두 방식 모두 client/round별 분리 난수를 사용하므로 원본 프로그램 전체의
공유 RNG transcript와 비트 단위 동일하다는 뜻은 아닙니다.

새 실행에 `--author-reference-dir ../Aion/input_validation/FL_Backdoor_CV`를
추가하면 원본 학습·SHPRG/MGF 소스와 실제 초기화 파일을 스냅샷으로
기록합니다. Verifier와 exporter가 hash 및 초기화 값 변경을 거부합니다.
이는 비교 기준 기록이며 그 원본 파일을 Flower worker가 직접 실행한다는
뜻은 아닙니다. 기존 완료 결과에는 소급 적용하지 않습니다.

원본 ASR-MMF와 학습 artifact MGF의 실제 데이터 흐름은 다음 구조 감사로
재검증할 수 있습니다. 네 원본 파일 hash와 핵심 함수 AST hash를 함께
기록하며, 학습 `aion()`에 client-side HPRF/DMC/DMR wire가 없다는 경계를
검사합니다.

```bash
python3 -m experiments.audit_author_mgf_dataflow \
  --source ../Aion --output .cache/NEW-author-mgf-dataflow.json
```

원본 HPRF의 논문 길이 수치 감사는 `audit_paper_dmc`에
`--rounds 60 --clients 100 --dimension 840`을 지정합니다. 이는 공개
fixture 감사이며 Flower 학습이나 프라이버시 증명은 아닙니다.

## 마스킹된 classifier MGF와 원본식 threshold

공식 Flower에서 classifier 평문 없이 MGF 선택과 전체 모델 ASR 집계를
실행하려면 `aion_mgf_beta`를 명시한다. 다음 옵션 세 개를 함께 켜면 첫
3라운드의 percentile bootstrap과 이후의 두 과거 집계 norm·전체 후보
mask norm을 사용한다. 기존 `aion_mgf_oracle`은 평문 classifier를 공개하는
별도 비교 경로이며, 아래 경로와 혼동하지 않는다.

```bash
python -m experiments.run_fmnist_official --phase all \
  --output .cache/fmnist/masked-artifact-bound-new \
  --modes aion_mgf_beta --mgf-projection --mgf-percentile --mgf-artifact-bound \
  --population 100 --participants 20 --aggregators 4 --rounds 4 --workers 4 \
  --attack-clients 4 --attack-rounds 1 4 --cohort-sampling individuals \
  --mgf-beta 0.1 --mgf-initial-alpha 0.1 \
  --mgf-initial-bound 1 --mgf-initial-term 1
```

이는 짧은 배선·공격 시험 설정이다. 논문 규모의 실험은 N=500/q=100,
aggregator 8개로 지정하며, 논문 길이 곡선은 별도로 60라운드가 필요하다.
cohort norm 복원은 2명 또는 10명 이상의 후보에서 지원한다. 모델·roster
인증서와 cohort norm 인증서를 검증하고, 실제 모델 변화에서 norm history와
다음 alpha를 재계산한다. worker 및 실행 소스 hash도 보존한다.

공식 결과 exporter는 원시 `trace`가 있는 경우 action별 `phase_timings`도
내보낸다. `seconds`는 coordinator가 본 RPC batch의 누적 경과 시간이며,
병렬 수신자 수를 곱한 CPU 시간이나 순수 암호 연산 시간이 아니다. CLI/Ray
기동·실행 후 평가·검증은 이 trace와 ServerApp 내부 총 시간 밖에 있다.
HotStuff를 켠 실행과 끈 실행의 총 시간을 같은 조건의 속도 개선으로
해석하지 않는다.

연구용 HPRF, 작은 bounded mask의 정보 노출, 개별 악성 client의 mask 일치
증명 한계는 남아 있다. 원본식 threshold 계산을 연결했다는 것이 논문의
전체 보안 보장이나 float32 결과의 비트 단위 동일성을 의미하지는 않는다.

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
## Flower Fashion-MNIST/LeNet5 정상·공격 실험

`run_fmnist_flower`는 checksum 검증된 Fashion-MNIST와 공식 `avg_300.pth`
checkpoint에서 시작한다. LeNet5 61,706개 파라미터, 같은 정규화, 정상 학습
SGD 2 epochs·batch 64·lr 0.001을 Flower ServerApp/ClientApp에 연결했다.
인증된 genesis vector 0은 checkpoint에서의 offset이다. 선택적으로 원 artifact의
FMNIST model-replacement trigger·120 local step·20배 증폭을 node-local
악성 trainer에서 실행한다.

```bash
PYTHONPATH=. python -m experiments.run_fmnist_flower \
  --output docs/experiments/fmnist-flower-new-run \
  --clients 4 --aggregators 4 --rounds 1
PYTHONPATH=. python -m experiments.run_fmnist_flower \
  --output docs/experiments/fmnist-flower-attack-new-run \
  --population 8 --clients 4 --aggregators 4 --workers 3 \
  --rounds 2 --attack-clients 2 --force-attack-rounds 1
```

이 선택형 workload에는 PyTorch가 필요하다. `--population N --clients q`는
미리 등록한 N명에서 매 라운드 q명을 선택하며, 사전 확정된 2인 privacy group
단위로 샘플링한다. `--workers`는 OS process 수를 제한하지만 각 논리 노드가
Flower ClientApp과 별도 영속 identity/share 상태를 사용한다. 이 로컬 pool은
공식 SuperLink/Ray runtime이 아니다.

`results.json`에는 라운드별 TER·ASR, 평문 fixed-point 모델 오차, 공격 일정,
참여자·partition hash, action별 시간·application payload bytes를 기록한다.
새 기본 `--partition-rng artifact`는 FMNIST 분할 전의 Python RNG 소비와
class 순서를 반영한다. 이후 공격 이미지 pool·학습 batch의 원본 RNG transcript까지
완전히 같다고 보장하지 않는다.
2인 group 샘플링은 논문의 CCS/VRF와 다르고, 현재 실험은 MGF를 사용하지 않는다.
따라서 q=100·60라운드 조건을 명령으로 지정할 수 있다는 사실만으로
Figure 5의 재현을 주장할 수 없다.

### 공식 Flower Simulation Runtime 경로

`run_fmnist_official`은 같은 FMNIST trainer를 공식 `flwr run`/SuperLink/Ray에서
실행하도록 입력·노드 identity·FAB를 스테이징한다. `aion`, 동일 코호트의
평문 `quantized`, `avg`, 평문 artifact-style `mgf`는 각각 **별도 Flower run**이다.
`--phase all`은 큰 입력을 만들기 전에 `flwr`와 `flower-superlink`가 PATH에
있는지 확인한다. 실행 Python 환경에는 Flower simulation·PyTorch가 함께
설치돼 있어야 한다. 상대 `PYTHONPATH` 항목은 launcher가 실행 시작 위치의
절대 경로로 바꿔, Flower CLI가 FAB 디렉터리로 이동해도 import가 유지된다.
새 실행의 기본 `--partition-rng artifact`는 원본의 첫 등장 class 순서와
정상 참여자 150명 사전 추첨에 따른 Python 난수 소비를 재현한다.
이전 보고서의 분할을 재실행하려면 `--partition-rng legacy`를 지정한다.
새 기본 `--poison-rng artifact`는 데이터 분할 뒤 같은 Python 난수기로 공격
이미지 풀을 뽑는다. 이전 보고서처럼 별도 seed 0에서 풀을 뽑으려면
`--poison-rng legacy`를 지정한다. 기존 결과와 새 기본 실행의 공격 성공률은
평가용 이미지 풀이 달라 직접 반복 실험으로 비교하지 않는다.
기본 `--cohort-sampling auto`는 oracle/평문 비교에서 원본처럼 client를
개별 추첨하고, 고정 키 `aion`이 포함되면 완전한 2인 privacy group을 추첨한다.
기존 oracle 보고서의 그룹 일정을 재현하려면 `--cohort-sampling groups`를 지정한다.
[N=500/q=100 원본 순서 분할 1라운드](../docs/experiments/fmnist-flower-official-artifact-partition-one-round-2026-09-29/report.md)는
공식 Flower에서 MGF 선택과 AION-ASR 집계까지 통과했다.
MGF는 개별 업데이트를 중앙에서 읽으므로 보안 집계 결과로 해석하면 안 된다.
MGF 선택과 집계 후 상태 갱신은 별도 함수로 분리되어 있으며, 현재 평문
경로의 선택·모델 결과는 변경하지 않았다. masked projection과 실제 ASR
update의 암호학적 결속은 아직 구현되지 않았다. 아래 oracle 경로에서만
MGF가 고른 부분 집합의 대규모 masked update를 합산한다.
선택형 `--modes aion_mgf_oracle mgf`는 별도의 **프라이버시 비보장 연결 시험**이다.
client가 서명한 분류기 층 840개 평문 업데이트를 Flower coordinator에 공개하여
artifact MGF와 동일하게 대상을 고른 뒤, 선택된 client의 전체 61,706차원
업데이트는 AION-ASR로 집계한다. 이 모드에서 동적 부분 집합은 고정 ASR 키를
재사용하지 않도록 client별 키를 매 라운드 새로 만들고 recipient-bound share로
집계한다. 그러나 공개 classifier 값과 masked 전체 업데이트가 같은 원본인지
영지식 증명으로 결속하지 않으며, classifier 자체는 coordinator에 노출된다. 따라서
`aion_mgf_oracle`의 높은 공격 방어 성능을 안전한 AION-MGF로 부르지 않는다.
기본 `aion` 모드는 변경되지 않으며, 이 모드는 명시적으로 지정할 때만 실행한다.
선택형 `--hotstuff`는 AION의 roster·모델 투표에 연구용 HotStuff를 켠다.
기본값은 꺼짐이며, N=500/q=100 첫 라운드 측정도 기본 서명 정족수 경로다.
기본값은 N=500, q=100, 10라운드, 악성 20명으로 첫 공격과 이후 변화를
보는 빠른 재현 경로다. 기본 `--modes`는 이번 10라운드에서 검증한
`aion_mgf_oracle mgf` 두 경로이며, 전자는 classifier 평문 좌표를 공개한다.
원래 AION·평문 양자화·평균 대조군이 필요하면
`--modes aion quantized avg mgf`를 명시한다. 논문 길이의 60라운드 곡선은 `--rounds 60`을
명시해야 하며 장시간 실행이다.
작은 공식 런타임 연결 검사는 다음처럼 실행한다(Flower simulation·PyTorch 설치 필요).

```bash
python -m experiments.run_fmnist_official \
  --phase stage --output .cache/fmnist/official-smoke-new \
  --population 4 --participants 4 --aggregators 4 --rounds 1 \
  --attack-clients 0 --attack-rounds --modes aion quantized
python -m experiments.run_fmnist_official \
  --phase run --output .cache/fmnist/official-smoke-new
```

출력은 새로운 경로여야 한다. `verify` 단계는 공식 런타임에서 저장한 매 라운드
모델과 TER·ASR을 평가하고, AION/평문 양자화 모델의 정확한 일치를 요구한다.
새로 스테이징한 실행은 manifest·참여 일정 입력 해시와 AION의 인증된
roster 서명을 다시 검증하고 각 라운드의 참여 집합·부모 모델·결과 모델
참조가 예정된 코호트와 일치하는지도 검사한다. 새 AION 실행은 공개 모델의
전체 인증서를 `*-certificates.json`에 보관한다. `verify`는 서명·commit
정족수와 인증서의 부모 체인을 확인하고 저장된 모델 배열과 정확히 대조한다.
평문 MGF 비교군은 저장된 masked norm의 순위·동적 bound·선택 수를 다시
계산하고, 기록된 집계 norm이 실제 저장 모델의 라운드별 변화와 일치하는지
확인한다. 개별 평문 update를 보관하지 않으므로 각 norm의 원본 값까지
독립 재계산하는 검증은 아니다.
[공식 런타임 첫 연결 결과](../docs/experiments/fmnist-flower-official-smoke-2026-09-29/report.md)는
N=q=4 정상 1라운드이며, 논문 규모·공격 방어 검증을 대신하지 않는다.
[N=8/q=4 공격·MGF 배선](../docs/experiments/fmnist-flower-official-dynamic-2026-09-29/report.md)과
[N=500/q=100 첫 공격 라운드](../docs/experiments/fmnist-flower-official-paper-scale-2026-09-29/report.md)는
각각 공식 Flower Runtime에서 실행했다. 후자도 60라운드 논문 곡선은 아니다.
[HotStuff·동적 참여 3라운드](../docs/experiments/fmnist-flower-official-hotstuff-dynamic-2026-09-29/report.md)는
큰 update의 단계별 전달과 서명된 모델 ancestry 복귀 검사를 함께 통과했다.
[N=500/q=100 HotStuff 첫 공격 라운드](../docs/experiments/fmnist-flower-official-hotstuff-paper-scale-2026-09-29/report.md)는
공식 Flower Runtime에서 커밋 증명과 평문 양자화 모델의 정확한 일치를 확인했다.
이 또한 60라운드 곡선이나 MGF의 보안 집계 내 실행은 아니다.
[N=500/q=100 두 라운드](../docs/experiments/fmnist-flower-official-two-round-paper-scale-2026-09-29/report.md)는
공격 후 새 코호트로 넘어갔고, 결정된 라운드의 큰 masked update와 staged
사본이 누적되지 않는 것을 확인했다. 이 실행은 HotStuff를 끈 경로다.
[N=500/q=100 10라운드](../docs/experiments/fmnist-flower-official-ten-round-2026-09-29/report.md)는
공격 라운드 5·7·10을 포함한 네 Flower 경로를 완료했다. AION/평문 양자화
모델은 모든 라운드에서 정확히 일치하며, 평문 MGF 대조군만 공격 update를
걸러냈다. 이 결과는 MGF가 AION 보안 집계 내부에 연결됐다는 뜻은 아니다.
[N=500/q=100 원본식 개별 client 추첨의 MGF→AION-ASR 10라운드](../docs/experiments/fmnist-flower-official-oracle-individual-ten-round-2026-09-29/report.md)는
새 기본 분할·참여 정책에서 모든 라운드의 MGF 선택·정확도·ASR이 평문
MGF와 일치했다. [2인 그룹 추첨](../docs/experiments/fmnist-flower-official-oracle-mgf-artifact-ten-round-2026-09-29/report.md)과
[이전 `legacy` 분할](../docs/experiments/fmnist-flower-official-oracle-mgf-ten-round-2026-09-29/report.md)의
10라운드도 별도 보존했다. 모든 `aion_mgf_oracle` 경로는 classifier 평문
좌표를 coordinator에 공개한다.
