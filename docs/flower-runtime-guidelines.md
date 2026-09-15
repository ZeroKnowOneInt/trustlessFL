# 실험 실행 지침: Flower Simulation Runtime

결정일: 2026-09-13.
상태: **Endpoint 일반 평균/FedProx의 공식 Runtime CPU·단일 GPU 테스트 완료. AION 연결은 미완료.**

[첫 연결 테스트](./experiments/endpoint-flower-runtime-2026-09-13/report.md): 8개 가상 노드, CPU worker 2개,
정상/label-flip × 일반 평균/FedProx의 네 조건에서 3 rounds 실행. NumPy 대조군과 모든 round 모델이 정확히 일치했다.

## 기본 원칙

앞으로 프로젝트의 **본 연합학습 실험은 공식 Flower Simulation Runtime으로 실행한다.**
일반 평균 집계, FedProx, AION 비교에 동일한 실행 기반을 사용한다.
이 지침은 기존 계획에 적힌 NumPy 반복문 또는 ProcessGrid 기반 본 실험 방침보다 우선한다.
이미 수행한 실험 기록은 당시 실행 방식을 그대로 보존한다.

기준 문서는 [Flower Run simulations](https://flower.ai/docs/framework/how-to-run-simulations.html)이다.
공식 Runtime은 Ray 기반으로 ClientApp 실행과 자원에 따른 스케줄링을 관리한다.
단순히 Flower API를 import하거나 ServerApp/ClientApp을 직접 호출한 것만으로 공식 Runtime 실행이라고 부르지 않는다.

| 실행 방식 | 앞으로의 용도 |
| --- | --- |
| 공식 Flower Simulation Runtime | 본 FL 실험, 일반 평균/FedProx/AION 비교 |
| 현재 NumPy 시뮬레이터 | 빠른 학습 아이디어 탐색, 수치적 대조군, 단위 테스트 |
| 자체 ProcessGrid | AION 프로토콜 회귀 검사, 기존 결과와의 대조 |
| 별도 공식 AION artifact 실행기 | 해당 논문 artifact 재현; 프로젝트 Runtime 실험과 구분 |

빠른 탐색·진단을 기존 실행기로 수행할 수 있지만 반드시 실행 방식을 명시한다.
공식 Runtime 결과를 대체하는 본 실험으로 사용하려면 먼저 사용자와 예외를 합의한다.
Runtime 연결이 실패하면 원인을 보고하고, 다른 실행기로 조용히 대체하지 않는다.

## 이전 순서

1. 현재 Endpoint 일반 평균/FedProx 학습기를 Flower ClientApp에 연결한다.
2. CPU에서 같은 데이터·초기 모델·학습 설정으로 NumPy 대조군과 결과를 비교한다.
3. 작은 합성 데이터로 AION을 공식 Runtime에 연결하고 기존 ProcessGrid 결과와 대조한다.
4. 상태 보존·신원 매핑·인증서 검증·장애 처리 검사가 통과하면 Endpoint AION 본 실험을 진행한다.
5. GPU 실행과 규모 확장은 CPU 기준선 검증 후 별도 조건으로 추가한다.

실행 환경 이전과 동시에 모델 구조·집계 가중치·전처리·방어 알고리즘을 바꾸지 않는다.
정확도 또는 오탐률 문제는 별도 학습 진단 과제로 다룬다. Runtime 변경 자체를 학습 품질 개선으로 해석하지 않는다.

## 역할과 상태 관리

- 일반 평균/FedProx: ServerApp 1개 + 학습 역할 가상 노드 8개.
- AION: ServerApp 1개 + 학습 역할 가상 노드 8개 + aggregator 역할 가상 노드 4개.
- AION aggregator는 별도의 논리적 신원으로 ClientApp을 실행하며 학습 데이터와 학습 역할을 갖지 않는다.
- Flower의 실행 worker와 AION 참여자 신원을 동일시하지 않는다. worker 재사용과 호출 순서에 관계없이 각 노드의 역할·키·데이터·상태가 올바르게 연결되어야 한다.
- 현재 `train → prepare → share → finalize → commit` 흐름과 서명 검증을 유지한다. Runtime 이전을 위해 서버가 집계를 대신 수행하도록 바꾸지 않는다.

ClientApp 인스턴스는 호출마다 생성·폐기될 수 있으므로 객체 메모리에만 상태를 두지 않는다.
[Flower 상태 관리 문서](https://flower.ai/docs/framework/how-to-design-stateful-clients.html)의 `Context.state` 또는 검증된 노드별 저장소를 사용한다.
현재 AION의 파일 기반 상태 저장을 이전할 때는 task별 namespace, 노드별 키·share, 서명 전 잠금 저장 및 중복 요청 처리를 보존한다.
`Context.state`의 실행 중 상태 보존을 장애 후 영구 저장·롤백 방지 보장으로 간주하지 않는다.

## 실행·비교 조건

- 프로젝트에서 고정한 Flower 버전을 사용한다. 현재 의존성은 `flwr==1.36.0`이며, 최신 웹 문서와 설치 버전의 CLI/API 차이를 실행 전에 확인한다.
- 공식 `flwr run` 경로를 기본으로 구성한다. 필요한 앱 설정·simulation 의존성·노드별 provisioning을 갖추고 실제 Runtime 시작 로그를 확인한다.
- 초기에는 GPU 없이 CPU로 실행하고 CPU 할당량, 전체 자원 한도, BLAS/OMP thread 수와 실제 동시 실행 수를 기록한다.
- GPU를 추가할 때는 자원 할당을 VRAM 강제 격리로 해석하지 않는다. 측정한 메모리 사용량과 OOM 여부를 기준으로 동시 실행 수를 제한한다.
- 같은 데이터 파일 hash, 분할 인덱스, feature/label 순서, 초기 모델, seed, batch 순서, local epochs, learning rate, 공격자를 비교군 사이에 고정한다.
- 현재 평균은 **클라이언트 동일 가중치**다. Flower 기본 전략을 연결하면서 표본 수 가중 평균으로 바뀌지 않도록 확인한다.
- 대조 검사는 마지막 정확도만 보지 않고 라운드별 모델·집계값을 확인한다. fixed-point 정수 합은 정확히 비교하고, 부동소수점 허용 오차는 실행 전에 정한다.
- 자원 부족으로 대기 중인 정상 노드가 timeout 때문에 악성/탈락 노드로 분류되지 않도록 실행 병렬도와 timeout을 함께 검증한다.

현재 root 앱 설정은 AION entrypoint를 유지한다. Endpoint는 별도 앱 템플릿과 `experiments.run_endpoint_flower`로 준비해 공식 `flwr run`으로 실행한다.
root에서 `flwr run`만 입력하면 Endpoint/AION 본 실험이 바로 실행된다고 안내하지 않는다.

## 단일 GPU 실행

[첫 GPU 테스트 결과](./experiments/endpoint-flower-gpu-2026-09-13/report.md): RTX 5060, worker 1개,
96개 학습 응답 전부 CUDA, CPU 대비 모델 최대 오차 2.8×10⁻¹⁶ 및 혼동행렬 일치.

CPU 기준선 이후 추가한 선택 경로는 `--backend torch-cuda`다. 기본 경로는 계속 NumPy CPU다.
RTX 5060의 Blackwell 지원을 위해 CUDA 12.8 PyTorch 2.8.0을 `gpu` extra로 고정한다.
[PyTorch Blackwell 지원 안내](https://pytorch.org/blog/pytorch-2-7/)를 따른다.
시스템 CUDA toolkit이나 드라이버를 새로 설치하지 않으며, 패키지는 프로젝트 가상환경에 설치한다.

```bash
uv sync --extra simulation --extra gpu --cache-dir .cache/uv
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  .venv/bin/python -m experiments.run_endpoint_flower \
  --backend torch-cuda --rounds 3 --output .cache/endpoint/runs/flower-gpu-new-run
```

- 가상 클라이언트 8개, Ray 전체 CPU 1/GPU 1, worker당 CPU 1/GPU 1로 설정한다.
  따라서 worker 하나가 8개 클라이언트를 순차 실행한다. 논리적 FL 참여자 수는 바뀌지 않는다.
- 로컬 SGD만 GPU에서 실행한다. 초기 모델·batch 순서는 NumPy와 동일하고, 31→128(ReLU)→9 모델,
  cross-entropy, SGD, FedProx 고정 anchor, 클라이언트 동일 가중 평균을 유지한다.
- 첫 검증은 float64다. float32/AMP/TF32를 사용하지 않는다. 평가와 집계는 CPU다.
  GPU 사용만으로 이 작은 모델이 빨라진다고 가정하지 않는다.
- 실행 전 별도 프로세스에서 CUDA forward/backward를 검사하고 종료하여 GPU context를 반납한다.
  CUDA가 없으면 실패하며 CPU로 자동 대체하지 않는다. 다른 GPU 작업을 중단하지 않는다.
- GPU 자원값 1은 **Ray 내부 스케줄링 한도**이지 VRAM 격리나 다른 프로그램의 GPU 사용 금지가 아니다.
  worker별 CUDA 기기명, 실제 tensor device, peak allocated/reserved bytes를 결과에 남긴다.
  이 값은 PyTorch allocator 통계이며 드라이버 context와 다른 프로그램까지 포함한 총 VRAM이 아니다.
- 순차 실행 대기를 고려해 요청 timeout은 300초, CLI timeout은 1,200초다.
- 검증 기준은 실행 전에 provenance에 저장한다: 매 round 모델 최대 절대 오차 ≤`1e-8`,
  혼동행렬 일치, cross-entropy 오차 ≤`1e-8`. 모든 학습 응답이 단일 PID의 `cuda:0`/float64여야 한다.
  CPU 경로는 기존과 동일하게 모델의 정확한 일치를 요구한다.
- `--phase prepare`에서 backend를 선택한다. 이후 `--phase run`/`verify`는 저장된 설정을 사용한다.
  출력 디렉터리는 새로 지정하고 기존 실험은 덮어쓰지 않는다.

위 `run_endpoint_flower` 경로는 평문 일반 평균/FedProx다.
추가한 `experiments.run_endpoint_aion`은 별도 FAB로 AION 및 평문 대조군을 공식 Runtime에서 실행한다.
[AION Runtime 실행 문서](./endpoint-aion-runtime.md)를 참고한다.
이 경로의 공개 recipe 모델은 float32이며, 위의 기존 모델 float64 GPU 동등성 테스트와 구분한다.

## 결과 보고와 한계

보고서에는 Runtime/Flower/Ray 버전, 실행 명령·설정, run ID, 노드 역할 수, 자원 설정, 소스 hash, 데이터·분할 hash, seed, 성공/abort 여부를 남긴다.
일반 평균과 AION의 비용 비교는 같은 Runtime과 자원 조건에서 수행한다. NumPy 순차 실행 시간과 Flower 병렬 실행 시간을 직접 비교해 보안집계 overhead라고 부르지 않는다.

가상 노드의 분리는 독립 기관 간 보안 격리가 아니다. 다음은 별도 검증 대상으로 남긴다.

- 실제 silo 방화벽·연결 방향·RTT·대역폭과 배포 네트워크 동작.
- 서로 다른 관리자/호스트 사이의 키 격리 및 운영상 비공모 가정.
- 실제 프로세스 장애·재시작·스토리지 롤백에 대한 동작.
- 현재 연구용 AION 암호 구성의 보안성. 공식 Runtime으로 옮겨도 `research-mode=true`와 기존 보안 한계를 유지한다.

기존 결과의 정확한 명칭은 다음과 같다.

- Crowdsensing 일반 평균/FedProx 결과: **NumPy 평문 학습 시뮬레이션**.
- 기존 프로젝트 AION/MNIST 결과: **Flower API + 자체 ProcessGrid 검사**.
- 이전 후 실제 실행 검증을 마친 결과만: **공식 Flower Simulation Runtime 실험**.
