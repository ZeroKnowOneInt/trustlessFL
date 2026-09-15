# Endpoint: 단일 GPU Flower Runtime 테스트

실행일: 2026-09-13. 결과: **통과**.
RTX 5060 한 개를 가상 클라이언트 8개가 순차 사용하여 실제 CUDA 학습을 완료했다.
현재 대상은 crowdsensing 일반 평균/FedProx **평문 학습**이며 AION 보안집계는 포함하지 않는다.

## 실행 구성

- 공식 `flwr run` → 로컬 SuperLink → Flower Simulation Runtime/RayBackend.
- Flower 1.36.0, Ray 2.55.1, NumPy 2.5.0, PyTorch 2.8.0+cu128 / CUDA runtime 12.8.
- NVIDIA GeForce RTX 5060, VRAM 8,151 MiB, driver 610.74, compute capability 12.0.
  사전 CUDA forward/backward 검사에 성공했고 wheel의 `sm_120` 지원을 확인했다.
- ServerApp 1개, 가상 SuperNode 8개. 전체 CPU 1/GPU 1, worker당 CPU 1/GPU 1.
  관측된 학습 worker PID는 `2419723` 하나이며 `CUDA_VISIBLE_DEVICES=0`이었다.
- 로컬 SGD만 CUDA float64. 초기화·batch 순서·평가·동일 클라이언트 가중 평균은 기존 NumPy 방식이다.
  AMP/TF32는 사용하지 않고 PyTorch deterministic algorithms 및 `CUBLAS_WORKSPACE_CONFIG=:4096:8`을 설정했다.
- Run ID: `15138946526726773533`. CLI 최종 상태: `finished:completed`.
- FAB SHA-256: `3feab63fb372c3ac593986c2ad1274ed08fef024cc6993a503cb637cfa7ba7ea`.

[Flower 자원 정책](https://flower.ai/docs/framework/how-to-run-simulations.html)에 따라 worker 수를 제한했다.
GPU 자원값은 Ray의 스케줄링 자원이지 VRAM 강제 격리나 다른 프로그램에 대한 GPU 독점이 아니다.
독립적인 silo/기관 8개가 같은 GPU 위에서 보안상 격리된다는 주장도 하지 않는다.

## 고정한 학습 조건

[CPU 연결 테스트](../endpoint-flower-runtime-2026-09-13/report.md)와 동일하게 유지했다.

- 공개 crowdsensing V2 CSV 8개, 31개 입력 특징, 9 classes.
- 중복 특징 그룹 단위 분할: train 102,509 / validation 34,227 / test 34,317.
  이번 테스트에서 validation으로 하이퍼파라미터를 다시 고르지 않았다.
- MLP 31→128(ReLU)→9, 5,257 parameters, cross-entropy + SGD.
- seed 42, 각 조건 3 rounds, local 3 epochs, batch 128, learning rate 0.1.
- 일반 평균 μ=0 / FedProx μ=0.1 × 정상 / 25% label-flip, 총 네 조건.
  공격 클라이언트는 `[1, 2]`, 공격은 local label `(y+1) % 9`다.
- FedProx anchor는 해당 라운드의 고정된 글로벌 모델이며 모든 조건을 같은 초기 모델에서 시작했다.

## 결과

| 조건 | 3라운드 test macro-F1 | 모든 라운드 모델 최대 절대 오차, NumPy 대비 |
| --- | ---: | ---: |
| 일반 평균, 정상 | 51.3728% | 2.776×10⁻¹⁶ |
| FedProx μ=0.1, 정상 | 47.9720% | 2.220×10⁻¹⁶ |
| 일반 평균, label-flip | 47.8275% | 2.220×10⁻¹⁶ |
| FedProx μ=0.1, label-flip | 47.6862% | 2.220×10⁻¹⁶ |

사전 기준은 round 0–3 각각 모델 최대 절대 오차 ≤`1e-8`, 혼동행렬 정확한 일치,
cross-entropy 오차 ≤`1e-8`이었다. 모든 조건이 통과했다.
모델은 비트 단위로 같지는 않지만 최대 오차가 `2.7755575615628914e-16`이며,
모든 라운드의 혼동행렬과 macro-F1은 CPU 기준과 정확히 같다.
cross-entropy 최대 차이는 `2.220446049250313e-16`이다.
별도 NumPy 순차 학습 대조군뿐 아니라 GPU checkpoint를 다시 평가하여 기록된 지표도 확인했다.

실제 GPU 사용과 상태 보존:

- 학습 응답 **96개 = 8 clients × 3 rounds × 4 conditions** 전부 `cuda:0`, `torch.float64`.
- 학습 PID 하나만 관측되었다. 가상 노드별 `Context.state` 호출 횟수는 모두 12까지 유지됐다.
- PyTorch peak allocated 최대 **67.76 MiB**, peak reserved 최대 **86 MiB**.
  이는 allocator 통계다. CUDA context·라이브러리·다른 프로그램을 포함하는 전체 VRAM 사용량이 아니다.
- 실행 중 `nvidia-smi` 표본에서는 전체 VRAM 2,817 MiB, GPU utilization 24%였다.
  한 시점의 전체 GPU 통계이며 이 실험의 전용 메모리나 평균 utilization으로 해석하지 않는다.
- OOM, 클라이언트 누락, timeout, CPU fallback 없이 완료했다.

시간 기록:

- Flower가 보고한 실행 시간: **39.52초**.
- `flwr run --stream` CLI wall time: **43.57초**(다운로드·사전 검사·사후 NumPy 대조 검증 제외).
- 서버가 측정한 12개 학습 라운드 wall time 합계: 31.54초.
- 클라이언트 내부 CUDA 동기화를 포함한 학습 구간 합계: 28.31초.

기존 CPU 2-worker 테스트는 Flower 실행 시간 13.78초였다. 이번 GPU 테스트가 더 빠르지는 않았다.
하지만 worker 수, 실행 시점의 다른 부하, CPU/GPU 구현이 다르므로 공정한 가속비 벤치마크는 아니다.
작은 MLP와 float64 조건의 **GPU 실행 가능성·수치적 동등성 확인**이 이번 목적이다.
GPU를 사용했다고 학습 품질이나 AION 보안성이 개선된 것은 아니다.

## 구현 및 재실행

- 선택적 CUDA 학습기: [endpoint_torch.py](../../../trustlessfl/endpoint_torch.py).
- ClientApp backend 분기: [endpoint_flower.py](../../../trustlessfl/endpoint_flower.py).
- staging·사전 검사·공식 실행·대조 검증: [run_endpoint_flower.py](../../../experiments/run_endpoint_flower.py).
- 기본 backend는 여전히 NumPy이며 root AION entrypoint는 변경하지 않았다.

```bash
uv sync --extra simulation --extra gpu --cache-dir .cache/uv
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  .venv/bin/python -m experiments.run_endpoint_flower \
  --backend torch-cuda --rounds 3 --output .cache/endpoint/runs/flower-gpu-new-run
```

새 출력 경로를 사용한다. 샌드박스에서는 GPU/로컬 socket 접근 권한이 필요하다.
이 실행은 준비 후 권한을 받아 같은 출력 경로에 `--phase run`으로 실행했다.
사전 CUDA 검사는 별도 프로세스에서 실행하고 종료하므로 Ray 실행 중 그 context를 유지하지 않는다.
CUDA가 없으면 명시적으로 실패하고 CPU로 대체하지 않는다. 다른 GPU 작업을 중단하지 않았다.

회귀 검사: CPU 환경 전체 **72 passed, 2 GPU tests skipped**.
별도 GPU 권한 실행 `ENDPOINT_TEST_CUDA=1 ... pytest -q tests/test_endpoint_torch.py`는 **6 passed**.
후자의 6개 중 4개는 앞의 CPU 실행과 중복되므로 테스트 수를 78개로 합산하지 않는다.
FedProx 고정 anchor, NumPy 수치 동등성, 입력 불변성, 반복 결정성, CPU fallback 거부를 검사했다.
기존 CPU Runtime 결과를 새 검증기로 재검사해 정확한 모델 일치를 다시 확인했고 기존 결과 파일은 보존했다.

## 증거 보존과 범위

원본 디렉터리: `.cache/endpoint/runs/flower-gpu-2026-09-13/` (git 제외).

- `provenance.json`: 버전, 소스/lock hash, 실행 전에 고정한 검증 기준.
- `shards/manifest.json`, `data-audit.json`, `split.npz`: 데이터와 분할 증거.
- `attempt-b16d303f/`: 명령, CUDA 사전 검사, CLI/SuperLink 로그, 최종 run 상태, 시간.
- `runtime-results/run-15138946526726773533/`: 모든 round checkpoint, 지표, 클라이언트 GPU metadata.
- `verification.json`: `passed=true`, `gpu_verified=true`, `all_exact=false` 및 round별 수치 오차.

이 결과는 1 seed / 3 rounds의 실행 검증이다. 논문 성능 재현, 학습 품질 개선, poisoning 방어,
악성 서버 내성, AION 보안집계 및 실제 silo 네트워크 정책 검증은 포함하지 않는다.
다음 단계는 별도의 AION aggregator 역할을 공식 Runtime에 연결하는 작업이다.
