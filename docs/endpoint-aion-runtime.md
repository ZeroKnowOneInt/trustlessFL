# Crowdsensing AION FL: 공식 Runtime 연결 및 첫 실험

첫 실행을 완료했다. [결과 보고서](./experiments/endpoint-aion-2026-09-13/report.md):
AION test F1 52.78 ± 0.20%, 평문 양자화와 모든 round 모델 정확히 일치.

## 목적과 고정 조건

Crowdsensing의 DFL 토폴로지를 재현하는 것이 아니라, 프로젝트의 연구용 AION-ASR에
공개 MLP 학습 설정을 연결한다. 보안집계가 같은 fixed-point 평문 집계와 동일한
모델을 산출하는지, 양자화 없는 일반 FL과 학습 품질이 얼마나 다른지 확인한다.

- Flower ServerApp 1개, 학습 역할 8개, 별도 aggregator 역할 4개.
- aggregator `n=4, f=1`, reconstruction threshold 2, certificate quorum 3.
- 전체 8개 client가 매 라운드 참여하며 동일 가중 평균을 유지한다. 표본 수 가중 평균이 아니다.
- V2 공개 데이터 171,053행, 31개 feature, 9개 클래스. 기존 seed42 feature-group 분할 유지.
  client 소유권은 원본 파일 0..7을 유지한다. 물리 장치 신원 매핑을 확인했다는 뜻은 아니다.
- train 102,509 / validation 34,227 / test 34,317. 이번에는 validation을 사용하지 않는다.
  최종 라운드를 사전 지정하며, 독립 test는 학습 종료 후 평가 harness에서만 로드한다.
- 공개코드 기반 `31→30→30→9`, ReLU 두 번, log-softmax 뒤 cross-entropy.
  float32 로컬 학습, Adam lr=.01, batch500, local epochs3, rounds10, seed42/43/44.
- Adam moment는 **매 라운드 초기화**, 로컬 3 epoch 동안 유지한다. 중앙집중 학습의
  epoch 간 Adam 상태 유지와 다른 정책이며 서버 FedAdam을 사용한다는 뜻도 아니다.
- 초기화는 seed별 PyTorch 기본 Linear 초기화. AION 초기 모델의 0 벡터는
  **초기 가중치로부터의 변위(offset)**다. 각 client는 고정된 초기 가중치에 변위를 더한다.
- batch 순서는 `SeedSequence([seed, partition, round])`에서 얻은 seed와 torch.randperm으로 고정.
- AION은 delta 소수 6자리 HALF_EVEN 양자화, |delta|≤100 범위 검사. clipping/poisoning 방어 없음.

## 비교군과 실행

1. `aion`: 기존 enrollment, VSS, masked update, prepare/share/finalize/commit 및 서명 검증 유지.
2. `quantized`: 동일 양자화의 평문 FL. 같은 Runtime에서 새 학습을 수행하고 정수 합을 저장한다.
3. `float`: 양자화 없는 평문 FL. 초기화·분할·optimizer·batch 순서는 같다.

각 비교군은 **서로 다른 FAB 및 Runtime run**이다. AION ClientApp에는 평문 delta를
요청하는 handler가 없다. 평문 대조군은 공개 데이터에 대한 별도 실험이며, 보안 경로의
개별 delta를 coordinator에 공개하여 검사하지 않는다.

공식 [Flower simulation](https://flower.ai/docs/framework/how-to-run-simulations.html)과
[stateful ClientApp](https://flower.ai/docs/framework/how-to-design-stateful-clients.html)을 참고한다.
시뮬레이션 partition-id를 사전 provisioning된 노드별 신원에 매핑한다. 기존 파일 기반
task별 잠금과 원자적 저장을 사용하여 서명/share 반환 전에 상태를 저장한다.

GPU 실행은 전체 CPU1/GPU1, worker CPU1/GPU1이며 12개 논리 역할을 한 worker가 순차 처리한다.
aggregator는 GPU 학습을 하지 않는다. GPU를 예약하는 worker 위에서 CPU 암호 연산을 수행한다.
이 배치는 GPU 메모리 공유를 제어하지만 역할별 CPU/GPU 자원을 최적화한 배치는 아니다.

```bash
# 먼저 작은 합성 데이터 Runtime 검사: CPU, 2 rounds
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  .venv/bin/python -m experiments.run_endpoint_aion \
  --workload synthetic --backend numpy --rounds 2 --seeds 42 \
  --output .cache/endpoint/runs/aion-smoke-new

# 그 다음 공개 Endpoint 데이터, GPU, 3 seeds × 3 modes
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  .venv/bin/python -m experiments.run_endpoint_aion \
  --rounds 10 --seeds 42 43 44 \
  --output .cache/endpoint/runs/endpoint-aion-new
```

출력 경로는 항상 새로 지정한다. `--phase prepare/run/verify`를 지원한다.
CPU Endpoint 경로는 `--backend numpy`지만 여기서 학습기는 PyTorch CPU이며,
옵션 이름은 공용 실행기의 GPU 예약 여부를 선택하기 위한 기존 명칭이다.

## 사전 검증 기준

- 합성 데이터: 정상/재요청/aggregator 1개 응답 억제는 fixed-point oracle과 모든 라운드 정확히 일치.
- client 탈락 및 인증서 본문 변조는 집계를 abort하고 aggregate share를 내보내지 않음.
  요청 억제/메시지 변조 주입이지 실제 프로세스 종료·TCP timeout 실험은 아니다.
- Endpoint: AION과 별도 평문 quantized 모델의 **모든 라운드 offset 정확히 일치**.
  차분에서 복원한 정수 합 오차 ≤1e-5 정수 단위, 최종 confusion matrix 정확히 일치.
- 학습 응답/노드별 저장소를 검사하여 실제 float32 CUDA 학습, 라운드 수, 역할 분리,
  aggregator의 최종 committed model 및 certificate quorum을 확인한다.
- float 비교군과의 모델/지표 차이는 관측값으로 보고한다. 임의의 정확도 목표를 사후 설정하지 않는다.

## 해석과 보안 한계

중앙집중 공개 recipe의 93.43%와 직접적인 보안집계 효과 비교가 아니다.
중앙집중은 validation early stopping을 사용했고, 이번 FL은 고정 라운드·분산 local step·
클라이언트 동일 가중치·라운드별 Adam reset을 사용한다.

연구용 masking surrogate는 검증된 암호학적 PRF가 아니다. 실제 비공개 데이터를 보호하는
production Secure Aggregation으로 사용할 수 없고 HotStuff/AMR/CCS/MGF 통합도 추가되지 않는다.
논리 aggregator 4개의 키/상태는 다르지만 같은 호스트·OS 사용자·worker를 공유하므로
독립 기관의 보안 격리나 비공모를 입증하지 않는다. 현재 provisioning catalog는 로컬 실험용이다.
malicious client가 정상 서명한 poisoned update의 품질을 검사하거나 방어하지 않는다.

키·share·masked update가 포함된 노드 상태는 `.cache`에만 남긴다. 문서로 내보내는 자료는
설정, hash, run ID, 검증 요약, 공개 모델의 평가 지표만 포함한다.
