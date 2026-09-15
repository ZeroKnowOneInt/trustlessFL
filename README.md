# TrustlessFL — AION-ASR on Flower

Flower 1.36의 `ServerApp`, `ClientApp`, `Message`, `Grid`를 사용하는 **AION-ASR 연구용 구현**입니다. 서버 1개가 여러 독립 aggregator와 학습 client를 조정합니다. 합성 NumPy 회귀 데이터로 여러 라운드의 집계·학습을 실행할 수 있습니다.

[MNIST 실험](experiments/README.md#mnist-전체-데이터-실험)에서는 전체 학습 60,000장·테스트 10,000장으로 softmax 분류기를 학습하고 일반 집계와 비교합니다.

현재 backend는 공개 artifact의 rounded-linear masking을 참고한 실험 구현입니다. 검증된 LWE-HPRF가 아니므로 실제 비공개 데이터 보호용으로 사용하지 마세요. 전체 논문의 AMR, VRF/CCS, HotStuff view-change, EMA는 아직 구현하지 않았습니다. MGF는 별도 수치 실험 모듈이며 네트워크 집계에 적용하지 않습니다.

## 실행

Python 3.12 이상, Linux/WSL 환경에서:

```bash
uv sync
uv run aion-demo --clients 4 --aggregators 4 --faults 1 --rounds 3
uv run pytest -q
uv run flwr build
```

데모는 실제 Flower 앱과 protobuf 직렬화를 사용하며, client 4개와 aggregator 4개를 각각 별도 프로세스에서 실행합니다. 네트워크 대신 로컬 `ProcessGrid`를 쓰므로 Ray, GPU, 외부 데이터셋, 실행 중 인터넷 연결이 필요하지 않습니다. 종료하면 임시 identity와 share 상태도 정리합니다.

구현한 흐름은 client별 일회성 Feldman VSS, X25519/HKDF/AES-GCM share 전달, 라운드별 masking, 서명된 참여 집합 정족수, 검증 가능한 집계 share 복원, DMC/DMR 정수 연산, aggregator별 결과 재계산 및 Ed25519 결과 인증입니다. 참여 집합은 고정되어 있으며 client 탈락 시 중단합니다.

[실행 및 배포 가이드](docs/aion-flower-implementation.md), [논문 구현 포인트](docs/aion-implementation-notes.md), [요구사항](docs/secure-aggregation-requirements.md)을 참고하세요.
