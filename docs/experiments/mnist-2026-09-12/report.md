# MNIST 전체 데이터: Flower / AION-ASR 실험

실행: 2026-09-12 19:16:47–19:17:30 KST. IID와 label-skew 각 1회,
각각 보안 집계 20라운드와 두 종류의 일반 집계 대조군을 완료했다.

## 결과 요약

| 조건 | AION 테스트 정확도 | 일반 fixed-point 정확도 | 일반 float 정확도 | 테스트 cross-entropy | AION 실행 시간 |
|---|---:|---:|---:|---:|---:|
| IID | 91.14% | 91.14% | 91.14% | 0.323303 | 17.83초 |
| Label-skew non-IID | 85.90% | 85.90% | 85.90% | 0.457390 | 17.27초 |

두 조건 모두 **모든 라운드·모든 파라미터에서 일반 fixed-point 집계와 AION 모델의
최대 절대 오차가 0**이었다. 모델 평균을 계산하는 프로토콜에 의해 추가되는 오차는
이 실험에서 관찰되지 않았다. float 대조군과의 전체 라운드 최대 절대 오차는
IID `0.0005626932`, non-IID `0.0003917262`다. 두 대조군은 각자 이전 모델에서
다음 로컬 학습을 수행하므로 이 차이는 delta 양자화와 이후 학습 경로 차이를 포함한다.

non-IID의 최종 정확도는 IID보다 **5.24 percentage points** 낮다. 일반 집계에서도
동일한 차이가 있으므로, 이 실험에서는 보안 집계 자체의 오류가 아니라 분할 및
로컬 학습 조건의 영향을 관찰한 것으로 해석할 수 있다. 단일 seed 결과이므로
일반적인 성능 하락 폭으로 확대 해석하지 않는다.

## 데이터와 모델

- **실제 MNIST 전체**: 학습 60,000장, 테스트 10,000장. 테스트셋은 local training에 쓰지 않았다.
- 28×28 grayscale 픽셀을 flatten하고 255로 나눈다. augmentation은 없다.
- 모델은 NumPy **softmax regression**이다. CNN이나 MLP가 아니다.
  weight 784×10 + bias 10 = **7,850개 파라미터**, float64, 초기값 모두 0이다.
- local optimizer: cross-entropy SGD, learning rate 0.1, batch size 256,
  round당 전체 local data 1 epoch. 마지막 152개 batch도 사용한다.
- client 4개, 각 15,000장. 매 라운드 전원 참여, 동일 가중 delta 평균.
- server 1개, 별도 aggregator 4개, f=1, share threshold 2, certificate quorum 3.
- 각 delta를 소수 4자리로 양자화하고 기존 masking / ASR / DMC·DMR / 서명 경로를 사용한다.
- 분할 및 batch 순서 seed=42. 라운드·client 번호로 minibatch shuffle seed를 구분한다.
  암호 키와 task ID는 조건마다 새로 생성한다.
- 학습 조건은 실행 전에 고정했다. 테스트셋으로 하이퍼파라미터를 탐색하거나 best round를 선택하지 않았다.

데이터는 [TensorFlow 공식 NumPy 데이터 예제](https://www.tensorflow.org/tutorials/load_data/numpy)에
명시된 저장소에서 받았다. [Keras MNIST 소스](https://github.com/keras-team/keras/blob/master/keras/src/datasets/mnist.py)의
SHA-256과 다운로드 파일을 대조했다:

```text
731c5ac602752760c8e48fbffcf8c3b850d9dc2a2aedcf2cc48468fc17b673d1
```

## 분할 방식

IID는 학습 인덱스를 무작위 permutation한 뒤 15,000개씩 나눈다.
Label-skew는 같은 라벨 안의 순서를 섞은 뒤 라벨로 정렬하여 7,500개짜리 shard
8개를 만들고 client당 2개씩 배정한다. 이는 **client당 숫자가 2종류만 있다는 뜻은 아니다**.
두 분할 모두 학습 데이터를 중복·누락 없이 사용한다.

실제 label-skew client별 숫자 개수:

| client | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 합계 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | 0 | 0 | 0 | 0 | 596 | 5,421 | 1,483 | 0 | 1,551 | 5,949 | 15,000 |
| 1 | 0 | 5,165 | 2,335 | 2,254 | 5,246 | 0 | 0 | 0 | 0 | 0 | 15,000 |
| 2 | 5,923 | 1,577 | 0 | 0 | 0 | 0 | 0 | 3,200 | 4,300 | 0 | 15,000 |
| 3 | 0 | 0 | 3,623 | 3,877 | 0 | 0 | 4,435 | 3,065 | 0 | 0 | 15,000 |

IID 분포와 두 분할의 index hash도 원시 결과에 저장했다.

## 테스트 학습곡선

| Round | IID accuracy | IID cross-entropy | Non-IID accuracy | Non-IID cross-entropy |
|---|---:|---:|---:|---:|
| 0 | 9.80% | 2.302585 | 9.80% | 2.302585 |
| 1 | 85.41% | 0.718127 | 63.62% | 1.441174 |
| 5 | 89.33% | 0.420566 | 76.74% | 0.725542 |
| 10 | 90.29% | 0.361556 | 82.58% | 0.556825 |
| 15 | 90.80% | 0.337215 | 84.58% | 0.494572 |
| 20 | 91.14% | 0.323303 | 85.90% | 0.457390 |

초기값 0에서는 모든 class 확률이 같고 argmax가 0을 선택한다.
초기 9.80%는 테스트셋의 숫자 0 비율이다.
최종 학습셋 정확도는 IID 90.5883%, non-IID 85.62%다.

## 측정 환경과 한계

WSL2 Linux 6.6.87.2, x86_64, logical CPU 12개, Python 3.12.12,
Flower 1.36.0, NumPy 2.5.0, cryptography 46.0.7.
OPENBLAS/OMP/MKL thread 수는 각 1로 고정했다. GPU는 사용하지 않았다.
실험은 순차 실행했고 성능 측정 중 pytest를 병행하지 않았다.

- 실제 Flower ServerApp / ClientApp / protobuf를 사용하지만, transport는 로컬
  multiprocessing pipe다. 실제 silo 네트워크, SuperLink, TLS 배포 측정이 아니다.
- 위 AION wall time은 프로세스 시작·local shard 로딩·학습·프로토콜·종료를 포함한다.
  사전 데이터 다운로드·분할·provisioning과 사후 평가는 제외한다.
- 일반 집계 대조군은 순차 로컬 계산이다. fixed-point 계산 시간은 IID 2.443초,
  non-IID 2.422초, float는 각각 1.621초·1.637초다. transport·병렬성·시작 비용이
  다르므로 AION과 나눈 비율을 **암호화만의 오버헤드**로 해석하면 안 된다.
- 요청과 응답의 canonical JSON payload 합은 IID 255,854,383 bytes,
  non-IID 254,416,044 bytes다. protobuf framing이나 네트워크 오버헤드는 포함하지 않는다.
- 조건별 1회 실행으로 분산·신뢰구간은 측정하지 않았다.
- **이번 MNIST 실행에는 악의적 actor를 주입하지 않았다.** 이전 실험에서 확인한
  signed poisoning 방어 부재는 해소되지 않았다.
- 연구용 masking surrogate, 미구현 AMR/CCS/HotStuff/EMA와 미연결 MGF의
  한계는 그대로다. 정확도 결과가 privacy나 Byzantine security를 입증하지 않는다.
- 따라서 **MNIST에서 현재 AION-ASR 연구 경로가 학습·집계를 수행함을 검증**한 것이며,
  원 논문의 모델·하이퍼파라미터·보안·성능 전체를 재현한 결과는 아니다.

## 재현 및 검증

[다운로드 및 실행 방법](../../../experiments/README.md#mnist-전체-데이터-실험)을 따른다.
실제 실행 명령:

```bash
FLWR_TELEMETRY_ENABLED=0 OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  .venv/bin/python -m experiments.run_mnist \
  --output docs/experiments/mnist-2026-09-12 --rounds 20
```

재실행 시 output은 새로운 경로로 바꾼다. 추가 패키지 설치는 필요 없다.
MNIST trainer는 node-local 설정으로만 연결한다. 서버가 메시지로 trainer 코드나
데이터 경로를 지정하지 않는다. aggregator에는 MNIST shard 설정이 없다.
평가 harness만 공개 데이터를 가지고 대조군을 계산한다. 같은 OS user의 프로세스는
독립적인 보안 경계가 아니므로 실제 배포 시 파일 접근·운영 권한을 별도로 분리해야 한다.

검증: 기존 프로토콜 및 새 MNIST 단위 테스트 **34 passed**.
MNIST 보안 집계 총 40라운드 완료, error reply 0, fixed-point 대조군과 모든 모델 동일.

결과 파일:

- [results.json](./results.json): 환경, dataset/source hash, 두 조건의 전체 결과
- [iid.json](./iid.json), [label-skew.json](./label-skew.json): 조건별 분포·21시점 학습곡선·단계 timing
- [iid-models.npz](./iid-models.npz), [label-skew-models.npz](./label-skew-models.npz):
  각 조건의 `secure`, `fixed`, `floating` 모델, 각각 shape `(21, 7850)`

저장된 모델은 공개 MNIST로 학습한 집계 모델이다. private key, share, masked update,
certificate는 결과 파일에 저장하지 않는다. 데이터 원본은 git 제외 `.cache/mnist`에 둔다.
