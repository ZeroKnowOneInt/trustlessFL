# 소형 CNN으로 사용자 모델 adapter 검증

2026-10-11, WSL `trustlessFL`, `work/aion-private-bound-no-wrap`.

## 결과

기존 사용자 MLP와 다른 구조인 FMNIST CNN을 **범용 adapter 그대로** 연결하여 공식 Flower와 active Rep4 native MPC로 2라운드를 완료했다. 프로토콜 코드에 CNN 전용 분기를 추가하지 않았다. 모델 plugin과 데이터/config 준비 예제만 추가했다.

모델은 `Conv2d(1,4,3) → ReLU → MaxPool2d → Conv2d(4,8,3) → ReLU → AdaptiveAvgPool2d(2,2) → Flatten → Linear(32,10)`이며 **666개 파라미터**다. 기존 LeNet5 61,706개 대비 약 1.08% 크기다. 학습 중 변하는 buffer는 없다.

- 학습: FMNIST의 disjoint IID client 4개, 각 1,024장, 라운드당 1 epoch, batch 64, SGD learning rate 0.05.
- 평가: 공개 테스트 2,048장.
- 정책: B=20,000, T=2,500,000,000, S=10,000, Q=65,536, minimum accepted=2.
- 모델에서 D=666을 자동 추출하고 norm 비교 폭 40, SIMD lane 64, padded D=1,024로 회로를 생성했다.
- 2라운드 모두 presence/accepted=4/4. 8개 local training의 quantized update, 두 정수 SUM, 모델 및 평가가 trusted 별도 재학습과 정확히 일치했다.
- 파라미터 이름·순서·Conv/Linear shape, 28×28 uint8 이미지의 N×1×28×28 전처리, float64 vector ↔ float32 parameter 복원을 확인했다.
- 컴파일은 최초 1회이며 round마다 재컴파일하지 않았다.

[전체 검증 JSON](small-cnn-adapter-2026-10-11/verification.json), [요약과 통신량](small-cnn-adapter-2026-10-11/summary.json), [데이터 선택/checksum](small-cnn-adapter-2026-10-11/dataset-manifest.json).

| 평가 | accuracy | loss |
|---|---:|---:|
| 초기 | 9.62% | 2.30233 |
| r1 | 15.63% | 2.26339 |
| r2 | 14.50% | 2.22468 |

이번 실행의 완료 기준은 모델 교체 후 프로토콜과 adapter가 정확히 동작하는 것이다. 위 축소 데이터·2라운드 정확도로 모델의 최종 학습 성능이나 poisoning 방어를 평가하지 않는다.

## 재현

Repo root의 WSL에서 기존 checksum 검증된 FMNIST cache를 사용한다.

```bash
export PATH="$PWD/.venv/bin:/usr/local/bin:/usr/bin:/bin"
.venv/bin/python -m experiments.prepare_seed_mpc_small_fmnist \
  --output .cache/small-cnn-data --rows-per-client 1024 --test-rows 2048
.venv/bin/python -m experiments.run_seed_mpc_flower \
  --output .cache/small-cnn-run --mode custom-model \
  --model-config .cache/small-cnn-data/model.json --rounds 2 \
  --snapshot-version 2 --collection-window-ms 20000 --timeout 300 \
  --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3-direct-rep4-v1 \
  --component-input holder-checked-direct-v1 --communication-meter
```

모델 factory와 `prepare_inputs`는 `examples/seed_mpc_custom/fmnist_small_cnn.py`다. 이 명령은 기존 신뢰된 로컬 oracle 검증용 raw audit을 client 디렉터리에 남긴다. 서버에 raw update를 반환하지 않는다. 공개 snapshot에는 private key/seed, raw client update 또는 client NPZ를 포함하지 않았다.

새 CNN의 flatten/load와 convolution training 재현성·partial batch를 검사했고 기존 adapter/cache 검사와 함께 **32개 pytest가 통과**했다. 이번 변경은 example plugin/준비 도구/테스트이며 기존 MPC·mask·bound·SUM 회로 로직을 변경하지 않았다. 이전 전체 회귀 363개 결과와 구분한다.

```bash
.venv/bin/python -m pytest -q tests/test_seed_mpc_model.py tests/test_seed_mpc_compile.py
```

## 통신 측정

Client 값은 네 client의 Flower application payload 평균이며 TCP/TLS overhead를 제외한다. 수신에는 모델과 인증 체인이 포함된다. Native 값은 네 aggregator의 tracked Player 송신 합계이며 live preprocessing을 포함한다. 자세한 정의와 counter reconciliation은 verification.json에 있다.

| round | client 송신 평균 | client 수신 평균 | aggregator 간 합계 |
|---|---:|---:|---:|
| r1 | 16.93 KB | 93.45 KB | 4.839 MB |
| r2 | 16.93 KB | 255.19 KB | 4.239 MB |

Native setup은 별도로 33,884 bytes다. 통신량은 모델 크기 외에도 padding, 정적 정책, 전처리 배치와 전달된 인증 체인 길이에 영향을 받는다.
