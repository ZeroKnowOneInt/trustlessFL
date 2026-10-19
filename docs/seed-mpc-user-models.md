# 사용자 모델 adapter와 정적 정책·회로 캐시

현재 WSL의 `work/aion-private-bound-no-wrap` 브랜치에서 로컬 Flower에 사용자 PyTorch **분류 모델**을 연결할 수 있다. 기존 tiny FMNIST와 LeNet5 실행 경로는 유지한다. 이 기능은 로컬 검증용이며 Flower Hub 게시 설정을 추가하지 않는다.

## 모델 계약

자체 `.py` 파일에 `make_model(**kwargs)`를 정의하고 CPU `torch.nn.Module`을 반환한다. 선택적으로 `prepare_inputs(x)`가 NPZ의 입력 배열을 모델에 맞는 CPU tensor로 변환한다. 모듈의 출력은 `[batch, classes]` logits이며 현재 학습은 cross entropy와 SGD다. 이미지 모델도 입력 전처리와 factory를 이 인터페이스에 맞추면 같은 MPC 경로를 사용한다. 외부 파일·동적 import에 의존하는 plugin의 자동 패키징, 회귀·언어 모델용 loss/학습 hook은 이번 버전의 범위에 포함하지 않는다.

`trustlessfl/seed_mpc_model.py`는 모든 파라미터의 이름, 등록 순서, shape, float32/float64 dtype, trainable 속성을 기록한다. 모델은 float64 벡터로 전달되며 클라이언트는 해당 dtype의 tensor로 복원한다. factory와 schema가 달라지거나 plugin/adapter 파일이 바뀌면 거부한다. 같은 메모리를 공유하는 tied parameter는 별도의 alias 계약이 필요하므로 현재 거부한다.

Buffer는 factory가 재생성하는 **고정된 공개 상태**이며 dtype·shape·내용 hash를 계약에 포함한다. 학습 중 바뀌는 BatchNorm running statistics/counter 등은 학습 완료 시 거부한다. 이를 그냥 제외하거나 평균해 모델 상태를 손실시키지 않는다. BatchNorm을 쓰려면 통계를 고정한 별도 모델 구현이 필요하다. 모델 객체의 별도 Python 속성이나 optimizer state는 집계 대상이 아니다. 사용자 plugin은 사용자가 승인한 로컬 코드이며 보안 sandbox가 아니다.

Plugin bytes, adapter 구현 hash, kwargs, schema, 초기화 seed와 학습 설정을 실행 hash에 연결한다. 각 클라이언트와 aggregator는 기존 서명·quorum certificate·durable lock을 통해 이 실행 계약에 고정된다. Aggregator는 plugin source/schema hash만 검사하며 모델을 만들거나 로컬 학습하지 않는다.

## 입력 데이터와 정책 설정

`model.json` 예시:

```json
{
  "plugin": "classifier.py",
  "kwargs": {"input_features": 6, "hidden": 5, "classes": 3},
  "train_data": ["C0.npz", "C1.npz", "C2.npz", "C3.npz"],
  "test_data": "test.npz",
  "training": {"epochs": 1, "batch_size": 16, "learning_rate": 0.05},
  "policy": {
    "coordinate_cap": 20000,
    "squared_threshold": 2500000000,
    "scale": 10000,
    "minimum_accepted": 2
  }
}
```

각 NPZ에는 숫자 배열 `x`와 음수가 아닌 정수 label 배열 `y`만 넣는다. 경로는 model.json의 위치를 기준으로 해석한다. 데이터 파일은 client별 비공개 영역에 복사하며 test 데이터는 공개 평가용이다. 기본 momentum과 weight decay는 0이며 설정할 수 있다. 현재 사용자용 runner는 `train_data` 목록에서 **클라이언트 N명**을 읽으며 aggregator는 4명으로 유지한다. 기존 `experiments.run_seed_mpc_flower` 벤치마크는 비교를 위해 클라이언트 4명으로 유지한다. 클라이언트별 샘플 수가 달라도 최종 평균은 기존 프로토콜처럼 통과한 클라이언트의 업데이트를 동일 가중치로 평균한다.

별도 `--policy-config static-policy.json`도 지원한다. 이 경우 model.json에 policy를 중복 지정할 수 없다. 사용자 모델은 정책을 명시해야 하며 모델별 threshold를 자동 추정하지 않는다. 기존 FMNIST에도 별도 정적 정책을 적용할 수 있다. 회귀 fixture는 고정된 검증 정책을 유지한다.

차원 D는 모델에서 계산한다. 설정에 dimension/max_clients를 넣으면 실제 값과 일치해야 한다. 종전 LeNet5 크기 61,706에 맞춘 상한은 제거했지만, 메모리·통신·RPC 크기와 컴파일 시간 등 실제 자원 한계는 남는다. 큰 모델의 학습 비용이 작아졌다는 의미는 아니다.

## wrap 방지와 MPC 검사

클라이언트의 유효 업데이트는 정수 `u = round(S × delta)`이고 wire는 `y = (u + m) mod Q`다. 현재 로컬 mask 구현은 **Q = 2^16**으로 제한한다. `SeedMPCPolicy`가 다른 실험의 32-bit 옵션을 갖더라도 이 runner에서는 32-bit를 거부한다.

MPC는 `r = (y - m) mod Q`를 정확하게 계산하고 `r >= Q/2`이면 Q를 빼서 canonical signed 정수를 만든다. 정책은 `2B < Q`를 요구하므로 허용 구간 `[-B, B]` 안의 값은 유일하다. 마스킹 wire에서 발생한 wrap은 이 복원을 방해하지 않는다. 무제한 원래 입력이나 올바른 SGD·마스크 생성 과정을 증명한다는 의미는 아니다.

클라이언트 i의 비밀 통과 비트는 다음과 같다.

```text
e_i = present_i AND (모든 j에서 |u_ij| <= B)
                     AND (모든 좌표의 제곱 합 <= T)
a   = sum_i e_i
U_j = sum_i e_i * u_ij
```

norm은 chunk마다 따로 통과시키지 않고 전체 D개 좌표의 제곱 합으로 검사한다. 부적합 좌표를 산술 계산에서 0으로 만들더라도 invalid 비트를 유지하여 그 클라이언트 전체를 제외한다. 최종 U는 wire modulus Q로 다시 줄이지 않는다. 64-bit ring의 signed 범위와 비교 회로 폭이 `D B²`, `N B`, T, N을 모두 담는지 **컴파일 전에** 검증한다. B·T·S·차원·클라이언트 수가 바뀌면 폭도 다시 계산한다. 부족한 폭의 회로는 생성하지 않는다.

예시 정책에서 실수 좌표 cap은 B/S = 2, quantized 업데이트 norm cap은 sqrt(T)/S = 5다. 이 값은 예시일 뿐 모든 사용자 모델에 적절하다는 주장은 아니다. 정책은 세션 시작 전에 고정한다. norm 안의 악성 업데이트를 추가로 탐지하는 기능은 없다.

## 회로 생성과 캐시

사용자 모델은 기본적으로 `.cache/seed-mpc-circuits`에 공개 회로를 캐시한다. `--compile-cache PATH`로 위치를 정할 수 있으며 기존 FMNIST/fixture 실행에도 적용할 수 있다.

캐시 key에는 MPC source bytes, AES circuit hash, 검증된 backend/compiler pin, 컴파일 옵션과 정책·차원·round slots·chunk 설정 등 config를 포함한다. 실행마다 바뀌는 client port만 제외한다. 캐시 entry의 recipe와 bytecode/schedule 전체 hash를 확인하며 누락·추가·변조된 파일은 거부한다. 동일 key의 빌드는 파일 lock과 완성된 임시 entry의 atomic rename으로 공개한다. 캐시에는 seed, key share, update, client별 입력 또는 private runtime state를 넣지 않는다. 캐시가 compiler provenance를 대체하지 않으며 동일 사용자 권한으로 cache/소스 전체를 변조할 수 있는 악성 host를 방어한다는 주장도 없다.

접속 port는 새 public-input prefix로 네 aggregator가 일치 여부를 확인하고 active check를 마친 다음 사용한다. 이 옵션을 쓰지 않는 기존 stream의 registration-tag 순서는 유지한다. 원래 port와 전체 실제 config는 세션의 execution hash에 포함하므로 캐시 재사용이 실행 계약을 느슨하게 만들지 않는다.

같은 D·정책·회로 config이면 새 세션에서도 캐시 hit이며 **컴파일 0회**다. 라운드 중에는 원래부터 다시 컴파일하지 않는다. D, N, threshold, round slots, backend 등 key 항목이 달라지면 cache miss다. 같은 D의 다른 모델이 bytecode를 공유할 수 있어도 모델 의미는 plugin/schema를 포함하는 별도의 execution hash에 고정한다. 세션과 private seed는 새로 생성하며 완료된 session state를 재시작하지 않는다.

## 사용자용 실행과 실험 실행

일반 사용자는 [사용자용 실행 경로](seed-mpc-user-runtime.md)를 사용한다. 아래 명령은 독립 재학습 검증을 위한 **trusted raw-audit 실험 모드**이며 일반 사용자 경로와 구분한다.

## 로컬 실험 실행

WSL repo root에서:

```bash
export PATH="$PWD/.venv/bin:/usr/local/bin:/usr/bin:/bin"
.venv/bin/python -m experiments.prepare_seed_mpc_custom_example --output .cache/my-model-example
.venv/bin/python -m experiments.run_seed_mpc_flower \
  --output .cache/my-model-run --mode custom-model \
  --model-config .cache/my-model-example/model.json --rounds 2 \
  --snapshot-version 2 --collection-window-ms 10000 --timeout 300 \
  --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3-direct-rep4-v1 \
  --component-input holder-checked-direct-v1 --communication-meter
```

이 명령은 기존 로컬 검증 harness와 동일하게 client별 raw quantized update audit을 생성하여 **신뢰된 사후 oracle**가 정확한 합과 모델 갱신을 비교한다. Raw audit은 Flower 응답 또는 ServerApp 입력이 아니며 실제 서비스의 프라이버시 설정으로 사용하면 안 된다. `stage(..., test_audit=False)`와 기존 isolated runner는 audit을 끌 수 있지만 raw oracle 기반 `verify_run`은 별도의 입력 증거가 필요하다. Audit 없는 사용자용 wrapper는 위의 사용자 실행 경로를 사용하며 독립 host 배포는 후속 작업이다.

예제 모델은 53개 파라미터의 6→5→3 MLP이고, `.cache` 디렉터리는 새로운 실행마다 고유한 이름을 써야 한다. 기존 실패/완료 session을 덮어쓰지 않는다.

전체 모델·캐시 native 검증:

```bash
.venv/bin/python -m experiments.validate_seed_mpc_models --output .cache/custom-model-check
```

검증 결과는 아래 재현 문서에 정리한다. 기존 Rep4 static f<=1 신뢰 모델과 최종 합/count에서 가능한 역추론 한계는 그대로다.


## FMNIST 소형 CNN으로 모델 교체 확인

666개 파라미터 CNN의 이미지 전처리·다차원 Conv/Linear parameter를 같은 adapter에 연결한 실제 Flower/Rep4 2라운드가 통과했다. [결과와 재현 명령](reproduction/small-cnn-adapter-2026-10-11.md), 예제 `examples/seed_mpc_custom/fmnist_small_cnn.py`와 준비 도구 `experiments/prepare_seed_mpc_small_fmnist.py`를 사용한다.
