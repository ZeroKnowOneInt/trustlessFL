# 실제 FMNIST: masked MGF·위원회 집계 검증·스케일링 범위

## 결론

공식 Flower에서 새 aggregate-validation profile의 정상 학습 4라운드를
완료했고, 선택된 클라이언트의 학습을 독립 재실행한 모델 오차는 0이었다.
그러나 동일 설정의 별도 공격 실행은 2라운드 commit 후 3라운드 복원에서
`ambiguous`로 실패했다. 실제 학습 연결은 검증했지만, 추가 share 없는
scaled-mask MGF의 일반적인 복원 문제를 해결한 것은 아니다.

같은 스케일을 쓰면 HPRF의 모듈러 관계는 유지된다. 이 사실과 **일반
학습 SUM을 유일하게 복원하는 것**은 별개다. 정상 실행에서도 2~4라운드
SUM은 centered lift의 반주기 범위를 넘는다. 단순 modulo/centering으로
현재 decoder를 대체하면 올바른 학습 값을 보존하지 못한다.

## 설정과 경로

- FMNIST/LeNet5, clients 20, committee 4, local epochs 2, seed 0.
- 전체 업데이트 61,706좌표, MGF classifier projection 840좌표.
- 모델 소수 정밀도 6자리, beta 0.2, 공개 checkpoint 초기 scale.
- 원본 저장 HPRF matrix/setup, 초기 일회성 randomized encrypted VSS.
- client-local masked VECTOR → 위원회별 MGF 재계산 → BFT① 선택 명단
  → aggregate key opening → 위원회별 집계/수치 재계산 → BFT② 모델.
- 추가 좌표별 mask share, 개별 평문 전달, 개별 키 탐색 fallback 없음.

prepared 실행의 공개 데이터·학습 설정만 재사용했다. 각 작업은 새 task,
키, identities와 Context를 생성했다. 이전 staged package/결과/실패 기록은
수정하지 않았다. 공식 로컬 SuperLink/Ray simulation이며 독립 물리 호스트
간 통신 또는 WAN 성능 측정은 아니다.

## 공식 결과

| 실행 | 공식 run ID | terminal 상태 | 완료 round | workflow 시간 |
| --- | --- | --- | ---: | ---: |
| 정상 학습 | 18444748918791361971 | finished:completed | 4 | 98.465603초 |
| model-replacement backdoor | 1868253990627955649 | finished:failed | 2 / 요청 4 | 70.752782초 |

정상 실행의 초기 key share는 **80개**, 추가 mask share는 **0개**다.
매 round 4개씩 총 16개의 signed aggregate-replay receipt를 검증했다.
선택 명단은 `[1,15]`, `[15,4]`, `[15,4]`, `[15,4]`이고, 선택된 학습
8회를 재현한 mean/model 최대 절대 오차는 **0**이다. 최종 test accuracy는
88.66%다. 공개 checkpoint에서 시작한 짧은 검증이지 논문의 전체 학습
곡선/60라운드 재현이나 프라이버시 증명은 아니다.

공격 설정은 clients 0~3, rounds 1~4, poison batch 6, attack steps 120,
boost 20이다. commit된 선택은 `[5,13]`, `[15,4]`로 공격자를 제외했다.
하지만 3라운드 `reconstruct`에서 실패했고 `results.json`은 없다.
최종 정확도/공격 성공률 또는 4라운드 방어 완료를 주장하지 않는다.
terminal failure와 `failure.json`을 보존했으며 같은 작업을 재시작하지 않았다.

결과 위치:

- `.cache/source-aggregate-replay-fmnist-clean-four-round-20261002/`
- `.cache/source-aggregate-replay-fmnist-attack-four-round-20261002/`

정상 작업의 `verification.json`은 초기 verifier의 재학습/receipt 검증
기록이다. 후속 range 필드를 추가한 verifier는 같은 결과를 read-only로
재검증했으며 기존 verification 파일을 덮어쓰지 않았다.

## 실제 SUM과 스케일링된 링

정상 결과에 대한 공개 history 감사와 독립 selected-training replay를 대조했다.
표의 SUM은 mean이 아니라 선택 인원 2를 곱한 합계다.

| round | 실제 SUM 최대 절댓값 | 스케일링된 주기 P | centered 충분조건 |
| --- | ---: | ---: | --- |
| 1 | 0.005906 | 9894833/83886080 | 관측값은 반주기 내 |
| 2 | 0.002244 | 0.0005906 | 반주기 초과 |
| 3 | 0.002461 | 0.0002244 | 반주기 초과 |
| 4 | 0.002042 | 0.0002461 | 반주기 초과 |

단순 centering으로 바뀌는 공개 SUM 좌표는 round 2~4 각각
2,217 / 12,055 / 9,125개다. 감사는 개인 키/share를 읽지 않고,
이미 공개된 SUM을 런타임 decoder의 oracle로 사용하지 않는다.
round 1의 관측값이 작다는 사실도 사전의 강제된 범위 증명은 아니다.

`experiments.verify_source_learning`은 이제 `scaled_ring_range_checks`에
재학습한 SUM norm, P/2, decimal/HPRF 오차, centered 범위 관측을 자동 기록한다.
이 필드는 사후 진단임을 명시하며 runtime bound를 새로 선언하거나
centering decoder를 실제 집계 경로에 연결하지 않는다.

## 공격 실행 실패의 공개 회귀

공격 실행 round 2의 공개 `next_linf=59/50000`에서 round 3의
`P=beta*next_linf=59/250000=0.000236`이다. 모델 quantum `10^-6`의
정확히 236배이므로 다른 carry 후보가 동일 양자화 격자와 mask 범위에
맞을 수 있다. 원본 공개 fixture 키 `(4,16)`, round 3에서도 실제로
`ambiguous`를 재현했다. 실행의 개인 키나 masked 업데이트는 회귀
입력으로 사용하지 않았다.

기존 clean 실패 scale `253/40000`, round 2의 사례와 함께
`tests/test_source_paper_numeric.py`에 고정했다. 정확한 모듈러 관계만으로
실수 SUM의 유일성을 보장할 수 없음을 검사한다. 원본 논문의 모든
프로토콜이 불가능하다는 주장이나 추가 share 도입의 정당화가 아니다.

관련 회귀 **84개 통과, 36.32초**:

```bash
PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m pytest -q tests/test_source_paper_numeric.py tests/test_scaled_ring.py \
  tests/test_source_aggregate_validation.py tests/test_source_asr_official.py
```

## 재현

출력에는 아직 존재하지 않는 새 경로를 지정한다. 완료/실패 작업을 덮어쓰지 않는다.

```bash
PATH="$PWD/.cache/flower-deps/bin:$PATH" \
PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m experiments.run_source_asr_official \
  --prepared .cache/source-paper-quantized-fmnist-mask-bounds-four-round-20261001 \
  --output .cache/NEW-source-aggregate-fmnist-clean --workers 4 --rounds 4

PATH="$PWD/.cache/flower-deps/bin:$PATH" \
PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m experiments.run_source_asr_official \
  --prepared .cache/source-paper-quantized-fmnist-mask-bounds-attack-four-round-20261001 \
  --output .cache/NEW-source-aggregate-fmnist-attack --workers 4 --rounds 4

PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m experiments.verify_source_learning \
  --run .cache/NEW-source-aggregate-fmnist-clean \
  --inputs .cache/fmnist/official-original-single-view-mgf-attack-four-round-20261001/inputs \
  --epochs 2 --seed 0
```

fresh 키/마스크에 따라 선택과 실패 라운드가 달라질 수 있다. 성공하는
작업을 고를 때까지 재시도하는 방식은 일반 복원의 완료 증거로 쓰지 않는다.
목표는 계속 미완료다. 실제 MGF 입력을 바꾸지 않으면서 추가 share 없이
학습 SUM을 유일하게 복원할 정당화가 남아 있다.
