# 사용자 모델·정적 정책·회로 캐시 구현 및 검증

2026-10-11, WSL `trustlessFL`, 브랜치 `work/aion-private-bound-no-wrap`.

## 결과

PyTorch 사용자 분류 모델을 기존 single-mask / active Rep4 / 비공개 global norm / 정확한 넓은 SUM 경로에 연결했다. 예제 MLP 두 크기(53·73 파라미터)를 실제 공식 Flower와 네 native aggregator에서 실행했고, 총 6라운드의 client별 독립 재학습·quantized update·정수 합·모델·평가가 정확히 일치했다. 같은 모델의 새 세션은 bytecode를 재사용하며 컴파일을 호출하지 않았다.

[사용법과 모델·정적 정책 계약](../seed-mpc-user-models.md), [검증 summary](user-models-2026-10-11/model-validation.json), [native 비용·회귀 비교](user-models-2026-10-11/comparison.json), [공개 artifact manifest](user-models-2026-10-11/manifest.json).

## 실제 실행

| 실행 | D | 라운드 | 컴파일 호출 | compiler 시간 | cache | 정수 합·모델·평가 |
|---|---:|---:|---:|---:|---|---|
| 6→5→3 MLP 최초 | 53 | 2 | 1 | 3.154초 | miss | 정확히 일치 |
| 같은 MLP 새 세션 | 53 | 2 | 0 | 0초 | hit, 복사·검증 0.007초 | 정확히 일치 |
| 6→7→3 MLP 최초 | 73 | 2 | 1 | 3.098초 | miss | 정확히 일치 |
| 기존 signed/wrap fixture | 65 | 3 | 1 | 공개 JSON 참조 | 비캐시/기존 stream | 정수 합·모델 정확히 일치 |
| 기존 tiny FMNIST | 170 | 1 | 1 | 공개 JSON 참조 | miss/새 port prefix | 재학습·정수 합·모델·평가 정확히 일치 |

첫 두 실행은 client port가 각각 24472와 20871이며 session ID, seed, identity, 실행 hash를 새로 생성했다. Cache key는 같고 execution hash는 다르다. 최초 실행을 재시작하거나 secret runtime state를 재활용한 결과가 아니다. 73개 모델은 다른 schema/cache key를 사용했다. 캐시는 공개 bytecode와 schedule만 담는다.

기존 fixture는 r1 SUM=80000, r2 SUM=-40000, 좌표 위반·전체 norm 위반을 제외한 통과 2명, r3 통과 1명에 따른 abort를 확인했다. 세 라운드 모델·인증 체인도 일치한다. Tiny FMNIST는 client별 64장, 테스트 1024장의 축소 회귀이며 전체 LeNet5 성능 실험이 아니다. 이번 변경 후 전체 LeNet5나 최신 5라운드를 다시 학습하지 않았다.

## 초기 등록과 round 통신

네 aggregator의 upstream tracked Player 송신 payload 합계다. Live preprocessing을 포함하며 native framing, TLS/TCP/IP, 재전송과 upstream의 일부 no_stats exchange는 제외한다. Flower/RPC 비용은 각 verification.json에 별도로 있다.

| 실행 | setup B | r1 B | r2 B | r3 B |
|---|---:|---:|---:|---:|
| MLP 53 최초 | 33,884 | 535,150 | 267,982 | — |
| MLP 53 cache 재사용 | 33,884 | 535,150 | 267,982 | — |
| MLP 73 최초 | 33,884 | 795,398 | 395,110 | — |

각 실행에서 setup+rounds+shutdown과 native 전체 counter가 일치했다. Cache는 컴파일 비용을 없애며 MPC round 통신은 줄이지 않는다. 첫 round와 이후 round의 차이에는 backend의 live preprocessing 배치가 포함되므로 이를 norm이나 모델 학습의 고유 비용으로 해석하지 않는다.

## 정책과 거부 검사

관련 Python 회귀 **363개 통과**, 기존 Click deprecation warning 2개.

```bash
.venv/bin/python -m pytest -q tests/test_seed_mpc_*.py tests/test_rep4_candidate.py
```

[검사 로그](user-models-2026-10-11/pytest.log). 새 검사에는 schema shape/order/dtype 변경, plugin/adapter 변조, buffer 변경, tied/shared-storage parameter, BatchNorm mutable state, cache bytecode 변조·누락·추가·symlink·잘못된 recipe/key, compiler 미호출 cache hit가 포함된다. B=Q/2, 과대한 T에 따른 ring 폭 초과, 정책 dimension/client 불일치, 지원하지 않는 32-bit wire, 정책 누락·알 수 없는 필드도 native 생성 전에 거부한다. 70,003 파라미터 모델의 schema/초기 vector로 과거 D=61,706 제한 제거를 검사했으며 그 모델의 native 학습은 실행하지 않았다.

MPC의 마스크 제거/비밀 검사 수식은 바꾸지 않았다. Cache용 runtime port는 기존 agreed-public 함수의 active CHECK·전폭 equality를 거친 뒤 접속에 사용한다. 이번 실행은 새 prefix의 정상 기능과 원래 stream의 호환성을 검사했으며, port 전용 악성 native message injection이나 전체 합성 보안 증명을 새로 완료했다는 주장은 하지 않는다. 기존 direct import의 변조 9건 검증은 별도 [이전 검증 기록](direct-rep4-import-2026-10-11.md)으로 유지한다.

## 구현 파일

- `trustlessfl/seed_mpc_model.py`: factory/source pin, 이름·shape·dtype·순서 schema, fixed buffer, flatten/load, 사용자 분류 학습·평가.
- `trustlessfl/seed_mpc_compile.py`: public recipe key, compiler cache, artifact hash 검사, 동일 key lock/atomic publication.
- `experiments/run_seed_mpc_flower.py`: custom-model, explicit static policy, 모델에서 D 유도, ring/wire 용량 검사, 실행 hash binding와 독립 oracle.
- `mpc/Programs/Source/seed_mpc_chunked_session.mpc` 및 `seed_mpc_service.py`: 선택형 agreed runtime client port prefix.
- ClientApp/ServerApp/session loader: 모델 계약 검사와 기존 masked/certified 출력 경로 연결.
- `examples/seed_mpc_custom/classifier.py`, `prepare_seed_mpc_custom_example.py`, `validate_seed_mpc_models.py`: 예제·데이터·native 재현.

공개 snapshot은 source SHA와 대조하고 manifest를 작성했다. Client별 seed, private identity, raw update audit, 학습 NPZ, private runtime state를 export하지 않았다. 실제 seed 문자열과 공개 artifact의 교차 검사도 통과했다. 초기 v1 시도는 CLI PATH 설정 오류로 Flower 시작 전에 중단했으며 재사용하지 않았다. 새 세션 v2의 성공 결과만 집계한다.

## 유지되는 범위와 남은 작업

현재 user model interface는 CPU PyTorch 분류, cross entropy/SGD, 고정 공개 buffer, client 4명이다. 임의 loss·optimizer·변동 buffer·tied parameter·멀티파일 모델의 자동 패키징, client N 범용화와 일반 사용자용 보안 배포 wrapper는 남아 있다. 이 runner는 기존 신뢰된 사후 oracle용 raw client audit을 사용하며 서비스의 프라이버시 실행 preset으로 배포하지 않는다.

Aggregator는 고정 4명이고 static f<=1이다. 통과한 입력의 좌표 cap/global norm만 검사하며 SGD/마스크 의도 증명 또는 norm 안의 poisoning 탐지는 추가하지 않는다. 개별 입력을 서버에 추가로 공개하는 출력을 만들지 않았다. 최종 합/count/abort의 추론 한계와 악성 host·가용성 범위는 이전 계약과 동일하다.

모델 범용화는 비용 감소의 증명이 아니다. 최신 61,706 파라미터 direct import의 round 274.11 MB는 과거 1라운드 측정이며 이번 두 toy 모델의 결과로 다른 큰 모델의 실용성을 보장하지 않는다. Flower Hub 계정·게시 설정은 변경하지 않았다.
