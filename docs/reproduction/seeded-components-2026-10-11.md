# Seed component 로컬 확장 적용·검증·통신량

작성일: 2026-10-11. WSL `trustlessFL`, `work/aion-private-bound-no-wrap`.
[현재 프로토콜](../aion-seeded-components-protocol.md), [실측 비교 JSON](seeded-components-2026-10-11/comparison.json).

## 1. 적용 결과

Flower staging의 기본 마스크 경로를 `rep4-seeded-components-v1`로 바꾸었다.
클라이언트마다 독립 seed 네 개를 만들고 수신자별 세 개씩 암호화·서명해 전달한다.
Aggregator는 자기가 가진 세 seed만 로컬에서 확장한다. MPC 내부의 AES 회로는 실행하지 않는다.
최종 XOR mask를 additive masking에 사용하므로 client는 single masked 벡터만 업로드한다.

기존 MP-SPDZ 0.4.3 악성 Rep4 backend와 pin을 유지한다.
로컬 component는 기존 악성 보안 binary input으로 입력하고 세 holder의 사본을 MPC에서 비교한다.
**따라서 이번 구현은 통신 없는 raw share import가 아니다.** Component 재공유·일치 검사 비용이 남는다.
개인 업데이트와 전체 mask는 aggregator에게 평문으로 공개하지 않는다.
좌표·global norm 검사, 정확한 modular subtraction, wide SUM, 사후 CHECK, 3서명 결과 인증과 기존 dropout/영속 상태 계약을 유지한다.

등록은 실제로 복호화한 holder seed를 native private input으로 검사한다.
TLS client socket은 등록 tag binding을 담당한다. Seed를 별도 TLS 경로로 중복 업로드하지 않는다.
`seed_mpc_prss.py`와 `seed_mpc_wire.py`의 source SHA-256을 config/execution hash에 포함하고 양쪽 runtime에서 확인한다.

## 2. 최종 버전의 전체 FMNIST/LeNet5 1라운드

- 모델: 61,706 parameters, 네 client, 전체 FMNIST IID 15,000 train examples/client, 10,000 test examples.
- Seed 42, local epoch 1, 기존 optimizer/정규화/quantization/정적 threshold 유지.
- 공식 Flower Simulation Runtime/Ray와 실제 네 Rep4 native process 사용; plaintext fallback 없음.
- 네 client가 모두 제출·통과. Native 정수 SUM/count, 모델, 독립 재학습, 평가 결과가 기준 계산과 정확히 일치.
- 초기 test accuracy 10.00%, 1라운드 후 **74.84%**. 보존된 기존 clean 실행의 1라운드 metric과 동일.
- 이번 변경의 최종 버전으로 전체 학습은 **1라운드** 검증했다. 과거 5라운드 결과를 새 버전의 5라운드 실행으로 표현하지 않는다.

[최종 전체 학습 검증 요약](seeded-components-2026-10-11/lenet-final/summary.json).

## 3. 초기 등록과 라운드 통신량

아래 수치는 네 aggregator의 native **송신량 합계**이며 live preprocessing을 포함한다.
Flower/RPC, TLS/TCP/IP, encrypted seed packet bootstrap 전달 비용을 포함한 전체 시스템 통신량과 구분한다.
MB는 1,000,000 bytes다.

| 구분 | 이전 secret AES | 최종 seeded component |
|---|---:|---:|
| Native 초기 등록 | 554,960 B (0.554960 MB) | 85,506 B (0.085506 MB) |
| 첫 라운드 native MPC | 829,863,684 B (829.863684 MB) | 675,883,188 B (675.883188 MB) |

첫 라운드 native 비용이 **18.55% 감소**했다.
같은 D/N/Q/B/T/S/chunk 크기, 동일한 training/data/model/seed와 all-present 첫 라운드를 대조했다.
이전 프로그램은 5 round slots, 이번 프로그램은 1 round slot으로 컴파일했으므로 동일 binary의 순수 한 함수 microbenchmark는 아니다.
전처리를 제외하거나 뒤로 옮겨서 감소한 것으로 보고하지 않았다.

최종 추가 등록 자료는 암호화된 수신자별 packet 16개, 본문 합계 **12,068 bytes**다.
로컬 bootstrap이 ciphertext 파일을 전달한 payload 크기이며 실제 네트워크 transport overhead를 계측한 수치는 아니다.
Native client tag/handshake application framing은 sent 656 B,
received 256 B로 별도 기록한다. TLS/TCP overhead는 제외한다.

## 4. 전체 차원 합성 3라운드와 검증 범위

61,706차원 합성 fixture의 native round bytes는
**675,883,188, 675,883,188, 675,242,900**다.
정수 SUM과 모델은 세 라운드 모두 기준과 정확히 일치했다.
양 끝 좌표에서 80,000/−80,000의 wide SUM을 검증하고, 마지막 좌표 범위 위반과 여러 chunk에 걸친 global norm 위반을 배제했다.
최소 통과 인원 미달 round는 정상적인 정책 abort다.

이 3라운드 측정은 등록 채널 통합·source binding의 최종 정리 전 snapshot이며, round 계산 구조는 동일하다.
최종 버전은 위 전체 LeNet 학습 1라운드와 아래 isolated fixture로 별도 검증했다.
3라운드 fixture의 마지막 snapshot은 `[1,1,1,0]`이다. 빠진 client는 원래도 norm 검사 탈락 입력이었다.
결과가 동일하다고 전부 all-present였다고 주장하지 않는다.

| 검사 | 결과 |
|---|---|
| Python 회귀 | **298 passed**, 기존 Click API deprecation warning 2개 |
| 최종 native 등록 seed equivocation | `inconsistent component seed registration`; aggregate/result checkpoint 0; model genesis 유지 |
| 최종 native component equivocation | `inconsistent local mask components`; aggregate/result checkpoint 0; result vote/certificate 0 |
| 최종 FMNIST 소형 모델, D=170 | 실제 1라운드, 독립 재학습·SUM·모델·평가 일치 |
| 최종 격리 Flower Deployment fixture, D=65 | 실제 3라운드, 12 receipt certificates, SUM/모델 일치, raw audit 없음 |
| 역할 격리 | 9개 filesystem/PID namespace, 타 역할 파일 접근 72개 거부 |
| Native/RPC 계측 | 송신 counter 합과 peer/service endpoint 계측 대조 통과 |

성공 경로의 공개값은 기존 SUM/count/abort와 인증 정보다.
Component나 개인 norm을 공개하지 않는다. Registration/component 일치 실패는 집계 공개 전에 중단한다.
Input fault 검사는 실제 native 경로에서 수행했지만 모든 악성 protocol message/공모 조합에 대한 구성 보안 증명을 대신하지 않는다.
Host bootstrap/admin은 신뢰한다. 로컬 격리는 host administrator/kernel이나 공유 loopback network DoS를 방어하는 모델이 아니다.

## 5. 남은 비용

MPC 내부 AES 제거만으로 830 MB를 수 MB 수준으로 만들지는 못했다.
기존 public wire 사본의 full-width 비밀 비교, binary coordinate 연산, binary-arithmetic 변환,
global norm, component의 악성 보안 private input과 사본 비교가 계속 비용을 만든다.
공개 wire 비교를 인증된 공개 비교로 바꾸거나 batching/direct share import를 개선하는 작업은 이번 변경에 섞지 않았다.
검증을 없애거나 semi-honest 모드로 바꿔 감소시킨 결과가 아니다.

Norm 이내의 malicious update, SUM/count로부터 가능한 역추론, aggregator 두 명 공모,
무조건적인 liveness를 해결했다고 주장하지 않는다. 기존 신뢰 모델과 허용된 출력 누출을 유지한다.

## 6. 재현과 공개 자료

```bash
.venv/bin/python -m pytest -q tests/test_seed_mpc_*.py tests/test_rep4_candidate.py
PATH="$PWD/.venv/bin:/usr/local/bin:/usr/bin:/bin" .venv/bin/python -m experiments.run_seed_mpc_flower \
  --output .cache/seeded-components-fresh \
  --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3-telemetry \
  --mode fmnist-lenet5 --rounds 1 --snapshot-version 2 --communication-meter \
  --collection-window-ms 600000 --timeout 600
```

Native 변조 재현은 `experiments.run_seeded_components_security --fault seed-equivocation`
또는 `--fault component-equivocation`을 사용한다. Output은 매번 새로운 directory를 지정한다.
기존 방식은 Flower runner에 `--mask-mode secret-aes-v1`을 추가한다.

공개 폴더에는 source snapshot, 검증 요약, native counter 경계와 hash manifest만 보존했다.
Client key/seed, component packet plaintext, raw learning update/audit, aggregator private identity는 내보내지 않았다.
Flower Hub 게시와 관련 설정은 만들지 않았다.
