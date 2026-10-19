# 졸업작품: 무필터·평문 bound·비공개 MPC 비교 실험 결과

2026-10-12, WSL Ubuntu-24.04, `work/aion-private-bound-no-wrap`. 실제 수행 완료한 결과만 기록한다.

**전체 FMNIST 실험에서 L2 초과 공격 시 무필터 평균 정확도는 19.58%, 평문 bound와 실제 MPC는 모두 86.03%였다. 악성 입력 15/15건을 제외했고 정상 입력 제외는 0/105건이다. 정상 조건은 세 방식 모두 평균 86.24%였으며, 실제 MPC 30라운드와 클라이언트 입력 120건을 참조와 정확히 대조했다.**

## 조건과 비교 방법

- Full LeNet5: **61,706개 파라미터**, Fashion-MNIST train **60,000** / test **10,000**.
- Client **4명**, IID 각 **15,000개**, local epoch 1, batch 64, SGD lr .01 / momentum .9 / weight decay .0005.
- Seed **42, 43, 44**, 조건별 **5라운드**. 공격 조건에서 C0 한 명만 악성.
- 고정 정책: S=10,000, Q=65,536, 좌표 B=20,000, norm 제곱 T=2,500,000,000(L2 반경 5), 최소 통과 2명.
- 무필터와 평문 bound는 trusted reference. 비공개 비교군은 **실제 공식 Flower + active Rep4**이며 평문 대체 경로가 아니다.
- MPC는 최신 seeded-component·holder-checked direct import·lane64 경로, 고정 aggregator 4명/최대 악성 1명 계약이다.

같은 seed에서 초기 모델·분할·학습·정책·공격 규칙을 맞췄다. 필터 유무로 모델이 달라진 뒤에는 각 현재 모델에서 새로 학습한다. 평문 필터와 MPC는 각 라운드 동일한 입력·정수 합·모델인지 별도로 검증했다.

공격은 C0의 **자기 업데이트를 부호 반전·확대**하여 L2 반경 약 10으로 만들고, 모든 좌표는 B 안에 유지한다. 최종 양자화 정수가 canonical signed wire 범위 안에 있고 전체 norm만 T를 넘는지 확인한다. Honest 업데이트를 공격 생성에 제공하지 않는다. Client의 정직한 사전 검사를 명시적 test hook으로 우회하여 MPC가 직접 거부하는지 시험하며 제품의 검사·정책은 변경하지 않는다.

## 최종 정확도

평균 ±는 3개 seed의 표본 표준편차이며 신뢰구간이 아니다.

| 조건 | 집계 방식 | seed별 최종 정확도 | 평균 ± 표준편차 |
|---|---|---|---|
| 정상 | 무필터 양자화 평균 | 86.24% / 86.07% / 86.42% | 86.24% ± 0.18%p |
| 정상 | 평문 동일 bound 검사 | 86.24% / 86.07% / 86.42% | 86.24% ± 0.18%p |
| 정상 | 비공개 Flower·MPC bound 검사 | 86.24% / 86.07% / 86.42% | 86.24% ± 0.18%p |
| L2 범위 초과 공격 | 무필터 양자화 평균 | 20.25% / 18.24% / 20.24% | 19.58% ± 1.16%p |
| L2 범위 초과 공격 | 평문 동일 bound 검사 | 86.03% / 86.04% / 86.03% | 86.03% ± 0.01%p |
| L2 범위 초과 공격 | 비공개 Flower·MPC bound 검사 | 86.03% / 86.04% / 86.03% | 86.03% ± 0.01%p |

무필터 공격 조건은 정상 대비 **66.67%p** 낮아졌다. Bound 검사 조건은 무필터 공격 대비 **66.46%p** 높았고, 정상 기준 대비 차이는 **0.21%p**였다.

![라운드별 정확도 비교](graduation-three-way-2026-10-12/accuracy.png)

정상 조건에서는 세 곡선이 모두 겹친다. 평문 bound와 비공개 MPC의 곡선이 겹치는 것은 측정 오류가 아니라 매 라운드 모델이 정확히 같다는 결과다. 정상 조건과 공격 조건의 정상 기준 비교는 참여 인원 4→3의 차이도 포함하므로 정확도가 동일해야 한다고 가정하지 않는다.

## 입력 제외와 정상 학습 유지

| 조건 | 방식 | 악성 입력 제외 | 정상 입력 제외 |
|---|---|---|---|
| 정상 | 무필터 양자화 평균 | 해당 없음 | 0/60 |
| 정상 | 평문 동일 bound 검사 | 해당 없음 | 0/60 |
| 정상 | 비공개 Flower·MPC bound 검사 | 해당 없음 | 0/60 |
| L2 초과 | 무필터 양자화 평균 | 0/15 | 0/45 |
| L2 초과 | 평문 동일 bound 검사 | 15/15 | 0/45 |
| L2 초과 | 비공개 Flower·MPC bound 검사 | 15/15 | 0/45 |

무필터의 제외 수는 검사 없이 전원을 평균에 포함했다는 뜻이다. 제외율은 trusted 실험 oracle에서 구한 평가 지표이며 제품 서버에 개별 norm·통과 비트를 새로 공개한 것이 아니다.

## 실제 MPC 정확성

| seed | 조건 | 확인한 라운드 | 정수 SUM/count | 모델·accuracy/loss |
|---|---|---:|---|---|
| 42 | clean | 5 | 전체 정확히 일치 | 전체 정확히 일치 |
| 42 | norm-overflow | 5 | 전체 정확히 일치 | 전체 정확히 일치 |
| 43 | clean | 5 | 전체 정확히 일치 | 전체 정확히 일치 |
| 43 | norm-overflow | 5 | 전체 정확히 일치 | 전체 정확히 일치 |
| 44 | clean | 5 | 전체 정확히 일치 | 전체 정확히 일치 |
| 44 | norm-overflow | 5 | 전체 정확히 일치 | 전체 정확히 일치 |

각 native 실행의 독립 재학습·수신증명·입력/결과 인증서·중복 모델 적용 방지도 검증했다. 모델 비교에 부동소수점 허용 오차를 적용하지 않았다.

## MPC 비용: 등록과 라운드 분리

네 aggregator의 추적된 Player payload **송신 합계**이며 각 transmission은 한 번만 센다. Live preprocessing을 포함하지만 TLS/TCP/IP·native framing·미추적 exchange와 Flower/RPC 통신은 제외한다. 전체 시스템 통신량으로 표현하지 않는다.

| seed | 조건 | 초기 setup bytes | round 1~5 송신량(MB, 10⁶ bytes) | ServerApp wall(초) |
|---|---|---:|---|---:|
| 42 | clean | 33,884 | 274.11 / 273.47 / 274.11 / 273.47 / 274.11 | 473.91 |
| 42 | norm-overflow | 33,884 | 274.11 / 273.47 / 274.11 / 273.47 / 274.11 | 477.12 |
| 43 | clean | 33,884 | 274.11 / 273.47 / 274.11 / 273.47 / 274.11 | 477.52 |
| 43 | norm-overflow | 33,884 | 274.11 / 273.47 / 274.11 / 273.47 / 274.11 | 478.14 |
| 44 | clean | 33,884 | 274.11 / 273.47 / 274.11 / 273.47 / 274.11 | 477.53 |
| 44 | norm-overflow | 33,884 | 274.11 / 273.47 / 274.11 / 273.47 / 274.11 | 480.56 |

Setup·round·shutdown counter 합을 global counter와 대조했다. 회로 compile/cache 조회와 seed 등록은 세션 준비 단계이며 라운드마다 재등록·재컴파일하지 않는다. Wall time은 학습·수집·MPC·인증을 포함한다. 평문 reference의 cache/직렬 학습과 Flower scheduling 조건이 달라 단순 시간 비율을 MPC 오버헤드로 주장하지 않는다.

## 검증 범위와 한계

- 이번 결과는 **범위를 넘는 악성 입력을 제외하면서 개별 업데이트를 직접 열지 않는 검사·집계**의 기능과 학습 효과를 보여준다.
- Norm 안의 poisoning, 실제 SGD 수행 여부, 모든 공격에 대한 방어를 증명하지 않는다.
- 실제 MPC 학습은 **동일 WSL UID의 trusted local Flower Simulation harness**다. 최신 독립-host 구현을 네 기관에 배포한 시험이 아니다.
- Post-run 정수·학습 대조를 위한 raw 업데이트 audit은 로컬 private `.cache`에만 만들었다. 일반 사용자 경로의 audit 정책이나 서버 권한을 확대하지 않았다.
- Aggregator 2명 공모, 공개 SUM/count/모델에서의 역추론, 전체 FL composition 프라이버시·DP·BFT liveness 증명을 대신하지 않는다.
- 3개 seed와 IID·클라이언트 4명·한 공격 조건의 결과이며 다른 모델·규모·non-IID로 일반화하지 않는다.

## 재현과 공개 자료

```bash
.venv/bin/python -u -m experiments.run_graduation_three_way \
  --output .cache/new-graduation-three-way \
  --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3-direct-rep4-v1 \
  --report docs/reproduction/new-three-way.md --seeds 42 43 44 --rounds 5
```

[공개 결과·정확성·비용 JSON](graduation-three-way-2026-10-12/results.json), [소스·공개 파일 hash](graduation-three-way-2026-10-12/manifest.json).
Native와 평문 학습을 순차 실행한다. 개인 키·seed·학습 데이터·raw 업데이트·SQLite 상태는 공개 파일에 포함하지 않는다. Hub 게시·계정 설정은 하지 않았다.

## 추가 입력 대조

별도 검증기에서 **120개 client-round 입력**을 로컬 private reference cache와 MPC client의 test audit 사이에 좌표별로 비교해 모두 일치했다. Seed·round·slot·현재 모델 hash로 cache를 선택했으며 keys/seed 파일은 읽지 않았다. [입력 일치 결과](graduation-three-way-2026-10-12/input-equality.json).

실제 공격 입력 15건은 모두 좌표 상한 안에 있었다. L2 반경은 **9.99971~10.00000**(한도 5), 최대 좌표 절댓값은 **0.76360**(한도 2)였다. 따라서 이번 제외는 좌표 초과 대신 전체 norm 위반을 검사한 결과다.

## 실행 전 회귀 검사

`tests/test_seed_mpc_poisoning.py`와 `tests/test_seed_mpc_flower.py` **59 passed**(4.84초, 기존 dependency warning 2개)였다. 새 global-norm 공격의 좌표 유효성·canonical 범위·norm 초과와 실제 Flower test hook의 연결을 확인했다. 프로젝트 전체 테스트 수로 표현하지 않는다.

추가 입력 대조를 재현하려면 첫 실행 명령 완료 후 다음을 실행한다.

```bash
.venv/bin/python -m experiments.verify_graduation_three_way \
  --output .cache/new-graduation-three-way \
  --report docs/reproduction/new-three-way.md
```
