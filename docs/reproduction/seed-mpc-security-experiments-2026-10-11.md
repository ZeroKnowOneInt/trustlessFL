# Seed-MPC 실험 결과: FMNIST poisoning과 무결성 검증

작성일: 2026-10-11. WSL Ubuntu-24.04, `work/aion-private-bound-no-wrap`.

**정적 norm 검사는 범위 밖 입력을 제외했지만, 범위 안의 방향 공격은 통과했다.** 4명 중 악성 클라이언트 1명이 norm 한도까지 부호 반전·확대한 경우, 5라운드 최종 정확도가 정상 평균 86.24%에서 73.82%로 12.42%p 낮아졌다. 이는 현재 필터가 업데이트 크기를 검사한다는 설계와 일치하며, 방향·데이터의 진실성까지 검증한다는 결과는 아니다.

## 실행 범위

평문 양자화 평균과 동일 정적 필터를 seed 42/43/44, 6개 조건, 각 5라운드에서 비교했다. Full LeNet5(D=61706), FMNIST train 60000/test 10000, 4명 IID 분할(각 15000), local epoch 1, batch 64, SGD lr .01/momentum .9/weight decay .0005, CPU deterministic을 사용했다. S=10000, Q=65536, B=20000, τ=2500000000, 최소 통과 2명을 고정했다. 시험 공격은 C0의 자체 데이터·업데이트와 공개 모델만 사용한다.

두 비교군의 모델이 달라지면 각자 현재 모델에서 학습을 다시 계산했다. 입력·모델이 같은 경우에만 trusted cache를 재사용했다. 아래 18조건은 평문 reference 실행 결과이며 실제 MPC 결과와 구분한다.

## 평문 대조군: 5라운드 최종 정확도

표의 ±는 3개 seeds의 표본 표준편차다. 하락은 같은 seed의 정상 결과와 비교한 평균 차이다. 3개 seed 결과로 모집단의 통계적 보장을 주장하지 않는다.

| 조건 | 무필터 양자화 평균 | 동일 정적 필터: 평균 ± 표준편차 | 정상 대비 하락 |
|---|---|---|---|
| 정상 | 86.24% | 86.24% ± 0.18%p | 0.00%p |
| 한 좌표 B+1 | 85.13% | 86.03% ± 0.01%p | 0.21%p |
| 부호 반전 | 83.61% | 83.61% ± 0.56%p | 2.64%p |
| 범위 내 확대: norm 한도 50% | 82.24% | 82.24% ± 0.72%p | 4.00%p |
| 범위 내 확대: norm 한도 100% | 73.82% | 73.82% ± 1.40%p | 12.42%p |
| 자체 train 라벨 0↔6 | 85.63% | 85.63% ± 0.23%p | 0.62%p |

범위 밖 입력 15건(3 seeds×5 rounds)은 모두 제외됐고, 정상 입력은 모두 통과하여 라운드마다 3명으로 학습했다. 부호 반전·범위 내 확대·라벨 변조의 악성 입력은 각각 15건 모두 통과했다. 정상 클라이언트의 입력 제외와 abort는 이 평문 행렬에서 발생하지 않았다. Norm 한도 50%/100% 공격은 양자화한 최종 정수 벡터를 좌표 상한과 global norm 안에 맞춰 생성했다.

라벨 변조는 공격자의 train 0↔6에만 적용했다. Test 라벨은 유지했다. 0→6/6→0 오분류율과 클래스별 정확도, 전체 confusion matrix는 조건별 JSON에 있으며 전체 정확도 하락과 함께 확인해야 한다. 방향 공격은 실제 SGD 수행을 증명하지 않는 현재 입력 계약의 범위 내 사례다.

## 실제 악성 aggregator: 작은 native 회로

정직한 P1~P3은 승인 observer build, P0만 테스트 전용 변조 binary를 실행했다. 실제 변조 marker와 binary/source hash를 확인했고, 해당 변조 build는 제품 backend pin이 거부했다.

| 변조 | 실제 검출·종료 | 잘못된 결과 인증/모델 갱신 |
|---|---|---|
| 산술 곱셈 share | DABIT에서 hash mismatch | 0/0 |
| Binary 곱셈 share | ANDS에서 hash mismatch | 0/0 |
| Opening 송신 데이터 | OPEN에서 MacCheck Failure | 0/0 |
| 라운드 시작 직후 P0 종료 | 연결 종료로 중단 | 0/0 |

실행 예약은 영속 상태에 남았고 불확실한 같은 라운드의 재실행은 거부됐다. D=65의 정상 실제 native 시험은 16개 제출 패턴을 포함한 21라운드에서 결과·모델·재적용 방지가 reference와 일치했다. 작은 fixture의 norm 정책은 전체 학습 정책과 다르며, 그 fixture의 범위 끝값·global norm·마지막 좌표·padding·wide SUM 사례에 대한 증거다.

산술 변조는 첫 변환, binary 변조는 첫 ANDS, opening 변조는 공개 입력 확인 단계에서 검출된 사례다. AES 내부·선택 단계·최종 비밀 SUM opening의 모든 변조를 검증했다고 표현하지 않는다. 중도 종료를 견디는 MPC 가용성은 현재 구조의 보장에 포함되지 않는다.

## 역할 격리 및 공식 Flower Deployment

Server/C0~C3/P0~P3의 filesystem/PID namespace에서 9개의 자기 파일 접근은 성공하고 72개 교차 비밀 파일 접근은 거부됐다. Host parent PID도 보이지 않았다. D=65의 공식 Flower Deployment 3라운드는 정상 SUM +80000, -40000과 인원 부족 abort를 reference·인증서와 대조했다. Client raw audit 파일은 생성하지 않았고 receipt 인증서 12개를 확인했다.

격리 종료 시 Python service보다 sandbox init을 먼저 종료하면 RPC 계측 파일이 남지 않는 문제가 있었다. Service를 먼저 정상 종료하도록 수정한 새 실행에서 native counter 및 RPC 양 endpoint byte 대조까지 통과했다. 공유 loopback과 호스트 관리자 신뢰 전제는 유지한다. 이 접근 제어 시험이 전체 프로토콜의 합성 프라이버시 증명은 아니다.

## Full LeNet5 실제 Flower + Rep4 비교

**검증 완료: 3/3 조건.** 완료한 조건은 seed 42, 각 5라운드다. 세 조건 모두 순차 실행과 독립 재학습 대조를 완료했다. Norm 한도 100% 조건은 평문 3-seed 결과에서 가장 큰 평균 하락을 보여 선택했다. 완료한 모든 라운드의 정수 SUM/count, 모델 bits, accuracy/loss가 평문 동일 필터 및 독립 재학습 reference와 정확히 일치했다.

| 조건 | 최종 정확도 | 라운드별 정확 일치 | 셋업 native 송신 bytes | r1~r5 native 송신 bytes |
|---|---|---|---|---|
| 범위 내 norm 한도 100% | 75.35% | 5/5 | 554,960 | 829,863,684, 829,863,684, 829,223,396, 829,863,684, 829,863,684 |
| 범위 밖 B+1 | 86.03% | 5/5 | 554,960 | 829,863,684, 829,863,684, 829,223,396, 829,863,684, 829,863,684 |
| 정상 | 86.24% | 5/5 | 554,960 | 829,863,684, 829,863,684, 829,223,396, 829,863,684, 829,863,684 |

실제 wire에서 Q를 넘는 carry 좌표 1,463건과 음수 borrow 좌표 1,441건을 trusted post-run oracle로 확인했다. 해당 마스크된 wire와 signed 복원·집계 대조가 모두 일치했다. 이 좌표 수는 전체 완료 조건의 합계이며 seed/mask/raw 업데이트는 공개하지 않는다. 최종 SUM은 Q로 줄이지 않았다.

Native 수치는 네 송신자 counter의 합이며 live preprocessing을 포함한다. TLS/TCP/IP/framing 및 upstream no_stats 전송은 제외한다. Flower 객체 그래프·RPC JSON·external seed socket은 각 verification JSON에서 별도로 확인하며 같은 전송을 중복 합산하지 않는다.

최초 병렬 실행은 native 빌드와 겹쳐 7.29 GiB WSL 메모리의 95% 한도를 넘었고 Ray가 학습 worker를 종료했다. 해당 누락 라운드는 정상 비교 조건을 만족하지 않아 중단·보존하고 결과에서 제외했다. 완료 결과는 다른 학습/빌드와 겹치지 않는 새 세션의 순차 실행이다. 수집 마감은 60초에서 600초로 늘렸고 조기 전원 수집 확정은 유지했다. 이는 대기 설정이며 B/τ는 변경하지 않았다.

첫 순차 정상 실행도 Flower/Ray의 직렬화 예외 후 actor pool 소진으로 3~5라운드가 abort하여 제외했다. 수정은 설치 라이브러리를 변경하지 않고 해당 실행의 source-hash로 고정한 process-local guard로 적용했다. 예외 시 actor를 반환하고, Ray pickle 준비 단계의 확인된 예외에만 bounded retry를 적용한다. 정상 조건은 새 세션 재실행 결과다. [오류 진단 및 수정](seed-mpc-runtime-failure-2026-10-11.md)을 참조한다.

전체 모델 실행은 Flower Simulation/Ray와 같은 Unix UID의 trusted test harness다. 서버 메시지에는 masked 업데이트만 있고 평문 audit은 별도 post-run reference에만 사용하지만, 이 학습 실행을 독립 운영자 격리의 증거로 제시하지 않는다. 위 작은 Deployment의 역할 격리 결과와 구분한다.

## 재현 자료·한계

[실험계획](../seed-mpc-security-experiment-plan.md), [공개 결과 JSON](seed-mpc-security-experiments-2026-10-11/results.json), [SHA256 manifest](seed-mpc-security-experiments-2026-10-11/manifest.json), [native 변조 시험](seed-mpc-security-experiments-2026-10-11/security/summary.json), [역할 격리 검증](seed-mpc-security-experiments-2026-10-11/isolation/public-fixture-verification.json).

최초의 모든 좌표 10배 확대 예비 실행은 무필터 모델의 후속 업데이트가 signed wire 범위를 넘어 중단했다. 그 불완전 기록은 `.cache/seed-mpc-experiments/poisoning-iid-2026-10-11`에 보존했고 위 결과에 합치지 않았다. 본 비교는 canonical B+1 좌표 대조군으로 새 실행했다. Flower CLI PATH 문제로 시작 전 중단한 native 시도도 별도 보존했다.

229개 입력/receipt/committee/dropout/meter/Flower 회귀와 공격·산술·정적 bound 관련 33개 검증이 통과했다. 구현 수정 후 공격/Flower 46개도 다시 통과했다. 이 숫자들은 겹치는 suite를 포함하므로 서로 더한 고유 테스트 수로 표현하지 않는다.

Non-IID, 2명 악성 클라이언트, 추가 native 학습 seeds, 긴 학습, 다른 poisoning 방법 및 threshold sweep은 이번 첫 실행 묶음의 완료 범위 밖이다. Aggregator 2명 공모, 공개 aggregate에서 알려진 기여를 빼는 역추론, DP와 전체 등록·변환·abort 프라이버시 증명은 별도 문제다. 현재 실험이 이를 제거했다고 주장하지 않는다.
