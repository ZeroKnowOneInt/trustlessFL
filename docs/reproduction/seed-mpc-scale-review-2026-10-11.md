# Seed-MPC 전체 모델 차원 검증과 자원 측정

작성일: 2026-10-11. 브랜치: `work/aion-private-bound-no-wrap`.

## 1. 시험 범위

**전체 61706좌표/3라운드에서 정수 SUM/count/abort와 모델 갱신이 참조 계산과 정확히 일치했다.** 실행 시간 733.502초, native 통신 2476.15MB, native 프로세스 1개당 최대 RSS 145.82MiB였다. 컴파일은 6.870초에 한 번, 클라이언트 seed 입력도 각 한 번이었다. 메모리에 올라가 실행되지만 집계 시간과 통신 비용이 큰 구현이다.

공식 Flower `flwr run`과 네 개의 별도 aggregator service, 실제 MP-SPDZ 0.4.3 `rep4-ring-party.x`를 사용했다. 클라이언트 4개가 생성한 AES seed는 등록할 때 한 번만 native private input으로 전달하고, 이후 3라운드는 동일한 native session의 share를 재사용한다. 각 모델 차원 시험은 별도의 새 session·seed·서명키로 시작한다.

이번 단계는 전체 LeNet5와 같은 **61706좌표의 고정 입력**을 검증하는 것이다. SGD를 수행한 LeNet5 학습 실험이나 학습 정확도 측정으로 해석하지 않는다. 정수 SUM/count/abort와 모든 좌표의 모델 갱신을 독립 참조 계산과 비교한다. 같은 WSL 호스트와 Unix UID의 기능 시험이다.

정책은 `Q=65536`, `w=16`, `B=20000`, `S=10000`, `T=2500000000`, 클라이언트 4명, 최소 통과 2명이다. Threshold는 세션 시작 전에 고정한다. 전체 norm의 최악 상한은 `D*B²=24682400000000 < 2^45`이고 좌표 합의 절댓값은 `4B=80000` 이하이므로 64비트 링과 공개된 비교 폭에서 계산한다. 실제 허용 norm은 이 최악 상한보다 작은 T로 검사한다.

## 2. 입력과 정확성 조건

정상 입력은 모든 좌표에 작은 양수·음수가 들어가는 dense 벡터다. 첫 좌표는 +B, 마지막 좌표는 −B로 설정한다. 둘의 제곱을 포함한 전체 norm은 T 안에 있다. 두 끝의 집계가 ±80000이므로 전송 modulus를 넘는 양수와 음수의 정확한 집계를 함께 확인한다. 내부 좌표도 0으로 채우지 않아 인덱스 오류와 누락을 확인한다.

| 라운드 | 입력 | 참조 결과 |
|---|---|---|
| 1 | 4명 모두 좌표·전체 norm 안 | count=4, 첫 합 +80000, 마지막 합 −80000 |
| 2 | C0/C1 정상 음수 방향; C2 마지막 좌표=20001; C3 7개 서로 다른 청크에 B | count=2, 첫 합 −40000, 마지막 합 +40000; C2/C3 전체 제외 |
| 3 | C0만 정상, 나머지 좌표 또는 norm 위반 | abort; 공개 모델 유지 |

C3는 각 32좌표 청크의 norm은 T 이하지만 전체 norm은 `7*B²=2800000000 > T`다. 따라서 청크별 검사로 바뀌었다면 잘못 통과할 입력이다. Native에서는 전체 norm과 한 개의 client 선택 비트를 계산한 뒤 모든 좌표에 그 비트를 적용한다.

전체 D는 32의 배수가 아니다. 마지막 청크는 실제 10좌표와 22개의 zero padding으로 구성한다. Padding은 입력 좌표로 해석하지 않으며 결과 로그는 정확히 D개 SUM 좌표만 출력한다. 묶음 opening에 포함된 내부 padding은 항상 0이므로 별도 입력 정보를 담지 않는다.

원래 마스크에는 클라이언트당 AES block `ceil(D/8)=7714`개가 필요하다. 네 block을 한 청크로 계산하는 native 회로는 padding 때문에 7716개를 계산하며 마지막 두 block은 사용하지 않는다. 모델 벡터는 float32 기준 246824바이트, 현재 공개 float64 전달 기준 493648바이트다. 클라이언트 한 명의 raw uint16 masked 벡터는 123412바이트이고 실제 JSON·서명 응답과 구분한다.

`(Y-mask) mod Q`는 마스크 덧셈에서 생긴 carry를 정확히 제거한다. 복원한 signed word의 좌표 범위를 MPC가 검사하고, 이 범위 안의 정수만 넓은 공간에서 norm·SUM에 사용한다. **최종 SUM은 Q로 다시 줄이지 않는다.** 정확성 대상은 실제 제출된 residue로 정의되는 정수 업데이트이며, 임의의 클라이언트가 제출했다고 주장하는 범위 밖 원래 정수까지 복구한다는 뜻은 아니다.

## 3. 최적화와 측정

출력의 `accepted_i * u_i,j`와 opening을 좌표별로 수행하던 루프를 32좌표 벡터 연산으로 바꿨다. 먼저 비밀 `ok * accepted_i`를 구하고 해당 청크 전체에 적용한다. 출력 순서와 허용 정보, 전체 norm 검사, 개별 선택 비트의 비공개 상태를 유지한다. CHECK 후 인증서 발급 조건도 유지한다.

로컬 native 로그 observer는 한 번에 최대 256개의 완성된 줄을 읽어 버퍼에 보관한다. 불완전한 줄은 소비하지 않는다. 결과는 전체 출력 개수·round·256비트 input hash·최종 CHECK를 확인하기 전까지 vote가 되지 않는다.

| 방식 / 차원 | compile 초 | 3라운드 ServerApp 초 | native 내부 통신 MB | native 1개 최대 RSS MiB |
|---|---:|---:|---:|---:|
| 기존 출력 / 1024 | 6.522 | 20.086 | 43.345 | 37.87 |
| 묶음 출력 / 1024 | 6.651 | 17.113 | 41.607 | 37.96 |
| 묶음 출력 / 4096 | 6.585 | 54.982 | 164.920 | 39.96 |
| 묶음 출력 / 61706 | 6.870 | 733.502 | 2476.150 | 145.82 |

1024좌표에서 두 개선을 함께 적용한 실행 시간은 14.8%, native 통신은 약 4.0% 감소했다. 새 seed와 session을 사용한 각 1회 실행의 관측값이며, 반복 평균이나 출력 최적화만의 효과를 뜻하지 않는다. 다른 측정 작업을 병행하지 않고 차원 시험을 순서대로 실행했다.

컴파일과 native 프로세스의 메모리·user/system CPU는 Linux `/usr/bin/time -v`로 기록한다. 표의 RSS는 네 native 프로세스 중 가장 큰 값이다. Python aggregator service·Flower·Ray·bootstrap 전체 메모리와 구분한다. 네 peak RSS를 더한 값은 동시 사용 메모리의 peak가 아니다.

ServerApp 시간은 registration/ready와 결과·모델 확인을 포함하되 compiler, 전체 Flower/SuperLink 시작 시간, 종료 후 독립 oracle 검증 시간을 제외한다. `execute_and_result_certificate_seconds`는 service의 입력 검증·FIFO 전달·MPC·출력 읽기·결과 서명 확인을 함께 포함하므로 순수 online cryptographic 시간으로 표시하지 않는다. Native 내부 MB는 MP-SPDZ의 전체 party 송신 합계인 decimal MB이며 3라운드와 등록을 포함한다.

전체 D에서 execute와 결과 인증 구간은 각각 212.959, 212.599, 212.503초였다. 합계 638.061초로 ServerApp 시간의 약 87%다. Client 결과 채택과 중복 적용 거부 시험은 라운드마다 약 21초였다. 비용의 주된 부분은 native MPC 구간에 남아 있다.

Party 0의 native 로그에는 preprocessing을 포함한 `Time=710.029초`, 약 `3017356`회의 통신 round가 표시되어 있다. 이는 **FL 라운드 3개 안에서 backend가 집계한 근사 통신 횟수**이며 실제 FL 학습 라운드 수가 아니다. Sending/receiving 항목은 675.521MB, 2727288회, 557.176초였다. 다른 호스트 사이에서는 왕복 지연이 추가되므로, 이 loopback 측정으로 WAN 성능을 보장할 수 없다. 패킷·latency 측정 및 순수 cryptographic round 분해는 별도다.

### 3.1. 실제 전달 내용의 크기

아래는 [기록된 메시지로 재구성한 내용 크기](seed-mpc-scale-2026-10-11/batched-61706/communication.json)다. 4클라이언트·3라운드의 모든 전달 횟수를 포함한다. TLS/HTTP/protobuf framing, identity/등록/ACK/ready/finish 제어 메시지와 전체 packet capture를 포함하지 않는다.

| 경로 / 내용 | 바이트 |
|---|---:|
| Flower 클라이언트 → 서버: masked ConfigRecord 내용 | 17530860 |
| 서버 → 4 aggregator: prepare/execute/decide JSON | 217851316 |
| 4 aggregator → 서버: round vote/decide 응답 JSON | 1494008 |
| 서버 → 클라이언트: 결정 인증 내용, 중복 commit 시험 포함 | 155187512 |
| 공개 float64 모델 배열: train + 두 번 commit | 17771328 |

`masked_application_json_bytes=18642048`은 ServerApp의 바깥 JSON wrapper까지 다시 직렬화한 기존 카운터다. 실제 ConfigRecord key/value 내용인 17530860바이트와 동일한 지표가 아니다. 중복 commit은 적용이 한 번뿐임을 확인하는 시험이므로, 이를 제거하면 결정 내용은 절반, 모델 배열은 3분의 2가 된다. 이 시험을 제거하더라도 native MPC 비용은 이번 측정에서 바뀌지 않는다.

첫 라운드의 raw masked words는 네 클라이언트 합계 493648바이트지만, 7716개 서명 청크를 포함한 입력 snapshot은 5843969바이트다. Native의 32좌표 처리 단위와 업로드의 서명 청크 크기를 함께 작게 설정한 현재 포맷이 비용을 키운다. 결과 인증서도 같은 body를 여러 vote envelope에 반복한다. 등록 seed가 작다는 사실만으로 이 메시지 비용이나 MPC 비용까지 작아지는 것은 아니다.

### 3.2. 다음 비용 개선 후보

우선 검토할 부분은 native AES/변환의 SIMD batch 폭이다. 현재 네 AES block, 32좌표씩 순차 처리하므로 반복 통신이 많다. 더 넓은 batch에서도 전체 norm·한 client 선택·고정 정수 폭·CHECK를 유지해야 한다. 단순히 보안 check를 빼거나 per-chunk 통과 비트로 집계하지 않는다. 넓은 batch를 시험할 때 악성 norm 입력도 그 실제 청크 폭에 걸쳐 분산하여 다시 확인해야 한다.

업로드 서명 청크는 native 회로 청크와 분리해 더 크게 구성할 수 있는 후보이며, 중복 body와 전체 masked snapshot의 client 전달도 검토 대상이다. 인증 context·입력 binding·모델 체인의 검증을 유지하는 별도 구현과 회귀 검증 후 반영한다. 이번 결과는 해당 후보를 적용한 수치가 아니다. 다음 학습 단계는 기존 reference와 같은 초기 LeNet5/partition을 사용한 FMNIST IID 1라운드이다.

## 4. 보안과 운영 범위

네 aggregator 중 static 악성 최대 1개라는 조건을 유지한다. 두 aggregator가 공모하면 seed shares를 복원할 수 있다. 선택 SUM/count/abort의 허용 누출에서 생기는 역추론도 그대로다. Norm 안의 악성 업데이트 의미 판별, 전체 BFT liveness, secret share의 안전한 디스크 복구·갱신, dropout과 committee 교체는 이번 시험 대상이 아니다. 악성 클라이언트와 악성 aggregator가 동시에 참여하는 전체 구성의 보안 증명은 미완료다.

MPC의 opening 자체와 애플리케이션의 결과 채택을 구분한다. Native 합계/count는 최종 CHECK 전 pending 값으로 observer에 들어오며, CHECK와 입력 hash가 확인된 뒤에만 결과 인증서에 서명한다. 이 버퍼링 자체가 추가적인 MPC 프라이버시 보안 증명은 아니다. 개인별 update/norm/통과 여부는 출력하지 않는다.

Rep4의 과거 delayed consistency check 문제는 [공식 보안 수정 설명](https://mp-spdz.readthedocs.io/en/latest/security-fixes.html#insufficient-checks-in-rep4)과 [0.4.3 릴리스](https://github.com/data61/MP-SPDZ/releases/tag/v0.4.3)에 기록되어 있다. 설치된 0.4.3 binary의 SHA256을 실행 계약에 고정하고 service 시작 및 종료 후 oracle 검증 시 확인한다. 설치 소스 `Rep4::exchange()`에서 `check_hashes()`를 multiplication 결과 사용 전에 호출하는 구현도 확인했다. 이는 vendor의 재현 가능한 build 증명이나 전체 구성의 안전성 증명을 대신하지 않는다.

시험용 원시 update audit은 클라이언트 로컬 검증 자료다. Flower 응답과 aggregator API에는 전달하지 않으며 공개 archive에도 넣지 않는다. 공개 archive는 allowlist를 사용하고 실제 시험 seed/서명 개인키의 hex 문자열이 포함되지 않았는지 검사한다. 운영 모드에서는 이 test-only audit을 꺼야 한다. Hub/publisher 설정은 이번 단계에서 바꾸지 않는다.

## 5. 재현

```bash
cd /home/hacho/@WSL-Projects/trustlessFL
source .venv/bin/activate
python -m experiments.run_seed_mpc_flower \
  --mode scale-fixture --dimension 61706 --timeout 1800 \
  --output .cache/seed-mpc-scale-full-new
python -m experiments.run_seed_mpc_flower \
  --phase verify --output .cache/seed-mpc-scale-full-new
python -m pytest -q tests/test_seed_mpc_flower.py tests/test_seed_mpc_committee.py
```

출력에는 새 경로를 사용한다. 같은 session의 불확실한 실행을 재시도하거나 새 key 없이 native session을 재시작하지 않는다. 라운드 수·정책·차원은 compile 시 고정하고, 라운드별 입력은 동일 bytecode에 전달한다.

신규 코드: `trustlessfl/seed_mpc_resources.py`, `experiments/export_seed_mpc_scale.py`. 수정: chunked MPC 출력 루프, `seed_mpc_native.py`, `seed_mpc_training.py`, Flower client/service/server와 시험 runner. Python 관련 검사 202개가 통과했다.

[네 실행 검증과 실행별 48개 파일 hash](seed-mpc-scale-2026-10-11/summary.json), [전체 D 검증 결과](seed-mpc-scale-2026-10-11/batched-61706/verification.json), [전체 D 측정·인증 기록](seed-mpc-scale-2026-10-11/batched-61706/results.json). 각 실행 archive에는 15개의 공개 log, resource counters, policy/provenance와 실제 당시의 Python/MPC source가 포함된다. Baseline과 변경 후 코드는 서로 다른 source hash로 보존했다.

Native 회귀 결과는 [묶음 출력 회귀 기록](rep4-batched-regression-2026-10-11/summary.json)에 보존한다. 65좌표의 마지막 partial chunk, 동일 bytecode에 새 입력, public 입력 불일치·high-bit 변조·noncanonical wire·padding·라운드 재사용 거부, 1024좌표 전체 norm, 32비트 signed 경계를 확인한다. 이 fault fixture의 성공을 전체 구성의 보안 증명으로 해석하지 않는다.
