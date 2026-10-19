# 실제 Flower·Rep4 FMNIST/LeNet5 IID 5라운드 (2026-10-11)

**전체 FMNIST로 실제 Flower + Rep4 MPC 학습 5라운드를 완료했고, 최종 정확도는 86.24%다.** 모든 라운드에서 클라이언트 4명이 통과했다. 기존 `FmnistTrainer`로 독립 재현한 20회 클라이언트 학습의 양자화 업데이트와 MPC 정수 SUM/count, 인증된 공개 모델이 모든 좌표에서 정확히 일치했다.

이전 1라운드 모델에서 추가 5라운드를 이어 학습한 실행이 아니다. 같은 초기 모델과 데이터 분할로 새 세션에서 1~5라운드를 실행했다. 새 실행의 초기 모델·1라운드 모델·평가 지표는 [이전 실제 MPC 1라운드](seed-mpc-lenet5-learning-2026-10-11.md)와 정확히 같았다.

## 설정과 학습량

공식 `flwr run` / Flower Simulation Runtime / Ray, WSL Ubuntu-24.04, branch `work/aion-private-bound-no-wrap`에서 수행했다. Client 4개, 별도 aggregator service/native process 4개와 coordinator를 사용했다. 모델은 전체 LeNet5 61,706파라미터다. 학습 60,000장을 seed 42 IID permutation으로 15,000장씩 나누고 테스트 10,000장 전체를 평가했다. 초기 모델도 Torch seed 42로 새로 초기화했다.

CPU 결정적 학습, 라운드당 로컬 1 epoch, batch 64, SGD lr 0.01/momentum 0.9/weight decay 0.0005를 사용했다. 각 라운드 optimizer는 새로 만들고 `SeedSequence([42, client_slot, round])`로 순서를 고정했다. 기존 reference와 같은 정규화 mean 0.1307/std 0.3081이다. Client당 라운드별 SGD 235회, 전체 **4,700회**이며 학습 샘플 방문은 **300,000회**다.

공개 모델은 float64, 실제 Torch 파라미터는 float32다. Delta는 공개 모델을 float32로 로드한 직후 값과 SGD 후 값의 차이다. `np.rint(delta*10000)`으로 양자화한다. 동일 샘플 수의 통과 client 평균을 적용했다.

정적 정책은 바꾸지 않았다: **S=10000, B=20000, T=2500000000, Q=65536, 최소 통과 2명**, MP-SPDZ 0.4.3 Rep4/64비트 링/32좌표 chunk. 세션 전체에서 compile 1회, client별 seed 입력 1회다. 각 라운드가 같은 비밀 seed shares를 재사용하지만 AES counter/context는 구분한다.

## 라운드별 결과

| 라운드 | 정확도 | Loss | 통과 | 독립 정수 SUM·모델 일치 |
|---|---:|---:|---:|---|
| 초기 | 10.00% | 2.307323 | — | 초기 모델 일치 |
| 1 | 74.84% | 0.679621 | 4/4 | 정확히 일치 |
| 2 | 80.54% | 0.511237 | 4/4 | 정확히 일치 |
| 3 | 83.72% | 0.441775 | 4/4 | 정확히 일치 |
| 4 | 84.99% | 0.408977 | 4/4 | 정확히 일치 |
| 5 | **86.24%** | **0.374406** | 4/4 | 정확히 일치 |

정상 업데이트 제외는 **0/20회**, abort는 0회다. 각 client는 결과 quorum 인증서와 모델 체인을 검증했다. 중복 commit 시험에서 재적용이 없었고, 마지막 client 모델 head가 coordinator와 같았다. Native 4개 process는 사후 CHECK와 정상 종료를 완료했다. 공식 Flower 상태는 `finished:completed`다.

독립 oracle는 새 `train_lenet` 함수를 다시 호출하는 대신 기존 `FmnistTrainer`를 사용한다. 매 라운드 공개 모델을 reference로 두고 offset=0에서 학습하여 float32 로드 기준을 일치시킨다. 20개 양자화 업데이트, 전체 norm/좌표 검사, 5개 정수 SUM/count와 공개 모델, 테스트 지표를 모두 다시 비교했다. Client-local raw audit은 이 로컬 시험 oracle에만 사용하고 Flower/RPC/공개 archive에 전달하지 않았다.

이전 평문 IID 5라운드의 86.37%는 CUDA 실행이다. 이번 CPU 실행과 숫자만 비교해 MPC에 의한 정확도 손실이라고 해석하지 않는다. 이번 실행과 동일한 CPU 입력·학습을 사용한 독립 reference는 모든 모델 좌표에서 오차 0이다.

## carry·wrap 확인 범위

매 좌표의 `y=(u+m) mod Q`를 MPC에서 정확히 마스크 제거하고 signed 복원한다. `2B<Q`가 허용 입력의 유일 복원을 보장한다. Invalid 좌표 sanitize와 전체 client invalid 비트를 유지한 상태로 61,706좌표의 global norm을 계산하고 하나의 비밀 선택 비트를 모든 좌표에 적용한다. SUM을 Q로 다시 줄이지 않는다.

정책 validator는 `DB²=24682400000000<2^45`, `nB=80000`과 비교폭을 확인했다. 이번 5라운드에서 모든 양자화 입력·집계·모델이 reference와 같으므로 carry/wrap으로 인한 값의 왜곡이 없었다. Q보다 큰 합 ±80000, 음수 합 ±40000, 마지막 좌표 위반·global norm 위반·abort는 별도 [전체 차원 합성 회귀](seed-mpc-scale-review-2026-10-11.md)에서 확인한 결과다. 이번 정상 학습 자체가 그런 극단 입력이나 악성 native party 시험을 대신하지 않는다.

## 시간·통신·메모리

| 항목 | 기록값 |
|---|---:|
| ServerApp 자체 wall counter | **1253.902초**, 약 **20분 54초** |
| Compile | 6.520초 / 1회 |
| Native execute + 결과 인증서 합계 | 1066.673초, 라운드 평균 213.335초 |
| Native 전체 party 통신 | **4126.98 MB = 4.12698 GB**, decimal |
| Native process별 최대 RSS 중 최대 | **209520 KiB = 204.61 MiB** |
| Compiler 최대 RSS | 223524 KiB = 218.29 MiB |
| Seed 입력 | client마다 세션 초기에 1회 |

| 라운드 | Upload·manifest(초) | 입력 인증(초) | MPC·결과 인증(초) | Coordinator·committee 적용(초) | Client commit·중복 검사(초) |
|---|---:|---:|---:|---:|---:|
| 1 | 7.625 | 2.891 | 212.098 | 4.993 | 22.411 |
| 2 | 6.285 | 2.918 | 213.444 | 4.960 | 22.117 |
| 3 | 5.983 | 2.883 | 213.989 | 5.012 | 22.156 |
| 4 | 6.000 | 2.803 | 213.519 | 5.086 | 22.140 |
| 5 | 6.057 | 2.732 | 213.623 | 4.986 | 22.113 |

Native execute·결과 인증 구간은 ServerApp counter의 약 85.1%다. 등록·전처리·대기를 포함한 세션 통신이므로 4.13GB를 순수 학습 입력 크기로 부르지 않는다. ServerApp counter와 Flower 상태 elapsed(1142.623163초), GNU time 및 MP-SPDZ 내부 시간은 계층별 측정값이므로 서로 더하거나 같은 시작·종료의 end-to-end 측정으로 해석하지 않는다. 단일 호스트/seed 관측값이며 WAN 처리량을 입증하지 않는다.

별도 [application 내용량](seed-mpc-lenet5-iid-5r-2026-10-11/iid-5r/communication.json):

| 전달 내용, 5라운드 합계 | bytes |
|---|---:|
| Client masked ConfigRecord 내용 | 29,217,583 |
| Aggregator round RPC 요청 JSON | 374,107,796 |
| Aggregator round RPC 응답 JSON | 4,695,708 |
| Client commit ConfigRecord, 중복 전송 시험 포함 | 280,698,664 |
| Public model raw float64 array, train + commit 2회 | 29,618,880 |

내용량에는 framing/TLS/HTTP/Flower protobuf 및 등록·identity·ACK·ready·finish 제어 메시지가 포함되지 않는다. Native 통신과 더해 총 wire 측정값으로 표시하지 않는다. ServerApp의 `masked_application_json_bytes=31069563`는 manifest 범위여서 client별 ConfigRecord 내용 합계와 다르다.

### 초기 셋업과 라운드별 통신 분리의 기록 범위

이번 native 로그에는 등록 완료 및 라운드별 CHECK가 있지만 그 지점의 통신 counter는 없다. **초기 셋업을 뺀 native 라운드별 실측값과 초기 aggregator 내부 셋업 통신은 기존 기록에서 정확히 분리할 수 없다.** 4126.98MB/5=825.396MB는 초기 셋업까지 포함한 평균이며 순수 라운드 실측값이라고 표시하지 않는다.

Native의 ExternalIO client communication counter는 각 aggregator 768bytes, 전체 3072bytes였다. 이 경로는 최초 private key 등록에서만 사용한다. 이는 해당 counter 범위의 입력 통신이며 TLS handshake/framing, 등록 서명/Flower 제어 메시지와 aggregator끼리의 초기 MPC 계산을 포함한 전체 셋업 통신이 아니다. Compile은 로컬 계산이다. 초기 제어 메시지의 총 wire 카운터는 기록하지 않았다.

각 party 로그의 online counter 합은 약 3483.650MB, preprocessing/offline 합은 약 643.3284MB다. 이는 **세션 전체의 연산 phase 분류**다. Preprocessing은 학습 연산용 자원을 계속 생성하므로 이를 모두 일회성 초기 셋업으로 빼지 않는다. Party별 출력값은 반올림되어 global 합계와 미세한 차이가 있을 수 있다.

공개 transcript에서 라운드별 application 내용량은 정확히 재구성했다. 아래 단위는 decimal MB이며 client 4개/aggregator 4개의 합계다. 실제 시험은 모델 commit을 두 번 보내 중복 적용 거부를 검사한다.

| 라운드 | Masked 업로드 | Aggregator RPC 요청·응답 | Client commit, 중복 시험 포함 | 공개 모델 raw array | 내용량 합계 |
|---|---:|---:|---:|---:|---:|
| 1 | 5.844 | 76.082 | 56.674 | 5.924 | 144.523 |
| 2 | 5.844 | 75.801 | 56.203 | 5.924 | 143.772 |
| 3 | 5.843 | 75.747 | 56.120 | 5.924 | 143.634 |
| 4 | 5.843 | 75.623 | 55.911 | 5.924 | 143.302 |
| 5 | 5.843 | 75.550 | 55.790 | 5.924 | 143.108 |

재시도 없는 모델 commit 1회로 환산하면 client commit JSON은 위 값의 절반, 공개 모델 raw array는 3전달(train+commit 2회)에서 2전달(train+commit 1회)로 줄어 3.949184MB/라운드다. 그 경우 application 내용 합은 순서대로 114.211396, 113.695837, 113.599309, 113.371679, 113.238118MB다. 이는 실제 시험에서 중복 검사 전달분만 제거한 환산이며 실제 시험 총량과 구분한다. 초기/종료 제어 메시지와 framing/TLS/HTTP/Flower protobuf는 이 표에도 포함하지 않는다.

[라운드별 분석 JSON](seed-mpc-lenet5-iid-5r-2026-10-11/round-communication.json)에 byte 단위 값을 별도 저장했다. 기존 측정 archive와 source hashes는 변경하지 않았다. Native의 정확한 초기/라운드별 분리를 얻으려면 등록 전후와 매 라운드 CHECK 뒤에 party별 누적 통신 counter를 기록하는 추가 계측 실행이 필요하다.

## 보존·재현

[공개 summary](seed-mpc-lenet5-iid-5r-2026-10-11/summary.json), [검증 결과](seed-mpc-lenet5-iid-5r-2026-10-11/iid-5r/verification.json), [학습된 모델](seed-mpc-lenet5-iid-5r-2026-10-11/iid-5r/model-final.npz)을 저장했다. 모델은 인증된 최종 float64 벡터를 `weights`로 저장하고 다시 로드해 모든 좌표를 비교했다.

Source snapshot, dataset metadata, 정책·provenance, 공개 실행/native 로그 및 checkpoint 등 **51개 보존 파일의 SHA-256**을 확인했다. Seed, signing/TLS private key, SQLite, 비밀 shares, raw client audit을 archive에서 제외했고 실제 private 값의 혼입을 검사했다. 네 Rep4 process가 모두 종료됐음을 확인했다.

검증기 SHA-256은 `2cdaf7435498bd5b27b5459736ea2cc3f67f30798f9f016407279920278ca9b1`, MPC 회로 SHA-256은 `383806e7b8ecd1fbc92a8be57649f0f9c788541e00b3841584ae743a1b3d608b`다. 학습/프로토콜 코드를 변경하지 않고 이전 1라운드에서 통과한 코드로 실행했다.

```bash
source .venv/bin/activate
python -m experiments.run_seed_mpc_flower \
  --mode fmnist-lenet5 --rounds 5 --timeout 1800 \
  --output .cache/seed-mpc-lenet5-iid-5r-new
```

새 경로에서 새 세션을 생성한다. 이 모드는 학습 60,000장 전체를 사용한다. `--phase verify`는 종료된 로컬 실행을 재검증할 수 있지만 이미 소비한 세션에 `run`을 다시 호출하지 않는다.

## 완료 범위

계획 G의 실제 IID 5라운드가 완료됐다. 전체 데이터 학습과 multi-round seed 공유 재사용, 정적 bound, 정수 집계·모델의 정확성을 확인했다. 같은 WSL/UID의 기능 시험이며 독립 운영자 격리, 악성 client·aggregator 공모의 전체 합성 증명, 안전한 share 복구/dropout, 전체 BFT liveness가 완료됐다는 뜻은 아니다. Rep4의 static 최대 1개 악성 aggregator 가정과 허용된 SUM/count의 역추론 가능성은 유지된다.

Norm 안의 악성 업데이트 탐지는 이번 목적이 아니다. Non-IID 실제 MPC 10라운드는 아직 실행하지 않았다. Flower Hub 설정·게시를 수행하지 않았다.
