# 실제 Flower·Rep4 FMNIST/LeNet5 IID 1라운드 (2026-10-11)

실제 학습 데이터 60,000장과 테스트 10,000장을 사용해 **61,706파라미터 LeNet5를 공식 Flower와 실제 Rep4 MPC로 1라운드 학습했다.** 테스트 정확도는 **10.00% → 74.84%**, loss는 **2.307323 → 0.679621**였다. 4개 클라이언트 모두 정적 바운더리를 통과했다. 기존 `FmnistTrainer`로 독립 재학습한 양자화 업데이트, MPC 정수 SUM/count 및 인증 후 공개 모델의 모든 좌표가 정확히 일치했다.

앞선 전체 차원 합성 입력 시험과 구분되는 실제 SGD 결과다. IID 5라운드나 non-IID 10라운드는 이번 실행에 포함하지 않았다. 기존 평문 IID 5라운드 86.37%와도 구분한다.

## 실행 설정

| 항목 | 설정 |
|---|---|
| 작업 환경 | WSL Ubuntu-24.04, `work/aion-private-bound-no-wrap` |
| 실행 경로 | 공식 `flwr run` / Flower Simulation Runtime / Ray |
| 역할 | 클라이언트 4개, 별도 aggregator service/native process 4개, coordinator 1개 |
| 모델 | `trustlessfl.fmnist.make_model()` LeNet5, 전체 61,706파라미터 |
| 초기 모델 | Torch seed 42로 초기화, 사전 학습 없음 |
| 데이터 | 해시 검증한 Fashion-MNIST, 학습 60,000장·테스트 10,000장 |
| 분할 | NumPy seed 42 IID permutation, 중복 없는 15,000장씩 4분할 |
| 로컬 학습 | CPU, 1 epoch, batch 64, 클라이언트마다 SGD 235회; 총 940회 |
| SGD | lr 0.01, momentum 0.9, weight decay 0.0005; 라운드마다 새 optimizer |
| 학습 순서 | `SeedSequence([42, client_slot, round])` 기반 결정적 shuffle |
| 정규화 | 기존 reference와 같은 mean 0.1307, std 0.3081 |
| 양자화 | `np.rint(delta * 10000)`, ties-to-even |
| 바운더리 | 정적 좌표 상한 B=20000, norm² threshold T=2500000000, 최소 통과 2명 |
| MPC | MP-SPDZ 0.4.3, Rep4, 64비트 링, wire Q=65536, 32좌표 chunk |
| 키·컴파일 | client별 seed 등록 1회, 회로 compile 1회 |

공개 모델 전달은 float64이고 실제 Torch 파라미터는 float32다. 업데이트는 모델을 float32로 로드한 직후의 값과 SGD 후 값의 차이로 정의한다. Reference도 이 정의를 사용한다. 모든 클라이언트의 샘플 수가 같으므로 통과 업데이트의 단순 평균을 적용했다.

## 검증 결과

공식 Flower 상태는 `finished:completed`다. 다음 항목을 실행 후 검증했다.

- ClientApp은 signed masked 입력만 반환한다. 개별 delta/norm/선택 비트는 Flower reply에 없다.
- 각 client-local 시험 audit의 양자화 업데이트를 기존 `FmnistTrainer`의 별도 CPU 재학습과 61,706좌표 전체에서 정확히 비교했다.
- 순차 정수 reference로 좌표·전체 norm 검사와 selected SUM/count를 계산했다. Native 결과는 SUM 전 좌표와 count=4가 일치했다.
- 입력/결과 quorum 인증서와 parent·모델 hash를 검증했다. 평균 갱신 모델과 테스트 지표를 다시 계산해 정확히 비교했다.
- 각 client가 최종 인증 모델 head를 채택했다. 같은 commit의 두 번째 전송은 모델을 다시 적용하지 않았다.
- Native process 4개가 사후 CHECK와 정상 종료를 완료했다. Seed는 각각 1회만 등록됐다.
- 기존 회귀와 새로운 독립 LeNet5 대조를 포함한 Python 검사 **204개**가 통과했다.

새 학습 경로의 독립 단위 대조는 65장/batch 64로 마지막 불완전 batch도 확인한다. 이 실행의 oracle는 동일한 학습 함수만 다시 호출하는 대신 기존 `FmnistTrainer`를 사용한다. 매 라운드 공개 모델을 reference 파일로 저장하고 offset=0으로 로드하여 float32 로드 기준을 일치시킨다.

## carry·wrap의 의미

이번 경로는 wire에서 carry/wrap이 발생하지 않도록 작은 mask를 쓰는 방식이 아니다. Client는 전체 wire 공간의 single AES mask로 `y=(u+m) mod Q`를 보낸다. MPC가 정확히 `r=(y-m) mod Q`를 계산한 뒤 signed 복원과 바운더리 검사를 수행한다. `2B<Q`이므로 허용된 signed 입력은 유일하게 복원된다.

Invalid 좌표는 norm 연산 전에 sanitize하지만 client 전체 invalid 비트를 유지한다. 전체 61,706좌표의 norm 판정을 끝낸 뒤 하나의 비밀 선택 비트를 모든 좌표에 적용한다. SUM은 Q로 줄이지 않고 넓은 64비트 링에서 계산한다. `DB²=24682400000000<2^45`, `nB=80000` 및 비교폭을 정책 validator로 확인한다.

실제 학습의 정확한 정수 SUM 대조는 이 경로가 학습 업데이트를 변형하지 않았다는 증거다. Q보다 큰 합 ±80000 및 음수 합 ±40000, 범위/norm 위반과 abort는 별도의 [전체 차원 합성 검증](seed-mpc-scale-review-2026-10-11.md)에서 확인했다. 단일 정상 학습 결과만으로 모든 wrap 경계와 악성 입력 보안을 증명한 것으로 해석하지 않는다.

## 비용

| 측정 항목 | 기록값 |
|---|---:|
| ServerApp 자체 wall counter | 256.587초, 약 4분 17초 |
| Compile | 6.300초 / 1회 |
| Masked upload + manifest | 7.594초 |
| 입력 인증서 | 2.845초 |
| Native execute + 결과 인증서 | 213.060초 |
| Coordinator + committee 적용 | 5.057초 |
| Client commit + 중복 적용 검사 | 22.394초 |
| Native 전체 party 통신 | 825.968 MB, decimal |
| Native process별 최대 RSS 중 최대 | 73,232 KiB = 71.52 MiB |
| Compiler 최대 RSS | 223,520 KiB = 218.28 MiB |

실행·결과 인증 구간은 ServerApp counter의 약 83%다. ServerApp counter, Flower 상태 elapsed(236.374532초), GNU time 및 MP-SPDZ 내부 시간은 각 계층이 보고하는 별도 측정값이며 서로 더하거나 같은 시작·종료의 end-to-end 시간으로 취급하지 않는다. 단일 호스트·단일 실행 관측값이므로 WAN 성능이나 엄밀한 speedup 측정으로 확대하지 않는다. 등록·전처리·대기가 native 세션 측정에 들어가므로 825.968 MB를 순수 온라인 학습 payload라고 부르지 않는다.

Native 로그의 약 1,005,917 communication rounds는 backend 왕복 횟수의 근사치이며 FL 학습 1라운드와 다른 개념이다. 전체 차원 합성 시험의 3라운드 통신 2476.15 MB와 비슷한 라운드당 비용이다. 실제 학습이 가능해졌지만 MPC 및 반복 인증 전달의 비용 개선은 필요하다.

별도 [application 내용량](seed-mpc-lenet5-learning-2026-10-11/iid-1r/communication.json)은 다음과 같다. Framing/TLS/HTTP/Flower protobuf 및 등록·identity·ACK·ready·finish 제어 메시지는 포함하지 않는다. 위 native 통신과 합쳐 전체 네트워크 측정값이라고 표시하지 않는다.

| 전달 내용 | bytes |
|---|---:|
| Client masked ConfigRecord 내용 | 5,843,689 |
| Aggregator round RPC 요청 JSON | 75,090,160 |
| Aggregator round RPC 응답 JSON | 992,448 |
| Client commit ConfigRecord, 중복 전송 시험 포함 | 56,674,176 |
| Public model raw float64 array, train + commit 2회 | 5,923,776 |

ServerApp의 `masked_application_json_bytes=6214085`는 전체 manifest 직렬화 크기이며 client별 ConfigRecord 내용 합계와 측정 범위가 다르다.

## 보존 기록과 재현

[공개 summary](seed-mpc-lenet5-learning-2026-10-11/summary.json)와 [검증 결과](seed-mpc-lenet5-learning-2026-10-11/iid-1r/verification.json)에 결과를 보존했다. 공개 archive에는 실행·native 로그, 정책, dataset metadata, source snapshot 및 SHA-256이 포함된다. Client-local raw audit, seed, signing/TLS private key, SQLite 및 비밀 share는 제외했고 실제 시험 private 값이 공개 파일에 들어 있지 않은지 검사했다. Audit은 로컬 correctness oracle의 시험 전용 입력이며 실제 coordinator/API 입력이 아니다.

[학습된 공개 모델](seed-mpc-lenet5-learning-2026-10-11/iid-1r/model-final.npz)은 인증된 최종 모델에서 직접 저장한 `weights` float64 벡터다. 저장 후 전체 좌표를 결과 기록과 비교했다. 모델을 포함한 보존 파일 **51개**의 SHA-256을 확인했고 네 Rep4 process가 모두 종료됐음을 확인했다.

검증기 SHA-256은 `2cdaf7435498bd5b27b5459736ea2cc3f67f30798f9f016407279920278ca9b1`, MPC 회로 SHA-256은 `383806e7b8ecd1fbc92a8be57649f0f9c788541e00b3841584ae743a1b3d608b`다. Versions와 전체 source hashes는 archive의 `provenance.json`에 있다.

```bash
source .venv/bin/activate
python -m experiments.run_seed_mpc_flower \
  --mode fmnist-lenet5 --rounds 1 --timeout 1800 \
  --output .cache/seed-mpc-lenet5-new-run
```

이 모드는 `--rows-per-client`와 무관하게 학습 60,000장 전체를 사용한다. 준비, 실행, 검증은 `--phase prepare/run/verify`로 분리할 수 있다. 비밀 실행 상태의 안전한 복구를 제공하지 않으므로 이미 실행한 세션에 `run`을 재호출하지 않는다. 새 경로로 새 세션을 만든다. Hub 설정·게시를 수행하지 않았다.

## 해석 범위와 다음 단계

이 시험은 같은 WSL/Unix UID에서 이루어졌다. 독립 운영자 격리나 production 배치를 입증하지 않는다. Rep4의 static 최대 1개 악성 aggregator 가정, 2개 aggregator 공모의 seed 복원 위험, 허용된 SUM/count의 역추론 가능성은 그대로다. 등록부터 결과까지 악성 client·aggregator를 함께 다루는 전체 합성 증명, 안전한 share 복구, dropout, 전체 BFT liveness는 미완료다. Norm 안의 악성 업데이트를 탐지하는 연구는 이번 목적에 포함하지 않는다.

계획 단계 G의 **IID 전체 데이터 1라운드**가 완료됐다. 다음 검증은 같은 계약의 IID 5라운드이며, 학습이 진행될 때의 정확한 모델 일치와 seed 세션 재사용을 함께 확인한다. 이번 실행이 이를 대신하지 않는다.
