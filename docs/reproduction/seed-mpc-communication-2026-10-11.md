# Seed-MPC 통신량 분석

측정일: 2026-10-11. WSL Ubuntu-24.04, MP-SPDZ 0.4.3, live MASCOT + active binary mixed computation. Aggregator 4명, client 4명, D=2, 3라운드, AES-128, 16-bit wire, 127-bit prime field.

**11.74 GB는 모델을 전송한 크기가 아니라 aggregator 사이의 MPC 통신이다. 그중 99.96%는 인증된 랜덤 재료를 생성·검증하는 전처리다. 현재 구현에서 가장 많은 통신이 발생한 구간은 모듈러 복원과 좌표 범위 검사였다.** 이 측정은 전체 FMNIST 모델 실행이 아니다.

## 측정 방법과 단위

- [일반 회로 재측정](seed-mpc-communication-2026-10-11.json): 기존 `seed_mpc_session.mpc`에 native `-v` 옵션과 외부 client 메시지 카운터를 적용했다. 기존 회로/primitive의 해시는 유지했다.
- [단계별 계측](seed-mpc-stages-2026-10-11.json): 별도 `seed_mpc_profile.mpc`에 timer 경계를 넣고 같은 연산과 공개 결과를 확인했다. 검사 조건이나 보안 파라미터를 낮추지 않았다.
- [집계 JSON](seed-mpc-communication-analysis-2026-10-11.json), [분석 스크립트](../../experiments/analyze_seed_mpc_communication.py), [원시 로그](seed-mpc-communication-2026-10-11/baseline/P0.log)를 보존했다. 같은 폴더의 baseline/profile에 네 party 로그와 compile 로그가 있다. 입력 키·인증서·share 파일은 복사하지 않았다.

Native의 `Global data sent`는 **네 MPC party가 보낸 바이트를 합산**한다. 수신량을 다시 더하지 않는다. MB=10^6 bytes, GB=10^9 bytes이며 TLS/TCP/IP overhead, 외부 client 통신, 설정 파일 배포를 포함한 NIC 전체 측정이 아니다. Backend의 `BaseMachine.cpp`, `TimerWithComm.cpp`, `Player.cpp`, `Processor.hpp`에서 집계 의미를 확인했다.

외부 client 계측은 ExternalIO 메시지 본문과 4-byte framing을 세며 TLS handshake/record 및 TCP/IP overhead는 제외한다. 방향은 client 기준이다. Native 내부 통신 표와 별도 범위다.

## 무엇을 통신하는가

1. **최초 키 등록:** client는 16-byte seed를 128개의 비밀 bit 입력으로 넣는다. 현재 ExternalIO는 각 bit를 16-byte field element로 다루며 네 aggregator 모두와 통신한다. Aggregator는 인증된 입력용 랜덤 triple의 share를 보내고, client는 랜덤값으로 가려진 입력을 돌려준다. 평문 seed를 보내는 구조가 아니다.
2. **라운드별 masked update:** 설계상 client는 `Y=(u+AES(seed,counter)) mod Q`의 unsigned 16-bit words를 보낸다. **현재 fixture에서는 Y가 확정된 public compile config이므로 이 업로드는 네트워크로 실행되지 않았다.** 실제 서비스의 입력 수신·합의 비용은 이번 결과에 없다.
3. **Aggregator 사이 MPC:** 비밀 AES의 AND 연산, arithmetic/binary 변환, 비밀 비교·곱셈을 수행하기 위한 랜덤 triple/bit/daBit을 생성·인증·검증한다. OT 관련 교환, 랜덤 마스킹된 중간값 opening, MAC 검사 등이 통신을 만든다. 이 데이터는 업데이트나 마스크 벡터를 반복 전송한 것이 아니다.
4. **결과 출력:** 합계·통과 인원·성공/abort 상태만 출력한다. Fixture는 세 라운드 결과를 마지막에 네 test client 모두에게 보내므로 실제 coordinator 하나에 출력하는 정책과도 다르다. 개별 업데이트·seed·norm·통과 비트는 출력하지 않는다.

Triple은 비밀 랜덤값 `(a,b,c=a*b)`로 비밀 곱셈을 돕는 재료다. daBit은 같은 랜덤 bit의 arithmetic share와 binary share를 연결하는 재료다. 이 재료의 share를 생성·검증하는 비용은 단순한 16-byte 입력 크기보다 훨씬 크다. 한 번 사용한 재료를 다른 연산에서 재사용해서는 안 된다.

## 내부 통신: 전처리가 대부분

| 구분 | 네 aggregator의 송신 합계 | 비중 |
|---|---:|---:|
| MPC 전처리 생성·검증 | 11738.79 MB | 99.9599% |
| 전처리 재료를 사용하는 online 연산 | 4.707792 MB | 0.0401% |
| 전체 | 11743.5 MB | 100% |

합계의 마지막 자릿수 차이는 native 로그의 반올림이다. P0 송신은 2939.86 MB, P1/P2/P3는 각각 2934.54 MB다. P0가 더 큰 것은 내부 전달 방식의 차이이며 개인 업데이트가 P0에 공개된다는 뜻이 아니다.

전처리를 입력 도착 전에 실행할 수 있어도 네트워크 비용 자체가 없어지는 것은 아니다. 현재 실행은 live 전처리를 포함한다. 키 share 재사용은 seed 입력을 반복하지 않게 하지만 새 AES/검사 연산의 triple·daBit 재사용을 허용하지 않는다.

## 내부 통신: 어느 실행 구간에서 발생했는가

| 계측 구간 | 네 aggregator 송신 합계 | 전체 비중 |
|---|---:|---:|
| 키 입력·Boolean 검증·A2B, 공통 전처리 생성 포함 | 3178.028 MB | 27.0620% |
| 비밀 AES binary 회로 | 897.899 MB | 7.6459% |
| AES mask word의 B2A 변환 구간 | 0.014976 MB | 0.000128% |
| 모듈러 복원·좌표 범위 검사·invalid sanitation | 6273.480 MB | 53.4209% |
| norm 제곱·정적 threshold·선택 합산 | 929.401 MB | 7.9142% |
| 최소 통과 인원 검사·출력 준비/전송 | 464.649 MB | 3.9566% |

**이 표는 생성 시점을 기준으로 비용을 나눈 것이다. 각 기능의 독립적인 총비용을 뜻하지 않는다.** Backend는 필요한 순간에 전처리 batch를 생성해 이후 연산도 사용한다. 특히 키 등록 구간에서 만든 공통 daBit 재료가 이후 mask B2A 변환에도 쓰인다. 따라서 B2A 전체 비용이 15 KB에 불과하다거나, 키를 재사용하면 다음 실행에서 반드시 3.18 GB가 사라진다는 해석은 틀리다. 출력 구간의 464.65 MB 역시 실제 결과 파일 크기가 아니라 해당 구간의 검사와 전처리 생성까지 포함한 값이다.

Timer는 compiler의 연산 batching 경계를 바꾼다. 일반 회로와 계측 회로의 비라운드 자원 개수는 모두 같았고, 전체 통신 및 offline/online 통신도 로그 정밀도에서 같았다. VM rounds는 1178→1190으로 바뀌었다. 이 표를 다른 dimension/batch 구성의 정확한 단가로 사용하지 않는다.

현재 결과에서는 **AES만을 가장 큰 병목으로 지목할 근거가 없다.** 모듈러 복원과 비밀 범위 검사에 쓰이는 arithmetic 비교와 그 전처리가 우선 검토 대상이다. 이는 이 backend·회로·batch 구성에 대한 판단이며 프로토콜 전체의 불가피한 하한은 아니다.

## 외부 client 통신: 네 client 전체

| 내용 | client→aggregator | aggregator→client | 양방향 합계 |
|---|---:|---:|---:|
| ID와 field specification 메시지 | 80 B | 928 B | 1008 B |
| 최초 seed 등록 | 32832 B | 98368 B | 131200 B |
| 세 라운드 최종 출력 | 0 B | 9280 B | 9280 B |
| 전체 | 32912 B | 108576 B | 141488 B |

한 client의 seed 등록은 업로드 **8208 B**, 다운로드 **24592 B**, 합계 **32800 B**다. 이후 두 라운드에서는 seed를 다시 입력하지 않았다.

현재 방식의 업로드 본문은 `128 bits × 16 B/field element × 4 aggregators = 8192 B`, 4개 메시지 header까지 8208 B다. 다운로드 본문은 입력용 triple의 값 share 3개이므로 `3 × 128 × 16 × 4 = 24576 B`, header까지 24592 B다. 이 계산은 키의 실제 정보량이 16 B라는 사실과 구별해야 한다. 이 외부 triple share 메시지는 native 내부의 인증 share 자료구조 크기와 동일한 형식이라고 가정하지 않았다.

각 client의 최종 결과는 12개의 field 값이다. Active ExternalIO의 triple 검증 경로 때문에 다운로드는 `3 × 12 × 16 × 4 + 16 = 2320 B`다. 네 client 전체 출력 9280 B는 내부 출력 구간의 464.65 MB와 별개의 측정이다.

## 회로 크기와 불필요한 변환

두 실행의 compiler requirement는 동일하다.

| 재료/연산 | 수량 |
|---|---:|
| Arithmetic triples | 23579 |
| Arithmetic random bits | 11049 |
| daBits | 2048 |
| Arithmetic random field values | 536 |
| Binary triples | 76800 |
| Arithmetic simple multiplications | 23067 |

4 clients × 3 rounds × 1 AES block = **12 AES blocks**다. 사용 회로는 block당 binary triple 6400개를 요구해 합계 76800개가 된다. 이 수량은 key schedule을 포함한 현재 회로의 requirement이며 대칭키 AES의 일반 CPU 비용과 다르다.

현재 D=2이지만 `aes_words()`는 block 전체의 8개 16-bit words를 모두 arithmetic share로 변환한다. 실제 필요한 값은 2개뿐이다.

- Key A2B: `4 × 128 = 512` daBits.
- 현재 mask B2A: `12 × 128 = 1536` daBits.
- 필요한 mask B2A: `12 × 2 × 16 = 384` daBits.
- 사용하지 않는 mask 변환: **1152 daBits**, 현재 mask 변환의 75%, 전체 daBit requirement의 56.25%.

이는 회로 비용을 줄일 수 있는 구체적인 지점이다. 다만 전체 통신이 56.25% 줄어든다는 뜻은 아니다. 이 분석에서는 원본을 보존하기 위해 변환 최적화를 적용하지 않았다. 전체 모델에서는 마지막 block의 남는 words만 불필요하므로 같은 비율이 유지되지 않는다.

Backend 종료 시 unused arithmetic triples 421개, arithmetic bits 951개, binary triples 6168개가 남았다. 작은 AES-only fixture에서 보였던 최소 batch 경고를 11.74 GB 전체의 유일한 원인으로 해석해서는 안 된다. 생성된 재료를 검증하는 비용과 실제 회로의 필요량도 크다. Compile 로그에는 현재 `-P` 경로가 일반 `-F` 코드보다 비효율적일 수 있다는 경고와 backend의 edaBit 사용 제안도 있다. 아직 바꿔 측정하지 않았으므로 개선 배수는 제시하지 않는다.

## FMNIST 전체 모델과의 관계

기존 LeNet5는 **61706 parameters**다. Float32 모델 본문은 246824 B이고, 16-bit masked update 본문은 client당 라운드당 **123412 B ≈ 120.5 KiB**다. 네 aggregator 모두에 직접 복제 업로드하면 본문만 493648 B가 된다. 실제 routing/BFT 전달/서명/metadata 비용은 별도다.

현 회로를 그대로 확대하면 client 한 명의 한 라운드에 `ceil(61706/8)=7714` AES blocks, binary triples **49369600개**가 필요하다. 이는 결정적인 회로 수량 계산이지 GB나 실행 시간 예측이 아니다. 이번 2좌표 결과에서 61706좌표 통신량을 선형으로 곱하지 않는다.

현재 구조는 wrap 복원의 산술 검증 단계까지 동작했지만, 이 구현 그대로 전체 FMNIST의 실용적인 성능을 달성했다고 볼 수 없다. 다음 비용 검토에서는 필요한 word만 변환하고, 비밀 range 비교 표현/edaBit 경로 및 4-party f=1 모델에 맞는 backend를 평가하는 것이 타당하다. 보안 가정을 바꾸거나 field 폭을 줄여 속도를 개선했다고 주장해서는 안 된다.

## 재현과 검증

새 output/log directory 경로를 사용한다.

```bash
.venv/bin/python -m experiments.run_seed_mpc_probe \
  --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 \
  --communication-stats --output /tmp/seed-baseline-new.json
.venv/bin/python -m experiments.run_seed_mpc_probe \
  --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 \
  --profile-stages --output /tmp/seed-profile-new.json
.venv/bin/python -m experiments.analyze_seed_mpc_communication \
  --baseline /tmp/seed-baseline-new.json --profile /tmp/seed-profile-new.json \
  --logs-directory /tmp/seed-logs-new --output /tmp/seed-analysis-new.json
```

일반/계측 회로 모두 기대 SUM `(80000,0)`, `(-40000,0)`, 마지막 라운드 abort와 일치했고 모든 native process가 정상 종료했다. 분석 스크립트는 단계 및 phase 합계의 로그 반올림 오차, 두 회로의 자원 수량 일치, daBit 수량 계산을 검사했다. 관련 산술/encoding 검사 18개 통과. Flower/BFT/독립 host/악성 aggregator fault injection은 이번 통신 분석의 범위가 아니다.
