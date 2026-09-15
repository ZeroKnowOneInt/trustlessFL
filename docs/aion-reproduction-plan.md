# AION 논문 실험 재현 계획

작성일: 2026-09-12. 업데이트: 2026-09-13. 상태: **P1 실제 FMNIST 공격/MGF 2라운드 pilot 완료**.
공식 checkpoint 정확도 88.56%와 avg/AION 필터 대조를 확인했다.
60라운드 논문 결과 재현은 아직 미완료이며, 현재 단계 판정은
[pilot 보고서](./experiments/fmnist-artifact-pilot-2026-09-13/report.md)와 [원본 감사](./reproduction/source-audit.md)를 따른다.
본 문서는 기존 MNIST 실험을 논문 재현으로 인정하지 않고, 원 실험과 비교 가능한
증거를 확보하기 위한 실행 순서와 판정 기준을 정의한다.

## 1. 목표와 범위

대상은 *Aion: Robust and Efficient Multi-Round Single-Mask Secure Aggregation
Against Malicious Participants*, USENIX Security 2025의 §7 및 부록 B·F다.
근거는 저장소의 [논문 PDF](./AION.pdf), [공식 출판 페이지](https://www.usenix.org/conference/usenixsecurity25/presentation/liu-yizhong),
[공식 artifact](https://zenodo.org/records/15870338)다.
로컬 PDF SHA-256은 `13bf563b9103ae1876fbb0828727357186b3eddf717268186d5adf20ae268b21`이다.

재현 작업을 다음 세 경로로 구분한다.

| 경로 | 목적 | 결과를 해석하는 범위 |
|---|---|---|
| A. 공식 artifact | 원 코드·설정·측정 방식으로 원 논문의 결과 확인 | 원 실험의 재실행 결과. 코드와 논문의 차이도 함께 기록 |
| B. Flower 이식 | A와 동일 입력·설정·프로토콜 의미를 Flower에서 실행 | 동작 동등성 및 이식으로 발생한 비용 측정 |
| C. 실제 silo 배포 | TLS·outbound-only·지연·단절 환경 검증 | 별도의 배포 검증. 논문 실험과 혼합하지 않음 |

사용자가 승인한 **Flower 서버 1개 + 학습 참여자와 별개인 여러 aggregator** 구성을 유지한다.
악의적 서버·client를 고려하며 aggregator는 `n >= 3f+1`의 임계치를 적용한다.
논문 대조군 ELSA의 2-server 구조는 해당 비교 실험의 구조일 뿐 AION의 서버 수 변경이 아니다.
동일 OS 사용자의 여러 프로세스는 독립된 운영·보안 경계라고 주장하지 않는다.

**첫 완료 목표:** 공식 artifact의 FMNIST/LeNet5 정상 학습과 poisoning 평가를 재실행하고,
같은 조건에서 Flower 결과를 대조한다. 이후 규모별 성능, 나머지 데이터셋, privacy 평가로 확장한다.
첫 목표 완료를 논문의 모든 실험 재현 완료로 표시하지 않는다.

## 2. 현재 출발점

- [기존 MNIST 실험](./experiments/mnist-2026-09-12/report.md)은 손글씨 MNIST / softmax,
  client 4개 / aggregator 4개 / 20라운드다. 논문의 FMNIST / LeNet5 실험과 다르다.
- 기존 결과의 일반 fixed-point 집계 대비 모델 오차 0은 수치 회귀 테스트로 유지한다.
- HPRF는 연구용 rounded-linear 대체 구현이다. 원 구현과 동등하거나 보안 정리를 만족한다고 가정하지 않는다.
- MGF는 단독 수치 모듈이고 실제 집계 경로에 연결되지 않았다.
- AMR, CCS/VRF, 완전한 BFT view-change, EMA는 미구현이다.
- fixed-cohort ASR은 client를 제외하면 abort한다. MGF와 동적 유효 집합을 바로 연결할 수 없다.
- 기존 통신량은 모델·인증서를 포함한 JSON 전체다. 논문의 모델 전송 제외 지표와 다르다.

구현 상세는 [현재 구현 현황](./aion-flower-implementation.md)을 따른다.
기존 실험 코드와 원시 결과를 덮어쓰거나 재현 결과로 이름만 바꾸지 않는다.

## 3. 논문 실험별 재현 매트릭스

아래 수치는 **논문에 보고된 목표/조건**이며 아직 측정한 재현 결과가 아니다.
표의 쪽수는 표지 포함 PDF 기준이며, 정확한 설정은 P0에서 실험별로 고정한다.

| ID / 우선순위 | 논문 위치 | 조건과 비교 대상 | 재현 산출물 |
|---|---|---|---|
| E1 / 우선 | Table 3, 부록 B, PDF 17–18쪽 | FMNIST/LeNet5 약 61k, q=256, n=8, 44 rounds. AION·Flamingo·ACORN·SecAgg+·SecAgg | 정상 학습곡선, client/aggregator별 비용, end-to-end 비용. AION 보고값 15.56 s/round, 추가 통신 0.60 MB |
| E2 / 우선 | §7.2, Figures 4–9, PDF 12–14쪽 | FMNIST와 CIFAR10, 60 rounds, round별 공격 확률 50%. FedAvg·Flame·ACORN·AION 및 NoDefense | poison ratio·boost rate·mask ratio별 공격 성공률과 test error, MGF 제거 실험 |
| E3 / 핵심 | §7.1, Figures 2–3, PDF 12쪽 | d=10K, VSS modulus 2048 bits. q={128,256,512,1024}, n=8; q=512, n={8,16,32,64} | 초기화/집계 시간 및 추가 통신 곡선; AION·Flamingo·ACORN·SecAgg+ 비교 |
| E4 / 핵심 | §7.3, Table 2, PDF 14쪽 | q={1024,2048,4096}, n=8. ASR/AMR × IV 유무, Flamingo | 역할별 시간·통신. q=4096에서 aggregator 집계 75.02 ms 대 42359.10 ms, 약 563.64배라는 보고값 검증 |
| E5 / 확장 | Table 3, PDF 18쪽 | q=256, n=8. Shakespeare/LSTM 818k·23 rounds, CIFAR10/ResNet18 2797k·173 rounds, EMNIST-Byclass/ResNet9 6700k·34 rounds | 모델 크기별 학습 및 end-to-end 비교. 이름만 같은 표준 모델로 임의 교체 금지 |
| E6 / 확장 | Figure 11 / Table 4, PDF 17·19쪽 | q=4096, n=8, 1000 rounds | 누적 비용과 mask creation/reconstruction 분리. Figure 11 AION 188.05 s·928.59 MB; Table 4와 서로 다른 측정 범위 유지 |
| E7 / 확장 | Figures 12–14, PDF 18–19쪽 | 단계 분석 q=1024,n=8; modulus={2048,3072,4096}와 네트워크 실험 q=256,n=8 | 단계별 비용; bandwidth={1,5,10,50,100} Mbps, delay={10,100,500} ms. 비변경 축의 기본값·지연 의미 확인 필수 |
| E8 / 확장 | Table 5, PDF 19쪽 | FMNIST, q=256; AION/Mario n=8 및 ELSA 2 servers | 서로 다른 SA 계열의 비용 비교. ELSA/Mario를 다른 알고리즘으로 대체하지 않음 |
| E9 / 확장 | Figure 15, PDF 19쪽 | EMNIST-Byclass/ResNet9, poison ratio sweep | 공격 성공률. 본문은 poison ratio 50% 미만에서 2.6% 미만을 보고 |
| E10 / 확장 | 부록 F / Figure 16, PDF 21쪽 | gradient inversion, private labels와 BN statistics를 공격자가 앎, beta=10%, rounds 20·48 | 원 이미지·복원 이미지 및 재현 가능한 공격 설정. 이미지가 흐리다는 사실을 암호학적 privacy 증명으로 해석하지 않음 |

E2의 Figure 4·5는 해당 공격 설정에서 최대 50% 악성 client에 대해 공격 성공률 0을 보고한다.
이는 모든 poisoning 공격이나 임계치 내 임의의 악성 입력에 대한 일반 보장이 아니다.
프로토콜의 **ASR(aggregated secret reconstruction)**과 지표의 **ASR(attack success rate)**를
코드·결과에서 각각 `asr_reconstruction`, `attack_success_rate`로 구분한다.

## 4. P0 — 원 설정 확보와 불명확한 사항 해결

구현·장시간 실행 전에 다음 작업으로 실험 명세를 동결한다.

1. 공식 artifact 전체 archive의 버전·checksum·라이선스·의존성·실행 entrypoint를 기록한다.
   기존 일부 코드 검토나 range-download 조각은 전체 artifact 검증을 대신하지 않는다.
   다운로드한 코드는 먼저 검토하고 격리된 환경에서 실행한다. 기존 개발 환경을 덮어쓰지 않는다.
2. 표·그림마다 생성 script, configuration, raw data, plotting script를 대응시킨다.
   원시 그래프 데이터가 없으면 PDF digitization 여부와 오차를 명시한다.
3. 논문, artifact, Flower 설정의 차이를 `paper / artifact / port / evidence / resolution`으로 기록한다.
   artifact와 논문이 다르면 둘을 몰래 혼합하지 않고 각각의 조건을 별도 실행한다.
4. 다음 미확정 항목을 해소한다. 확인되지 않으면 `unknown`으로 남기고 그 실험의 엄밀 재현을 보류한다.

| 확인 대상 | 구체적으로 필요한 정보 |
|---|---|
| 데이터 | 정확한 버전·checksum, train/validation/test split, IID/non-IID 방식, shard 인덱스, N과 round별 q, sampling 방식 |
| 학습 | LeNet5/ResNet/LSTM 레이어·parameter count·buffer, 초기화, optimizer, local epochs, batch, learning rate/schedule, seed, checkpoint, 종료 조건 |
| 집계 | gradient/model/delta 중 무엇을 집계하는지, sum/mean, sample weighting, local data가 없는 client, 탈락 후 분모 |
| 숫자 표현 | dtype, decimal precision, field/key/output 공간, HPRF approximation error, rounding 및 overflow 규칙 |
| MGF | 초기 bound와 첫 두 round bootstrap, zero-gradient/zero-denominator, h_max, alpha·beta 적용 순서, update sum/mean 단위 |
| 공격 | 목표 class/trigger/label 조작 여부, gradient 증폭 정의, 공격 대상 선정·실행 시점, 공격 성공 판정과 분모, sweep 외 축의 기본값 |
| 분산·측정 | f와 threshold, BFT 구현, client 실행 병렬도, GPU 사용 방식, transport/simulation, 시간의 합/최댓값/평균, 통신의 send/receive 집계 방식 |

특히 다음 사항은 이미 확인된 해결 과제다.

- **mask ratio 불일치:** §5는 실험에서 beta=0.2라고 설명하지만 §7.2 기본 설정은 이전 global update의
  10% 미만 제약을 기술한다. Figure별 artifact 값과 코드 적용 의미를 확인하고 임의로 하나를 선택하지 않는다.
- **모델 크기 불일치:** EMNIST 모델은 Table 3에서 6700k, Figure 15 설명에서 trainable 6.598M으로
  기술된다. 반올림·buffer·모델 변형 여부를 확인한다. ResNet18도 Table 3의 2797k에 맞는 실제 구조를 확인한다.
- **분할/가중치:** FMNIST 60,000개를 q=256으로 균등하게 나눌 수 없다. 누락·복제하거나 기존 동일 가중치를
  그대로 적용하지 말고 artifact의 배정·가중치 정책을 따른다.
- **공격 정의:** gradient 증폭만 구현한 뒤 임의의 오분류 비율을 공격 성공률이라고 부르지 않는다.
  원 공격의 target과 성공 판정이 확인되지 않으면 TER만으로 Figure 4–9 재현을 선언하지 않는다.

현재 계획 작성 시 Zenodo 페이지 조회는 HTTP 429로 실패했다. 이는 archive가 없다는 뜻이 아니다.
P0에서 재시도하고, 확보가 계속 안 되면 공식 출처의 대체 배포나 사용자 제공 archive가 필요하다.
불명확한 설정에 대한 저자 문의·외부 연락은 사용자 승인 후 진행한다.

**P0 산출물(예정):** `docs/reproduction/source-audit.md`, `configs/reproduction/*.json`,
원본 의존성 lock, 데이터 manifest, paper target CSV.
**통과 조건:** 첫 목표 E1·E2의 입력·실행·지표를 추측 없이 재구성할 수 있음.

## 5. 실행 단계와 통과 조건

### P1 — 공식 artifact 기준선 실행 (경로 A)

- 원 코드의 암호·수치 테스트와 작은 정상 실험부터 실행한다. 수정이 필요하면 원본과 patch를 모두 보존한다.
- FMNIST/LeNet5의 일반 학습과 AION 학습을 동일 초기화·partition·batch 순서로 비교한다.
- E1의 원 설정으로 확대하고, E2는 원 공격·방어 코드로 먼저 재실행한다.
- 성능 측정에 학습이 실제 실행되는지, 비용이 시뮬레이션/추정치인지 확인해 구분한다.
- 그림 생성 코드가 실제 raw run에서 수치를 계산하는지 확인한다. 상수 배열을 그린 그림은 재실행 증거가 아니다.

**통과 조건:** 저장된 로그·실행 설정·모델·지표로 결과를 독립 재계산할 수 있음.
원 결과와 다르면 먼저 원 경로의 차이를 진단하고 Flower 결과로 덮지 않는다.

### P2 — Flower 수치·프로토콜 동등성 확보 (경로 B)

기존 연구 경로를 보존하고 명시적인 새 backend/config로 추가한다.

1. 원 HPRF/VSS와 DMC·DMR에 대한 고정 입력 test vector를 확보하고 이식 코드와 대조한다.
   보안 가정을 검증하지 않은 artifact 코드가 실행된다는 이유로 secure LWE-HPRF라 부르지 않는다.
2. FMNIST/LeNet5 trainer를 node-local 설정으로 연결한다. sample weighting 및 tensor/buffer 직렬화를 명세한다.
3. 동일 local update를 양쪽 집계기에 넣는 수치 대조와, 각자 학습까지 수행하는 end-to-end 대조를 분리한다.
4. client 집합·모델의 인증, share 검증, retry lock을 유지한다. 원 실험에서 쓰는 BFT/인증 비용과
   현재 개별 서명 certificate 비용을 분리한다. mock consensus 비용을 실제 BFT 비용으로 보고하지 않는다.
5. 4 clients로 smoke test 후 q=256,n=8로 확대한다. 축소 조건은 논문 규모 재현으로 표시하지 않는다.

**통과 조건:** mask 제거 결과가 승인된 입력의 clear 집계와 명세된 수치 오차 내에서 일치하고,
local training·집계·model broadcast를 포함한 정상 실행이 검증됨. 내부 exact fixed-point 비교는 오차 0을 요구한다.
CPU/GPU 학습 차이는 별도의 사전 정의한 dtype별 허용 오차로 평가한다.

### P3 — 유효 참여 집합과 MGF 통합

**MGF를 켜기 전에 집합 변경 시 privacy 문제를 해결한다.**
현재 fixed-cohort ASR에서 필터로 일부 client만 제외해 여러 subset의 secret 합을 공개하면
차분을 통한 개인 secret 추론 위험이 생긴다. 기존 abort 조건을 단순 제거해서는 안 된다.

- ASR+CCS 경로: 원 sortition과 참여 정책을 재현하고, MGF·dropout으로 생기는 추가 subset 공개까지 분석한다.
  CCS가 있다는 이유만으로 모든 필터링 집합이 안전하다고 가정하지 않는다.
- AMR 경로: 반복 참여·유효 집합 변경에 대해 aggregated secret을 공개하지 않는 복원과
  악성 HPRF share 검증을 구현한다. 원 ASR 실험을 AMR로 대체하면 별도 변형 실험으로 표시한다.
- 양쪽 경로의 client identity, round, committed valid set, share 집합과 mask 합이 일치해야 한다.
  최소 정직 client 수의 보안 가정과 최소 집계 인원 정책을 구분한다.
- Algorithm 6의 alpha, mask scaling, bound evolution, bootstrap, 필터 시점과 unmask를 연결한다.
  현재 modular residue에 L2 norm을 그대로 적용하지 않는다. signed/real 표현과 DMC·DMR의 결합을 먼저 명세한다.
- 다른 aggregator도 같은 입력에 대해 같은 valid set을 산출해야 한다. 경계값·반올림·재시도·전원 제외를 테스트한다.
- masked 값 외에 plaintext delta, client secret, 공격자 표시를 실제 필터에 전달하지 않는다.
  oracle/clear 필터는 평가 대조군에서만 허용하고 보안 경로와 분리한다.

**통과 조건:** 정직 update 오탐률과 악성 update 통과율을 기록할 수 있고, 필터 뒤 집계가
선택된 입력의 clear 집계와 일치하며, 선택된 membership 경로의 privacy 전제가 명시됨.
이 조건이 해결되지 않으면 standalone MGF 재실행만 보고하고 end-to-end 보안 재현으로 분류하지 않는다.

### P4 — 입력 검증 결과 재현 (E2 우선)

- FMNIST부터, 이후 CIFAR10으로 확장한다. client 수·분포·학습 설정은 E2의 artifact를 따른다.
  Table 3의 q=256을 공격 실험의 미확정 설정에 자동 적용하지 않는다.
- 60 rounds와 50% round별 공격 확률을 고정한다. 동일 seed의 공격 일정·악성 client·batch 순서를 모든 방어에 공유한다.
- poison ratio 0.05–0.50, mask ratio 0.05–0.50 및 boost sweep을 그림/원 raw config에 맞춘다.
  boost의 본문 범위 1.25–12.5에서 실제 샘플 지점은 artifact로 확인한다.
- FedAvg, NoDefense, Flame, ACORN 및 AION을 비교한다. ACORN의 plain clipping만 구현한 결과를
  ZK 포함 ACORN 프로토콜의 비용으로 보고하지 않는다.
- 공격 성공률·TER 외에 clean accuracy, 악성 입력 통과율, 정직 입력 오탐률, 유효 집합 크기,
  완료 라운드, abort 사유를 기록한다. 공격이 없었던 round나 중단된 run을 성공률 0으로 처리하지 않는다.
- Figure 7·9를 먼저 완료한 뒤 Figure 5 및 CIFAR10의 Figure 4·6·8로 확장한다.

**통과 조건:** 정상 학습 성능을 유지하면서 원 공격 조건에서 각 그림의 주장과 비교할 수 있는
전체 곡선·원시 분모·불확실성 범위를 확보함. 공격 성공 사례가 나오면 숨기지 않고 해당 조건을 미재현으로 표시한다.

### P5 — 성능·확장성 재현 (E3·E4, 이후 E5–E9)

- client/aggregator 수를 논문 축에 맞추며 `N`, `q`, `n`, `f`, 실제 동시 실행 수를 별도 기록한다.
- 논문 backend와 Flower backend를 각각 측정한다. 논리 client 4096개를 OS 프로세스 4096개로
  강제 생성하지 않는다. 원 실행 모델을 먼저 확인하고 batching/worker pool 변경은 명시한다.
- 비교 알고리즘을 같은 host·동일 workload·동일 실행 모형에서 측정한다.
- 초기화는 독립적으로, round 집계는 local training과 분리해 측정한다. 전체 학습 wall time도 별도 보존한다.
- 단계별 protocol overhead, model data bytes, transport framing/TLS bytes를 분리한다.
  논문의 모델 제외 지표와 실제 운영 전체 트래픽을 모두 보고하되 섞지 않는다.
- aggregator의 send/receive 중복 계수, broadcast fan-out, certificate 크기, 재전송을 명세한다.
  현재 서버 중계의 전체 복제 비용을 논문의 collect-aggregate-transfer 복잡도와 동일시하지 않는다.
- 563.64배는 동일 역할·동일 집계 단계의 `Flamingo / AION`으로 계산한다.
  client 비용, end-to-end 비용, 전 round 누적 비용과 혼합하지 않는다.
- Figure 14는 원 코드의 네트워크 모델을 확인한 후 별도 namespace/container에서 조건을 적용한다.
  host 전체 네트워크 정책을 바꾸거나 permission 없이 cloud 인프라를 만들지 않는다.

**통과 조건:** 비교 대상별 raw timing/bytes와 측정 경계를 감사할 수 있고,
hardware-normalized 결과와 논문 절대값 일치 여부를 서로 다른 판정으로 보고함.

### P6 — privacy 및 실제 silo 검증

- E10은 원 공격 optimizer·iteration·초기화·이미지·batch·checkpoint를 고정하여
  unmasked와 masked 입력을 같은 조건에서 비교한다. 정성 이미지 외 지표 추가 시 확장 지표라고 표시한다.
- 악성 share, equivocation, model inconsistency, replay, subset 차분, 최대 f개 실패를 별도로 검사한다.
  abort는 safety 증거일 수 있으나 BFT liveness의 재현을 뜻하지 않는다.
- EMA를 재현하려면 늦은 update의 원 round binding, 최소 집계 인원, 중복 사용 방지와
  ASR/AMR 집합 privacy를 함께 검증한다. 논문에 정량 target이 없으면 구현 검증으로 분류한다.
- 경로 C에서는 실제 Flower SuperLink/SuperNode와 TLS, outbound-only client 정책,
  독립 identity/저장소/운영 권한을 검증한다. 중앙 relay 차단 시 가용성 한계를 명시한다.

**통과 조건:** 주장한 공격 모델과 네트워크 조건에서 검증 증거 확보.
GIA 실패나 통계 테스트 통과를 formal privacy 증명으로 바꾸지 않는다.

## 6. 측정·반복·성공 판정 정책

다음은 **이 프로젝트가 제안하는 검증 정책**이지 논문에 명시된 반복 수나 허용 오차가 아니다.
P0에서 원 정책을 찾으면 원 재실행과 추가 반복 검증을 구분한다.

- ML·공격 실험: 서로 다른 seed 최소 5회. 분할·초기화·공격 seed를 독립적으로 기록하며
  비교 방법 사이에는 paired seed를 사용한다. test set으로 bound나 optimizer를 튜닝하지 않는다.
- microbenchmark: setup 비용 별도 기록, 측정 제외 warm-up 3회 후 독립 측정 최소 10회.
  중앙값·IQR·p95와 표본 수를 보존한다. 긴 1000-round 실험은 pilot 후 반복 횟수를 사전 결정하고 단회 한계를 표시한다.
- 공격 성공률은 성공/평가 대상 건수를 함께 저장한다. 같은 run 내 상관을 고려하여
  run별 값과 run 단위 bootstrap 95% CI를 보고한다. 관측 0%를 실제 공격 확률 0의 증명으로 표현하지 않는다.
- 절대 실행 시간은 논문 하드웨어·software stack·실행 모형을 맞춘 경우에만 직접 비교한다.
  다른 장비에서는 실제 절대값과 같은 장비 내 speedup/추세를 보고하고 절대값 재현은 미검증으로 남긴다.
- 모델 accuracy/TER/ASR의 비교 허용 범위는 P0의 원 raw data 분산과 PDF 판독 오차로
  결과를 보기 전에 정의한다. 근거 없는 고정 ±1%p나 임의의 목표 정확도를 설정하지 않는다.
- raw data가 없으면 논문에 명시된 정량 주장만 판정하고, 그래프와의 대략적 시각 일치를 정확 재현으로 부르지 않는다.

각 E1–E10 결과에 다음 중 하나를 붙인다.

| 판정 | 의미 |
|---|---|
| 재현 | 사전 고정한 동등 조건과 해당 지표 기준을 충족함. 어느 경로·어느 표/그림인지 명시 |
| 부분 재현 | 일부 조건/곡선/동작만 일치하거나, 다른 하드웨어에서 상대 추세만 확인 |
| 미재현 | 유효한 대조 실험을 완료했으나 사전 기준을 충족하지 못함 |
| 미검증 | 미실행, 설정 미확정, 자원 부족, protocol 선행 조건 미충족 |

**전체 완료:** E1–E10의 적용 가능한 모든 항목에 판정·근거가 있고 미실행 항목이 숨겨지지 않아야 한다.
모든 항목이 ‘재현’으로 판정되지 않았다면 “논문 전체 재현 성공”이라고 요약하지 않는다.

## 7. 자원과 위험 관리

논문 환경은 RTX4090 / i9-14900KF다(§7). 현재 확인한 실행 환경은 WSL2,
Ryzen 5 9600X, 논리 CPU 12개, 메모리 약 7.3 GiB다.
`nvidia-smi`는 OS의 GPU 접근 차단 메시지로 실패했으므로 **GPU 종류·사용 가능 여부는 미확인**이다.
물리 GPU가 없다고 단정하지 않는다. 본 계획에서는 추가 설치·GPU 설정 변경·장시간 학습을 수행하지 않았다.

- P0 뒤 CPU FMNIST 소규모 pilot으로 peak RAM, GPU 사용 가능 여부, wall time, 출력량을 측정한다.
- 각 대규모 sweep의 비용과 중단 기준을 pilot 결과로 정한다. 현재 단계에서 근거 없는 소요 시간은 약속하지 않는다.
- RAM/VRAM을 넘는 모델·대규모 client 실행을 무리하게 시작하지 않는다.
  정밀도를 낮추거나 dataset을 줄인 대체 실행은 별도의 축소 실험으로 표시한다.
- dependency는 별도 환경에 pin한다. GPU driver 변경, 외부 서버·유료 자원 사용, 대규모 실행은 필요한 승인을 받은 후 진행한다.
- 임계치·mask 표현·subset privacy가 미해결이면 관련 보안 실험만 보류하고 원 설정 확인이나 독립 수치 테스트는 계속할 수 있다.
- 공식 코드가 실행 불가하거나 논문 수치와 다르면 실패 로그와 최소 재현 조건을 남긴다.
  결과에 맞추려고 undocumented shortcut이나 보안 검사 생략을 도입하지 않는다.

## 8. 예정 산출물과 실행 순서

아래 경로는 **구현 예정**이며 현재 존재하거나 실행 가능하다는 뜻이 아니다.

```text
configs/reproduction/           # 표·그림별 동결 설정
experiments/reproduction/       # 공식 adapter, Flower adapter, 측정·그림 생성
tests/reproduction/             # 교차 backend test vectors, membership/MGF 검증
docs/reproduction/
  source-audit.md               # 논문·artifact·이식 차이 및 근거
  experiment-manifest.md        # command/config/seed/환경/측정 범위
  results/<run-id>/             # 불변 raw JSON/CSV, 지표, 공개 데이터 모델
  report.md                    # E1–E10 판정과 미해결 항목
```

run별 필수 기록: git revision 및 dirty source hash, artifact hash, dependency lock,
dataset/partition hash, 모든 seed, backend, model parameter count, q/n/f와 valid client 수,
실행 command, stage timing, 분리된 bytes, CPU/GPU/RAM, stdout/stderr, 완료/중단 사유.
학습한 공개 데이터 모델은 보존 가능하지만 identity private key, VSS share, client별
plaintext/masked update는 기본 결과 로그에 기록하지 않는다. test vector는 공개 fixture만 사용한다.
실험 실패도 보존하고 출력 디렉터리는 덮어쓰지 않는다.

의존 순서는 다음과 같다.

```text
P0 원 설정 동결
 ├─ P1 공식 artifact 정상·공격 기준선
 └─ P2 Flower 수치·정상 학습 동등성
      └─ P3 membership privacy + MGF
           └─ P4 poisoning 곡선 대조

P1 + 해당 Flower 기능 준비 → P5 규모·비용·추가 데이터셋
membership/인증/복원 검증 → P6 privacy·EMA·실제 silo 배포
```

2026-09-13 기준 즉시 실행할 다음 작업은 **P1의 공식 FMNIST avg/AION 60라운드 기준선**이다.
원본 확보·설정 매핑·2라운드 pilot은 완료했으며, 이후 정상-only 대조와 Flower 수치 경로를 준비한다.
설정·membership 문제가 해결되기 전에 CNN 학습 정확도만 올리는 작업은 재현 완료를 앞당기지 않는다.
