# Crowdsensing Endpoint Security: 현재 AION 기준선 실험 계획

작성일: 2026-09-13. 상태: **AION 연결 단계는 보류; 먼저 평문 학습 효과를 검증하도록 순서 변경**.

최신 실행 방침: 이후 본 FL 실험은 [공식 Flower Simulation Runtime 지침](./flower-runtime-guidelines.md)을 따른다.
아래의 ProcessGrid 실행 계획은 이전 검사용으로만 유지하며, 공식 Runtime 연결 완료를 의미하지 않는다.

후속 결정: AION 실행 없이 일반 평균 집계와 FedProx의 정상/label-flip 탐색 실험부터 수행한다.
`experiments.run_endpoint`를 별도 경로로 추가하며 기존 AION 프로토콜은 수정하지 않는다.
실제 V2의 장치별 특징 CSV 감사 결과는 31개 입력 + label, 총 171,053행으로 아래 논문 기반 예상과 다르다.
파일 그대로 사용하고 차이를 보고한다. 아래 내용은 이후 AION 연결을 위한 원래 계획으로 유지한다.

## 1. 목적과 범위

공개 IoT 호스트 행위 데이터로 정상/악성 행위를 분류하는 연합학습을 구성한다. 현재 Flower AION-ASR 구현을 기준선으로 삼아 다음을 확인한다.

1. 같은 학습 조건에서 일반 집계와 같은 모델을 얻는가?
2. 보안집계 경로의 실행 시간·통신량·메모리 추가 비용은 얼마인가?
3. 정상적으로 서명했지만 오염된 학습 결과를 제출하는 클라이언트가 있으면 탐지 품질이 얼마나 저하되는가?

첫 실험의 주장은 **“보안집계를 적용한 Endpoint Security 학습 기준선과 그 한계”**다. AION 자체가 정확도를 높인다거나, poisoning을 방어한다고 가정하지 않는다. FedProx, MGF, 앞서 논의한 MPC 내부 clipping은 넣지 않는다. 이후 방어 방법은 이 기준선과 비교한다.

여기서 Endpoint Security는 **사전 수집된 호스트 행위 특징의 오프라인 분류**다. 완성된 EDR 제품, 실시간 대응, 실제 단말에서의 탐지 지연을 평가하는 것은 아니다. 데이터의 악성코드 클래스와 연합학습의 악의적 클라이언트는 서로 다른 개념이다.

## 2. 기준선으로 고정할 구현

현재 경로는 [구현 설명](./aion-flower-implementation.md), [프로토콜](../trustlessfl/protocol.py), [워크플로](../trustlessfl/workflow.py)를 기준으로 한다.

| 항목 | 기본 설정 및 해석 |
| --- | --- |
| 조정 서버 | Flower ServerApp 1개 |
| 학습 참여자 | 데이터의 장치별 클라이언트 8개; aggregator와 역할 분리 |
| aggregator | 4개, 허용 Byzantine 수 `f=1`, 복원 threshold 2, 인증 quorum 3 |
| 참여 방식 | 고정 cohort, 매 라운드 학습 클라이언트 전원 참여 |
| 집계 | 클라이언트 delta의 동일 가중 평균; 데이터 수 가중 평균이 아님 |
| 수치 설정 | 기존 fixed-point 설정 `decimals=4`, `max_abs=100.0`에서 시작 |
| 실행 | 기존 ProcessGrid: 별도 프로세스와 Flower 메시지, 로컬 Pipe 전송 |
| 학습 장치 | CPU, 프로세스별 BLAS thread 1; 초기 실험은 GPU 공유 없음 |
| 제외 | FedProx, MGF 통합, clipping 방어, 동적 위원회, 클라이언트 dropout 복구 |

주의할 보장 범위:

- 현재 HPRF 경로는 연구용 surrogate이며, 검증된 프로덕션 암호 구현이 아니다. 반드시 `research-mode=true`를 유지하고 “실서비스 프라이버시 검증 완료”라고 보고하지 않는다.
- 인증서·서명 검증과 학습 결과의 무해성은 다르다. 로컬 범위 검사는 악성 클라이언트에 대한 검증 가능한 clipping이 아니다.
- 악성 서버의 잘못된 모델/메시지에 대한 거부와 서비스 가용성을 구분한다. 서버가 전달을 중단하면 전체 진행을 강제할 수 없다.
- 동일 호스트의 별도 프로세스는 독립 기관 간 신뢰 격리가 아니다. 여기서 측정하는 통신량은 실제 silo 네트워크 비용을 대신하지 않는다.
- 공식 AION artifact의 별도 Fashion-MNIST/MGF pilot 결과를 이 Flower 기준선의 기능이나 결과로 섞지 않는다.

## 3. 데이터 확보와 사전 감사 — P0

사용 자료는 제공된 [논문 PDF](./a%20crowdsensing%20intrusion%20detection%20dataset%20for%20decentralized%20federated%20learning%20models.pdf)다. 논문은 8개 Raspberry Pi, 정상 및 8개 악성 행위 클래스, 처리 후 342,106개 레코드와 32개 선택 특징을 설명한다. 원문은 [Scientific Data 논문](https://www.nature.com/articles/s41597-026-07155-w), 데이터 출처는 논문에 기재된 [Science Data Bank DOI](https://doi.org/10.57760/sciencedb.25380)다.

클래스 이름은 Normal, Ransomware-PoC, TheTick, Bashlite, HttpBackdoor, Beurk, Backdoor, Bdvl, XMRig를 예상하되, **실제 배포 파일의 표기와 label mapping을 확인한 뒤 확정**한다.

데이터 수령 후 학습 전에 다음을 기록한다.

- 배포 버전, 라이선스, 파일별 크기와 SHA-256. 논문 라이선스를 데이터 라이선스로 간주하지 않는다.
- 장치 ID 8개가 보존되는지, 파일별 행 수·열 이름·dtype·클래스 수·결측·무한값.
- 32개 특징의 정확한 이름과 순서; label, device ID, timestamp, 파일명 등 메타데이터의 입력 제외.
- 원시 로그/687개 후보 특징/32개 선택 특징 중 실제 제공되는 표현과 전처리 상태.
- timestamp, 수집 세션, 윈도 시작·종료·stride의 존재 여부. 논문의 30초 윈도 설명과 실제 레코드 구성의 일치 여부.
- 특징이 같은 중복 레코드와 상충 label, 장치/파일 사이 중복 여부. 행 수 차이는 원인을 기록하고 임의로 논문 수에 맞추지 않는다.

논문이 연결한 [전처리·학습 저장소](https://github.com/Cyber-Tracer/iot-feature-engineering)는 특징 생성 과정을 감사하는 참고 자료다. 코드와 데이터 버전의 대응 관계를 먼저 확인한다. 수집기나 실제 악성코드는 실행하지 않으며, 이번 실험에는 배포된 수치 특징만 사용한다.

현재 데이터 DOI의 배포 목록·용량·라이선스는 확인되지 않았다. 실제 파일에 접근하지 못하면 필요한 CSV와 메타데이터를 요청한다. 다른 IoT 데이터나 장치 ID를 임의 생성한 데이터로 조용히 대체하지 않는다.

### 전처리 누수에 따른 두 가지 평가 수준

논문의 공개 특징은 전체 데이터에 대한 특징 선택·정규화를 포함한다. 공개된 32개 특징을 다시 train/test로 나누는 것만으로 이 영향을 제거할 수 없다.

- **1차 기준선: released-feature benchmark.** 공개 32개 특징을 동일하게 사용하고 전처리 누수 가능성을 명시한다. 방법 사이의 통제된 비교에 사용한다.
- **후속 일반화 평가:** 원시 또는 정규화 전 특징에서 train만으로 선택·대치·scaler를 학습한다. 687개 특징도 이미 전체 정규화되었는지 확인한다. 필요한 원본이 없으면 이 수준의 평가를 했다고 주장하지 않는다.

## 4. 데이터 분할

주 실험은 **원래 장치 1개 = FL 클라이언트 1개**로 구성한다. 8개 장치는 가상 silo 역할을 하지만 실제 8개 기관을 의미하지는 않는다. 장치별 표본 수와 label 분포를 먼저 공개한다.

1. 장치별 train/validation/test를 약 60/20/20으로 분리한다. 세션과 중복 그룹을 깨지 않는 것을 정확한 비율보다 우선한다.
2. 신뢰할 수 있는 시간/세션 정보가 있으면 시간순으로 분리하고, 경계에 겹치는 윈도는 제거한다. 간격은 확인된 윈도·stride에 따라 고정한다.
3. 시간 정보가 없으면 중복 그룹을 고려한 label-stratified 분할을 사용한다. CSV 행 순서를 시간으로 간주하지 않으며, 결과를 **비시간적 분할 평가**로 표시한다.
4. 동일 특징의 정확한 중복이 분할 사이에 남지 않도록 전체 파일에서 검사한다. 서로 다른 장치에 걸친 중복은 장치 소유권을 유지하면서 동일 split에 배정한다. 상충 label은 별도 감사 후 처리 원칙과 제거 수를 기록한다.
5. 분할 후 train에서만 poisoning을 적용한다. validation/test의 특징과 정답은 모든 방법에서 동일하고 변경하지 않는다.

분할은 seed 42로 한 번 고정한다. 학습 반복 seed는 `[42, 43, 44]`로 하고, 초기화·mini-batch·공격자 선정의 난수 흐름을 분리한다. 세 반복을 독립 데이터셋이나 독립 기관의 결과로 해석하지 않는다.

자연 장치 분포가 실제로 얼마나 non-IID인지 먼저 측정한다. IID 또는 Dirichlet `alpha=0.1` 재분배는 후속 선택 실험이며, 사용 시 train pool에만 적용하고 “합성 클라이언트 분할”로 명시한다.

## 5. 학습 설정과 필요한 연결 작업 — P1

다음은 논문의 MLP 크기와 학습 길이를 참고한 **프로젝트용 설정**이다. 논문의 topology나 모든 하이퍼파라미터를 그대로 재현한다는 뜻은 아니다.

| 항목 | 계획 |
| --- | --- |
| 모델 | 32 → 128 ReLU → 9 logits MLP, bias 포함 5,385개 파라미터 |
| 구현 | NumPy float64 CPU 학습기; 기존 의존성·결정적 수치 비교 활용 |
| 목적함수 | 다중 클래스 cross-entropy |
| optimizer | SGD, momentum/weight decay 없음 |
| 초기 learning rate | 0.01; validation으로 `[0.001, 0.01, 0.1]` 중 확정 |
| batch size | 128, 마지막 작은 batch 포함 |
| local epochs | 3 |
| FL rounds | 10; 연장 실험은 별도 조건으로 사전 고정 |
| 초기화 | seed별 공통 He 초기화의 가중치와 0 bias; 모든 방법·노드에 동일 벡터 |
| 집계 가중치 | 각 클라이언트 1/8, 기존 AION과 일치 |

learning rate는 seed 42의 깨끗한 plaintext validation macro-F1로만 선택하고, 모든 비교군과 공격 실험에서 고정한다. 테스트 결과로 재선택하지 않는다. 이 최대 3개 tuning run은 본 평가와 별도 기록한다.

구현해야 할 최소 변경은 다음과 같다. **보안집계 알고리즘을 추가하는 작업은 아니다.**

- 데이터 준비기: manifest, label/feature schema, 분할 인덱스, 클라이언트별 train shard 생성. NPZ는 `allow_pickle=False`로 읽는다.
- Endpoint 학습기: 기존 node-local `trainer` 연결을 이용한 MLP 학습과 delta 반환. 정규화·특징 선택을 서버의 런타임 학습 데이터 접근으로 구현하지 않는다.
- 초기 모델 연결: 현재 0 벡터 초기화는 ReLU MLP에 부적합하므로 공통 초기 모델을 지원한다. flatten 순서는 `W1(32,128), b1(128), W2(128,9), b2(9)`로 고정한다.
- 초기화 검증: 노드가 사전 승인한 schema·학습 설정·초기 모델 hash를 task에 결부해 확인한다. 서버가 노드별로 다른 초기 모델을 보내는 경우 거부한다. 기존 합성/MNIST 기본 동작은 보존한다.
- Flower 연결: MNIST 전용 shard 설정을 Endpoint에도 확장하고, aggregator에 학습 shard를 제공하지 않는 기존 역할 분리를 유지한다.
- 실험 runner: 기존 [MNIST 비교 구조](../experiments/run_mnist.py)를 참고해 plaintext float, plaintext fixed-point, AION을 동일 조건으로 실행한다.

필수 테스트는 schema/차원 오류 거부, MLP 유한차분 gradient 검사, 학습 손실 감소 smoke test, 동일 seed 재현성, 서로 다른 초기 모델 거부, fixed-point 집계 일치, 기존 프로토콜 회귀 테스트다.

클라이언트별 표본 수가 달라도 동일 가중 평균을 유지한다. 표본 수 가중 FedAvg로 바꾸면 별도 알고리즘 조건으로 분리한다. 정상 업데이트가 기존 수치 범위를 벗어나면 실패를 기록하고 설정을 다시 고정한 뒤 비교군 전체를 재실행한다. 조용한 clipping이나 방법별 설정 변경은 금지한다.

## 6. 최소 실험 행렬

| ID | 집계 | 학습 데이터 | 반복 | 목적 |
| --- | --- | --- | --- | --- |
| B1 | Plaintext float, 동일 가중 평균 | 정상 | 3 seeds | 비양자화 학습 기준 |
| B2 | Plaintext fixed-point, AION과 동일 codec | 정상 | 3 seeds | 수치적 oracle |
| B3 | 현재 Flower AION-ASR | 정상 | 3 seeds | 학습 동등성·추가 비용 |
| A2 | B2 | 클라이언트 2/8 label-flip | 3 seeds | 오염된 평균 집계 기준 |
| A3 | B3 | A2와 같은 공격 | 3 seeds | 현재 AION의 poisoning 한계 |

본 실험은 **15개 FL run × 10 rounds**다. 데이터 감사·단위 테스트·짧은 pilot·하이퍼파라미터 탐색은 이 수에 포함하지 않는다. B1/B2/B3는 같은 초기화·분할·mini-batch 순서·local epochs를 사용한다.

주 공격은 미리 고정한 9개 클래스 순서에서 `y → (y+1) mod 9`의 untargeted label-flip이다. 공격 클라이언트 2개는 seed로 선정하고, 해당 클라이언트의 train label 전체를 한 번 변환한 고정 shard를 라운드 1부터 10까지 사용한다. 프로토콜과 서명은 정상 수행한다. A2/A3의 공격자·오염 shard·난수는 짝지어 고정한다.

이 공격은 재현 가능한 학습 오염 기준선이지 최강 공격은 아니다. clean 9개 run을 먼저 완료한 뒤 poisoning 6개 run을 진행한다. 공격 영향이 작아도 결과를 그대로 보고하며, 테스트 결과를 보고 공격자를 재선택하지 않는다.

선택 확장 순서는 다음과 같다.

1. `Backdoor → Normal` targeted label-flip: 악성 행위를 정상으로 놓치는 정도 평가. 대상 클래스가 공격자 train에 존재하는지 사전 확인하고 실제 변조 수를 공개한다.
2. 악성 클라이언트 1/8, 4/8, 6/8; 자연 분포와 합성 non-IID 비교.
3. local-only 모델: 장치별 30 epochs로 공동학습의 이득을 별도 확인.
4. FedProx 또는 새로운 방어 추가. 반드시 현재 기준선과 별도 이름·설정으로 비교.

학습 클라이언트의 악성 비율과 aggregator의 Byzantine 허용 수 `f=1`을 혼동하지 않는다.

## 7. 측정 지표와 판정

### 탐지 품질

- 주 지표: pooled test의 9-class macro-F1, round별 곡선과 마지막 round 결과.
- 보조 지표: 클래스별 precision/recall/F1 및 support, confusion matrix, accuracy.
- Endpoint 의미 지표: 정상의 악성 오탐률, 악성의 정상 오분류율. 기본 판정은 9-class argmax로 고정한다.
- 장치별 macro-F1 평균과 최저 장치 성능. 장치별 값은 해당 test에 존재하는 클래스 기준으로 계산하고 클래스 수·support를 함께 기록한다. pooled 값은 전체 9개 클래스, undefined precision/F1은 0으로 고정한다.
- targeted 공격을 추가하면 대상 클래스가 Normal로 예측된 비율을 별도로 보고한다. 이를 trigger 기반 backdoor ASR와 혼용하지 않는다.
- 각 seed의 값과 평균±표본 표준편차를 모두 공개한다. 3 seeds만으로 통계적 유의성을 주장하지 않는다.

별도 threshold 검출기를 추가할 때는 `1-P(Normal)`의 임계값을 validation에서만 정하고, 목표 FPR 및 실제 test FPR을 함께 보고한다. 첫 실행의 필수 조건은 아니다.

### 집계 동등성

- B2/B3와 A2/A3의 매 라운드 복원 정수 합은 정확히 같아야 한다.
- 동일 NumPy float64 연산 순서에서 모델의 최대 절대 차이 0을 목표로 검증한다. 불일치 시 암호/codec, 초기화, shard, batch 순서, delta 생성부터 조사한다.
- B1과 B2의 모델 오차·macro-F1 차이는 별도 보고해 양자화 영향과 보안집계 영향을 분리한다.
- AION이 B2와 같다면 “집계 과정에서 추가 품질 저하 없음”이라고 해석한다. B1보다 항상 좋아야 한다는 기준은 두지 않는다.
- B1/B2 사이 macro-F1 차이 1 percentage point 초과를 수치 설정 점검 신호로 삼는다. 원래 실패 결과를 보존하며, 이 기준을 정확도 보장으로 해석하지 않는다.

### 실행 비용

- 초기 setup/enroll과 round 비용 분리; round wall time 및 train/prepare/share/finalize/commit별 시간.
- 전체 프로세스와 역할별 peak RSS, 실제 학습 표본 수, 성공/abort round 수.
- 기존 관측기의 canonical JSON payload bytes를 우선 기록하고 **실제 wire bytes가 아님**을 표시한다. protobuf 직렬화 크기를 추가 측정하면 별도 열로 구분한다.
- 시간 비교용 plaintext는 같은 프로세스 배치·학습 병렬도·메시지 전송 방식을 갖춘 단순 집계 경로로 측정한다. 순차 수치 oracle의 시간을 AION 병렬 실행과 비교해 overhead라 부르지 않는다.
- 초기화·데이터 로딩 포함/제외 시간을 분리하고, 실험 run은 서로 겹쳐 실행하지 않는다. CPU/RAM/OS/의존성·thread 설정을 기록한다.

실제 네트워크 정책, RTT, 대역폭 제한, TLS/SuperLink, GPU 가속은 이번 로컬 기준선 측정 범위 밖이다.

## 8. 프로토콜 장애 시험 — 학습 오염과 분리

전체 10-round 실험과 별도로 작은 2–3 round 설정에서 기존 fault injection을 재사용한다.

| 조건 | 확인할 기대 동작 |
| --- | --- |
| 서버의 모델/parent 변조 또는 replay | 잘못된 상태 거부, 잘못된 모델 commit 없음 |
| aggregator 1개 무응답 | 나머지 3개 정상 노드로 완료 가능한지 확인 |
| aggregator 2개 무응답 | quorum 부족으로 abort; 보장 범위 밖임을 표시 |
| 서명된 잘못된 share/result | 검증 실패 후 배제, 정상 quorum 확보 여부에 따른 완료/abort |
| 학습 클라이언트 1개 미제출 | 현재 fixed-cohort 정책상 abort |
| 정상 서명된 label-flip update | 수락 가능; 탐지 성능 영향은 poisoning 실험으로 평가 |

현재 메시지 억제 fault injection은 실제 프로세스 사망이나 TCP timeout 재현이 아니다. 미검증 장애 종류는 결과표에 구현 여부부터 표시한다. Abort한 run을 F1=0으로 바꾸거나 성공 run만 골라 평균내지 않는다.

## 9. 실행 순서와 산출물

| 단계 | 작업 | 다음 단계 진입 조건 |
| --- | --- | --- |
| P0 | 데이터 수령·라이선스·schema·장치·중복·시간 정보 감사 | data manifest와 평가 수준 확정 |
| P1 | 데이터 loader, MLP, 공통 초기화, Flower runner 연결 | 새 단위 테스트와 기존 회귀 테스트 통과 |
| P2 | seed 42, 8 clients/4 aggregators, 2-round pilot | finite 학습·인증서·B2/B3 동등성·자원 사용 확인 |
| P3 | validation tuning 후 clean B1/B2/B3 총 9개 run | 조건 고정 및 깨끗한 기준선 보고서 |
| P4 | 25% label-flip A2/A3 총 6개 run, 별도 장애 시험 | 품질·비용·실패를 포함한 최종 기준선 보고서 |

Pilot에서 데이터를 줄이면 장치·클래스별 상한과 표본 수를 명시하고 본 결과와 분리한다. 소요 시간은 pilot 측정 후 산정한다. 데이터가 없거나 메타데이터가 불충분하면 해당 단계의 제한을 보고하고 평가 주장을 축소한다.

예정 산출물 위치는 `docs/experiments/endpoint-baseline-<run-id>/`다.

- `report.md`: 평가 수준, clean/poisoning 결과, 보안·구현 한계, 후속 비교 기준.
- `config.json`: topology, 모델/codec, split/seed, 학습·공격·thread 설정.
- `data-manifest.json`: 출처·버전·파일 hash·feature/label schema·장치별 split 통계.
- `metrics.csv`, `rounds.csv`, `confusion-matrices.json`: seed별 지표, 시간·메시지량·abort 원인.
- 소스 commit과 dirty diff 또는 소스 snapshot hash, 의존성 버전, 모델 checkpoint hash.

원본 데이터·실제 split 인덱스·대형 checkpoint는 로컬 cache에 두고 라이선스 및 재배포 조건 확인 전 문서 폴더에 복제하지 않는다. 개인키·share·개별 update를 공개 보고서에 넣지 않는다. 중앙 test evaluator와 plaintext oracle은 **공개 데이터 실험용 평가 장치**이며 실제 배포에서 서버가 같은 정보를 볼 수 있다는 가정이 아니다.

첫 완료 목표는 **공개 32-feature 데이터 / 원래 8개 장치 / MLP / 일반 집계 대비 AION 동등성·비용 / 25% label-flip 한계**까지다. 이 결과를 얻은 뒤에만 학습 품질 개선 또는 악성 클라이언트 방어를 추가한다.
