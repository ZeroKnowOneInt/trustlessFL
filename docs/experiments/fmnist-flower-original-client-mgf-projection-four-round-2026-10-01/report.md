# 원본 HPRF·클라이언트 마스킹 MGF·HotStuff: 공식 Flower 4라운드

2026-09-30 실행 시작, 2026-10-01 재검증 완료.
이전 oracle 경로가 아닌 클라이언트 마스킹 경로의 실제 학습 실험이다.

## 결과

| 경로 | 4라운드 정확도 | 공격 성공률 | ServerApp 시간 |
| --- | ---: | ---: | ---: |
| 원본 HPRF·masked classifier MGF·HotStuff | 88.60% | 0.390625% | 1,130.70초 |
| 동일 조건 무방어 양자화 평균 | 66.24% | 66.40625% | 18.85초 |

N=100, q=10, aggregator 4개/f=1, seed=0, CPU worker 4개.
1·4라운드에 두 model-replacement 공격자를 참여시켰다.
두 공격 라운드 모두 공격자는 선택되지 않았다. 각 라운드에는 정상 클라이언트
2명이 선택됐으며, 참여 집합과 선택 집합은 라운드마다 달랐다.
최소 2명 집계 조건 때문에 q=10에서는 10%보다 큰 20% 하한을 적용했다.
전체 분할에 실제 배정된 데이터는 저자 방식의 버림 처리를 포함해 59,972장이다.

| 라운드 | 정확도 | 공격 성공률 | 선택 클라이언트 |
| --- | ---: | ---: | --- |
| 1 | 88.73% | 0.585938% | client-51, client-67 |
| 2 | 88.48% | 0.390625% | client-19, client-76 |
| 3 | 88.38% | 0.390625% | client-11, client-41 |
| 4 | 88.60% | 0.390625% | client-44, client-57 |

## 검증

Flower 1.36.0의 실제 SuperLink/Ray 런타임에서 두 앱을 별도로 실행했다.
원본 HPRF matrix·initialization_values·hprf.py와 public setup을 hash로 고정했다.
학습은 저자 DataLoader batch semantics를 포팅한 `author-loader`다.
원본 학습 artifact의 SHPRG와 원본 ASR HPRF를 동일한 것으로 취급하지 않는다.

선택 집합과 모델의 HotStuff commit QC, 모델 인증서 체인, 원본 HPRF 설정,
실행 입력·학습 source hash를 재검증했다.
후보 40개 signed update를 검사하여 평문 classifier 필드가 없는지,
서명·task/round/parent·mask scale·probe/update digest·선택 roster hash가
일치하는지 확인했다. 저자 sampling policy의 실제 학습 호출도 40회 확인했다.
이는 simulation cache 감사이며 정직한 학습이나 입력 프라이버시의 증명이 아니다.

선택된 업데이트 8개를 같은 staged 데이터·seed·이전 인증 모델로 다시 학습했다.
네 라운드의 전체 LeNet5 61,706좌표 모델은 양자화 평균과 **최대 절대 오차 0**으로
일치했다. 개별 plaintext delta는 결과나 문서에 저장하지 않았다.

처음 재학습 검사는 3라운드에서 `5e-7` 차이로 실패했다. Flower worker의
OMP/MKL thread 수는 1인데 host replay는 다른 thread 수를 사용한 것이 원인이었다.
thread 1개로 맞추면 동일한 기존 실행 결과와 오차 0이 됐다. replay 코드가
자동으로 `torch.set_num_threads(1)`을 적용하고 성공/실패 양쪽에서 원래
host 설정을 복원하도록 수정했다. 허용 오차 `1e-12`는 완화하지 않았다.

## 실제 MGF 상태 전이

코드의 alpha는 HPRF/p에 곱하는 최대 마스크 진폭이다.
첫 3라운드는 masked classifier의 percentile로 bound를 초기화했다.
4라운드는 인증된 cohort mask norm과 이전 두 aggregate norm을 사용하는
저자 artifact 방식의 evolving bound를 적용했다.

| 라운드 | 입력 마스크 진폭 | 실제 선택 bound | 다음 진폭 |
| --- | ---: | --- | ---: |
| 1 | 0.001 | squared_integer=684013259 | 0.0005749 |
| 2 | 0.0005749 | squared_integer=623023424 | 0.0006734 |
| 3 | 0.0006734 | squared_integer=462605808 | 0.000339 |
| 4 | 0.000339 | decimal=0.011490047433 | 0.000508 |

`squared_integer`는 실수 L2 norm 자체가 아니라 scale=1,000,000의 정수
probe에 대한 norm 제곱이다. 따라서 decimal bound와 직접 비교하지 않는다.
이 상태 전이는 인증 모델의 실제 양자화 delta로 다시 검증했다.
숫자·hash·상태·단계별 시간·replay 결과는 [results.json](results.json)에 있다.

## 실행법

```bash
python experiments/run_fmnist_official.py \
  --output .cache/fmnist/official-original-client-mgf-projection-attack-four-round-20260930 \
  --phase all --modes aion_mgf_beta quantized \
  --population 100 --participants 10 --aggregators 4 --rounds 4 \
  --attack-clients 2 --attack-rounds 1 4 \
  --original-hprf-dir ../Aion/agent/Aion/HPRF \
  --training-sampling author-loader --mgf-beta 0.2 \
  --mgf-projection --mgf-percentile --mgf-artifact-bound --hotstuff \
  --workers 4 --device cpu --cli-timeout 3600

python experiments/run_fmnist_official.py \
  --output .cache/fmnist/official-original-client-mgf-projection-attack-four-round-20260930 \
  --phase verify --replay-selected
```

실행 시 캐시 의존성의 PYTHONPATH와 Flower CLI의 PATH를 지정했다.
같은 실험을 다시 실행할 때는 새 output 경로를 사용한다.
raw run ID: masked MGF `8544949020608371780`, 무방어 `3036871043251977447`.
관련 회귀 시험은 두 별도 실행에서 80개와 20개, 총 100개가 통과했다.

## 남은 차이

classifier 840좌표를 검사하는 축소된 한 seed·4라운드 실험이다.
전체 모델은 ASR 집계하지만 전체 gradient norm을 검사한 것은 아니다.
논문 규모·길이의 60라운드 결과나 일반적인 방어 성능을 입증하지 않는다.
논문 Algorithm 6의 직접 bound만 사용하는 모드와 저자 artifact의
percentile/bootstrap·rank clipping 경로도 구분한다.

매 라운드 fresh key와 좌표별 bounded mask share가 남아 있다.
원본의 일회성 키 공유·경량 통신량은 아직 재현되지 않았다.
bounded mask의 입력 정보 노출, 개별 mask-key 관계 증명, 모든 부분 동기
상황의 HotStuff 진행 보장, CCS/VRF·EMA와의 합성도 해결됐다고 주장하지 않는다.
projection은 같은 HPRF 출력으로 전체 modular vector와 bounded probe를 만들므로,
두 표현을 함께 관찰했을 때의 정보 노출도 별도로 다뤄야 한다.
평문 classifier 필드가 없다는 검사는 입력 프라이버시 보장과 같지 않다.
