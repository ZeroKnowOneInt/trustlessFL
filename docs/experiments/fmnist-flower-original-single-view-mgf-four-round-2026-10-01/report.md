# Single-view MGF: 공식 Flower FMNIST 공격 4라운드

2026-10-01. 원본 HPRF를 사용하는 새 single-view 경로의 실제 다중 라운드
학습·공격 검증이다. 이전 dual-view 결과를 전용하지 않고 별도로 실행했다.

## 결과

| 경로 | 최종 정확도 | 최종 공격 성공률 | ServerApp 시간 |
| --- | ---: | ---: | ---: |
| 원본 HPRF·single-view MGF·HotStuff | 88.60% | 0.390625% | 1197.55초 |
| 동일 조건 무방어 양자화 평균 | 66.24% | 66.40625% | 18.11초 |

N=100/q=10, aggregator 4개/f=1, seed=0, CPU worker 4개, 4라운드.
저자 artifact 데이터 분할과 author-loader 학습을 사용했다.
1·4라운드에 client-0/client-1을 공격자로 참여시켰고 두 라운드 모두 제외했다.
각 라운드의 선택 집합은 51/67, 19/76, 11/41, 44/57이었다.
작은 cohort의 최소 집계 인원 2명 정책을 적용했다.

## 검증 범위

- 공식 Flower 1.36.0 SuperLink/Ray에서 전체 61,706좌표 모델을 집계했다.
  MGF 검사는 classifier 840좌표이다. 해당 좌표는 bounded probe만 전송하고
  modular 벡터에서는 인증된 0 placeholder를 사용한다.
- 후보 signed update 40개 모두의 서명·문맥·진폭·update/probe 연결과
  single-view 정책을 검사했다. 평문 classifier 필드는 0개였다.
  인증 roster 및 모델의 HotStuff commit QC를 다시 검증했다.
- author-loader 학습 metadata 40회와 실제 선택된 업데이트 8개를 확인했다.
  동일 staged 데이터·seed·이전 모델로 선택된 클라이언트를 다시 학습하여,
  네 라운드 모두 **전체 모델의 양자화 평균 최대 절대 오차 0**을 확인했다.
  replay의 CPU intraop thread는 Flower worker와 동일한 1개이다.

## 마스크 진폭과 threshold 전이

| 라운드 | 입력 진폭 | 다음 진폭 | 다음 bound |
| --- | ---: | ---: | ---: |
| 1 | 0.001 | 0.0005749 | 0.025640488002 |
| 2 | 0.0005749 | 0.0006734 | 0.025329996250 |
| 3 | 0.0006734 | 0.0003390 | 0.020942066230 |
| 4 | 0.0003390 | 0.0005080 | 0.011188142267 |

첫 3라운드는 masked percentile bootstrap을 사용했다.
4라운드의 실제 필터 bound는 최근 집계 norm과 cohort mask norm으로 계산한
`0.011188142267`이었다. 기존 값을 읽기만 한 것이 아니라 실제 선택·집계에
사용했으며, 선택 및 상태 인증서와 함께 검증했다.
초기 진폭=0.001, bound=10, term=1은 명시적인 실험 bootstrap이다.

수치·원본 HPRF/모델/검증 hash·phase 시간·wire 감사·replay는
[results.json](results.json)에 있다. secure run ID는 `4583544140951393554`,
무방어는 `6540553475524534176`이다. raw 입력과 검증 결과는
`.cache/fmnist/official-original-single-view-mgf-attack-four-round-20261001`에 있다.
개인 키·share·gradient는 공개 결과에 넣지 않았다.

## 재현

```bash
python -m experiments.run_fmnist_official \
  --output .cache/fmnist/NEW-single-view-four-round \
  --phase all --modes aion_mgf_beta quantized \
  --population 100 --participants 10 --aggregators 4 --rounds 4 \
  --attack-clients 2 --attack-rounds 1 4 \
  --original-hprf-dir ../Aion/agent/Aion/HPRF \
  --training-sampling author-loader --mgf-beta 0.2 \
  --mgf-projection --mgf-single-view --mgf-percentile --mgf-artifact-bound \
  --hotstuff --workers 4 --device cpu --cli-timeout 3600 --replay-selected
```

이번 실행은 stage 후 허용받은 로컬 socket 환경에서 phase run을 실행했다.
캐시된 Flower/PyTorch PYTHONPATH와 Flower CLI PATH를 지정했다.
재현에는 아직 존재하지 않는 새 output 경로를 사용한다.

## 남은 차이

한 seed의 4라운드 검증이며 논문의 전체 라운드·여러 seed 실험은 아니다.
full-vector MGF 검사, 일회성 키 공유, 추가 mask share 없는 경량 통신량은
재현하지 않았다. 현재는 fresh key와 실제 bounded mask 좌표의 Pedersen
share를 매 라운드 사용한다.

[일회성 공유·share 제거 제약](../../mgf-key-sharing-reduction.md)에 원본 HPRF
반례와 완료 조건을 기록했다. 입력 프라이버시와 개별 mask-key 관계의 증명,
CCS/VRF·EMA 결합 및 HotStuff의 일반적인 부분 동기 진행 보장도 남아 있다.
정확한 집계와 공격 실험 통과를 이 보안 보장의 근거로 사용하지 않는다.
