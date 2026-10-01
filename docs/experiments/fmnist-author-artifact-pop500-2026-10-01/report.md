# 저자 학습 artifact MGF: population 500, participation 100

## 범위

이 실행은 공개 `FL_Backdoor_CV/roles/attack3_fmnist.py`의 population 500,
sample 100, adversaries 20, checkpoint `avg_300.pth`, local epoch 2,
learning rate 0.001, boost 20, `min_threshold=0.1`, `weight=0.1`에 맞춘다.
원본 DataLoader 의미, artifact class-order/Dirichlet partition RNG와 poison
pool RNG를 사용한다. 공식 Flower SuperLink/Ray에서 CPU worker 8개로
실행한다.

이것은 공개 학습 artifact의 **중앙 평문 MGF 대조군**이다. server가 평문
classifier update에 원본 SHPRG mask를 붙여 selection하고 선택된 평문 전체
update를 평균한다. client-side HPRF secure aggregation이나 논문 Algorithm
6–8 wire 재현이라고 부르지 않는다. 그 차이는
[데이터 흐름 대조](../../reproduction/author-mmf-mgf-dataflow-2026-10-01.md)에
고정했다.

## 완료된 10라운드 대조

출력: `.cache/fmnist-author-artifact-pop500-q100-ten-round-20261001`.
공격 라운드는 1, 4, 7, 10으로 명시했다. `mgf`와 동일 cohort의 무방어
fixed-point `quantized` 경로를 각각 fresh Flower run으로 실행했다.

| 경로 | run ID | 실행 시간 | 최종 정확도 | 최종 ASR | 학습 10라운드 평균 ASR | 최대 ASR |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 저자 SHPRG/MGF | `16036114210808680658` | 65.2944 s | 88.59% | 0.5859375% | 0.5859375% | 0.5859375% |
| 무방어 quantized | `14002877315089177759` | 160.6271 s | 65.79% | 0.78125% | 60.078125% | 100% |

평균은 checkpoint round 0을 제외했다. MGF의 평균 clean accuracy는 88.605%,
무방어는 35.977%였다. MGF 선택 수는 라운드별
`[10,10,10,22,19,18,10,16,12,10]`이고 선택된 공격자는 모든 라운드 0명이다.
MGF 최종 모델의 checkpoint 대비 L∞ 변화는 0.00102598이다. 이는 실제
선택 결과와 안정성을 보여주지만, 60라운드에서의 장기 수렴 또는 비공개
MGF를 증명하지 않는다.

verifier는 1,000개 client/round training metadata가 staged participation과
일치하는지, 실제 `author-loader` policy인지, 모델 shape/finite 값과 매
라운드 MGF trace가 원본 torch.float32 수식과 일치하는지 확인했다.
`verification.json`이 생성됐으며 단순 마지막 지표만 읽지 않았다.

## 60라운드 실행

출력: `.cache/fmnist-author-artifact-pop500-q100-sixty-round-20261001`.
저자 launcher의 `retrain_rounds=60`, `poison_prob=0.5`에 맞춰 partition 이후
고정 RNG가 60라운드 중 정확히 30개 공격 라운드를 선택했다:

`1,2,5,6,7,10,11,12,13,16,18,20,22,23,25,27,28,29,32,33,36,40,43,45,46,48,50,53,57,59`.

두 공식 Flower 실행과 전체 verifier가 완료됐다.

| 경로 | run ID | 실행 시간 | 최종 정확도 | 최종 ASR | 60라운드 평균 TER | 평균 ASR | 최대 ASR |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 저자 SHPRG/MGF | `6965790347658103367` | 350.2039 s | 88.80% | 0.78125% | 11.338667% | 0.631510% | 0.78125% |
| 무방어 quantized | `15400511059710316236` | 886.5262 s | 56.81% | 100% | 50.473% | 83.141276% | 100% |

평균은 checkpoint round 0을 제외한 60개 학습 라운드다. MGF는 매
라운드 10~24명을 선택했고 60라운드 전체에서 선택된 공격자는 **0명**이며
small-cohort floor override도 0회다. 두 경로 모두 각 6,000개의 실제
client/round metadata가 staged cohort와 `author-loader` policy에 일치했다.
MGF trace도 매 라운드 원본 torch.float32 selection/history 수식으로 다시
검사했다.

hash-linked 공개 요약은
`.cache/fmnist-author-artifact-pop500-q100-sixty-round-public-20261001/results.json`에
있다. 저자 source snapshot 6개, checkpoint/partition/input provenance,
모델과 raw result hash를 포함한다. 좋은 MGF 곡선은 중앙 artifact 방어의
재현 결과이며 private Aion wire의 증거는 아니다.

## 원본 대비 남은 차이

- 원본 프로그램 전체의 공유 Python/NumPy/Torch RNG transcript가 아니라
  단계별 분리·고정 RNG다.
- 공개 트리에 `matrix_840` 파일이 없어, SHPRG matrix는 포팅에 고정한
  seed-0 transcript다. 계산 수식은 직접 차등 검증됐지만 저자 실행 당시
  비공개/미포함 matrix와 동일하다는 증거는 없다.
- 원본 CUDA가 아니라 CPU torch.float32다. 선택/평균 수식은 원본 AST
  실행과 대조했지만 CUDA 비트 단위 동일성은 주장하지 않는다.
- 무방어 대조는 float32 FedAvg가 아니라 소수 6자리 fixed-point 합산이다.
- 논문은 Algorithm 6 설명에서 beta=0.2를 들지만 공개 FMNIST launcher는
  `weight=0.1`이다. 이 보고서는 공개 launcher를 우선한다.
