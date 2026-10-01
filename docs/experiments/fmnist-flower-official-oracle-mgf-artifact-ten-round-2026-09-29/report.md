# Fashion-MNIST: 원본 분할 순서의 공식 Flower 10라운드

Fashion-MNIST·`avg_300.pth` LeNet5에서 N=500, 라운드 참여자 q=100,
aggregator 8개, 악성 client 20명, seed 0, 공격 라운드 5·7·10으로 실행했다.
`--partition-rng artifact`가 원본의 class 첫 등장 순서
`[9,0,3,2,7,5,1,6,4,8]`와 정상 참여자 150명 사전 추첨의 난수 소비를 따른다.
각 class의 client별 배정 수를 반올림하므로 학습 이미지 60,000장 중
59,941장이 중복 없이 배정되고 59장은 남는다. `aion_mgf_oracle`와 평문
MGF는 같은 입력·참여 일정을 쓰는 별도 Flower 1.36.0 SuperLink/Ray run이다.

| 항목 | `aion_mgf_oracle` | 평문 MGF |
| --- | ---: | ---: |
| 최종 test 정확도 | 88.60% | 88.60% |
| 최종 공격 성공률(ASR) | 0.390625% | 0.390625% |
| 공격 라운드 5·7·10의 선택된 악성 client | 각 0명 | 각 0명 |
| 내부 실행 시간 | 925.9초 (15.4분) | 49.7초 |

두 경로의 **10개 라운드 모든 선택 집합과 정확도·ASR 곡선이 일치**했다.
모델 시퀀스의 최대 좌표 차이는 2.18×10⁻⁶이다. MGF 선택 인원은 라운드별로
`10, 10, 10, 13, 10, 28, 13, 11, 12, 10`명이었다. `verify`는 저장된
Flower 모델·선택 trace, AION의 roster·모델 서명 정족수와 부모 체인을
재검증한다. [검증 요약](results.json)은 원시 결과·모델·provenance 해시와
분할 정책 `artifact`를 기록한다.

[이전 분할의 10라운드](../fmnist-flower-official-oracle-mgf-ten-round-2026-09-29/report.md)는
class 번호순·사전 추첨 생략 transcript(`--partition-rng legacy`)에서 최종 정확도
88.66%였다. 분할이 다르므로 두 수치를 같은 입력의 반복 실행으로 취급하지 않는다.

이 경로는 실험용 **oracle MGF**다. client의 classifier 840개 평문 좌표가
coordinator에 공개되고, 개별 공개 좌표와 masked 전체 update의 결속을
암호학적으로 증명하지 않는다. 따라서 논문의 보안 MGF·CCS/VRF·검증된
LWE-HPRF나 60라운드 결과를 입증하지 않는다. 시간은 이 CPU 환경에서의
각 Flower run 내부 기록으로, 환경 준비와 논문 하드웨어 성능은 제외한다.

원시 결과는 `.cache/fmnist/official-oracle-10round-artifact-seed0/`에 있다
(저장소에서 ignored). 재실행:

```bash
python3 -m experiments.run_fmnist_official --phase all \
  --output .cache/fmnist/official-oracle-10round-artifact-reproduce \
  --population 500 --participants 100 --aggregators 8 --rounds 10 \
  --attack-clients 20 --attack-rounds 5 7 10 --workers 8 \
  --modes aion_mgf_oracle mgf --partition-rng artifact \
  --cohort-sampling groups
python3 -m experiments.export_fmnist_official \
  --source .cache/fmnist/official-oracle-10round-artifact-reproduce \
  --output docs/experiments/fmnist-flower-official-oracle-mgf-artifact-ten-round-reproduce
```
