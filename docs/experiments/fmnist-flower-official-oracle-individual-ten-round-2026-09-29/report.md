# Fashion-MNIST: 개별 client 추첨의 공식 Flower 10라운드

Flower 1.36.0 SuperLink/Ray에서 원본 Fashion-MNIST와 `avg_300.pth` LeNet5를
사용했다. 모집단 N=500, 라운드당 q=100, aggregator 8개, 악성 client 20명,
seed 0이며 공격 라운드는 5·7·10이다. 기본 `--partition-rng artifact`는 원본의
class 첫 등장 순서와 정상 참여자 150명 사전 추첨을 반영한다. 60,000장 중
59,941장을 중복 없이 배정했다.

`--cohort-sampling individuals`는 원본의 포함 규칙대로 정상 라운드에는
정상 client 100명을 개별 추첨하고, 공격 라운드에는 악성 client 20명 전원과
정상 client 80명을 추첨한다. 매 라운드의 참여 목록은 Flower 실행 전에
확정해 저장한다. 원본 코드에서는 local training의 Python 난수 호출이
다음 라운드 추첨과 섞이므로 **원본의 정확한 난수 순서까지 재현한 것은 아니다**.

| 항목 | `aion_mgf_oracle` | 평문 MGF |
| --- | ---: | ---: |
| 최종 test 정확도 | 88.58% | 88.58% |
| 최종 공격 성공률(ASR) | 0.390625% | 0.390625% |
| 공격 라운드 5·7·10의 선택된 악성 client | 각 0명 | 각 0명 |
| 내부 실행 시간 | 903.7초 (15.1분) | 51.6초 |

두 경로의 **모든 10라운드에서 MGF 선택 집합과 정확도·ASR 곡선이 일치**했다.
모델 시퀀스 최대 좌표 차이는 1.96×10⁻⁶이다. 선택 인원은 라운드 순서대로
`10, 10, 10, 22, 12, 25, 11, 11, 10, 11`명이다. 검증은 참여 일정을
개별 추첨 규칙으로 재계산하고, 저장된 모델·MGF trace·AION roster와 모델의
서명 정족수 및 부모 체인을 확인했다. [검증 요약](results.json)에 원시 결과·
모델·입력 provenance 해시와 분할·참여 정책을 기록했다.

[2인 그룹 추첨의 10라운드](../fmnist-flower-official-oracle-mgf-artifact-ten-round-2026-09-29/report.md)는
같은 분할에서도 다른 참여 일정으로 실행돼 최종 정확도 88.60%였다. 두 실험은
참여 집합이 다르므로 같은 입력의 반복으로 비교하지 않는다.

`aion_mgf_oracle`는 **보안 MGF가 아니다**. 각 client의 classifier 840개
평문 좌표를 coordinator에 공개하며, 이 값과 masked 전체 update의 개별
정합성을 암호학적으로 증명하지 않는다. 60라운드 논문 곡선, CCS/VRF 또는
검증된 LWE-HPRF 보안성을 이 결과로 주장하지 않는다. 원시 실행은
`.cache/fmnist/official-oracle-individual-artifact-10round-seed0/`에 있다
(저장소에서 ignored).

```bash
python3 -m experiments.run_fmnist_official --phase all \
  --output .cache/fmnist/official-oracle-individual-reproduce \
  --population 500 --participants 100 --aggregators 8 --rounds 10 \
  --attack-clients 20 --attack-rounds 5 7 10 --workers 8 \
  --modes aion_mgf_oracle mgf --partition-rng artifact \
  --cohort-sampling individuals
python3 -m experiments.export_fmnist_official \
  --source .cache/fmnist/official-oracle-individual-reproduce \
  --output docs/experiments/fmnist-flower-official-oracle-individual-reproduce
```
