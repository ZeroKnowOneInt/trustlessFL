# Fashion-MNIST: 원본식 기본 공격 확률 추첨의 Flower 10라운드

Flower 1.36.0 SuperLink/Ray CPU simulation에서 원본 Fashion-MNIST와
`avg_300.pth` LeNet5를 사용했다. N=500, q=100, aggregator 8개,
악성 client 20명, seed 0, Dirichlet alpha 0.5, 10라운드다.
59,941/60,000개 학습 행을 중복 없이 배정했다. 참여자는 개별 client로
추첨했다.

이번에는 `--attack-rounds`를 지정하지 않았다. 데이터 분할에 사용한 NumPy
난수기의 상태를 이어 사용하고 원본의 `uniform >= 1 - poison_prob` 조건으로
확률 0.5를 적용한 결과, 공격 라운드는 **1·2·5·6·7·10**이었다.
이전 [명시적 5·7·10 실험](../fmnist-flower-official-oracle-individual-ten-round-2026-09-29/report.md)과
공격 일정이 다르므로 동일 입력의 반복 결과로 비교하지 않는다.

| 항목 | `aion_mgf_oracle` | 평문 MGF |
| --- | ---: | ---: |
| 최종 test 정확도 | 88.62% | 88.62% |
| 최종 공격 성공률(ASR) | 0.390625% | 0.390625% |
| 10라운드 중 선택된 악성 client | 0명 | 0명 |
| 매 라운드 선택 client 수 | 10명 | 10명 |
| 내부 실행 시간 | 800.2초 | 73.1초 |

두 Flower 실행의 매 라운드 MGF 선택 목록과 정확도·ASR 곡선이 일치했다.
저장된 모델 이력의 최대 좌표 차이는 `1.6963448594935436e-06`이다.
검증기는 참여 일정, 저장된 모델과 MGF trace, AION roster·model
서명 정족수 및 부모 체인을 검사했다.
[해시 연결된 결과](results.json)에 입력 provenance와 두 실행의 해시를 남겼다.
원시 실행은 `.cache/fmnist/official-oracle-individual-default-rng-seed0/`에
보관한다(저장소에서 ignored).

`aion_mgf_oracle`은 보안 MGF가 아니다. 각 client의 classifier 840개
평문 좌표가 coordinator에 공개되고, 이 좌표와 masked 전체 update의
client별 정합성 증명은 없다. 원본 학습 중 Python 난수 호출과 다음 라운드
참여자 추첨의 정확한 interleaving도 재현하지 않았다. 60라운드 곡선이나
논문의 보안 성질을 이 결과로 주장하지 않는다.
공개 FMNIST 입력 검증 artifact도 서버가 client별 평문 전체 update를 받은 뒤
MGF를 계산한다. 따라서 이번 oracle은 **그 공개 실험의 선택 규칙**과 비교하기
위한 경로이며, artifact 자체가 보안 분산 집계를 증명한다고 해석하지 않는다.

```bash
PATH="$PWD/.cache/flower-deps/bin:$PATH" \
PYTHONPATH="$PWD/.cache/torch-deps:$PWD/.cache/flower-deps:$PWD" \
python3 -m experiments.run_fmnist_official --phase all \
  --output .cache/fmnist/official-oracle-individual-default-rng-reproduce \
  --population 500 --participants 100 --aggregators 8 --rounds 10 \
  --attack-clients 20 --workers 8 --modes aion_mgf_oracle mgf \
  --partition-rng artifact --cohort-sampling individuals
python3 -m experiments.export_fmnist_official \
  --source .cache/fmnist/official-oracle-individual-default-rng-reproduce \
  --output docs/experiments/fmnist-flower-official-default-rng-reproduce
```
