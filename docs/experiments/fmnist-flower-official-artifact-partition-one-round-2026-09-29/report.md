# 공식 Flower: 원본 순서의 FMNIST 분할 1라운드 확인

원본 `ImageHelper.sample_dirichlet_train_data`의 class 첫 등장 순서와
`Trainer.__init__`의 정상 참여자 150명 사전 추첨을 반영한
`--partition-rng artifact`로 N=500, q=100, aggregator 8개, 악성 client
20명, seed 0, 공격 1라운드를 실행했다. Fashion-MNIST 60,000장 중
59,941장이 중복 없이 배정됐다. 이전 `legacy` 분할과 배정 수는 같지만
client-0 인덱스 해시는 `6501e11f01f3680a1eae5a42cda8ee2b9d7492f41279e666311858c1f56b6a7a`로
달라졌다.

공식 Flower 1.36.0 SuperLink/Ray Simulation Runtime에서
`aion_mgf_oracle`와 평문 MGF가 같은 client 집합을 선택했고 악성 client는
0명 포함됐다. 둘 다 최종 정확도 88.58%, ASR 0.390625%였으며 모델 최대
좌표 차이는 3.54×10⁻⁷이다. 내부 실행 기록은 각각 73.3초와 19.5초다.
[검증 요약](results.json)은 원시 결과·모델·입력 provenance의 해시를 연결한다.

이 실행은 분할 수정의 1라운드 통합 검증이다. 10라운드 곡선은
`--partition-rng legacy`로 만든 [기존 결과](../fmnist-flower-official-oracle-mgf-ten-round-2026-09-29/report.md)다.
`aion_mgf_oracle`는 classifier 평문 좌표를 coordinator에 공개하며 보안 MGF가
아니다. 원시 실행은 `.cache/fmnist/artifact-partition-stage-smoke-20260929/`에
있다(저장소에서 ignored).

```bash
python3 -m experiments.run_fmnist_official --phase all \
  --output .cache/fmnist/artifact-partition-reproduce \
  --population 500 --participants 100 --aggregators 8 --rounds 1 \
  --attack-clients 20 --attack-rounds 1 --workers 8 \
  --modes aion_mgf_oracle mgf --partition-rng artifact \
  --cohort-sampling groups
```
