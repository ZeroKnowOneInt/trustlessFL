# 동일 조건 Flower 비교: 마스킹 MGF 대 무방어 집계

N=100/q=20, aggregator 4개, worker 4개, seed 0, 공격 client 4명, 공격 라운드 1·4의 공식 Flower 4라운드 실행을 비교했다. 방어는 마스킹된 classifier MGF와 AION-ASR, 대조군은 후보 20명 모두를 집계하는 평문 양자화 경로(`quantized`)다.

`compare_fmnist_official`이 실제 training catalog와 manifest에서 학습률·양자화·epoch·batch·device·공격 설정을 읽고, checkpoint·분할·입력 파일 hash·poison pool·참여 일정·훈련 소스 hash까지 같은지 검사했다. 양쪽 실행을 다시 검증한 뒤 결과를 생성했다. 비교 조건이 다르면 결과 생성을 거부한다. 새로운 staging부터는 training catalog hash와 학습 hyperparameter도 provenance에 기록한다.

| 라운드 | MGF 정확도 | 무방어 정확도 | MGF 공격 성공률 | 무방어 공격 성공률 |
|---|---:|---:|---:|---:|
| 0 | 88.56% | 88.56% | 0.390625% | 0.390625% |
| 1 | 88.42% | 10.03% | 1.562500% | 100.000000% |
| 2 | 88.64% | 68.64% | 1.562500% | 94.726563% |
| 3 | 88.74% | 78.10% | 1.367188% | 94.921875% |
| 4 | 88.82% | 64.92% | 1.367188% | 46.484375% |

MGF는 매 라운드 정상 client 2명을 선택했다. 이 실행에서는 model-replacement 공격의 영향이 무방어보다 작았지만, 단일 seed·축소 규모·4라운드 결과이므로 일반적인 방어 성능으로 확대하지 않는다. 두 경로는 각자 집계한 모델로 다음 라운드를 학습하므로 공격 라운드 1 이후의 local update 자체는 같지 않다.

ServerApp 내부의 초기화·학습·집계·모델 저장 시간은 MGF 644.57초, 무방어 26.28초였다. CLI/Ray 기동과 실행 후 평가·검증은 제외한다. 현재 연구 구현의 계산·통신 최적화가 남아 있으며, 이 수치를 논문의 순수 집계 비용으로 해석하지 않는다.

방어의 구현·threshold·검증 범위는 [4라운드 보고서](../fmnist-flower-masked-artifact-bound-four-round-2026-09-30/report.md)에 기록했다. privacy 증명이나 논문 시간·통신량 재현 결과로 해석하지 않는다.

```bash
python -m experiments.compare_fmnist_official \
  --defense .cache/fmnist/official-masked-artifact-bound-four-round-seed0 \
  --control .cache/fmnist/official-quantized-artifact-bound-control-four-round-seed0 \
  --output docs/experiments/another-matched-comparison
```

`results.json`은 두 실행의 곡선·선택 수·선택 공격자, 비교 조건 digest와 provenance·verification hash를 포함한다. 조건 hash는 비교 당시 실제 training catalog에서 산출했으며, 기존 방어 실행에 없었던 staging-time catalog hash를 소급해서 제공하는 것은 아니다.
