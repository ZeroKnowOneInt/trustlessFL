# Flower FMNIST: 원본식 threshold의 마스킹 MGF 4라운드

공식 Flower 1.36.0 SuperLink/Ray CPU runtime에서 `aion_mgf_beta --mgf-projection --mgf-percentile --mgf-artifact-bound`의 공격·회복 4라운드를 완료했다. classifier 평문을 coordinator에 공개하지 않고 마스킹된 840좌표로 선택하며, 전체 61,706좌표를 AION-ASR로 집계한다.

## 조건과 검증

- N=100, q=20, aggregator 4개, seed 0, CPU worker 4개
- 공격 client 4명, model-replacement 공격 라운드 1·4를 명시적으로 지정
- 원본 FashionMNIST/LeNet5 checkpoint, artifact식 분할·poison RNG와 개별 client 추첨
- local epoch 2, batch 64, lr 0.001; 공격 steps 120, boost 20, poison batch 6
- 초기 alpha 0.1, beta 0.1; percentile 초기화 및 10~80% 선택 수 제한
- 매 라운드 정상 client 2명 선택; 선택된 공격 client 0명
- Flower ServerApp 내부 측정 시간 644.57초, 약 10분 45초. 초기화·학습·집계·모델 저장을 포함하며 순수 집계 시간이 아니다. CLI/Ray 기동과 실행 후 평가·검증 시간은 별도다.

전체 후보의 합계 key share는 aggregator 수신자별로 암호화하고, 동일 후보 집합의 승인 정족수를 확인한 뒤 aggregator 내부에서 합계 키를 복원한다. 공개되는 cohort mask norm의 정족수 인증서를 roster에 포함한다. 첫 3라운드에는 실제 percentile threshold를 저장하며, 4라운드에는 최근 두 집계 norm과 전체 후보 mask norm으로 다음 식을 적용했다.

```text
b_current = b_previous * (norm_latest + mask_linf_current)
                         / (norm_older + mask_linf_previous)
```

4라운드의 실제 threshold는 `0.010437575902`였다. 실행 후 verifier가 후보 서명·집합·norm 인증서·선택·모델 인증서를 검증하고, 저장된 모델 변화에서 양자화한 집계 정수를 복원해 norm history와 다음 alpha를 재계산했다. 이 강화된 verifier로 실행을 다시 검증했다.

## 학습 결과

| 라운드 | 정확도 | 공격 성공률 | 선택 수 |
|---|---:|---:|---:|
| 0 | 88.56% | 0.390625% | — |
| 1 | 88.42% | 1.562500% | 2 |
| 2 | 88.64% | 1.562500% | 2 |
| 3 | 88.74% | 1.367188% | 2 |
| 4 | 88.82% | 1.367188% | 2 |

[동일 조건의 무방어 양자화 대조군 비교](../fmnist-flower-masked-artifact-bound-comparison-2026-09-30/report.md)도 별도 공식 Flower run으로 완료했다. 두 경로의 모델 궤적은 의도적으로 다르며, 같은 모델이라는 검사를 적용하지 않는다.

## 재현과 범위

실행 명령은 [실험 README](../../../experiments/README.md#마스킹된-classifier-mgf와-원본식-threshold)에 있다. 원시 실행은 `.cache/fmnist/official-masked-artifact-bound-four-round-seed0`에, 모델·실행·검증 hash는 이 폴더의 `results.json`에 보존했다.

이 실행은 N=500/q=100의 [기존 1라운드](../fmnist-flower-masked-percentile-paper-scale-one-round-2026-09-30/report.md)와 다른 축소 조건이다. client 분할에 이어 poison RNG를 사용하므로 평가 이미지 풀도 다르다. 이번 4라운드로 q=100의 다중 라운드 곡선, 여러 seed, 60라운드 재현 또는 논문의 집계 성능을 주장하지 않는다. HotStuff도 이번 공식 실행에서는 비활성화했다.

세 연구 HPRF backend의 process pool 대조 시험에서는 동일 masked probe와 동일 cohort mask norm을 원본식 `ArtifactMGF`에 넣어 4라운드 threshold·선택·history를 비교했다. 현재 고정소수점 계산과 연구 HPRF의 난수·행렬·모듈러스는 원본 float32/SHPRG 실행과 다르다. 작은 bounded mask의 정보 노출, 개별 악성 client의 mask 일치 증명, LWE 보안 파라미터와 완전한 BFT 진행 보장은 별도 한계로 남아 있다.
