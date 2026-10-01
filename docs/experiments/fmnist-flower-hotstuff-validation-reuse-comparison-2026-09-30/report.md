# Flower 마스킹 MGF·HotStuff와 무방어 학습 대조

두 공식 Flower 실행의 입력 hash, checkpoint·분할·poison pool, 공격 및 참여 일정, 학습 seed·epoch·batch·lr·공격 설정, 양자화 자리수와 worker 수를 비교했다. 모델·인증서·선택 및 지표를 각각 다시 검증했다. 실제 학습 catalog와 학습 소스 hash도 확인했다. 조건 digest와 두 provenance·verification hash는 `results.json`에 있다.

| 라운드 | MGF 정확도 | 무방어 정확도 | MGF 공격 성공률 | 무방어 공격 성공률 |
|---|---:|---:|---:|---:|
| 0 | 88.56% | 88.56% | 0.390625% | 0.390625% |
| 1 | 88.23% | 10.03% | 0.390625% | 100.000000% |
| 2 | 88.30% | 68.64% | 0.390625% | 94.726563% |
| 3 | 88.38% | 78.10% | 0.390625% | 94.921875% |
| 4 | 88.52% | 64.92% | 0.390625% | 46.484375% |

N=100/q=20, 집계자 4개, 학습 seed 0, 공격 client 4명이며 공격 라운드는 1·4다. MGF는 정상 client 2·2·2·4명을 선택했고 무방어는 매번 20명 전체를 집계했다. 필터링 때문에 모델 궤적은 달라지는 것이 정상이다. MGF 경로는 HotStuff를 사용하지만 평문 양자화 대조군은 사용하지 않으므로 학습 조건 일치와 프로토콜 비용 일치를 구분한다. 두 총 시간을 공정한 암호·합의 성능 비교로 쓰지 않는다.

원시 실행은 `.cache/fmnist/official-masked-artifact-bound-hotstuff-validation-reuse-four-round-seed0`와 `.cache/fmnist/official-quantized-artifact-bound-control-four-round-seed0`다. 비교 명령은 `python -m experiments.compare_fmnist_official --defense <첫 경로> --control <둘째 경로> --output <새 경로>`다. 이 짧은 단일-seed 결과는 장기 또는 일반적인 공격 방어·프라이버시 성능을 입증하지 않는다. [MGF 실행·코드·시간 상세](../fmnist-flower-hotstuff-validation-reuse-four-round-2026-09-30/report.md)에 추가 한계를 명시했다.
