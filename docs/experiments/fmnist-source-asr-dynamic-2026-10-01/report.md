# 소스 ASR의 동적 참여: 모집단 100명, 라운드별 10명

2026-10-01. 새 소스 ASR 학습 경로에서 고정 cohort 제약을 제거했다.
미참여자는 학습 요청을 받지 않으며, 재참여자는 기존 키/share를 유지하고
직전 모델의 정상 경로 commit을 검증한 뒤 학습한다. 클라이언트에서 마스킹한다.

원본 학습 코드의 개별 참여 규칙을 별도 seed=0 RNG로 사용했다. 공격 라운드
1·4에는 공격자 0·1을 포함하고, 다른 라운드는 benign 모집단에서 추출했다.
전체 저자 RNG transcript, CCS/VRF 또는 논문 전체 실험의 재현은 아니다.
원본 ASR MMF의 큰 mask norm 문제도 아직 남아 있다.

## 초기화와 실제 학습

모집단 100명, committee 4명, 별도 aggregator 1명. VSS share는 학습 전
전체 모집단에 대해 400개를 한 번 전달한다. 재참여·선택 집합 변경 시 새 키나
좌표별 mask share는 추가하지 않는다. 이는 population upfront 초기화 정책이며
q=10만 초기화한 통신량 40개라고 표시하지 않는다. 고정 키를 서로 다른 선택
집합에서 재사용할 때의 차분 노출도 해결됐다고 주장하지 않는다.

저자 100-way FMNIST 분할, reference checkpoint, LeNet 61,706좌표,
소수 6자리·max_abs 100, author-loader, 2 epoch·batch 64·lr 0.001.
업데이트의 정수 인코딩·마스킹·원본 MMF·복원·모델 commit은 기존 소스 경로다.

공통 staged 온라인 cohort:

| round | client IDs |
| --- | --- |
| 1 | 0, 1, 51, 99, 55, 7, 35, 67, 64, 53 |
| 2 | 40, 63, 47, 76, 29, 66, 19, 38, 98, 14 |
| 3 | 81, 34, 70, 92, 79, 20, 41, 14, 95, 11 |
| 4 | 0, 1, 89, 44, 62, 73, 14, 47, 57, 42 |

オンライン commit의 population 비트맵과 선택 집합을 이 schedule에 대조한다.

## 실행 결과

| 실행 | 최종 정확도 | 최종 공격 ASR | workflow 시간, 평가 제외 |
| --- | ---: | ---: | ---: |
| 로컬 독립 ProcessGrid | 88.26% | 0.1953125% | 37.9896초 |
| 공식 Flower SuperLink/Ray, worker 2개 | 10.00% | 100.00% | 102.3045초 |

두 실행 모두 키 share 400개·추가 mask share 0개, 4개의 최종 모델 commit을
완료했다. 다만 개인 mask seed와 committee seed는 별도 생성됐으므로 동일
난수 조건의 transport 대조는 아니다.

로컬 선택은 `[7,51,67,35]`, `[76,29,38,40]`, `[92,70,79,14]`,
`[42,47,14,89]`이었다. 이 실행에서 두 공격자가 제외됐지만 방어가 해결됐다고
해석하지 않는다. 전체 모델 재학습 대조 16회, 최대 오차 0(허용 1e-12)을 확인했다.

공식 Flower 선택은 `[67,51,99,64]`, `[66,63,40,19]`, `[92,41,70,79]`,
`[1,62,57]`이었다. 4라운드에서 공격자 1을 선택했고 정확도가 붕괴했다.
Flower run ID는 `13082306539161190452`, 상태는 `finished:completed`,
CLI wall time은 113.1060초다. 원본 MMF의 방어 실패가 재현됐다.
선택된 client의 재학습 15회로 전체 평균·모델을 대조했고 최대 절대 오차는
0(허용 1e-12)이었다. 초기·온라인·최종 commit 증명도 검증했다.
결과는 실행의 `verification.json`에 기록했다.

## 원본과 MGF의 차이를 추가 확인

논문 Algorithm 6은 작은 마스크 범위와 evolving bound를 서술한다.
[원문](https://www.usenix.org/system/files/usenixsecurity25-liu-yizhong.pdf)의
Algorithm 6/7/8과 source ASR의 수치 표현을 별개로 대조한다. 원본 학습 소스는
중앙에서 individual SHPRG mask 합을 계산하지만, ASR은 sum key로 HPRF를 생성한다.
bounded 실수 표현으로 바꾸면 기존 모듈러 carry 복원과 같지 않다.

`test_original_large_ring_norm_can_ignore_maximum_learning_perturbation`은 공개
합성 키의 원본 HPRF로 실제 norm 필터를 호출한다. max_abs 100·decimals 6·
padding 100에서 허용된 최대 업데이트 항을 한 client에 더해도 선택 집합이
그대로인 구체적인 입력을 확인했다. 모든 seed나 공격의 실패 증명은 아니지만,
단순히 float64 대신 정수 집계를 쓰는 것만으로 MGF까지 고쳐지지 않는다는 증거다.

클라이언트 마스킹·정확한 bounded MGF·추가 share 제거를 동시에 완료했다고
주장하지 않는다. 추가 share 경로, 중앙 평문 baseline 또는 원본 MMF 유지 사이의
우선순위는 사용자에게 요청했다. 새 암호 프로토콜을 임의로 도입하지 않는다.

## 보존된 실행과 명령

- `.cache/author-asr-source-dynamic-fmnist-100-10-four-round-20261001`
- `.cache/author-asr-official-dynamic-fmnist-100-10-four-round-20261001`

```bash
PYTHONPATH=.cache/author-asr-deps:.cache/flower-deps:.cache/torch-deps:. \
  python3 -m experiments.run_author_asr_flower \
  --output .cache/NEW-source-dynamic --workload fmnist \
  --fmnist-inputs .cache/fmnist/official-original-single-view-mgf-attack-four-round-20261001/inputs \
  --clients 100 --participants 10 --committee 4 --workers 4 \
  --rounds 4 --attack-clients 2 --attack-rounds 1 4

PATH="$PWD/.cache/flower-deps/bin:$PATH" \
PYTHONPATH=.cache/author-asr-deps:.cache/flower-deps:.cache/torch-deps:. \
  python3 -m experiments.run_source_asr_official \
  --prepared .cache/NEW-source-dynamic --output .cache/NEW-source-dynamic-official --workers 2
```

로컬 CLI는 큰 population에서 기본 worker 4개를 사용하도록 수정했다. 위 완료
로컬 실행은 이 수정 전에 독립 101 프로세스로 실행된 결과다. worker 공유 정책의
4/20라운드 합성 평균 재현은 별도 시험이며, worker pool과 독립 프로세스의
FMNIST 시간 비교 결과라고 표시하지 않는다.

최종 관련 회귀는 55개 통과·deprecation warning 2개, 95.13초였다. 고정 source
경로, 동적 4/20라운드·독립/pooled transport, 재참여, enrollment 재시도,
부적합 cohort 거부, 공식 staging의 schedule 확장과 기존 HPRF 시험을 포함한다.
전체 저장소 테스트를 모두 실행했다는 의미는 아니다.
