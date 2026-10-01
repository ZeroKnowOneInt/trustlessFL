# 새 소스 ASR 경로의 공식 Flower 실행

2026-10-01. 원본 ASR 함수를 실행하는 새 포팅 경로를 공식 Flower CLI →
SuperLink → Ray simulation에 연결했다. 기존 연구 프로토콜의 공식 Flower
실행 결과를 새 경로의 증거로 재사용하지 않고 새 task로 실행했다.
목표는 진행 중이며 논문 MGF의 공격 방어 재현은 아직 완료되지 않았다.

## 구현

- `aion_source_official.py`: simulation partition을 actor 설정에 대응시키고,
  node별 Context에 개인 키·일회성 VSS share·round 상태를 유지한다.
- `run_source_asr_official.py`: 공개 workload 설정에서 새 task·committee를
  구성한다. 이전 개인 상태는 복사하지 않는다. 준비된 원본 소스와 학습 입력의
  hash를 검증하고, 새 manifest·node catalog·Python 소스·FAB 설정 hash를 기록한다.
- FMNIST test/poison-test 입력도 실행 전에 hash로 고정한다.
- 현재 round의 큰 응답만 재시도 cache에 보관하고, 이전 round은 요청 digest만
  보관한다. 만료 요청은 재실행하지 않는다. 키와 VSS share는 정리하지 않는다.
  원본 계산 변경이 아니라 Ray Context 전송량을 제한하는 adapter 정책이다.
- 원본 ASR MMF·HPRF·일회성 키 공유·정상 경로 BFT는 유지했다.
  전체 view-change 진행 보장이나 원격 네트워크 측정은 아니다.

## 완료 실행

| workload | round | Flower run ID | 키 share / 추가 mask share | 재학습 모델 오차 |
| --- | ---: | --- | --- | ---: |
| synthetic | 4 | 6135302405076674431 | 40 / 0 | 0 |
| FMNIST 공격, bounded Context | 4 | 5043089410508037123 | 40 / 0 | 0 |
| FMNIST 공격, cache 정리 추가 전 snapshot | 20 | 3507944370804980247 | 40 / 0 | 0 |

각 공식 Flower run-status는 `finished:completed`다. 모든 FMNIST 실행은
저자 100-way 분할의 첫 10개 shard 고정 참여, committee 4명·aggregator 1명,
worker 2개, 소수 6자리 정수 학습 어댑터, 2 epoch·batch 64·lr 0.001이다.
공격자는 0·1, 공격 일정은 모두 1·4라운드다. 20라운드를 돌렸다고 해서
논문의 동적 참여 규모·장기 공격 일정까지 재현했다는 뜻은 아니다.

### FMNIST 4라운드

선택 집합은 `[5,1,0,3]`, `[1,5,0,6]`, `[1,5,0,6]`, `[1,5,0]`이었다.
두 공격자가 1·4라운드 모두 포함되었다. 최종 정상 정확도는 10.27%, ASR은
0%다. 정확도가 붕괴했으므로 ASR 0%를 방어 성공으로 해석하면 안 된다.
선택된 client를 15회 다시 학습한 전체 평균·모델 오차는 0(허용 1e-12)이었다.
초기 참여자·온라인 참여자·최종 모델의 commit 서명도 독립 검증했다.

workflow 시간은 54.2655초(평가 제외), Flower CLI wall time은 65.0734초였다.

### FMNIST 20라운드

마지막 정상 정확도는 84.78%, ASR은 81.0546875%였다. 첫 공격 라운드에서
공격자 0을 선택했고, 마지막에도 해당 공격 효과가 남았다. MMF의 방어 실패다.
workflow 시간은 465.6828초(평가 제외), CLI wall time은 485.9457초였다.
이 실행은 cache 제한 추가 전 snapshot이므로 4라운드와 시간을 나누어 성능
개선 비율을 계산하지 않는다. committee/mask seed도 새로 생성된 별개 실행이다.

선택된 client를 67회 다시 학습하여 20라운드 전체 평균·모델을 비교했고 최대
절대 오차는 0(허용 1e-12)이었다. 초기 참여자 1개·온라인 참여자 20개·최종 모델
20개의 commit 증명을 검증했다. 결과는 같은 실행 디렉터리의 `verification.json`에
기록했다. 계산 오차 검증과 필터 방어 성능 검증을 구분한다.

## 보존된 실행과 재실행

- `.cache/author-asr-official-synthetic-four-round-20261001`
- `.cache/author-asr-official-fmnist-bounded-state-four-round-20261001`
- `.cache/author-asr-official-fmnist-attack-twenty-round-20261001`

각 실행에는 manifest, source snapshot, node-configs, staging hash,
`attempt-*/commands.json`, Flower 로그·run-status·timing과 전체 결과를 보관한다.

```bash
PATH="$PWD/.cache/flower-deps/bin:$PATH" \
PYTHONPATH=.cache/author-asr-deps:.cache/flower-deps:.cache/torch-deps:. \
  python3 -m experiments.run_source_asr_official \
  --prepared .cache/author-asr-fmnist-attack-four-round-20261001 \
  --output .cache/NEW-source-official --workers 2 --rounds 20

PYTHONPATH=.cache/author-asr-deps:.cache/flower-deps:.cache/torch-deps:. \
  python3 -m experiments.verify_source_learning \
  --run .cache/NEW-source-official \
  --inputs .cache/fmnist/official-original-single-view-mgf-attack-four-round-20261001/inputs
```

현재 코드로 재실행하면 현재 round cache 제한을 사용한다. 공격 일정을 늘리려면
`--attack-rounds`를 지정한다. 기존 20라운드 결과의 공격 일정은 바꾸지 않는다.

관련 회귀 시험 46개 통과(75.14초) 후 cache 제한 변경에 대해 source/official
시험 19개가 다시 통과(30.20초)했다. 전체 저장소 시험 실행을 의미하지 않는다.
다음 핵심 과제는 큰 모듈러 마스크 위의 ASR MMF와 저자 학습의 bounded classifier
MGF 차이를 해소하는 것이다. 중앙 평문 MGF나 새 암호 설계를 원본 비공개 MGF로
표시하지 않는다.
