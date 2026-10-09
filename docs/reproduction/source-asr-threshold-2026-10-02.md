# ASR 복원 임계값·잘못된 aggregate share 처리 보정

## 논문과의 불일치

[Aion 논문](https://www.usenix.org/system/files/usenixsecurity25-liu-yizhong.pdf)의
Algorithm 2는 ASR의 threshold를 `f+1`로 지정한다. Algorithm 3은 각
aggregate share를 commitment와 검증하고 **유효한 share 집합**이 threshold에
도달했을 때 복원한다. AMR(Algorithm 5)로 바꾸는 수정이 아니다.

기존 learning adapter는 초기 randomized VSS와 복원에서
`max(2, committee_size // 3)`을 사용했다. BFT의 fault bound는
`f=(committee_size-1)//3`이므로 위원회 7·8·10명에서 잘못된 임계값이었다.

| 위원회 수 | BFT f | 기존 threshold | 새 learning threshold |
| --- | ---: | ---: | ---: |
| 4 | 1 | 2 | 2 |
| 7 | 2 | 2 | 3 |
| 8 | 2 | 2 | 3 |
| 10 | 3 | 3 | 4 |

새 learning 작업에는 `sharing_profile.threshold_rule=bft-f-plus-one-min-two-v1`
및 명시적인 `threshold`를 고정한다. 초기 share의 다항식 차수, 초기 수신
commitment 차수 검사, aggregate key 복원이 모두 같은 설정을 사용한다.
알 수 없는 규칙/잘못된 숫자는 actor state 변경 전에 거부한다.

Pedersen adapter는 n=2/3에도 최소 2-share를 유지한다. 이때 f=0이며
논문의 t=1과 같은 설정이라고 주장하지 않는다. n<4의 Byzantine tolerance를
제공하는 수정도 아니다. 원본 ones-vector benchmark와 과거 metadata 없는
encrypted 작업은 명시적으로 기존 threshold 동작을 유지한다. 과거 결과를
새 threshold로 성공한 결과처럼 재분류하지 않는다.

## Algorithm 3의 유효 집합 처리

새 profile의 `recover_key_opening`은 sender/context/signature/recipient
encryption/VSS 검증에서 실패한 packet을 유효 share 집합에 넣지 않는다.
동일 commitment에 대해 서로 다른 committee index가 t개 이상 있어야 한다.
반복된 packet은 한 share로만 센다. 잘못된 commitment group 하나가 먼저
도착했다고 정상 group을 버리거나 임의의 group을 선택하지 않는다.

서로 다른 group이 각각 threshold에 도달하면 실패한다. 정상 동작과 일관된
초기 commitment를 가정할 때, t=f+1이므로 f명의 악성 sender만으로 새로운
group을 복원 대상으로 만들 수 없다. 초기 VSS dealer의 모든 equivocation을
해결했다는 증명은 아니다. 최종 합계 opening은 기존 committee-local
commitment 대조와 BFT② 전에 수행하는 numeric replay도 통과해야 한다.

기존 키 share의 선택 합계만 복원한다. 새 share, 개별 업데이트/키 노출,
개별 키 탐색, 숫자 실패 시 plaintext fallback을 추가하지 않았다.
HPRF 출력·스케일링·masked VECTOR·MGF 선택 규칙은 바꾸지 않았다.

이 개선은 **이미 수신한 share의 검증/복원**에 한정한다. 현재 Flower
workflow는 모든 요청 actor의 응답을 요구하므로, silent/offline committee나
Flower error reply가 있어도 전체 workflow가 반드시 진행한다는 주장은 하지
않는다. HotStuff view-change/전체 부분 동기 liveness를 구현한 것도 아니다.

## 검증

테스트는 다음을 포함한다.

- n=2/3/4/7/8/10의 share 차수·threshold·여러 유효 subset 복원.
- threshold 미만 또는 같은 share를 반복한 집합의 복원 거부.
- 변조된 signature/ciphertext/members/recipient와 올바르게 서명했지만
  VSS가 틀린 packet을 제외한 뒤 정상 share로 복원.
- n=7에서 악성 sender 2개의 별도 유효 commitment group은 t=3에
  도달하지 못하며 정상 집계 키를 바꾸지 못함.
- 두 qualifying commitment group이 있으면 입력 순서와 무관하게 거부.
- 과거 n=7 encrypted transcript는 t=2로 재현하며 legacy strict rejection 유지.
- Flower Message worker pool의 n=7 통합 시험에서 aggregate share 2개의
  signature를 변조해도 실제 ASR→위원회 재검증→BFT②→학습 대조가 완료됨.
  초기 shares 140, 추가 masks 0, 모델 오차 0. silent actor 시험은 아님.

기존 MGF/VSS/BFT/source/Flower 연결을 포함한 관련 회귀는 **239개 통과,
90.40초**다. 이후 offline verifier에도 threshold profile 검사를 연결하고
`key_reconstruction_threshold`와 rule을 결과에 명시했다. 그 수정 후
sharing/official/aggregate 검증을 묶은 **92개가 39.57초에 통과**했고,
잘못된 profile의 actor/offline 선제 거부 7개도 확인했다. 시험 범위가
겹치므로 수를 합산하지 않는다. compileall과 `git diff --check`도 통과했다.

## 공식 Flower 실행

| 실제 위원회 | round | 공식 run ID | terminal | workflow 시간 | 초기 shares | 추가 masks | 재학습 오차 |
| --- | ---: | --- | --- | ---: | ---: | ---: | ---: |
| 4 | 4 | 5852870417429538798 | finished:completed | 30.604610초 | 80 | 0 | 0 |
| 7 | 1 | 17894051157477854720 | finished:completed | 27.958351초 | 140 | 0 | 0 |

두 작업은 synthetic 학습이며, 실제 FMNIST의 장기 carry 문제가 해결됐다는
증거가 아니다. n=7 작업은 aggregate replay receipt 7개와 선택된 학습
2회의 정답을 대조했다. n=4 작업은 receipt 16개와 학습 8회를 대조했다.

결과 위치:

- `.cache/source-asr-threshold-seven-official-20261002/`: 이름과 달리 실제
  manifest의 위원회는 **4명**이다. committee override 없이 먼저 실행한
  호환성 대조이며 7명 검증으로 집계하지 않는다.
- `.cache/source-asr-threshold-seven-corrected-official-20261002/`: 명시적으로
  `--committee 7`을 지정한 새 작업이다. 첫 작업을 덮어쓰거나 재시작하지 않았다.

`experiments.run_source_asr_official --committee`는 prepared의 공개 workload
설정만 유지하면서 새 위원회 크기와 task/identities/key를 생성한다. 범위
밖의 값은 staging 전에 거부하며 기존 준비/실험 결과는 변경하지 않는다.

```bash
PATH="$PWD/.cache/flower-deps/bin:$PATH" \
PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m experiments.run_source_asr_official \
  --prepared .cache/source-aggregate-replay-ten-round-fixed-20261002 \
  --output .cache/NEW-source-asr-threshold-seven --committee 7 --workers 4 --rounds 1

PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m experiments.verify_source_learning --run .cache/NEW-source-asr-threshold-seven
```

## 남은 핵심

threshold/VSS 검증과 scaled-MGF의 carry 모호성은 별개의 문제다. 이 변경으로
논문 Algorithm 3과 새 learning 복원의 대응을 보강했지만, 일반적인 실제
학습 SUM의 유일한 복원, CCS/VRF, 모든 부분 동기 상황의 진행, HPRF 보안
증명이 완료된 것은 아니다. 전체 활성 목표는 계속 미완료다.
