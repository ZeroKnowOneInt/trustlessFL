# MGF 이력 기반 판정: 최소 인원 강제 채움·80% 제한 제거

## 실제 필터에서 찾은 차이

[논문 Algorithm 6](https://www.usenix.org/system/files/usenixsecurity25-liu-yizhong.pdf)의
Lines 5–8은 masked L2 norm이 해당 round의 bound 이하인 클라이언트를
통과시킨다. 통과자가 적다는 이유로 bound 밖의 클라이언트를 추가하거나,
통과자 수가 많다고 80%에서 잘라내는 규칙은 그 판정에 없다.

기존 `source_paper_numeric.select_masked`는 이력에서 bound를 계산한 뒤에도
`count=max(minimum,min(maximum,rank))`를 사용했다. minimum=10%, maximum=80%
이므로 다음 두 차이가 있었다.

- bound 안에 0~1명만 있어도 최소 2명을 골라 일부 bound 밖의 입력을 포함함.
- 20명 모두 bound 안에 있어도 최대 16명만 선택함.

이것은 carry 또는 수신/IPC 방식의 문제가 아니라 **필터 선택 규칙 자체의
불일치**다. 논문의 norm 판정과 artifact의 rank override를 혼동하지 않는다.

## 새 작업에 적용한 수정

fresh paper manifest에는 `paper_numerics.filter_rule=inclusive-historical-bound-v1`
을 넣는다. 이력 기반 단계인 round 4 이후에는:

1. 기존 두 committed history term으로 bound를 계산한다.
2. `sum(masked_integer_coordinate^2)/D^2 <= bound^2`를 정확한 유리수로 판정한다.
3. bound 안의 입력을 모두 선택한다. 80% 제한과 강제 채움은 적용하지 않는다.
4. 통과자가 2명 미만이면 `insufficient-valid`로 중단한다. singleton key
   release나 bound 밖의 입력 추가로 진행하지 않는다.

첫 세 round는 기존에 선언한 **E2 percentile bootstrap**을 그대로 유지한다.
이 초기화, classifier projection, selected-mean 학습 adapter와 실제 mask-SUM
history는 여전히 원본 논문의 모든 수식/전체 wire와 같은 구현이라고 주장하지
않는다. 이번 수정은 실제 이력 기반 단계의 Algorithm 6 bound 판정을 맞춘 것이다.

원본 HPRF·마스크 크기/스케일링·DMC 정밀도·초기 일회성 VSS는 변경하지 않았다.
추가 mask share, 개별 plaintext 전달, 키 탐색 fallback은 추가하지 않았다.
많은 입력이 통과해 carry 복원이 모호해져도 임의 답을 골라 진행하지 않는다.

## manifest·BFT·오류 연결

새 filter rule을 `FINAL_SUM.paper_numeric`에도 넣어 BFT② 인증서가 해당
rule과 집계 metadata를 함께 바인딩하도록 했다. 위원회가 같은 rule로 선택과
집계를 재계산하며, 다른 rule을 제안한 aggregate도 local replay에서 거부한다.
offline verifier는 manifest/metadata rule 일치 및 signed replay receipt를 검사한다.
VECTOR가 기록에 없는 결과의 norm을 오프라인에서 독립 재계산한 것이라고
표시하지 않는다.

공식/일반 Flower ClientApp은 닫힌 코드 `insufficient-valid`만 공개한다.
workflow는 이 코드를 carry의 `ambiguous`와 구분하고, selection 실패 뒤에
키 복원/BFT②를 계속 진행하지 않는다. exception text·key·mask·좌표값은
오류 응답에 넣지 않는다.

rule이 없는 과거 manifest는 `e2-ranked-minmax-v1`의 기존 의미로 검증한다.
명시적으로 해당 legacy rule을 지정한 재현 작업도 구분한다. unknown rule은
provisioning/actor/offline에서 거부하며 cached reply로 우회하지 못한다.
이전 staged package나 완료 결과는 변경하지 않았다.

## 검증 항목

- bound와 정확히 같은 값도 통과하는 inclusive 경계.
- 20개 후보 중 2/3/16/17/19/20개가 통과하면 그 입력을 모두 유지.
- 0~1명만 통과할 때 거부하며 입력 history는 변경하지 않음.
- legacy min/max 결과와 새 결과를 구분; bootstrap round 1~3은 유지.
- client-signed VECTOR를 받은 실제 source selection에서 모두 bound 밖이면
  pending aggregate·성공 reply를 만들지 않고 last committed round를 유지.
- 양쪽 Flower entrypoint의 닫힌 오류 코드와 workflow failure 분류.
- unknown filter rule 및 BFT② 전에 rule metadata 변조 거부.

기존 source/VSS/BFT/Flower와 수치 경로를 포함한 관련 회귀는 **259개 통과,
96.02초**다. 아래 실제 FMNIST 실패의 공개 스케일 재현 시험도 별도로
추가해 통과했다. compileall과 `git diff --check`도 통과했다.

## 공식 Flower synthetic 실행

`.cache/source-inclusive-mgf-four-round-official-20261002`:

- 공식 run ID `6904584388886915818`, terminal `finished:completed`.
- clients 20, committee 4, rounds 4, workers 4, dimension 8.
- workflow 시간 32.117477초, 초기 shares 80, 추가 masks 0.
- 선택 집합 `[0,3]`, `[2,1]`, `[2,1]`, `[2,1]`.
- aggregate replay receipt 16개; selected-training replay 8회; 모델 오차 0.
- round 4가 새 이력 기반 필터로 실행됐다. 이 작업의 실제 통과자는 2명이며,
  80% 초과/통과자 부족의 분기는 별도 경계·source tests에서 검증했다.

과거 `.cache/source-aggregate-replay-ten-round-fixed-20261002`도 read-only로
재검증했다. 10 rounds, 모델 오차 0, 추가 masks 0이며 verifier가 filter rule을
legacy로 표시했다. 새 규칙으로 수행한 10-round 결과로 재분류하지 않는다.

## 실제 FMNIST의 후속 실행: 미완료

`.cache/source-inclusive-mgf-fmnist-four-round-official-20261002`는 clients 20,
committee 4, local epochs 2, decimals 6, 전체 update 61,706좌표/classifier
projection 840좌표, beta 0.2의 새 공식 Flower 작업이다. 기존 공개 학습
설정/입력만 재사용하며 키·Context는 새로 생성했다.

- run ID `15708048047186839701`, terminal **finished:failed**.
- 3라운드 commit 후 round 4 `reconstruct`에서 **ambiguous**.
- workflow 시간 86.269052초. `results.json` 없음.
- commit된 선택은 `[17,12]`, `[15,4]`, `[15,4]`.
- 각 committed body의 rule은 `inclusive-historical-bound-v1`이다.

즉 round 4의 selection/첫 번째 BFT 뒤에 numeric 복원이 실패했다.
실패 기록을 보존하고 재시작하지 않았다. 최종 모델 정확도/방어 성능/4-round
학습 완료 또는 selected-training 전체 재학습 대조를 주장하지 않는다.

공개 round-3 `next_linf=541/400000`이므로 다음 mask period는
`P=541/2000000=0.0002705`, 모델 quantum의 **270.5배**다. 정수배가 아닌
경우에도 carry가 2만큼 다르면 541 quantum 차이로 다른 후보가 격자에
맞을 수 있다. 공개 fixture 키 `(4,16,20)`, round 4, 8좌표의 zero-update
합을 만들어 실제 mask capacity 안에서도 `ambiguous`를 재현했다.
이 fixture는 실패 작업의 실제 개인 키/누락된 round-4 선택 인원이 아니며,
그 실행의 private Context를 읽어 만든 것이 아니다. 해당 회귀는
`test_inclusive_fmnist_failure_scale_can_alias_larger_valid_cohort`다.

## 재현 명령

새 output 경로를 사용한다. 이전 완료/실패 작업을 덮어쓰지 않는다.

```bash
PATH="$PWD/.cache/flower-deps/bin:$PATH" \
PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m experiments.run_source_asr_official \
  --prepared .cache/source-aggregate-replay-ten-round-fixed-20261002 \
  --output .cache/NEW-source-inclusive-mgf --workers 4 --rounds 4

PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m experiments.verify_source_learning --run .cache/NEW-source-inclusive-mgf
```

전체 목표는 계속 미완료다. 새 bound 판정의 정확성이 scaled mask의 모듈러
carry를 결정해 주지는 않는다. 논문과 유사한 실제 학습 경로에서, 추가 share
없이 유일한 학습 SUM을 복원하는 문제는 별도로 남아 있다.
