# 원본 float32 norm·wire 정밀도 대조와 비공개성 실패

## 원본 대조

학습 E2의 `roles/aggregation_rules.py`는 선택된 업데이트의
`float().mean(dim=0)`를 계산하고 그 결과에 `torch.norm(..., inf).item()`을
적용한다. `roles/server.py`의 업데이트는 local parameter minus global
parameter이며, 다음 scale은 최종 모델 자체가 아니라 선택 업데이트 평균의
classifier norm에서 나온다. 공개 모델 norm으로 바꿔야 한다는 근거는 없다.

현재 decimal source adapter는 선택 평균을 정확한 Fraction으로 유지하고
scale 적용 후 wire를 DMC 정밀도(이 설정에서 decimal 8)로 반올림한다.
float32 norm 및 post-scale 정밀도를 분리해 조사했다. 이것은 원본과의
표현 차이 조사이며 모든 E2 연산을 bit-exact 재현했다는 주장이 아니다.

## exact-rational 후보: 집계 성공, 비공개성 실패

공개 실패 norm 253/40000을 float32로 표현하면 6791417/1073741824다.
이 norm과 정확한 scaled mask 표현의 조합은 원본 키 fixture의 선택 2/4/10명,
10라운드·32좌표 집계를 모두 정확히 복원했다. 그러나 공개 wire만으로 개별
업데이트가 드러났다. 비공개 집계 경로로 채택할 수 없다.

공개 wire를 공통 정수 분모로 나타내면 `Y = E*x + C*h`다. x는 모델 격자의
정수 업데이트, h는 [0,p]의 HPRF 값이고 E,C는 공개 값이다.
`g=gcd(E,C)`일 때 공개 연산으로
`h mod (E/g) = (Y/g) * inverse(C/g) mod (E/g)`를 계산할 수 있다.
허용 범위에 h가 하나만 남으면 x도 `(Y-C*h)/E`로 복원된다.
비밀 key, matrix 검색, VSS share 또는 aggregate key가 필요 없다.

`.cache/author-scale-wire-precision-privacy-20261001.json`의 exact 후보 전체에서
개별 업데이트 **20,480/20,480좌표**가 공개 연산으로 복원됐다.
rounded-wire에 대한 tested=0은 이 exact 식을 적용하지 않았다는 뜻이지
rounded-wire의 비공개성을 증명한다는 뜻이 아니다.

실험 중 exact 후보의 local Flower 10라운드도 실행됐다:
`.cache/source-paper-author-precision-clean-ten-round-20261001/`.
runtime 127.246초, 최종 정확도 88.54%, 추가 mask-share 0개다.
이는 **비공개성 실패로 기각한 수치 trial**이며 목표의 성공 결과가 아니다.
선택 학습 전체의 offline 재검증이나 공식 SuperLink 실행을 주장하지 않는다.
원본 기록은 삭제/덮어쓰지 않았다.

해당 Flower 연결, CLI flag와 payload 확장은 제거했다. source provisioning,
codec 및 기존 manifest의 actor 실행에서도 exact-scale 설정을 거부한다.
개별 비밀 상태를 만들거나 학습하기 전에 거부하는 회귀 테스트를 추가했다.

## 유한 정밀도 후보: offline 검증만

별도 `finite_precision_audit`는 exact 표현 대신 decimal 16으로 wire를
반올림한다. beta, 원본 HPRF, 모델 decimal 6 및 물리적 mask 범위는 유지한다.
wire 정밀도는 기존 decimal 8과 다른 **명시적 연구 후보**다. 이것을 논문이
요구한 정밀도나 보안 검증된 float64 구현으로 표시하지 않는다.

`.cache/author-scale-finite-wire-precision-20261001.json`에서 같은 실패 norm의
float32 표현은 선택 2/4/10명 각각 10라운드·32좌표가 정확히 복원됐다.
정확한 분수 norm은 계속 실패했다. 틀린 합을 받아들인 경우는 0이다.
추가 share는 없다. 이 시점에는 아직 Flower에 연결하지 않았고 입력 비공개성도 검증되지 않았다.

후속 검증에서 유한 후보도 **작은 원본 scalar key domain의 공개 탐색으로
개별 업데이트가 복원돼 기각**했다. 기존 decimal8 표현에도 같은 종류의
공격이 재현됐다. 따라서 keyless 복원 검사의 결과는 이 후보를 채택할 수
없다는 것이다. [키 범위·finite wire 후속 감사](source-keyspace-privacy-2026-10-01.md).

후속 조건은 finite wire의 keyless 입력 복원 가능성과 반올림·carry 정합성을
함께 검증하는 것이다. 단순한 집계 성공만으로 채택하지 않는다. 기존 bounded
decimal Flower의 공식 clean/공격 4라운드 결과와 10라운드 실패는 그대로 유지한다.
