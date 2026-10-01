# 작업 목표 재설정: 저자 Aion 구현의 Flower 포팅

## 현재 활성 목표: 클라이언트 마스킹 기반 MGF 연결

사용자가 요구한 실제 경로는 client local update → 초기 일회성 키 공유와
round 기반 원본 HPRF masking → Flower masked-vector 전달 → masked MGF
filter → 선택된 key sum만 복원 → 집계 mask 제거다. 이 전체 경로의
scaled-mask MGF 정확성은 아직 완료되지 않았다. 아래 연구용 source 포팅과
중앙 plaintext artifact의 완료 기록은 이 목표의 완료 증거가 아니다.
추가 mask share를 보내거나 서버에 개별 plaintext update를 전달하는
우회 경로를 현재 목표의 성공으로 사용하지 않는다.

후속으로 현재 decimal wire와 bootstrap 필터를 함께 검사하는 공개 반례를
추가했다. 키 `(1,20000)`·입력 `(0.012087,0.007913)`과 키
`(94,19907)`·입력 `(0,0)`이 같은 개별 masked 값
`(0.01329224,0.01264423)`을 생성한다. 20명 후보의 동일한 filler를
추가하면 두 실행에서 같은 두 client가 선택되며 key sum도 20001로 같다.
실제 plaintext sum은 0.02와 0으로 다르므로 현재 numeric decoder는
`ambiguous`를 반환한다. norm filtering이나 소수 정밀도 검사만으로 이
반례의 누락된 carry를 결정할 수 없다.

이 반례는 1좌표 numeric decoder 입력에 관한 것이며, 두 실행의 개별 VSS
commitment는 다르다. 전체 protocol transcript의 동일성이나 모든 HPRF의
불가능성을 주장하지 않는다. 개별 키 탐색은 private aggregate 복원의
대체 방법으로 채택하지 않는다. 감사 코드
`experiments/audit_masked_mgf_collision.py`, 결과
`.cache/masked-mgf-collision-20261001.json`, source Flower 수치 경로를 포함한
관련 회귀 66개 통과. 컴파일 및 `git diff --check`도 통과했다.

다음 감사에서 원본 VSS의 고정 다항식 계수와 source Flower outbox의 평문
share 중계를 확인했다. 실제 원본 함수의 공개 fixture 단일 share 54개에서
모두 개인 키가 복원됐다. 일반적인 문턱 VSS의 비공개성을 이 source 경로에
적용할 수 없다. 새 manifest에 sharing profile을 명시하며, 원본 HPRF와
일회성 공유 구조를 유지한 무작위 VSS 계수·수신자별 암호화가 별도로 필요하다.
[원본 VSS 비공개성 감사](reproduction/source-vss-privacy-2026-10-01.md).

후속으로 새 learning 작업의 초기 공유를 randomized Pedersen VSS와
수신자별 암호화·client 서명으로 변경했다. 초기 개인 share는 committee만,
aggregate share는 aggregator만 복호화한다. 원본 HPRF·초기 일회성 공유·
추가 mask share 0개 구조는 유지한다. singleton 및 동일 round의 다른 subset
key release를 거부한다. 원본 benchmark/과거 manifest는 별도 legacy 기록이다.
관련 64개 회귀와 로컬 synthetic 4라운드 keys 40/extra masks 0/replay 19회
model error 0을 확인했다. private MGF carry 및 across-round cohort 보안은
계속 미완료이며 이 부분 수정으로 전체 목표를 완료하지 않는다.
공식 Flower fresh 4라운드도 runtime 26.235321 s, keys 40/extra masks 0,
15회 selected training replay model error 0으로 검증했다.

새 paper-scale 작업은 signed masked VECTOR와 위원회별 masked-filter
replay를 key release 앞에 연결한다. 이전 commit과 두 history term,
현재 client 서명/parent/scale을 확인하고 요청 명단이 독립 filter 결과와
다르면 첫 요청부터 key sum share를 거부한다. signed authorization receipt를
실행 history 및 offline verifier에 연결한다. 모든 전달은 Flower 메시지로
수행하며 node별 masked inbox를 사용한다. 추가 mask share와 개별 평문
전달은 없다. 이것은 selected key sum 공개 대상을 제한하는 진전이지
scaled-HPRF carry 문제나 악성 aggregate metadata의 증명을 해결한 것이
아니다. 전체 목표는 계속 미완료다.
[선택 명단 인증과 잔여 경계](reproduction/source-selection-authorization-2026-10-01.md).
최종 관련 회귀 77개 통과, 공식 Flower synthetic 1라운드 19.861095초,
초기 key share 80건/추가 mask share 0건/committee receipt 4개,
selected training replay 2회의 model error 0으로 검증했다. 이 짧은
조건부 복원 fixture를 장기 private MGF 완료로 해석하지 않는다.

후속 공식 fresh 10-round 시도는 3라운드 commit 후 4라운드 `reconstruct`의
`ambiguous`로 실패했다. 공개 next norm 1/1250은 다음 mask period가 정확히
160 model quanta가 되는 실제 학습 사례다. 실패한 run을 완료로 표시하지
않고 terminal failure 기록과 Flower 실제 run-state 검사도 추가했다.
[다중 라운드 실패와 필요한 완료 조건](reproduction/source-authorized-long-run-2026-10-01.md).

## 현재 작업 목표: 추가 share 없는 논문 수치 경로 재현 (2026-10-01)

최신 재개 작업은 원본 primitive를 교체하지 않고 연구용 Flower 포팅을
계속하는 것이다. 500명 모집단·100명 라운드 참여를 위해 원본 masked
VECTOR를 Flower 메시지로 분할 전달하는 inbox를 추가했다. 추가 mask
share나 평문 update 전달은 추가하지 않았다. 강제 분할 4라운드와
오프라인 모델 재계산이 일치하며, 기존 관련 테스트 51개가 통과했다.
이후 paper-scale 조건부 adapter도 분할 경로에서 검증했다(관련 25개
테스트 통과). 수정 후 전체 관련 회귀는 52개가 통과했다. 대규모 로컬
4라운드는 168.1151초에 완료됐으며 키 share 2,000건·추가 mask share 0건,
선택 학습 127회 재계산의 모델 오차 0을 검증했다. 새 통신 scheduling도
별도 공식 Flower synthetic 4라운드에서 모델 오차 0으로 대조했다.
500명·100명 참여의 공식 Flower 4라운드도 575.9410초에 완료했고,
68개 masked 메시지 묶음·일회성 키 share 2,000건·추가 mask share 0건을
확인했다. 선택 학습 123회 재계산에서도 모델 오차 0이다. 마지막 clean
정확도 47.41% 및 앞선 세 라운드 공격 성공률 100%를 함께 기록한다.
원본 MMF 실행을 classifier MGF 방어 재현으로 표시하지 않는다.
[500명 모집단 실행 기록](experiments/fmnist-source-asr-pop500-2026-10-01/report.md).

원본 ASR-MMF와 학습 artifact MGF의 차이는 별도 구조 감사로 고정했다.
원본 파일 4개와 핵심 함수 5개의 hash를 기록하고 15개 AST/source 데이터
흐름 조건을 검증했다. 학습 `aion()`은 서버 보유 평문 update에 별도
SHPRG mask를 더해 selection하고 선택된 평문 update를 평균하며, client-side
scaled-HPRF/DMC/DMR network 경로는 해당 함수에 없다. ASR simulator는
client HPRF masking·일회성 VSS·masked MMF·aggregate-HPRF removal을
수행하지만 학습 classifier MGF와 threshold 설정이 다르다.
[세 경로 소스 대조](reproduction/author-mmf-mgf-dataflow-2026-10-01.md).

논문 길이의 수치 재검증도 완료했다. 원본 HPRF 공개 fixture로 q=100,
60라운드, classifier 840좌표를 검사했다. 합계 비교 100,800좌표 모두에
modular carry가 있었고 literal DMR은 실패했다. carry 문제가 사라지는
raw-hmax 후보는 개별 wire 5,040,000좌표 전부가 단순 반올림으로 평문
복구됐다. normalized 후보의 bounded 복원 180회는 모두 모호성을 거부했다.
추가 share는 0이며, 실패한 후보를 학습 경로의 성공으로 표시하지 않는다.
[60라운드 수치 결과](reproduction/paper-dmc-no-extra-share-2026-10-01.md#논문-길이참여-규모-수치-재검증).

공개 학습 artifact도 저자 규모로 별도 검증했다. population 500,
participation 100, adversaries 20, author-loader의 공식 Flower 10라운드에서
저자 SHPRG/MGF는 최종 정확도 88.59%·ASR 0.5859375%, 무방어 quantized는
65.79%·0.78125%였다. 마지막 ASR만 보면 차이가 작지만, 학습 10라운드
평균 ASR은 MGF 0.5859375%, 무방어 60.078125%이고 무방어 최대 ASR은
100%였다. MGF는 매 라운드 공격자를 0명 선택했다. 이 결과는 중앙 평문
artifact 재현이며 secure MGF라고 표시하지 않는다. 같은 설정의 60라운드
확률적 공격 일정 실행도 별도 fresh task로 완료했다. 60라운드 중 30개가
공격 라운드였고, MGF는 최종 정확도 88.80%·평균 ASR 0.631510%·최대
ASR 0.78125%였으며 선택 공격자는 총 0명이다. 무방어 quantized는 최종
정확도 56.81%·평균 ASR 83.141276%·최대 ASR 100%였다. 두 경로의
12,000개 training metadata와 60라운드 trace를 검증하고 hash-linked
공개 요약을 만들었다.
[저자 규모 학습 보고서](experiments/fmnist-author-artifact-pop500-2026-10-01/report.md).

최종 전체 저장소 회귀는 소켓 허용 환경에서 554개 통과·4개 skip·실패
0개, 494.22초였다. sandbox 소켓 차단 실행은 완료 증거로 사용하지 않았다.
[요구사항별 완료 감사](reproduction/aion-flower-completion-audit-2026-10-01.md)에
구현 완료 범위와 CCS/VRF·EMA·private MGF·HotStuff 전체 liveness 등
명시적으로 재현하지 않은 경계를 함께 고정했다.

사용자가 추가 라운드별·좌표별 mask share를 명시적으로 금지하고 작업을
재개했다. 원본 HPRF 및 초기 일회성 키 공유를 유지하며 논문 Algorithm 6의
스케일링과 Algorithm 7/8 DMC/DMR을 재현·검증한다. 개별 평문 업데이트를
수집하거나 추가 share로 우회하지 않는다. 기존 Flower 실행 도구를 재사용하되
정확성이 확인된 조합만 학습 집계 경로에 연결한다.

아래 문단은 무추가-share 수치 경로를 처음 감사하던 당시의 작업 기준과
중간 결과를 보존한 이력이다. 당시 완료 조건은 (1) 정확한 수치 참조 구현,
(2) 원본 HPRF의 다중 키·라운드·
좌표 및 선택 부분집합 검증, (3) 추가 share 없는 Flower 경로의 실제 학습
집계 재검증이다. 반올림 오차, 모듈러 carry, 스케일링을 구분하고 실패를
숨기지 않는다. 새 목표 등록 도구는 기존 미완료 목표 때문에 교체를 거부했다.
기존 목표를 허위 완료 처리하지 않고 이 문서에 변경된 작업 기준을 기록한다.

첫 작업으로 exact-rational 참조 구현과 20라운드·840좌표 공개 fixture
감사를 완료했다. DMC-only의 명시적 modular 복원은 수치상 통과했지만
MGF의 작은 mask 조건까지 통과한 후보는 없다. raw 이중 스케일링은
wire 반올림으로 평문이 드러나므로 채택하지 않는다.
[수치 감사와 다음 완료 조건](reproduction/paper-dmc-no-extra-share-2026-10-01.md)을
참고한다. 추가 share를 도입하지 않았으며 이 시점에는 목표가 미완료였다.

후속 감사로 공식 v5 Python 130개 전체를 검증했다. 로컬과 일치한 119개와
원격 hash 검증한 11개를 모두 조사했으며, 명시적인 DMC/DMR precision
식별자를 발견하지 못했다. MGF의 실제 client-sum 호출과 sum-key 함수
정의를 구분했다. 논문 MGF history/bound 참조 계산도 추가했고 관련
테스트 34개가 통과했다. [전체 Python 대조 기록](reproduction/author-numeric-coverage-2026-10-01.md).
이 결과는 작은-mask 복원 문제의 해결이나 새 Flower 학습 완료가 아니다.

이어 양자화 격자로 carry 후보를 구분하는 추가-share 없는 조건부 수치
복원기를 구현했다. DMC wire 정밀도와 전송 반올림 오차도 반영했다.
20라운드·32좌표 감사에서 일부 실제 공개 aggregate 스케일은 정확히
복원됐으나 bootstrap=0.1 및 여러 선택 규모에서 모호성을 거부했다.
관련 테스트 48개 통과. 논문 Algorithm 8 그대로인 구현이 아니라 별도
수치 어댑터이며 아직 Flower 학습에 채택하지 않았다.
[조건부 복원 결과](reproduction/quantized-lift-2026-10-01.md).
다음은 공개 초기 모델의 실제 표현과 bootstrap 조건 대조다.

공개 초기 checkpoint hash를 검증해 전체/classifier norm을 직접 사용한
20라운드·840좌표 추가 감사에서 선택 2/4명은 모두 정확히 복원됐다.
선택 10명, 기존 ASR 초기값 0.1 및 저자 E2 초기값 1에서는 모호성이 남았다.
실제 checkpoint 초기화는 E2 고정 초기값과 다른 후보이며, 이를 숨기지 않는다.
[bootstrap 감사](reproduction/paper-bootstrap-2026-10-01.md).
다음은 조건부 경로의 실험 opt-in Flower 연결과 학습 commit 전 실패 처리다.

아래 blocked/선택 대기 기록은 사용자 재개 **이전**의 이력이다.

후속으로 조건부 수치 adapter를 명시적 opt-in으로 Flower에 연결했다.
공식 SuperLink/Ray의 clean 1라운드와 선택 클라이언트 재학습 대조를 완료했다.
원본 HPRF·초기 VSS를 유지하며 추가 mask share는 0개다. 선택 합 복원 이후
실제 decimal mask 합으로 history norm을 계산하도록 수정했다. 전체 cohort
norm 문제와 조건부 복원의 다중 라운드 실패는 해결된 것으로 표시하지 않는다.
clean 4라운드 실행은 reconstruct 3라운드에서 실패했다. 공개-safe 오류
범주와 실패 기록을 추가했다.
진단 fresh 실행은 3라운드 commit 후 4라운드에서 carry/양자화 모호성으로
중단됐다. 공개 scale에서 두 period가 모델 grid에 정확히 정렬되는 반례를
회귀 테스트로 고정했다. 조건부 adapter를 일반적인 완료 경로로 채택하지 않는다.
후속 grid-only preflight는 실제 mask 합의 범위를 누락한 과도한 거부였다.
이를 제거하고 후보별로 물리적 mask 합 범위를 먼저 검사하도록 수정했다.
기존 공개 실패 fixture가 정확히 복원되며, 실제 범위 내 모호성은 계속 거부한다.
새 clean 로컬 4라운드와 선택 학습 8회 재학습 대조가 완료됐다(모델 오차 0).
초기 key-share 80개, 추가 mask-share 0개이며 scale/HPRF는 변경하지 않았다.
관련 68개 및 기존 source/dynamic 18개 테스트 통과.
공식 SuperLink/Ray clean/공격 각각 4라운드도 완료했다. 공격자는 20명 중
4명이며 최종 정확도 88.60%, 공격 성공률 0.390625%, 추가 mask-share 0개다.
선택 전 cohort oracle 차이, 큰 선택 집합의 모호성 및 장기 검증은 여전히 남는다.
후속 clean 10라운드 fresh 실행은 1라운드 commit 후 2라운드에서 범위 내
모호성으로 중단했다. 공개 next-linf=253/40000의 period/grid 정렬을
원본 공개 키 fixture로 재현했다. 4라운드 결과는 유지하되 장기 복원 완료로
확대하지 않는다. 네 완료 실행의 재학습 대조 오차는 모두 0이다.
[실제 실행 기록](experiments/fmnist-source-paper-mask-bounds-2026-10-01/report.md).
원본 E2의 float32 평균/norm과 wire 정밀도를 후속 대조했다. exact-rational
후보는 local 10라운드 집계를 완료했으나 공개 연산으로 개별 업데이트가
복원돼 기각했다. Flower 연결을 제거하고 해당 manifest 설정도 거부한다.
유한 정밀도 후보는 offline 수치 검증만 완료했으며 비공개성 검증 전에는
학습 경로에 채택하지 않는다.
[표현·비공개성 감사](reproduction/author-scale-wire-privacy-2026-10-01.md).
유한 후보의 후속 key-domain 탐색에서도 원본 1..100000 scalar seed가
공개 wire로 좁혀졌다. current decimal8은 3좌표, finite16은 1좌표로 fixture
seed가 하나 남았으며 두 표현 모두 fixture의 개별 업데이트 2520/2520좌표가
복원됐다. finite 후보는 채택하지 않고 source manifest에 원본 연구 key
profile과 production_privacy=false를 추가했다. 키/primitive 교체는 원본
포팅 범위를 넘어서는 별도 결정이며 임의로 적용하지 않았다.
[후속 keyspace 감사](reproduction/source-keyspace-privacy-2026-10-01.md).
[구현·검증·남은 한계](reproduction/source-paper-mgf-norm-2026-10-01.md).

## 이전 상태: blocked — MGF 연결 방식 선택 대기

2026-10-01. 같은 연결 제약과 사용자 선택 미응답을 세 차례의 연속 목표 턴에서
확인한 후 목표 상태를 `blocked`로 변경했다. 목표 달성이나 사용자 요청에 의한
pause가 아니다. 현재 source sum-key decoder의 bounded carry 모호성 시험은
재실행에서도 통과했고, 공식 Flower 동적 실행은 완료됐지만 공격 방어는 실패했다.
공식 최신 소스 재대조에서도 현재 사용 메서드와 다른 복원 경로를 확인하지 못했다.

추가 share를 허용한 client-masked MGF, 중앙 평문 학습 baseline 또는
무추가-share MMF 유지 중 우선순위 선택이 필요하다. 선택 전에는 새 암호
프로토콜·개별 키 공개·원본 대비 통신 비용 변경을 임의로 적용하지 않는다.
기존 구현·실험 결과와 전체 목표는 유지한다.

## 활성 목표 재등록: 2026-10-01

사용자의 `/goal` 요청에 따라 목표 관리 도구에 다음 목표를 새로 등록했다.
**저자 Aion-ASR 구현을 최대한 보존한 Flower 포팅과 논문에 가까운 실제 학습·공격
실험 재현**이다. 이 문단은 활성 목표를 등록한 당시의 기록이며, 최종 상태는
문서 맨 위의 최신 결과와
[요구사항별 완료 감사](reproduction/aion-flower-completion-audit-2026-10-01.md)를 따른다.

현재 새 소스 경로는 원본 ASR MMF를 사용한다. 4라운드 실제 학습의 수치 집계는
검증됐지만 공격 방어는 실패했다. 별도 학습 artifact의 MGF까지 같은 경로로
재현됐다고 주장하지 않는다. 클라이언트 마스킹·원본 HPRF·일회성 키 공유를
유지하고, 다음 순서로 진행한다.

1. 공식 Flower SuperLink/Ray에 새 소스 경로를 연결하고 노드별 Context 상태를 검증한다.
2. 실제 FMNIST 다중 라운드와 전체 모델 재학습 대조를 수행한다.
3. 원본 ASR MMF와 학습 MGF의 데이터·마스크·필터 차이를 소스 기준으로 해소한다.
4. 논문에 가까운 참여 규모·공격 일정으로 실험하고 원본 대비 차이를 기록한다.

새 암호 프로토콜 설계, 모든 예외 상황에 대한 형식적 보안 증명, 외부 오픈소스
기여는 이 목표의 완료 조건이 아니다. 평문 classifier를 받는 저자 중앙 실험을
비공개 클라이언트 마스킹 경로로 표시하거나 실패한 방어를 성공으로 표시하지 않는다.

이후 공식 Flower의 합성 4라운드, 실제 FMNIST 공격 4·20라운드가 완료됐다.
20라운드 전체 모델 재학습 대조 오차는 0이며 키 공유 40개·추가 mask share
0개다. 공격 방어 실패 때문에 목표는 완료로 변경하지 않았다.
[실행·검증 기록](experiments/fmnist-source-asr-official-2026-10-01/report.md)을 참고한다.

후속으로 모집단/라운드 참여자를 분리하는 동적 경로를 추가했다. 원본 VSS를
한 번 등록하고, 미참여 라운드는 학습하지 않으며 재참여 시 직전 commit을
검증한다. 로컬 worker pool과 공식 Flower의 actor Context에 같은 경로를 연결한다.
이는 원본 MMF의 큰 mask norm 문제나 bounded-MGF carry 복원을 해결한 것이 아니다.
MGF 연결 방식 선택은 사용자에게 요청했으며, 추가 share·중앙 평문 baseline·
무추가-share MMF의 의미를 혼동하지 않는다.
100명/10명 FMNIST 4라운드를 로컬과 공식 Flower에서 각각 실행·재검증했다.
두 실행의 전체 모델 오차는 0, 키 share는 각각 처음 400개, 추가 mask share는
0개다. 공식 실행에서는 방어가 실패했다. [동적 참여 보고서](experiments/fmnist-source-asr-dynamic-2026-10-01/report.md)에 기록한다.

원본 공개 버전의 추가 경로도 재확인했다. 공식 v5에서 현재 포팅에 사용한
8개 ASR 메서드 AST가 모두 일치했다. 로컬 role 파일의 전체 hash 차이는 prime
주입 생성자 차이였으며, 이 포팅은 해당 simulator 생성자를 실행하지 않는다.
[공식 원본 정체성 재대조](reproduction/source-identity-2026-10-01.md)에 근거를 남겼다.
이 시점에는 bounded-MGF 연결 방식 선택이 남아 있어 목표가 미완료였다.

## 2026-10-01 사용자 재확인: 원본 ASR 통신 포팅 우선

원본 ASR 로직을 유지하고 Flower 메시지로 실행하는 별도 경로를 추가했다.
새 bounded-MGF의 보안 재설계·추가 share 제거를 원본 포팅의 완료 조건으로
혼합하지 않는다. [새 경로와 검증 범위](source-asr-flower-port.md)를 참고한다.
아래의 과거 학습 실험 완료 감사는 새 ASR 소스 경로의 완료 판정이 아니다.

## 저자 코드의 두 필터 및 결과 요약 구분

원본 `SA_AggregatorAgent.MMF`와 실제 학습 실험의
`roles/aggregation_rules.py::aion`은 동일한 필터 설정이 아니다.
원본 함수를 AST로 분리해 직접 실행하는 read-only 시험으로 아래
차이를 확인했다. 원본 파일은 수정하지 않았다.

| 항목 | ASR 모의실험 MMF | 학습 실험 MGF / 현재 author-mgf |
|---|---|---|
| 최소 선택 비율 | 30% | 10% |
| threshold 경계 | norm <= bound 포함 | searchsorted(left), norm < bound |
| 이후 mask norm 항 | 같은 이전 HPRF norm을 분자·분모에 사용 | 현재 전체 후보 mask norm / 이전 mask norm |

과거 `author-mgf` 학습 포팅은 오른쪽 학습 실험을 기준으로 했다. 새
`aion_source_asr` 경로는 왼쪽 MMF를 원본에서 실행한다. 둘을 혼합해
한 경로의 완료 증거로 제시하지 않는다.

Exporter에 저자 trainer의 전체 학습 라운드 평균 ASR·평균 TER·최대 ASR
요약을 추가했다. 로드된 checkpoint인 round 0은 제외하고, 공격하지 않은
라운드도 포함한다. 값은 0~1 비율이며 최종 라운드 지표와 구분한다.
이는 포팅 실행의 요약이며 특정 논문 그림이 이 요약을 사용했다는 뜻은 아니다.

2026-09-30 사용자 요청에 따라 기존의 신규 연구 백엔드 중심 구현에서
저자 공개 구현의 계산 및 실험 의미를 보존하는 Flower 포팅으로 전환한다.
목표 관리 도구는 미완료 목표 교체를 거부했으므로 이 문서에 변경된 작업
기준을 기록한다. 기존 목표가 달성됐다고 표시하지 않는다.

## 완료 순서

1. 원본 ASR HPRF의 저장된 행렬, 실제 initialization 파일, 입력식,
   반올림을 보존한 어댑터를 만들고 원본 코드와 출력 전체를 비교한다.
2. 원본 ASR의 키 합/VSS 필드, 수치 인코딩, 복원 오차 처리를 확인한 뒤
   Flower 프로토콜에 명시적인 원본 호환 백엔드로 연결한다.
   현재 출력 링 2^128에 원본 출력을 그대로 넣지 않는다.
3. 학습 실험의 SHPRG/MGF와 ASR HPRF를 구분하고, 해당 원본 실행 경로의
   실제 학습 입력·마스크·선택·임계값 갱신을 대응시킨다.
4. 짧은 다중 라운드 및 동일 학습 조건 대조 실험을 완료한다.
   4라운드 기능 검증 후 10라운드 반복 갱신을 확인하고 장기 재현은 별도로 한다.
5. 실행 명령, 원본 대비 수정 이유, 소스·입력 해시와 결과를 기록한다.

## 완료 감사: 저자 구현 기반 Flower 연구용 실험 포팅

사용자가 지정한 방향은 신규 암호 설계보다 저자 구현을 우선 사용하는
Flower 포팅이며, 모든 예외·형식적 보안 증명보다 논문 실험과 유사한
학습 실행을 우선한다. 위 완료 순서 1~5를 다음 실제 증거로 확인했다.
완료 판정은 이 연구용 실험 포팅에 대한 것이며 아래 유지할 경계를
운영 보안이나 논문 전체 실험의 완료로 바꾸지 않는다.

| 요구사항 | 확인한 증거 |
|---|---|
| 1. 원본 ASR HPRF 계산 보존 | test_aion_original_hprf.py의 원본 함수 직접 비교, block 경계·raw rounding·10,000/61,706좌표 전체 일치; 실제 initialization/matrix 사용 |
| 2. Flower ASR 연결과 수치 복원 | 원본 p 링의 mask/unmask·설정 해시·recipient-bound VSS 시험; ProcessGrid 및 실제 SuperLink/Ray 결합 실행의 모델·인증서 재검증 |
| 3. 저자 학습 SHPRG/MGF 대응 | 원본 SHPRG·aion 함수의 직접 계산 대조, float32 layer 평균·threshold·resume 분기; 원본 Client.local_train 정상 학습 대조와 author-loader 배선 검증 |
| 4. 짧은 반복·동일 조건 대조 | 최신 author-loader 결합 4 및 10라운드에서 평문 MGF와 모든 선택 일치; 별도 무방어 대조; 최신 10라운드 후보 200회 sampling 감사 |
| 5. 명령·차이·hash·결과 보존 | 각 실험 report/results.json, 원본 HPRF setup/hash, 저자 소스 스냅샷 hash, 입력·staged source/config/catalog 검증 및 원본 대비 경계 기록 |

전체 테스트 358개 통과·GPU opt-in 2개 skip과 최신 10라운드 완료 후
verifier 재실행을 확인했다. Torch optional collection 수정 후 해당
SHPRG 시험 9개 재통과 및 torch 미설치 모사의 collection 성공도 확인했다.
[최신 완료 결과](experiments/fmnist-flower-author-reference-hprf-loader-hotstuff-ten-round-2026-09-30/report.md)에
측정값·run ID·정확한 실행 명령과 범위를 기록했다. 이 단계에서는 외부
기여·재배포·논문 규모 장기 실험을 수행하지 않았다.

## 유지할 경계 (완료 후에도 동일)

- Flower ClientApp/ServerApp 및 검증·실험 도구는 재사용한다.
- 기존 artifact/lwe-reference/lwe-192-reference 백엔드와 결과는 보존한다.
  이들의 기존 결과를 저자 HPRF 재현 결과로 바꾸지 않는다.
- 원본 코드의 버그·실험용 설정은 숨기지 않고 변경 근거를 기록한다.
- 새로운 암호 보안 증명이나 모든 장애 스케줄의 형식적 증명은 이번
  실험 포팅의 완료 전제조건이 아니다. 운영 보안이나 전체 진행성은 주장하지 않는다.
- 원본 트리는 수정하지 않는다. 코드 재배포 전 라이선스 확인도 필요하다.

## 저자 학습 소스의 재현 기록

새 실행에는 `--author-reference-dir ../Aion/input_validation/FL_Backdoor_CV`를
추가할 수 있다. `--author-mgf`와 함께 사용하며 원본 SHPRG 코드·실제
initialization 파일, aggregation_rules.py, client.py, trainer.py,
image_helper.py를 `author-reference`에 스냅샷으로 보존하고 각 SHA-256을
provenance에 담는다. initialization의 실제 (n,m,p,q)가 포트의
(1,8,173569775688864,5000999999999999)와 달라지면 staging 전에 거부한다.
classifier width는 학습 코드처럼 별도로 840으로 정하며 원본 m=8을
그대로 classifier width라고 해석하지 않는다.

Verifier와 exporter는 스냅샷의 전체 inventory·초기화 값·hash를 재검사한다.
원본 소스 실행이나 전체 RNG transcript의 동등성을 의미하지는 않는다.
기존 완료 실행에 나중에 이 hash를 삽입해 staging 당시 기록인 것처럼
바꾸지 않는다. 기존 소스 hash와 새 스냅샷 provenance를 구분한다.

[소스 스냅샷 포함 공식 Flower 4라운드](experiments/fmnist-flower-author-reference-loader-four-round-2026-09-30/report.md)를
완료했고 관련 시험 60개가 통과했다.
[최신 결합 10라운드](experiments/fmnist-flower-author-reference-hprf-loader-hotstuff-ten-round-2026-09-30/report.md)도
`official-author-reference-hprf-loader-hotstuff-ten-round-seed0`에서 완료 후
재검증했다. author-loader·원본 HPRF·HotStuff·저자 reference 기록을 모두
사용하며 공격 라운드는 1·4·7·10이다. 평문 MGF와 매 라운드 선택이 같고
후보 200회 학습이 실제 author-loader인 것을 확인했다. 최종 정확도
88.67%·공격 성공률 0.585938%, 두 모델 최대 차이 3.54471641517674e-5다.
전체 회귀 시험은 358개 통과·2개 skip이었다.

## 현재 진행

원본 HPRF 어댑터와 원본 코드 직접 비교 시험을 추가했다.
`aion-original` 선택형 백엔드로 Flower ClientApp/ServerApp의 고정 cohort
학습·ASR 경로에 연결했다. 원본 p를 wire 모듈러스로 사용하고, 키는
원본과 같은 1~100000 범위에서 생성하며 등록 후 재사용한다.
공개 열 합과 n/m/p/q는 task manifest에 포함해 설정 해시로 묶는다.
원본 float64의 1 벡터 대신 실제 delta를 전달하기 위한 고정소수점
인코딩·오차 흡수 padding은 유지한다. VSS·암호화·합의도 기존 Flower
구현을 사용하므로 전체 저자 프로토콜의 비트 단위 포팅 완료는 아니다.
일반 합의 및 HotStuff 각각에서 4라운드 ProcessGrid 실행과 양자화
학습 대조 모델의 정확한 일치를 확인했다. 원본 출력 비교·기존 ASR·
MGF·HotStuff를 포함한 선택 회귀 시험 110개가 통과했다.
원본 ASR HPRF를 기존 bounded MGF에 무조건 연결하지 않도록 해당 조합은
명시적으로 거부한다. 별도 SHPRG 학습 필터를 사용하는 classifier-plaintext
선택 연결 경로는 아래처럼 추가했으며, 보안 MGF 통합 완료는 아니다.

실행 위치는 `trustlessFL`이다.

```bash
PYTHONPATH=.cache/flower-deps:.cache/torch-deps:. python3 -m trustlessfl.demo \
  --mask-backend aion-original \
  --original-hprf-dir ../Aion/agent/Aion/HPRF --rounds 4
```

실제로 로드되는 `Aion/agent/Aion/HPRF/initialization_values` 파일은
`n=128`, `m=512`, `p=14760426300877770769`, `q=73802131504388853845`다.
이 값은 `init.py`에 쓰인 더 큰 p/q와 다르다. 어댑터는 실제 파일을
사용하며 init.py를 실행해 기존 행렬·설정을 재생성하지 않는다.
이는 파일 기반 실행 재현의 기준이며, 논문 권장 보안 파라미터라는 뜻이 아니다.

## 저자 학습 SHPRG·MGF 포팅

`OriginalAionSHPRG`는 원본 `shprg.py`의 정수 반올림 및 float 곱셈/나눗셈
순서, 좌표 반복, client별 mask 합산을 보존한다. 실제 initialization 파일의
`n=1`, `p=173569775688864`, `q=5000999999999999`를 기준으로 한다.
원본 SHPRG의 `G()`는 seed를 한 행으로 만들므로 n>1로 임의 확대하지 않는다.

`AuthorArtifactMGF`는 CPU torch.float32로 masked norm·sort·searchsorted,
레이어별 선택 평균, 4라운드 이후 scalar tensor threshold 갱신을 수행한다.
원본 `aggregation_rules.py::aion` 함수를 AST로 분리해 직접 실행한
차등 시험에서 4라운드 선택 집합·평균·threshold·norm 이력이 정확히 일치했다.
시험에서 CUDA 호출만 CPU로 대체했으므로 CUDA 결과의 비트 단위 일치나
전체 원본 프로그램의 난수 호출 순서 일치를 입증하지 않는다.
추가로 원본 함수의 resume 이후 MGF bootstrap 분기를 포팅했다.
`AuthorArtifactMGF(resume_round=300)`의 301~304라운드에 대해 원본
함수의 resume 설정과 선택·평균·bound·norm 이력이 정확히 일치했다.
이는 계산 모듈의 resume 의미이며 Flower 프로세스 전체의 checkpoint
복구·인증서 이력 재설치가 완료됐다는 뜻은 아니다. 공식 실행은 여전히
로드된 checkpoint 이후의 상대 라운드 1부터 시작한다.
명시적으로 공급된 SHPRG 행렬에서는 원본의 기존 matrix 파일 로드
분기처럼 새 행렬용 RNG 호출을 소비하지 않도록 했다.

기존 `ArtifactMGF`는 보존한다. 새 경로는 `--author-mgf` 옵션으로
공식 Flower의 평문 `mgf` 경로에 연결했다. q>=20을 요구하며, 작은 q에서
원본 최소 선택 수를 몰래 2로 늘리지 않는다. 원본 MGF 입력은 평문이고
ASR HPRF와 별개이므로 bounded-MGF와의 혼합 실행은 현재 거부한다.
단일 seed·동일 공개 행렬/seed transcript를 기준으로 원본 계산을 비교하며,
원본 학습 전체 프로그램의 공유 RNG 순서 재현은 별도 점검이 필요하다.

```bash
PATH="$PWD/.cache/flower-deps/bin:$PATH" \
PYTHONPATH=.cache/flower-deps:.cache/torch-deps:. \
python3 -m experiments.run_fmnist_official --phase all \
  --output .cache/fmnist/official-author-shprg-mgf-four-round-seed0 \
  --modes mgf quantized --author-mgf --population 100 --participants 20 \
  --aggregators 4 --rounds 4 --workers 4 --attack-clients 4 \
  --attack-rounds 1 4 --cohort-sampling individuals --timeout 600
```

기존 실행 디렉터리는 재사용하지 않는다. 무방어 `quantized` 대조군은
같은 학습·참여·공격 조건이나 업데이트 소수점 양자화를 적용하므로,
이를 원본 무방어 float32 실행과 비트 단위 동일하다고 표시하지 않는다.

[공식 Flower SHPRG·MGF 4라운드 결과](experiments/fmnist-flower-author-shprg-mgf-four-round-2026-09-30/report.md)를
완료하고 별도 출력으로 보존했다. 최종 정확도 88.77%, 공격 성공률
0.78125%이며 무방어 양자화 경로는 64.92%·46.484375%다.
이 결과로 ASR HPRF와 MGF의 통합이 완료됐다고 해석하지 않는다.

## SHPRG 선택과 원본 HPRF ASR 연결

### 학습 batch 구성의 원본 대응

추가 선택 옵션 `--training-sampling author-loader`는 정상 학습에
원본 `get_train`처럼 DataLoader/SubsetRandomSampler를 사용하고,
공격에는 poison DataLoader의 첫 batch와 Python sample로 뽑은 clean
subset의 첫 batch를 결합한다. poison row는 batch 안에서 중복하지 않는다.
기존 직접 randperm·poison randint 경로는 `legacy` 기본값으로 유지해
이미 완료된 결과를 새 경로 결과로 바꾸지 않는다.

원본 `Client.local_train` 함수를 AST로 분리해 실제로 실행한 정상 학습
차등 시험에서 동일한 로컬 generator를 제공했을 때 두 epoch의 모든
업데이트 좌표가 정확히 일치했다. 공격 표본 중복 방지·결정성도 시험했다.
관련 시험 20개가 통과했다. 원본 전체 프로그램의 공유 RNG 순서 일치가
아니며, 원본 attacker의 round 간 cached clean index 순서 대신
client/round별 분리 Python stream을 사용한다. 모델·optimizer·학습
계산을 원본에 대응시키되 이 경계를 숨기지 않는다.

[공식 Flower author-loader 4라운드](experiments/fmnist-flower-author-shprg-loader-four-round-2026-09-30/report.md)를
별도 `official-author-shprg-loader-four-round-v2-seed0`에서 완료했다.
MGF 최종 정확도 88.69%·공격 성공률 0.78125%이며 무방어는
63.50%·43.945313%다. 첫 v1은 평문 핸들러가 옵션을 전달하지 않아
legacy를 사용했으므로 유효한 새 경로 결과에서 제외했다. 현재 verifier와
exporter는 그 실제 training policy 불일치를 거부한다. 기존 HPRF 결합
10라운드는 `legacy` sampling으로 수행됐으므로 새 loader의 HPRF 결합
실험 결과로 해석하지 않는다. 새 provenance의 training.sampling_policy와
worker catalog에 해당 선택을 기록하고 공개 exporter에도 training을 담는다.

보안 집계 경로도 새로운 non-legacy sampling을 선택하면 verifier가
task-scoped client state의 training_meta를 실제 참여 일정과 대조한다.
MGF가 탈락시킨 후보도 포함하며, client/round 누락·불필요한 라운드·
잘못된 partition·실제 policy 불일치를 거부한다. 요약에는 policy와
검증된 training call 수만 공개하고 키/share/업데이트는 내보내지 않는다.
이는 시뮬레이션 사후 감사이지 악성 client의 학습을 증명하는 기법은 아니다.

[author-loader + 원본 HPRF·SHPRG/MGF·HotStuff의 공식 Flower 4라운드](experiments/fmnist-flower-author-hprf-shprg-loader-hotstuff-four-round-2026-09-30/report.md)도
완료 후 최신 verifier로 재검증했다. 보안 집계 후보의 80회 학습 metadata가
모두 author-loader였고, 평문 저자 MGF와 네 라운드 모두 선택이 같았다.
최종 정확도 88.69%·공격 성공률 0.78125%, 두 모델 최대 차이는
1.3784517033358268e-5였다. 전체 회귀 시험은 345개 통과·2개 skip이며,
후속 exporter의 secure sampling 감사 요구 gate는 별도 선택 시험으로 검증한다.

`--author-mgf --original-hprf-dir ../Aion/agent/Aion/HPRF`로 공식 Flower의
`aion_mgf_oracle` 경로에 두 계산을 연결했다. 클라이언트는 전체 업데이트를
원본 HPRF로 마스킹하고 classifier 840개 좌표만 평문으로 서명해 보낸다.
coordinator는 해당 좌표에 저자 SHPRG 마스크를 더해 원본 MGF 계산으로
선택하고, 집계자들이 선택된 업데이트의 키 share를 검증·합산·복원하여
원본 HPRF 합계 마스크를 제거한다. HotStuff 선택 옵션도 유지한다.
이름의 oracle은 의도적인 classifier 공개를 뜻하며 숨기지 않는다.

원본 ASR 고정 cohort 경로와 달리 필터 연결 경로는 기존 연구 포트의
**매 라운드 새 ASR 키·새 VSS 공유**를 유지한다. 반복된 부분집합의 키 합
공개를 장기 키로 차분하는 것을 피하기 위한 변경이며, 원본 one-time
sharing 비용 재현이 아니다. 키 범위와 HPRF 계산·원본 출력 링은 보존한다.
MGF의 다음 norm 이력은 인증된 양자화 모델의 변화에서 얻으므로,
평문 float32 평균만 사용하는 대조군과 수치 이력이 미세하게 달라질 수 있다.
실행 후 두 경로의 모든 라운드 선택 집합이 같은지 별도로 확인한다.

```bash
PATH="$PWD/.cache/flower-deps/bin:$PATH" \
PYTHONPATH=.cache/flower-deps:.cache/torch-deps:. \
python3 -m experiments.run_fmnist_official --phase all \
  --output .cache/fmnist/official-author-hprf-shprg-hotstuff-four-round-seed0 \
  --modes aion_mgf_oracle mgf quantized --author-mgf \
  --original-hprf-dir ../Aion/agent/Aion/HPRF --hotstuff \
  --population 100 --participants 20 --aggregators 4 --rounds 4 --workers 4 \
  --attack-clients 4 --attack-rounds 1 4 --cohort-sampling individuals --timeout 600
```

원본 HPRF public setup의 digest와 원본 hprf.py/matrix/initialization 파일
해시는 provenance에 저장한다. 검증 시 task manifest의 실제 백엔드·
public setup이 해당 digest와 일치해야 한다. 큰 원본 행렬 대신 동일한
공개 열 합을 task manifest에 담으므로 worker가 원본 디렉터리를 읽거나
새 행렬을 생성할 필요가 없다.

[공식 Flower 결합 4라운드](experiments/fmnist-flower-author-hprf-shprg-hotstuff-four-round-2026-09-30/report.md)를
완료했다. HotStuff roster/model 인증서와 실제 공개 HPRF setup을 다시
검증했고, 저자 MGF 대조군과 모든 라운드 선택이 같았다. 최종 정확도
88.77%, 공격 성공률 0.78125%, 전 모델 최대 차이는 2.832545083171446e-6이다.
관련 회귀 시험 132개가 통과했다.

[공식 Flower 결합 10라운드](experiments/fmnist-flower-author-hprf-shprg-hotstuff-ten-round-2026-09-30/report.md)도
별도 디렉터리 `official-author-hprf-shprg-hotstuff-ten-round-seed0`에서
완료 후 재검증했다. 공격 라운드는 명시적 1·4·7·10이다. 저자 MGF
대조군과 10라운드 모두 선택이 같았고, 최종 정확도 88.88%·공격 성공률
0.78125%였다. 무방어 경로는 79.31%·97.851563%다. 두 MGF 경로의
모델 최대 차이는 6.194870467055784e-5이며 비트 단위 일치를 주장하지
않는다. 평균 ASR·TER 및 최대 ASR도 exporter로 보존했다. 이로써 축소
조건의 4→10라운드 기능 검증은 완료했지만 위 원본 대비 경계는 유지한다.
이후 전체 회귀 시험도 331개 통과·2개 skip으로 완료했다. 정상 실행의
검증과 연구용 포팅의 경계를 분리하며 보안 검증 완료로 표시하지 않는다.
