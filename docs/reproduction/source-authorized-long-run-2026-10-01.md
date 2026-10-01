# Signed masked-MGF 공식 Flower 다중 라운드 검증: 미완료

## 실행과 판정

새 키와 node Context로 20명 synthetic client, committee 4명, 차원 8,
model decimal 6, beta 0.2, initial norm 0.012347, 최대 10라운드를 실행했다.
클라이언트 로컬 학습/마스킹, encrypted one-time key sharing, signed masked
VECTOR, 위원회 독립 MGF authorization과 signed receipt를 모두 활성화했다.
추가 mask share와 개별 평문 fallback은 없다.

실행 디렉터리:
`.cache/source-mgf-authorized-synthetic-ten-round-official-20261001`.
run ID `15571011848534870746`, `failure.json`의 runtime 30.960407초.
1–3라운드는 commit했고, 4라운드 `reconstruct`가 `ambiguous`로 실패했다.
`results.json`은 생성되지 않았다. 공식 `run-status.json`도
`finished:failed`다. 이 실행은 10라운드 통과 증거가 아니다.

## 복원 경계가 실제 학습에서도 재현됨

3라운드의 committed public `next_linf=1/1250`이고 다음 round의 normalized
mask period는 beta*norm = 1/6250이다. model quantum 1/10^6의 정확히
160배다. Carry를 1 바꾸면 복원 후보가 정확히 160 model quanta만큼 이동해
양자화 정합성 검사만으로 후보를 구분할 수 없다. 실제 bounded decoder도
4라운드에 여러 후보가 남아 거부했다.

이 근거는 공개 aggregate history와 실패 category다. private node seed/share를
읽거나 개별 키를 검색해 실패를 우회하지 않았다. 별도 회귀에서는 같은
public norm과 원본 공개 fixture keys (4,16), round 4의 1좌표를 사용해
physical mask bounds 안의 `ambiguous`를 확인한다. 이 fixture가 실패 실행의
실제 private keys 또는 좌표라고 주장하지 않는다.

논문 [Algorithms 6–8 및 §6.1](https://www.usenix.org/system/files/usenixsecurity25-liu-yizhong.pdf)은
작은 HPRF rounding error를 extra decimal digits로 제거한다. 현재 원본
finite-field HPRF의 real-valued scaling에는 그 작은 오차와 별도로 modular
carry가 남는다. 여기서 누락된 대표값/carry 결합 규칙을 논문이 명확히
제공한다고 확인하지 못했다. 논문 전체 또는 모든 HPRF에 대한 불가능성
주장이 아니라 현재 표현과 decoder의 재현 실패다.

## 실행 기록 보완

`aion_source_official.main`은 이제 numeric/protocol 실패 시 exception 값이나
private state 없이 category, 실패 action/round, 이전 committed metadata만
`failure.json`에 저장한다. 이미 result/failure가 있는 task는 fresh staging
없이 재실행하지 않는다. 기존 terminal record는 덮어쓰지 않는다.

Flower CLI와 `flwr list`가 exit 0 및 `success:true`를 반환해도 app run status는
`finished:failed`일 수 있다. `run_endpoint_flower.run`은 새 격리 runtime의
유일한 run이 `finished:completed`인지 확인하고, 실패/미완료/불명확한 상태를
성공으로 반환하지 않도록 수정했다. status-details의 exception 값은 오류
메시지에 복사하지 않는다. 기존 1-round 완료 record는 이 검사에 통과하고
이번 failed record는 거부한다.

최종 관련 회귀 68개 통과(10.19초). 새 actual-public-norm carry regression,
실패 기록의 private 값 미포함, terminal task 재실행 거부, completed/failed
runtime state 판정, 기존 signed filter와 1-round aggregate 시험을 포함한다.
컴파일과 `git diff --check`도 통과했다. 테스트 통과는 실패한 10-round
학습이 성공했다는 뜻이 아니다.

## 목표와 다음 완료 조건

Client-masked scaled-MGF 전체 목표는 여전히 미완료다. 통신이나 서명
수정으로 이 numeric ambiguity가 사라졌다고 주장하지 않는다. 현재 원본
HPRF/scaling을 유지하고 추가 share/평문/개별 키 탐색을 금지한 조건에서는
일반적인 정확한 복원 방법을 확인하지 못했다.

진행하려면 저자의 실제 결합 wire·대표값 처리 코드/규칙을 확보해 기존
반례와 실제 다중 라운드에 검증하거나, 사용자 동의 하에 다른 HPRF/wire
프로토콜을 설계하고 원본 재현과 명확히 분리해야 한다. 추가 share 경로나
중앙 plaintext baseline을 이 목표의 완료로 대체하지 않는다.
