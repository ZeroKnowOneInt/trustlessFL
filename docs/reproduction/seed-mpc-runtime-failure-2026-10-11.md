# 정상 조건 실행 오류 진단

실험 프로세스는 종료됐으나 정상 조건은 2라운드만 전원 참여 학습을 완료했다. 3~5라운드는 전원 transport-error로 인원 0, abort했다. 기존 `passed=true`는 이 참여집합에 대한 마스크 제거·집계·abort의 정확성을 확인한 결과이며, 계획된 전원 참여 5라운드 학습 완료를 의미하지 않는다.

## 확인한 오류 경로

1. 정상 조건의 1라운드 완료 뒤 Flower RayBackend의 `a.run.remote(...)` 호출에서 cloudpickle 직렬화가 `RuntimeError: dictionary changed size during iteration`를 냈다.
2. Flower 1.36의 `BasicActorPool.submit`은 actor를 `self.pool.pop()`으로 먼저 꺼내고 remote 호출을 실행한다. 그 호출이 동기적으로 실패하면 actor를 pool에 반환하지 않는다.
3. RayBackend의 예외 처리도 `future is not None`일 때만 반환한다. submit이 실패하면 future는 None이라 반환되지 않는다. 이 실행은 actor 1개를 사용했으므로 첫 오류 뒤 pool이 비었다.
4. 이후 모든 작업이 `IndexError: pop from empty list`로 실패했다. 정상 로그에서 최초 dictionary 오류 1건과 후속 empty-pool 오류 27건을 확인했다. 나머지 두 공격 조건 로그에는 두 오류가 없다.
5. Server는 오류 reply를 transport-error로 처리하고, 수집 기한 후 참여 0명으로 MPC를 실행했다. MPC는 min-accepted 조건에 따라 abort하고 모델을 유지했다.
6. 최종 exporter는 평문 전원 참여 정상 모델과 다름을 확인하고 결과 보관을 거부했다. 이 차이는 잘못된 집계의 증거가 아니라 서로 다른 참여집합의 결과이며, 정상 대조 실험으로 사용할 수 없는 실행이다.

## 재현과 증거의 범위

설치된 BasicActorPool을 빈 생성자로 준비한 뒤 actor 1개를 넣고 remote callback이 동일 RuntimeError를 던지게 했다. 첫 submit 직후 actor 수는 0이었고, 두 번째 submit은 동일 IndexError를 냈다. 이는 실제 native MPC나 Ray worker를 재실행하지 않고 해당 예외 경로를 재현한 시험이다.

최초 직렬화 중 변경된 dictionary가 Message, Context 또는 app callable의 어느 객체인지 기존 trace만으로는 확정할 수 없다. 동시 메시지 처리나 공유 객체 변경 가능성을 원인으로 단정하지 않는다. 이 정상 조건 Flower 로그에는 OOM signature가 없으며 이전 병렬 실험의 메모리 부족과는 별도 오류다. 이번 조사에서 학습 재실행은 시작하지 않았다.

원본 로그: `.cache/seed-mpc-experiments/native-sequential-clean-2026-10-11/attempt-0fcd3148/flwr.log`. 의존성 코드: `.venv/lib/python3.12/site-packages/flwr/simulation/ray_transport/ray_actor.py`의 BasicActorPool.submit와 `.venv/lib/python3.12/site-packages/flwr/server/superlink/fleet/vce/backend/raybackend.py`의 process_message. 진단 시점 SHA256 및 재현 결과는 [공개 진단 JSON](seed-mpc-security-experiments-2026-10-11/runtime-failure-diagnosis.json)에 기록했다.

## 수정 방향

- Runtime 어댑터에서 remote submit 예외 시 예약한 actor를 반환하거나 unhealthy 상태를 명시적으로 처리해야 한다. 설치 라이브러리를 기록 없이 직접 수정하지 않는다.
- 직렬화 실패 객체를 분리해 확인하고, 필요한 경우 제출 시점의 객체 snapshot이나 작업 직렬화를 적용한다. 단순 worker 수 증가만으로 예외를 숨기지 않는다.
- 실험 성공 여부를 protocol/abort 정확성과 계획된 학습 workload 완료로 분리한다. Dropout 실험의 정상적인 abort는 유지하되, 전원 참여 대조 실험에서는 예기치 않은 누락 라운드를 실패로 표시해야 한다.
- 수정과 회귀 확인 후 새 세션에서 정상 조건만 재실행하고 동일 평문 기준에 비교한다. 성공한 두 공격 조건을 재실행할 필요는 없다.

## 적용한 수정과 검증

`seed_mpc_flower_runtime.py`의 process-local 어댑터를 해당 Flower 실행의 PYTHONPATH bootstrap에서 설치한다. Flower 1.36.0, Ray 2.55.1, 원본 BasicActorPool.submit source SHA256 및 어댑터 파일 SHA256을 고정한다. 설치 라이브러리는 수정하지 않으며 일반 Endpoint 실행에는 적용하지 않는다. 각 Python 프로세스의 설치 확인 기록은 JSON으로 별도 보존한다.

예약한 actor는 동기 submit 예외 시 반환한다. RuntimeError의 문자열과 traceback이 Ray `_serialize_to_pickle5` 준비 단계임을 함께 확인한 경우에만 같은 작업을 최대 3회 시도한다. 임의 RuntimeError, 네트워크 오류, ClientApp 오류, 원격 완료가 불확실한 오류는 재시도하지 않는다. 따라서 학습을 다시 시작하거나 새 마스크를 만드는 재시도가 아니다. 최초 dictionary 변경 자체의 정확한 객체는 여전히 미확정이며, 이번 수정은 확인된 예외가 pool 전체 소진으로 번지는 경로를 차단한다.

검증 JSON은 `protocol_correctness_passed`와 `learning_workload_completed`를 구분한다. 전원 참여 학습 실험에 누락 입력이나 abort가 있으면 `passed=false`로 저장하고 verifier가 실패한다. Dropout fixture의 의도된 abort는 프로토콜 검증으로 유지한다. Exporter도 예전 형식의 passed=true 파일을 신뢰하는 것만으로 결과를 보관하지 않고, 실제 참여집합과 라운드 상태를 먼저 확인한다.

Bootstrap import로 발생하는 CLI 경고는 JSON stdout과 분리한 stderr 파일에 보존한다. 경고를 숨기거나 JSON 앞부분을 임의 삭제해서 성공 처리하지 않는다.

회귀 테스트 104개가 통과했다. 동기 실패 뒤 actor 복구, 확인된 직렬화 오류의 제한 재시도, 임의·불확실 오류 재시도 금지, guard source pin, 누락/abort workload 실패 및 경고/JSON 분리를 포함한다. 수정된 실제 Flower+Rep4 D=65 3라운드 fixture는 성공했고, 12개 시작 프로세스의 guard 설치 source hash가 일치했다. 해당 fixture의 3라운드 abort는 의도된 인원 부족 사례다. FMNIST 정상 조건은 별도 새 세션에서 5라운드 재실행과 독립 재학습 검증을 완료했으며, 모든 라운드의 정수 합·모델·평가값이 동일 평문 기준과 정확히 일치했다.

## 정상 조건 재실행 결과

정상 FMNIST 5라운드는 매 라운드 4명 참여·통과, abort 없이 완료했고 최종 정확도는 86.24%다. 5/5라운드의 정수 합, 모델 bits 및 평가값이 동일 평문 기준과 정확히 일치했다. 실제 실행에서 확인된 pre-submission 직렬화 예외가 1회 재시도로 복구됐고 actor pool 소진은 발생하지 않았다. 로그에 best-effort 메시지 TTL 만료 진단 1건은 남았으나 전원 참여 학습과 인증 모델 진행에는 영향이 없었다. 세 조건 결과 보관과 SHA256 manifest 검증을 완료했고 실험 프로세스는 모두 종료됐다. [재실행 확인 기록](seed-mpc-security-experiments-2026-10-11/runtime-guard-recovery-outcome.json)을 참조한다.
