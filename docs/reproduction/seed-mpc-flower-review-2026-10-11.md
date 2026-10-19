# Flower masked 업로드와 인증된 모델 갱신 검증

작성일: 2026-10-11  
WSL Ubuntu-24.04, 브랜치 `work/aion-private-bound-no-wrap`  
Flower 1.36.0의 공식 `flwr run`·SuperLink·Ray runtime, 실제 MP-SPDZ Rep4

단계 F의 작은 로컬 연결을 구현했다. Flower ClientApp은 원시 업데이트 대신 **서명된 masked chunk만** 반환한다. 네 aggregator service는 별도 Python/native process와 서명키·ledger를 사용하며, coordinator는 입력 전달과 인증된 공개 모델 적용을 담당한다. 65좌표 합성 반례와 **170개 파라미터의 작은 FMNIST 모델**을 각각 3라운드 실행했다. 전체 61706개 파라미터 LeNet5의 완료 결과는 아니다.

## 1. 역할과 전달값

| 역할·경로 | 전달하는 값 | 비밀 상태 |
|---|---|---|
| ClientApp → Flower coordinator | Client가 서명한 session/epoch/round/model/policy/handle/offset와 masked Y | Seed·서명 개인키·원시 업데이트는 client에 유지 |
| Client의 등록 helper → 네 native aggregator | 기존 Rep4 입력 adapter의 blinded seed 응답과 공개 등록 descriptor digest | 최초 한 번 등록, 이후 secret shares 유지 |
| Coordinator → 각 aggregator service | 동일 signed input snapshot과 입력/결과 인증서 | Coordinator가 seed나 aggregator 서명 개인키를 받지 않음 |
| 각 aggregator → coordinator | 입력 투표와 로컬 CHECK 이후 결과 투표 | 자기 서명키와 자기 MPC share만 보유 |
| Coordinator → ClientApp | 입력 snapshot·입력 인증서·결과 인증서·공개 float64 모델 | Client가 인증서·parent·모델 hash를 검증하여 채택 |

Native 공개 결과는 선택 SUM/count 또는 abort다. 개별 업데이트·norm·마스크·통과 비트를 추가로 공개하지 않는다. 새 masked reply schema는 `wire/envelopes`만 허용하고 기존 앱의 `delta`, `delta_sha256`, norm metadata 등은 거부한다. 서명된 body에 다른 값을 붙이는 경우도 snapshot 검증에서 거부한다.

실행 계약과 native binary·AES 회로·bytecode/schedule·설정 hash를 bootstrap 시 고정한다. Client와 aggregator는 각자 로컬 설정의 deployment hash를 확인한다. 로컬 등록 helper가 seed를 생성하므로 ServerApp이 키를 생성하거나 수집하지 않는다. 시험 bootstrap은 별도 client subprocess에서 개인 파일을 준비하고 공개 등록 정보만 읽는다.

등록 helper는 최초 연결 후 종료한다. Flower runtime이 Ray worker 한 개로 네 client를 순차 예약할 수 있으므로 ClientApp의 등록 callback은 helper를 시작한 뒤 즉시 반환한다. 모든 등록 입력이 도착하고 native 내부 검사가 완료됐는지는 aggregator service가 자신의 process에서 확인한다. Callback의 ACK만으로 키 등록 완료를 주장하지 않는다.

## 2. 라운드 순서와 클라이언트의 검사

1. ClientApp은 자기 영속 공개 모델 상태와 요청 모델의 dtype·차원·유한성·hash를 비교하고 다음 round인지 확인한다. 초기 모델도 로컬 계약의 모델이어야 한다.
2. **학습 전에** `calls.sqlite`에 round/context를 commit한다. 동일 context의 재요청에는 저장된 동일 ciphertext·서명만 반환한다. 다른 모델/context 또는 결과가 저장되지 않은 불확실한 실행은 거부한다. 동일 seed/counter에서 다시 학습해 다른 업데이트를 마스킹하는 문제를 막는다.
3. Local SGD → 공개 scale의 양자화 → AES single mask → signed chunk를 수행한다. 정상 클라이언트의 좌표 체크와 별개로 악성 입력의 실제 좌표·norm 검사는 여전히 MPC 안에서 수행한다. Client에게 ZKP를 추가하지 않았다.
4. Coordinator는 pinned identity와 Flower node mapping을 확인하고 전체 signed snapshot을 네 service에 전달한다. 각 service는 자기 ledger의 입력 lock을 유지하고 입력 인증서 검증 후 실행을 예약한다.
5. 각 service가 자신의 FIFO에 확정된 입력을 넣고 자신의 native CHECK marker를 기다린다. 로컬 관찰만 결과 서명의 근거로 사용하며 peer가 보내는 `checked=True` API는 없다. Coordinator는 서로 다른 3개 이상의 결과 서명을 검증한 뒤 모델을 적용한다.
6. ClientApp에도 전체 인증된 결정과 모델을 전달한다. **요청 모델이 결과의 next-model hash와 일치하는지 먼저 검사**하고, quorum·입력·parent를 검증한 뒤 공개 모델 상태를 원자적으로 갱신한다. ACK는 Client가 서명한다.
7. 매 라운드 같은 commit을 다시 전달해 client가 `applied=False`로 응답하는지 확인했다. Coordinator의 같은 결과 재적용도 False여야 한다. 다음 학습은 인증된 head에서만 시작한다.

Global model은 canonical float64 flat vector다. 작은 FMNIST 모델을 학습할 때는 이를 torch.float32 weight/bias에 복사하고, 학습 후 float64 vector에서 delta를 계산한다. 공개 모델 갱신은 양자화 정수 SUM에 대한 `model[j] + SUM[j]/(S*count)`다. 재학습 reference도 동일한 모델·데이터·순서·dtype 변환을 사용해 모든 round의 정수와 모델을 정확히 비교했다. Float32 학습 오차와 모듈러 wrap 문제를 혼동하지 않는다.

## 3. 실제 Flower 실행 결과

| 시험 | 좌표/파라미터 | round | compile | ServerApp 경과 시간 | Native 내부 통신 |
|---|---:|---:|---:|---:|---:|
| 공개 adversarial fixture | 65 | 3 | 6.527초, 1회 | 6.053초 | 4.18145 MB |
| 작은 FMNIST 학습 | 170 | 3 | 6.229초, 1회 | 10.242초 | 8.34355 MB |
| 인증되지 않은 모델 전달 | 65 | 첫 학습 전 거부 | 별도 계약 1회 | 완료 실패가 정상 결과 | 성공 출력 없음 |

두 정상 실행은 공식 run status가 **`finished:completed`**였고 각 client의 private seed 입력은 1회였다. 네 native process는 각각 세 라운드 동안 같은 키 shares를 유지하고 마지막에 정상 종료했다. 결과 인증서·정수 SUM/count/abort·공개 모델·client 최종 head가 모두 일치했다.

65좌표 fixture는 첫 합 80000, 두 번째 합 -40000, 세 번째 count 부족에 따른 abort를 인증했다. **Q=65536으로 최종 합을 줄이지 않았으므로 80000이 14464로 바뀌지 않았다.** 좌표 범위 위반과 norm 초과 client는 MPC가 전체 입력을 제외했다. Abort 모델은 이전 모델과 같았다.

FMNIST는 이미지 28×28을 7×7 평균 pooling하여 16개 feature로 만든 뒤 10-class linear layer를 학습한다. 파라미터는 `10×16+10=170`개다. IID permutation seed=42, client당 256개 training image, CPU, 1epoch/round, batch=64, learning rate=.05, public test 1024개를 사용했다. Scale=10000, B=20000, 정적 squared threshold=2500000000, 최소 통과 인원=2다. 세 라운드 모두 네 입력이 통과했다. 매 round 별도 순차 재학습의 양자화 update와 정수 SUM 및 공개 모델이 정확히 일치했다.

작은 모델의 test accuracy는 10.64% → 11.23% → 11.23% → 11.23%, loss는 2.3026 → 2.2949 → 2.2877 → 2.2806이었다. 데이터와 학습량을 줄인 **연결·정확성 시험**이며 유용한 FMNIST 모델 성능을 검증한 결과로 해석하지 않는다. 기존 86%대 평문 LeNet5 결과를 실제 seed-MPC 성능으로 표시하지 않는다.

음성 시험에서는 coordinator가 초기 인증 모델의 첫 좌표를 1 증가시켜 전달했다. 공식 Flower status는 예상대로 **`finished:failed`**였고 client는 학습 전에 거부했다. Training audit 생성·native round 출력·모델 갱신이 모두 0이었다. 평문 집계로 fallback하지 않았다. 실패를 성공 학습 run으로 집계하지 않는다.

## 4. 통신 범위와 비용

170좌표/3라운드 기록에서 확인 가능한 전달량은 다음과 같다. Native 통신과 앱 계층 내용의 범위를 분리한다.

| 경로 | 크기 | 계산 범위 |
|---|---:|---|
| Native aggregator 내부 | 8.34355 MB | MP-SPDZ all-party decimal MB, preprocessing 포함 |
| Client masked ConfigRecord 내용 | 52777 bytes | JSON envelope 문자열과 record key, 네 client·3round |
| Aggregator round RPC request JSON | 748000 bytes | 네 service의 prepare/execute/decide 본문 |
| Aggregator round RPC response JSON | 20744 bytes | 입력/결과 투표와 decide 응답 |
| Client commit ConfigRecord 내용 | 630208 bytes | 전체 snapshot·인증서 전달, 중복 commit 시험 포함 |
| 공개 모델 array의 raw bytes | 48960 bytes | Train 1회+commit 2회씩, float64, 네 client·3round |

앱 계층 수치는 저장된 공개 transcript와 실제 serializer 규칙으로 재구성한 내용 크기다. HTTP/TLS/TCP/Flower protobuf framing, 등록·identity·ACK·ready·finish의 control 메시지를 포함한 packet capture 총량이 아니다. ServerApp의 `masked_application_json_bytes=56317`은 envelope 문자열을 바깥 JSON에 다시 넣어 측정한 값이므로 ConfigRecord 자체의 내용 52777 bytes와 다르다. [기록된 통신 계산](seed-mpc-flower-2026-10-11/tiny-fmnist/communication.json).

현재 각 단계에서 전체 snapshot을 다시 보내고 모든 client에 전체 결정도 전송하므로 fanout 비용이 있다. 중복 commit은 검증을 위한 추가 전송이다. 이 overhead와 실제 전체 모델 비용을 별도로 평가해야 한다. 작은 D의 내부 통신만으로 실용성을 단정하지 않는다.

## 5. 검증과 보안 한계

관련 Python 검사 **196개 통과**: 기존 169개와 새 Flower/client 경계 검사 27개다. Raw delta·불필요한 metadata·서명 변경·다른 client 매핑, 모델/dtype/round 변경, 불확실한 학습 재시작, 같은 round의 두 연결, client commit 이전 validation, 잘못된 quorum/parent와 재시작 후 중복 commit을 확인했다. 기존 Typer/Click 폐기 예정 API 경고 2개가 남는다. 실제 Flower·Rep4 실행은 단위 시험과 별도로 위 세 사례로 수행했다.

신뢰 모델은 계속 N=4, static 악성 aggregator f<=1이며 coordinator는 신뢰하지 않는다. 등록 adapter·Rep4·변환·검사·결과 출력의 악성 client–aggregator 공동 공모 합성 증명은 여전히 남는다. 결과 인증서가 native 계산을 quorum 3개만으로 지속하게 만들지는 않는다. 고정 입력 lock에는 view change/pacemaker가 없어 장애나 split proposal로 멈출 수 있다.

**한 WSL 호스트와 같은 Unix UID로 실행한 기능 검증**이다. 독립 운영자·OS 격리를 실험하지 않았다. 같은 UID의 공격자가 다른 process의 파일/메모리를 읽을 수 있는 문제를 process 분리만으로 해결했다고 주장하지 않는다. 실제 배치는 client별 개인 파일·aggregator별 키/share와 채널을 독립 host/권한 경계로 분리해야 한다.

시험용 client-local audit에는 양자화 원시 update를 저장하고, 종료 후 신뢰된 검증 도구만 읽어 reference와 비교했다. ServerApp과 aggregator API에는 이를 전달하지 않는다. 실제 서비스에서는 이 test-only audit을 끄고 민감한 client-local 자료를 운영 정책에 따라 보호해야 한다. 공개 archive에는 audit·AES seed·서명/TLS 개인키·MPC shares를 복사하지 않았다.

계속 실행되는 session 안의 seed share reuse만 지원한다. Native 재시작 시 secret share 복구, proactive refresh, committee 교체, client 입력 dropout은 미완료다. 디스크 rollback 방지는 운영 가정이다. 허용된 SUM/count에서 honest 기여 하나를 역추론하는 문제와 2 aggregator 공모의 share 복원 위험도 그대로다.

## 6. 파일과 재현

신규 모듈: `trustlessfl/seed_mpc_client_app.py`, `seed_mpc_server_app.py`, `seed_mpc_service.py`, `seed_mpc_session.py`, `seed_mpc_training.py`. 실행 도구: `experiments/run_seed_mpc_flower.py`.

```bash
cd /home/hacho/@WSL-Projects/trustlessFL
source .venv/bin/activate
python -m experiments.run_seed_mpc_flower \
  --mode fixture --output .cache/seed-mpc-flower-fixture-new
python -m experiments.run_seed_mpc_flower \
  --mode tiny-fmnist --output .cache/seed-mpc-flower-fmnist-new
python -m experiments.run_seed_mpc_flower \
  --mode fixture --fault uncertified-model --output .cache/seed-mpc-flower-reject-new
python -m pytest -q tests/test_seed_mpc_flower.py tests/test_seed_mpc_committee.py
```

출력에는 새 경로를 사용한다. 초기 compile/bootstrap 이후 `--phase run`, 완료 기록에는 `--phase verify`를 사용할 수 있다. Native session 재시작은 같은 session의 복구로 처리하지 않는다. 실패나 상태 유실에는 새 output/session/key가 필요하다.

[실행 요약과 45개 공개 로그의 hash](seed-mpc-flower-2026-10-11/summary.json), [FMNIST 검증](seed-mpc-flower-2026-10-11/tiny-fmnist/verification.json), [합성 반례](seed-mpc-flower-2026-10-11/fixture/verification.json), [잘못된 모델 거부](seed-mpc-flower-2026-10-11/model-reject/verification.json).

공식 API의 역할 구분은 [Flower의 ClientApp/ServerApp 설명](https://preview.flower.ai/docs/framework/tutorial-series-write-your-first-flower-app.html)을 참고한다. 실제 지원 여부는 설치된 1.36.0 코드와 공식 run 상태를 기준으로 확인했다.

다음 단계는 전체 LeNet5의 61706좌표로 확대하기 전, 중간 크기와 전체 D의 고정 fixture에서 CPU·메모리·내부 통신·마지막 SUM 출력 병렬화 비용을 확인하는 것이다. Flower 학습 성능을 작은 classifier 결과로 대신하지 않는다. Root Flower 앱/publisher 및 Hub 게시 설정은 변경하지 않았다.
