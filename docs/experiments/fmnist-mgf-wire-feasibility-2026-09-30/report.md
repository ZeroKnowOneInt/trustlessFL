# FMNIST bounded-mask MGF 메시지·계산 비용 확인

## 현재 실행 상태

공식 FMNIST 실행기에 `aion_mgf_beta` 모드를 추가해 기존 `mgf_beta` 프로토콜을 연결했다. 이 모드는 classifier 평문을 추가하는 oracle 경로를 사용하지 않고 전체 masked vector와 수신자별 Pedersen share를 보낸다. bootstrap beta·alpha·norm bound·reference term은 CLI 인자와 manifest에 명시한다.

N=q=2, aggregator 4개, 전체 61,706차원, 1라운드를 공식 Flower runtime에서 시작했다. 두 client의 계산이 10분 넘게 계속됐으며 첫 모델 결과가 나오지 않아 해당 실행을 종료했다. 실행 폴더는 `.cache/fmnist/official-secure-mgf-beta-two-client-one-round-seed0`; 생성된 로그·manifest·초기 상태는 보존했다. 이 실행은 완료된 실험이 아니다.

## 메시지 크기 측정

현재 프로토콜은 각 좌표마다 2047비트 필드의 mask·blinder share를 각 수신자에게 별도로 암호화한다. 1좌표의 실제 직렬화 샘플을 동일한 형식으로 61,706개에 확장하면 MGF 재료만 약 726,964,738 bytes, 즉 693MiB로 추정된다. 랜덤 정수의 십진수 길이에 따라 조금 달라지는 추정치이며, 전체 메시지를 직접 생성한 측정값은 아니다. Flower adapter의 현재 AION payload 한도는 16MiB다.

따라서 native 정수 계산 가속만으로는 큰 모델 실행을 완료할 수 없다. wire 표현·전달 단위를 바꾸거나 mask share 비용이 적은 프로토콜 경로를 구현하고, 원래 선택 규칙과 집계 결과를 다시 확인해야 한다. 현재의 full-dimensional per-coordinate Pedersen 구성은 논문의 경량 통신량을 재현하지 않는다.

## 선택형 계산 가속

`fast-crypto` extra의 `gmpy2`를 사용하면 그룹 모듈러 거듭제곱을 GMP로 계산한다. Python fallback과 같은 RFC 3526 그룹, 값, commitment, 직렬화를 유지한다. 동일한 polynomial/blinder 입력으로 두 구현의 commitment와 복원이 일치하는 회귀 시험을 추가했다.

`gmpy2` 2.3.1에서 고정 그룹 입력 6개를 비교한 짧은 측정은 Python 0.113초, native 0.0135초, 약 8.3배였다. 전체 MGF 또는 Flower 성능 측정값은 아니다. 관련 Pedersen·MGF wire 시험 27개와 Runtime·FMNIST 시험 14개가 통과했다. 가속은 기존 bounded-mask 프라이버시 및 악성 client 증명 한계를 해결하지 않는다.

## 수신자별 벡터 암호화 구현

MGF mask share를 고정 길이의 이진 벡터로 묶고, 집계자마다 한 번의 X25519/HKDF/AES-GCM 교환으로 암호화하도록 바꿨다. ciphertext는 base64로 전송한다. AAD는 전체 commitment 행렬의 hash, 차원, task, client, 수신자와 round를 포함한다. 수신자는 기존 좌표별 Pedersen share 검증을 계속 수행한다. 원래 좌표별 packet 목록의 decoder도 유지해 이전 서명 update를 읽을 수 있다.

같은 64좌표 share의 두 표현을 실제 생성해 비교했다. 기존 material은 760,178 bytes, 벡터 material은 261,036 bytes로 65.7% 감소했다. 전체 FMNIST 차원으로 환산하면 약 233.5MiB이며 여전히 16MiB 한도를 초과한다. 이는 실제 61,706차원 runtime 측정값이 아니다. 원시 수치는 [vector-wire-size.json](./vector-wire-size.json)에 보존했다.

재현 명령은 다음과 같다. 각 실행의 랜덤 share 값에 따라 직렬화 크기는 조금 달라진다.

```bash
PYTHONPATH=.cache/flower-deps:. python3 -m experiments.measure_mgf_wire
```

변경 후 Pedersen·MGF wire 시험 29개와 MGF 입장 실패·HotStuff peer 복구 TCP 시험 3개가 통과했다. task/round/수신자 변경, commitment 좌표 순서 변경, ciphertext 변조·절단을 거부하고, 이전 packet 표현과 같은 share를 복원한다. 전체 차원 MGF와 q=100 실험은 아직 완료되지 않았다.

## Flower 메시지 분할 전달

Flower `ClientApp`와 `Grid` 경로에 4MiB 단위 업로드·다운로드를 추가했다. 각 Flower 메시지의 16MiB 한도는 유지하고, 최대 1GiB의 application envelope를 노드별 임시 파일에 모은다. 업로드가 완성되면 원본 SHA-256을 확인한 뒤 기존 application 처리기로 넘긴다. 큰 응답은 노드가 서명한 descriptor로 알리고, coordinator가 조각을 모아 해시와 원래 서명을 검증한다. 전체 blob 수신을 확인한 뒤 해당 임시 `.bin` 파일을 제거한다.

중단된 업로드는 같은 offset·내용으로 재전송할 수 있다. 충돌한 내용, 순서가 어긋난 조각, 틀린 해시 및 경로 형식은 거부한다. 복원한 요청이 다른 transport 명령을 재귀 실행할 수도 없다. 큰 `stage_update` 파일은 이후 `prepare`의 기존 서명·round·parent·digest 검사를 그대로 거친다.

실제 Flower Message 직렬화를 사용하는 ProcessGrid에서 16MiB보다 큰 요청과 서명된 응답을 왕복하고, 큰 update를 집계자 네 곳에 staging한 뒤 같은 update hash의 roster 인증서를 얻었다. 테스트가 모든 실제 메시지의 크기를 확인했다. 이는 공식 SuperLink/Ray의 전체 FMNIST 실행 증거는 아니다. P2P sidecar의 대형 프레임 분할, 전체 차원 Pedersen 계산 비용 및 q=100의 메모리 사용은 별도 과제로 남아 있다.

분할 전달·기존 AION 라운드·Runtime·MGF wire·pooled Grid를 함께 확인한 관련 회귀 시험은 93개 통과했다. 큰 업데이트 시험은 전송 경로를 확인하기 위한 인위적인 서명 payload이며, 실제 FMNIST 학습 결과를 검증한 시험으로 해석하지 않는다.
