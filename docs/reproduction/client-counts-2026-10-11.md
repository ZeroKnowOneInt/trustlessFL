# Client N 범용화와 실제 Flower/Rep4 검증

작성일: 2026-10-11. 브랜치 `work/aion-private-bound-no-wrap`.
사용자용 로컬 실행에서 client 4명 고정을 제거했다. Aggregator는 A0..A3의 4명이며 정적 악성/공모 aggregator 최대 1명이라는 Rep4 계약을 유지한다. Flower Hub 계정·게시 설정이나 업로드는 수행하지 않았다.

## 구현

`model.json`의 `train_data` 목록 길이로 client N을 정한다. 선택적인 `prepare --clients N`은 목록과의 일치 검사다. Provisioning, TLS client 등록, seed 전달, client slot, Flower node mapping, 인증된 제출 집합, 공개 검증과 프로세스 정리에 N을 사용한다. Seed component와 aggregator의 4개 상수는 유지한다.

정책 `max_clients`를 생략하면 N을 사용하고 명시하면 실제 N과 같아야 한다. Empty roster, N 불일치, `minimum_accepted>N`, backend ring 용량 초과는 session directory/backend 실행 전에 거부한다. `N*B`와 count/SUM 폭은 실제 N을 기준으로 검사한다. 공개 회로 cache recipe에 N과 폭이 포함되므로 N 변경은 새 회로를 만들며 동일 설정의 새 세션은 cache hit다. 라운드마다 컴파일하지 않는다.

세션 중 roster는 고정이다. Registered client의 dropout/복귀는 presence와 인증 모델 head 동기화로 처리한다. 신규 client의 세션 중 가입을 구현한 것이 아니다. 기존 `experiments.run_seed_mpc_flower`의 4-client benchmark는 비교를 위해 그대로 유지한다.

## 실제 학습 검증

53-parameter MLP, synthetic client별 64개 학습 샘플/공개 평가 96개, SGD·cross entropy, 2라운드를 공식 Flower CLI와 승인된 direct Rep4 backend에서 실행했다. 사용자 실행의 raw update audit은 비활성화했다. 별도 trusted 개발 검증기만 원래 NPZ로 재학습하여 인증된 SUM, 모델 전이, 평가값과 정확히 비교했다. 이 재학습 oracle는 일반 사용자 summary verifier에 포함하지 않았다.

| Client N | Aggregator | Flower round | 매 round 통과 | SUM 폭 / count 폭 | Wire / norm 폭 | 원래 실행 compile |
|---:|---:|---:|---:|---:|---:|---:|
| 4 | 4 | 2 | 4 | 19 / 5 | 18 / 37 | 0 (기존 cache hit) |
| 8 | 4 | 2 | 8 | 20 / 6 | 18 / 37 | 1 |
| 16 | 4 | 2 | 16 | 21 / 7 | 18 / 37 | 1 |

모든 라운드의 정수 SUM·모델·평가는 정확히 일치했고 raw audit 파일은 0개다. 폭은 현재 구현의 보수적인 여유 폭을 포함한다. B=20,000, T=2,500,000,000, S=10,000, Q=65,536이며 64-bit backend ring 용량 검사를 통과했다.

### 초기 setup과 native 라운드 송신량

네 aggregator의 upstream tracked Player payload 송신 bytes 합계다. 각 transmission은 한 번만 센다. Live preprocessing은 포함하고, native framing/TLS/TCP/IP, retransmission, untracked setup/final exchange 및 Flower/RPC 통신은 이 표에서 제외한다. Client 한 명의 송수신량을 뜻하지 않는다.

| Client N | Setup bytes | Round 1 bytes | Round 2 bytes |
|---:|---:|---:|---:|
| 4 | 33,884 | 535,150 | 267,982 |
| 8 | 61,580 | 1,062,798 | 528,878 |
| 16 | 116,780 | 1,584,526 | 1,584,526 |

두 라운드 비용 차이에는 preprocessing batch 경계가 영향을 준다. 이 작은 D=53 측정에서 대형 모델의 비용을 단순 비례로 확정하지 않는다. 원본 counter와 reconciliation은 [공개 검증 JSON](client-counts-2026-10-11/verification.json)에 보존했다.

## Native wrap·dropout·바운더리·abort

각 N에서 새 세션으로 4라운드를 실행했고 reference와 인증 결과 및 네 aggregator의 모델 head가 일치했다.

| Round | 입력 조건 | N=4 | N=8 | N=16 |
|---:|---|---|---|---|
| 1 | 전원 제출, 마지막 좌표 +20,000 | count 4, tail SUM 80,000 | count 8, tail SUM 160,000 | count 16, tail SUM 320,000 |
| 2 | 마지막 client dropout, 나머지 tail −20,000 | count 3, tail −60,000 | count 7, tail −140,000 | count 15, tail −300,000 |
| 3 | 전원 복귀, C0 좌표 cap 초과, C1 전체 norm 초과 | count 2 | count 6 | count 14 |
| 4 | C0만 제출, minimum_accepted=2 | abort | abort | abort |

Round 3의 유효 입력은 첫 좌표 3·마지막 좌표 4이며, invalid client 전체를 제외했다. Round 4는 SUM/count를 내보내지 않고 모델을 유지했다. 누락 client가 있는 집합은 collection deadline 이후 확정했다.

Round 1의 SUM은 Q를 넘는다. MPC는 각 wire에서 `(y-mask) mod Q`와 signed lift를 수행한 뒤 최종 합을 넓은 ring에서 계산하여 위 SUM을 정확히 보존했다. 등록 roster를 늘려도 wire modulus로 최종 합을 다시 줄이지 않는다.

## 최고 slot 등록 변조

N=16의 C15에서 component 1의 A0 사본만 수정하고, 클라이언트의 올바른 서명·수신자 암호화 packet으로 다시 만들었다. 다른 holder 사본은 원래 값을 유지했다. 네 native party 모두 `inconsistent component seed registration`으로 거부했다. 네 ledger의 head는 genesis round 0이고 rounds row는 0개였으며 checked registration·public result 출력도 없었다. N=4의 첫 등록 batch를 넘어선 client까지 active consistency 검사가 적용됨을 확인했다.

특정 변조 사례의 기능 회귀이며 모든 악성 실행의 프라이버시 증명이 아니다.

## 패키지와 회귀 검증

관련 `tests/test_seed_mpc_*.py`와 `tests/test_rep4_candidate.py` **404개**가 통과했다. 기존 Click deprecation warning 2개는 남아 있다. 전체 프로젝트 테스트 통과를 의미하지 않는다.

Wheel을 새로 빌드하여 별도 target directory에 설치하고 저장소 밖 `/tmp`에서 설치 모듈을 호출했다. 8-client 사용자 세션의 실제 Flower/Rep4 2라운드가 통과했다. Compile은 0회/cache hit이고, 별도 재학습의 정수 SUM·모델·평가는 모두 일치했다. Raw audit 파일은 0개다. Wheel에는 packaged MPC source resource가 있고 experiments/tests, NPZ, SQLite, TLS private key는 없다. [Package 검사](client-counts-2026-10-11/package-checks.json), [설치 경로 실행 검증](client-counts-2026-10-11/wheel-training-8.json).

공개 JSON 3개와 hash manifest만 보존했으며 실제 사용한 client seed·client/aggregator private identity 문자열 포함 여부를 검사해 clean을 확인했다. [Manifest](client-counts-2026-10-11/manifest.json).

## 재현

WSL repo root에서 같은 승인 backend와 의존성을 사용하고 새 output directory를 지정한다. 다음은 일반 사용자 실행과 달리 NPZ 재학습을 수행하는 trusted 개발 검증 도구다.

```bash
.venv/bin/python -m experiments.validate_seed_mpc_client_counts \
  --output .cache/seed-mpc-client-count-validation-new \
  --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3-direct-rep4-v1 \
  --clients 4 8 16 --native-fixtures --registration-fault
```

일반 사용자는 [audit 없는 사용자 CLI](../seed-mpc-user-runtime.md)를 따른다. 같은 UID의 로컬 bootstrap이며 독립 운영자/host 격리, 대규모 N의 가용성, DP 및 전체 프라이버시 증명을 추가하지 않았다. 공개 SUM/count/abort의 역추론 한계와 f<=1 가정은 유지된다. 다음 운영 과제는 backend 설치 자동화와 독립 host provisioning이다.
