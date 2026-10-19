# 공개 입력 비교와 SIMD packing 최적화 검증

작성일: 2026-10-11. WSL `trustlessFL`, branch `work/aion-private-bound-no-wrap`.
[프로토콜](../aion-seeded-components-protocol.md), [공개 비교 자료](public-packed-2026-10-11/comparison.json).

## 1. 구현한 최적화

### 이미 공개된 입력은 인증된 공개 비교

이전 `agreed_public`은 aggregator의 wire 사본 네 개를 비밀 입력한 뒤,
사본 차이를 64-bit binary로 바꾸어 비밀 OR 회로로 비교했다.
새 `checked-open-v1`은 기존 악성 보안 Rep4 입력으로 사본 네 개를 넣고,
네 사본을 연 다음 CHECK를 완료하고 전체 64-bit 공개 equality를 검사한다.
검사 완료 전에는 clear 값을 branch, 마스크 제거 또는 집계에 사용하지 않는다.
불일치하면 `inconsistent public chunk`로 집계 공개 전에 중단한다.
등록 TLS digest tag 역시 네 사본의 일치와 확정된 등록 digest의 일치를 검사한다.

대상은 이미 공개 자료인 masked wire, snapshot header, presence, 등록 digest tag다.
Seed, component, 개인 update, norm, selection bit는 공개하지 않는다.
Component의 세 holder 사본은 계속 기존 비밀 입력과 비밀 equality로 검증한다.

### SIMD lane 수 증가

이전에는 lane 4개, 즉 chunk당 32좌표를 처리했다.
큰 모델의 기본값을 lane 64개, chunk당 512좌표로 변경했다.
D>=512에서 64, 소형 입력에서는 기존 4가 기본이며 `--chunk-blocks 1..64`로 지정할 수 있다.
동일한 binary subtraction, 좌표 검사, binary-arithmetic 변환과 global norm을 더 크게 묶어 실행한다.
Private component 입력과 public wire FIFO의 패딩·순서를 같은 처리 chunk 크기에 맞췄다.

Client의 서명된 wire 업로드 단위 32좌표는 바꾸지 않았다.
처리 묶음 크기는 global norm을 chunk별 판정으로 바꾸지 않는다.
마지막 chunk의 padding은 0이고, inactive 좌표는 norm과 SUM에서 제외한다.

## 2. 실제 FMNIST/LeNet5 결과

D=61,706, client 4명, 전체 FMNIST IID 15,000 train rows/client와 10,000 test rows,
seed 42, local epoch 1, 동일 optimizer/quantization/static threshold다.
고정 aggregator 4명 중 최대 악성 1명의 기존 신뢰 모델을 유지한다.
세 버전 모두 실제 공식 Flower Simulation Runtime/Ray와 native Rep4로 **1라운드** 실행했다.
모든 client가 제출·통과했고, 독립 재학습·정수 SUM·모델·평가가 정확히 일치했다.
초기 accuracy 10.00%, 첫 라운드 accuracy **74.84%**, loss 0.6796211730957031이다.

아래는 네 aggregator의 native **송신 payload 합계**다. Live preprocessing을 포함하고,
setup과 round를 분리한다. MB=1,000,000 bytes다.
Application/Flower/RPC, untracked native framing/exchange, TLS/TCP/IP는 이 수치에 포함하지 않는다.

| 버전 | 초기 native 등록 | 첫 라운드 native MPC |
|---|---:|---:|
| 이전 seeded component, lane 4 | 85,506 B | 675,883,188 B (675.883188 MB) |
| 인증된 공개 비교, lane 4 | 33,308 B | 446,533,798 B (446.533798 MB) |
| 인증된 공개 비교, lane 64 | 33,308 B | **345,574,822 B (345.574822 MB)** |

공개 비교가 33.93%, 이어 packing이 22.61%를 줄였다.
이번 작업 전체로 이전 675.88 MB 대비 **48.87% 감소**했다.
최초 secret-AES의 첫 라운드 829,863,684 B와 비교하면 총 58.36% 감소다.
후자의 historical secret-AES는 5 round slots로 컴파일했고, 이번 세 비교 버전은 모두 1 slot이다.
이를 동일 bytecode의 microbenchmark라고 표현하지 않는다.

세 버전의 정책·학습·backend pin을 exporter에서 대조한다.
각 실행은 fresh session과 등록 seed를 사용하며 execution hash도 다르다.
Counter는 native global sum과 endpoint 계측 대조를 통과했다.
수신 byte를 다시 더해 비용을 이중 계산하지 않는다.
암호화 seed bootstrap 본문은 native 비용에 합치지 않고 각 실행 요약의 별도 항목으로 기록한다.

참고로 로컬 ServerApp wall time은 160.024 → 123.211 → 41.246초였다.
이는 해당 단일 WSL 실행의 관측값이며 서비스 workflow를 포함하고 compile/Flower startup은 제외한다.
반복 성능 실험이나 원격 WAN 지연에 대한 보장은 아니다.

## 3. Packing 비교와 산술 검증

같은 1,024차원 scale fixture를 각각 세 라운드 실행했다.
모든 snapshot의 네 client가 제출했고 정수 합과 모델이 기준 계산과 정확히 일치했다.

| SIMD lanes | round 1 | round 2 | round 3 |
|---|---:|---:|---:|
| 4 | 7,843,686 B | 7,204,294 B | 7,204,294 B |
| 16 | 6,478,886 B | 5,846,854 B | 5,846,854 B |
| 64 | 6,140,182 B | 5,510,006 B | 5,510,006 B |

첫 라운드와 후속 라운드의 live preprocessing 비용이 달라질 수 있으므로 숫자를 분리해 보존한다.
Fixture는 80,000/−80,000의 wide SUM, 마지막 좌표 범위 위반,
여러 chunk에 걸친 global norm 위반 및 최소 통과 인원 미달을 포함한다.
실제 61,706차원 학습에는 512로 나누어떨어지지 않는 마지막 chunk도 포함된다.

## 4. 보안·회귀 검증

- Python 회귀: **315 passed**, 기존 Click deprecation warning 2개.
- Native fault 검증: lane 4에서 9종, lane 64에서 3종이 **모두 통과했다**.
  공개 wire 하위/최상위 bit, input tag 최상위 bit, presence 상위 bit,
  noncanonical wire, nonzero padding, TLS 등록 digest binding, seed equivocation,
  component equivocation을 검사한다. Lane 64에서 wire 최상위 bit/padding/component를 다시 검사한다.
- 각 fault의 native rejection과 aggregate/result checkpoint 0,
  durable genesis head 유지, 결과 vote/certificate 0은 probe가 검증한다.
- 격리 Flower Deployment에서 lane 64의 D=65 fixture **3라운드가 통과했다**.
  Raw audit 없이 공개 fixture 수식·인증서·native/RPC counter로 결과를 검증한다.
  역할 9개의 filesystem/PID 격리, cross-role 접근 72개 거부를 확인한다.

검증 결과 요약과 source snapshot은 [공개 자료 폴더](public-packed-2026-10-11/)에 보존한다.
개인 key/seed, packet plaintext, raw learning update/audit는 내보내지 않는다.
Local host bootstrap/admin과 공유 loopback network의 기존 전제를 유지한다.
위 fault 검증은 모든 악성 native message나 FL 구성의 형식적 보안 증명을 대신하지 않는다.

## 5. Wrap 정확성과 남은 비용

Wire는 Q=65,536에서 wrap될 수 있지만, 비밀 W-bit subtraction으로
`(y-mask) mod Q`를 정확히 복원한 뒤 canonical signed 정수를 검사한다.
2B<Q, 좌표 cap B=20,000, global norm, 넓은 ring SUM 계약은 바꾸지 않았다.
최대 좌표 합 80,000과 DB²=24,682,400,000,000의 ring 용량 검사도 유지한다.
공개 비교와 packing은 복원식이나 acceptance 조건을 바꾸지 않는다.

Component의 악성 보안 private input/사본 비교, binary 검사, 변환, norm,
selection, SUM, preprocessing/CHECK 비용은 남아 있다.
Native share 직접 import는 구현하지 않았으며, 입력·일치 검사를 삭제해 통신을 줄이지 않았다.
Norm 이내의 악성 update, 허용된 SUM/count/abort 역추론, 두 aggregator 공모에 대한 계약도 동일하다.
Flower Hub 게시 설정과 git commit/push는 수행하지 않았다.

## 6. 재현

```bash
.venv/bin/python -m pytest -q tests/test_seed_mpc_*.py tests/test_rep4_candidate.py
PATH="$PWD/.venv/bin:/usr/local/bin:/usr/bin:/bin" .venv/bin/python -m experiments.run_seed_mpc_flower \
  --output .cache/public-packed-fresh \
  --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3-telemetry \
  --mode fmnist-lenet5 --rounds 1 --snapshot-version 2 --communication-meter \
  --collection-window-ms 600000 --timeout 600
```

전체 모델은 기본 lane 64를 사용한다. `--chunk-blocks 4`로 packing 전과 비교할 수 있다.
공개 비교 이전 경로는 `--public-agreement secret-bit-compare-v1 --chunk-blocks 4`로 지정한다.
전체 secret-AES 이전 경로에는 추가로 `--mask-mode secret-aes-v1`을 지정한다.
Native fault 재현은 `experiments.run_seeded_components_security --fault ...`를 사용하며
lane 64 재현은 `--chunk-blocks 64`를 추가한다. Output은 새 directory를 지정한다.
