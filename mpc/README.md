# Local private-bound MPC prototype

## 공식 Flower masked 입력 연결

`experiments.run_seed_mpc_flower`는 ClientApp의 signed masked 업로드를 네 별도
aggregator/native process에 전달하고, ClientApp도 결과 인증서를 검증하도록 한다.
최초 seed 등록 후 share를 유지하며 170파라미터 FMNIST 모델의 실제 3라운드를
검증했다. [Flower 검토서](../docs/reproduction/seed-mpc-flower-review-2026-10-11.md).

```sh
python -m experiments.run_seed_mpc_flower --mode tiny-fmnist --output .cache/seed-mpc-flower-new
```

이후 `--mode scale-fixture --dimension 61706 --timeout 1800`으로 전체 LeNet5
크기의 dense 고정 입력을 3라운드 검증했다. 모든 정수 합·모델·abort가 참조와
일치했다. Compile 6.870초/1회, ServerApp 733.502초, native 통신 2476.15MB,
native 프로세스 최대 RSS 145.82MiB였다. [전체 차원 자원·통신 검토서](../docs/reproduction/seed-mpc-scale-review-2026-10-11.md).

`--mode fmnist-lenet5 --rounds 1 --timeout 1800`으로 학습 60000장·테스트
10000장의 실제 전체 LeNet5 학습도 완료했다. 정확도 74.84%, 통과 4/4명이며
독립 재학습의 정수 SUM과 최종 모델이 정확히 일치했다. ServerApp 256.587초,
native 통신 825.968MB였다. [실제 학습 보고서](../docs/reproduction/seed-mpc-lenet5-learning-2026-10-11.md).

같은 설정의 `--rounds 5`도 완료했다. 정확도 86.24%, 정상 제외 0/20회이며
모든 정수 SUM·모델이 독립 재학습과 정확히 일치했다. ServerApp 1253.902초,
native 통신 4126.98MB, compile/seed 등록 각각 1회였다.
[실제 IID 5라운드 결과](../docs/reproduction/seed-mpc-lenet5-iid-5r-2026-10-11.md).

단일 WSL/UID의 로컬 기능 시험이다. Non-IID 실제 MPC 학습·운영자 격리·완전한
합성 보안 및 BFT liveness는 미완료다. Hub 설정은 변경하지 않는다.

## 입력 인증과 계속 실행되는 세션

`experiments.run_seed_mpc_certified`는 서명된 입력 snapshot, SQLite 실행 예약,
등록 handle 바인딩, native 사후 CHECK, 3서명 결과 인증서와 모델 중복 적용 방지를
실제 Rep4에 연결한다. FIFO로 다음 라운드를 전달하며 키는 최초 한 번 등록한다.

```sh
.venv/bin/python -m experiments.run_seed_mpc_certified --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 --dimension 65 --output /tmp/certified-result.json
```

고정 committee 안전성 구현이며 일반 BFT liveness나 Flower 서버 앱의 완료 결과는
아니다. [인증 경로 검토서](../docs/reproduction/seed-mpc-certified-review-2026-10-11.md)에
실제 실행, 변조 중단, 재시작과 wrap 검증을 정리했다. 아래는 이전 probe 경로다.

## Rep4·비트 회로 후보 (2026-10-11)

4 aggregator 중 최대 1개 static 악성을 가정한 Rep4 후보를 추가했다.
기본 등록 입력은 AES-128 키를 두 개의 64bit word로 공유하며, 전체 replicated
triple components와 blinded 응답의 일치를 검사한다. 마스크 제거와 signed 좌표
범위 검사는 비트 회로에서 수행하고, 안전한 정수만 넓은 링에서 norm/집계한다.
최종 SUM/count/실패 상태는 native MPC의 공개 출력으로 전달한다.

```sh
.venv/bin/python -m experiments.run_seed_mpc_probe --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 --backend rep4 --coordinate-circuit binary --case multi-round --communication-stats
```

이 후보도 public Y는 compile 시 정한 synthetic fixture이며 전체 Flower 앱에
연결되지 않았다. [Rep4 검토서](../docs/reproduction/rep4-candidate-review-2026-10-11.md)에
통신 비교, 등록 adapter의 링 전환 문제와 수정, 검증 결과 및 남은 범위를 기록했다.
아래 기본 명령은 기존 MASCOT 기준선이다.

추가된 `seed_mpc_chunked_session.mpc`는 AES block 병렬 처리와 runtime chunk
반복을 사용한다. 공개 입력은 각 party의 실행 시 파일에서 읽어 전체 폭으로
일치를 확인한다. `--coordinate-circuit chunked --dimension 1024`로 실행한다.
`--compiled-workspace`에 이전 결과의 workspace를 지정하면 정책/회로/bytecode
검증 후 다시 컴파일하지 않는다. 전체 norm 판정 전에는 chunk SUM을 공개하지
않는다. [chunk·재사용 검토서](../docs/reproduction/rep4-chunked-review-2026-10-11.md)를 참고한다.

The new seed-MPC path uses `seed_mpc_session.mpc` and the shared compiler
helpers in `seed_mpc_primitives.py`. Run it with:

```sh
.venv/bin/python -m experiments.run_seed_mpc_probe --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 --case multi-round
```

It inputs four synthetic AES seeds once and reuses their authenticated shares
in one session for three rounds. Public masked fixture data is fixed at compile
time. `seed_aes_probe.mpc` is TEST ONLY and opens ciphertexts for known fixture
keys; never register real users through it. See the [native report](../docs/reproduction/seed-mpc-native-2026-10-11.md)
for results and remaining registration/BFT/Flower work. The old HPRF fixture
described below remains a separate baseline.

Use `--communication-stats` for native phase and external message counters, or
`--profile-stages` for the separate timer-instrumented synthetic circuit.
The [communication report](../docs/reproduction/seed-mpc-communication-2026-10-11.md)
explains preprocessing batching and why stage totals are not independent costs.

This directory contains the active MPC circuit used by the WSL fixture runner.
It is **not connected to the existing Flower apps**. No Hub configuration is
needed. See [scope and results](../docs/reproduction/private-bound-no-wrap-2026-10-10.md).

```sh
.venv/bin/python -m experiments.prepare_private_bound_mpc
.venv/bin/python -m experiments.run_private_bound_mpc --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 --case wrap
```

The installer uses the official MP-SPDZ 0.4.3 archive with a pinned SHA-256.
It requires Linux/WSL, Python 3.12+, OpenSSL CLI and the existing project virtual
environment (including cryptography). Binaries, certificates, private fixture
inputs and bytecode remain under ignored `.cache/private-bound-mpc`.

The runner starts four MASCOT parties and four separate ExternalIO clients with
fresh TLS identities. Every party receives authenticated shares of each
client's private key and canonical offset bits. The circuit validates bits,
privately evaluates HPRF and exact integer mask scaling, rejects invalid
coordinates before squaring, and emits only status/count/sum. No aggregate-key
release, modular output reduction, per-client norm or selected roster exists in
this path. The local harness knows the test inputs and waits for all native
parties to finish their MAC checks before recording a successful result.

Fixtures: `wrap`, `negative-wrap`, `norm`, `off-grid`, `coordinate-large`,
`nonboolean`, `insufficient`; `--mask-max 1` tests a small mask domain. `--real-moduli` selects
the original adapter's p/q constants with a controlled matrix, but does not
reproduce the missing author matrix artifact. Native tests with those constants
must be reported separately from the toy p=101, q=505 fixtures.

Field choice is separate from HPRF modulus choice. All integer intermediates
and the comparison/decomposition statistical margin must fit in the selected
127- or 255-bit prime field. Oversized configurations fail instead of wrapping.

This is an expensive baseline with active preprocessing. Local correctness
checks do not establish BFT liveness, malicious-party deviation coverage,
production security, poisoning robustness or practical FL-scale performance.
Do not reuse the trusted fixture harness as a server that collects real users'
private input files.
