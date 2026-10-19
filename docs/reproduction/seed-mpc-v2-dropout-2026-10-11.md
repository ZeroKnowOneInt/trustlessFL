# Seed-MPC v2 Flower dropout·비차단 commit·복귀 구현

작성일: 2026-10-11. WSL Ubuntu-24.04의 `work/aion-private-bound-no-wrap` 브랜치에서 [다음 구현 계획](../seed-mpc-next-implementation-plan.md)의 단계 3을 구현했다. Single AES mask·최초 seed 등록·비밀 바운더리 검사와 기존 wrap 복원 회로는 유지했다.

## 구현한 처리

- V2 train 요청은 Flower Grid에 push하고 reply를 polling한다. 도착한 입력을 즉시 완전성 검증·receipt 저장한다. 한 client를 기다린 뒤 나머지 receipt를 발행하지 않는다.
- Error·timeout·불완전 입력은 해당 client의 미제출 후보로 분류한다. 마감까지 완전한 입력과 receipt QC가 있는 client만 snapshot에 넣는다. 조기 subset close는 허용하지 않는다. 범위 밖이지만 형식·서명이 유효한 wire는 기존처럼 MPC에서 검사한다.
- Receipt RPC가 실패하면 보존된 payload/receipt를 조회한다. 0명 receipt이면 미제출 처리할 수 있고, 3명 이상이면 QC를 구성한다. 1~2명만 receipt를 가진 상태는 조용히 제외하지 않고 명시적으로 확정 실패로 보고한다.
- 인증 결과 적용 후 commit을 한 번 push한다. ACK는 polling하고 **전원 ACK를 기다리지 않는다.** 누락·변조 ACK는 다음에 보낼 suffix 길이에만 영향을 준다. 세션 끝의 최대 0.5초 drain도 best effort이며 성공 조건이 아니다.
- 다음 train 요청에 client가 확인하지 못한 결정 suffix와 현재 모델을 넣는다. Client는 전체 suffix의 계약·input/result QC·연속 parent·모델 hash를 먼저 검증한 뒤 새 결정을 영속 적용한다. 자기 입력이 absent였던 결정과 abort도 검증한다.
- 동일 결정을 다시 받으면 저장된 결과와 대조하고 재적용하지 않는다. 늦은 과거 commit은 head를 되돌리지 않는다. 학습에는 정확히 다음 round와 그 인증 모델을 요구한다. 같은 counter로 새 ciphertext를 만들지 않는다.
- V1의 역사적 전원 제출·ACK 경로를 보존했다. 새 dropout 경로는 `snapshot_version=2`를 명시해서 실행한다.

진행 중인 ServerApp은 client별 유효 ACK round와 결정 목록을 유지한다. ACK를 못 받았지만 client가 이미 적용했다면 동일 결정 replay가 발생할 수 있으며, client의 영속 ledger가 이를 확인한다. 유효한 suffix 적용 중 crash가 나면 인증 prefix가 남아 재전송으로 이어갈 수 있다. Coordinator/native 세션 자체의 crash 복구를 추가한 것은 아니다.

## 실제 Flower·Rep4 검증

Official Flower Simulation Runtime/Ray, 네 aggregator의 실제 `rep4-ring-party.x`, D=65, Q=65536, B=20000, 정적 squared threshold 2500000000, a_min=2로 실행했다. Client별 최초 seed 등록 1회, 같은 native 세션에서 10개 round를 소비했으며 compile은 1회였다. 합성 입력의 처음/마지막 좌표는 ±20000이어서 전원 참가 시 ±80000 SUM도 확인한다.

| Round | 주입한 전송 조건 | 실제 presence | 인증 결과 |
|---|---|---|---|
| 1 | 전원 정상 | 1111 | count=4 |
| 2 | C3 train handler가 window를 넘겨 응답, commit 부재 | 1110 | count=3 |
| 3 | C2/C3 업로드 전 unavailable, commit 부재 | 1100 | count=2 |
| 4 | C2/C3 복귀, C1 전체 업로드 후 commit 부재 | 1111 | count=4 |
| 5 | 전원 업로드, 네 client 모두 commit/ACK 부재 | 1111 | count=4 |
| 6 | C2 일부 청크만 reply, C3 unavailable | 1100 | count=2; r5 ACK 없이 진행 |
| 7 | C1/C2/C3 unavailable | 1000 | abort; 모델 유지·head 전진 |
| 8 | 전원 복귀 | 1111 | count=4; 누락 정상/abort 검증 |
| 9 | 전원 unavailable | 0000 | abort; 모델 유지·head 전진 |
| 10 | 전원 복귀 | 1111 | count=4; empty-round abort 검증 |

모든 10개 정수 SUM/인원 및 모델이 로컬 독립 oracle과 정확히 일치했다. Present 입력의 receipt QC 28개를 전체 signed payload와 대조했다. C3는 r4 학습 전에 head 1→3, r8 전에 4→7, r10 전에 8→9의 결정을 검증했다. C1도 r4 commit 부재 뒤 r5 학습 전에 3→4를 동기화했다. 모든 client는 이 실행의 종료 시 head 10에 도달했지만, 종료 시 전원 동기화는 일반 프로토콜의 필수 조건이 아니다.

시험의 unavailable/부분 reply/ACK 부재는 pinned test schedule에서 ClientApp에 주입했다. R2는 실제 handler 지연으로 Flower reply가 collection window를 넘기는 경우다. 다른 unavailable 사례는 ClientApp Error reply다. 실제 Flower/Ray 및 native MPC를 실행한 기능 검증이며 물리 장치 전원 종료·독립 네트워크 배치나 악성 native 구현 전체를 시험한 것으로 확대하지 않는다.

| 검증 | 결과 |
|---|---|
| Python 관련 회귀 | 322 passed; 기존 Typer/Click deprecation warning 2개 |
| 신규 dropout 검사 | 31개: 체인/모델/QC 변조·gap·replay·stale train, streaming deadline, ACK absence/위조, 불완전 receipt 상태 등 |
| 공식 Flower v2 정상 fixture 회귀 | 3라운드·12개 receipt QC; 정상 count=4, 위반 제외 count=2, abort |
| 공식 Flower v1 정상 fixture 회귀 | 3라운드; 기존 인증·전원 commit·중복 적용 거부 유지 |
| 세 실행의 aggregator public ledger | 16라운드 × 4 party = 64개 decided 상태 및 v2 collection/proof/digest 대조 |

Bad suffix의 마지막 인증서가 잘못된 경우에도 앞선 새 결정이 먼저 저장되지 않음을 검사했다. 이미 완료한 suffix의 반복 및 늦은 과거 commit은 모델을 재적용하거나 rollback하지 않았다. Client의 raw update는 test-only oracle 파일에만 기록되고 Flower reply에는 signed masked 입력만 들어간다.

## 시간·통신 기록

| 실행 | Compile | ServerApp counter | Native Global 누적 |
|---|---:|---:|---:|
| v2 dropout 10라운드 | 6.431초 | 25.972초 | 13.6411 MB |
| v2 정상 3라운드 | 7.684초 | 6.667초 | 4.14499 MB |
| v1 정상 3라운드 | 8.433초 | 5.946초 | 4.12635 MB |

Dropout window는 3000ms, 정상 v2 window는 60000ms다. Subset round에는 의도적인 마감 대기가 있다. 회귀 실행 일부는 같은 호스트에서 겹쳐 실행했으므로 위 시간으로 버전 간 성능 개선을 주장하지 않는다. Compile은 ServerApp counter 밖이며 Flower CLI 전체 시작/종료 시간과도 구분한다.

Native Global은 setup 포함 누적이다. 정확한 setup/round/shutdown counter 분리는 다음 단계다. Dropout 실행의 수집된 masked reply JSON은 62572 bytes이며 commit 체인·모델·receipt RPC와 transport overhead를 모두 센 값이 아니다. 불확실한 전체 application 통신량으로 합산하지 않는다. 결정 suffix는 full signed snapshot을 포함하므로 긴 부재 후 catch-up 비용도 후속 계측 대상이다.

## 재현과 공개 자료

새 출력 경로로 WSL 저장소에서 실행한다.

```bash
source .venv/bin/activate
python -m experiments.run_seed_mpc_flower \
  --output .cache/dropout-new \
  --mode dropout-fixture --dimension 65 --rounds 10 \
  --snapshot-version 2 --collection-window-ms 3000
```

정상 v2 회귀는 `--mode fixture --rounds 3 --collection-window-ms 60000`, v1 회귀는 `--snapshot-version 1`을 사용한다. 실제 학습 전에 수집 window를 여는 현재 경로에서 full FMNIST를 실행할 때는 학습·업로드를 포함할 충분한 window가 필요하다.

[공개 요약·소스/자료 SHA256](seed-mpc-v2-dropout-2026-10-11/summary.json), [실제 dropout 공개 transcript](seed-mpc-v2-dropout-2026-10-11/dropout-results.json), [독립 검증·client sync trace](seed-mpc-v2-dropout-2026-10-11/dropout-verification.json), [전송 실패 일정](seed-mpc-v2-dropout-2026-10-11/transport-fault-schedule.json), [영속 상태 대조](seed-mpc-v2-dropout-2026-10-11/durable-state-verification.json), [JUnit](seed-mpc-v2-dropout-2026-10-11/unit-tests.xml)을 보존했다. Public archive에는 공개 identity·등록·masked 입력·합계·모델·인증자료만 있으며 seed, private signing/TLS keys, raw client updates/audits, secret shares와 private input 파일은 제외했다.

## 남은 범위

이번 복귀는 고정 client roster·동일 Flower node mapping·보존된 client seed/ledger와 계속 실행 중인 native 세션을 전제로 한다. 초기 등록 도중 dropout, 새 node ID 자동 재매핑, coordinator/native 재시작 복구, committee 변경과 full BFT liveness는 구현하지 않았다. Aggregator가 멈추면 기존 native 계산은 진행을 보장하지 않는다.

다음은 단계 4의 setup/round/shutdown byte counter 및 Flower/RPC 계측이다. 역할 격리·악성 native 경로·전체 합성 보안 증명과 전체 FMNIST dropout 5라운드는 단계 5/6에 남아 있다. 이번 10라운드는 FMNIST 재학습이 아닌 합성 fixture다. 공개 합계·count로 가능한 역추론은 기존 보안 한계로 유지한다. Flower Hub 설정·게시를 수행하지 않았다.
