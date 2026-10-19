# Seed-MPC v2 수신증명·마감·입력 확정 구현

작성일: 2026-10-11. WSL Ubuntu-24.04, `work/aion-private-bound-no-wrap` 브랜치에서 [다음 구현 계획](../seed-mpc-next-implementation-plan.md)의 단계 2를 구현했다. 현재 wrap 복원·비공개 바운더리 회로는 유지하고, 그 회로에 들어갈 입력을 확정하는 수집 규칙을 추가했다.

## 구현한 동작

1. `collect-open`: 인증된 head의 다음 round/context/parent에 수집을 연다. 계약에 window 길이를 묶고 각 aggregator의 로컬 마감을 영속 저장한다. 재요청·재시작으로 마감을 연장하지 않는다.
2. `collect`: 한 client의 완전한 signed D좌표 입력을 검증한다. 전체 payload와 receipt를 함께 저장하고 commit 이후에만 서명을 반환한다. Partial·tampered·상충 입력, 잘못된 context/handle은 거부한다. Wire residue의 크기는 업데이트 norm 판정이 아니므로 여기서 plaintext 바운더리 검사를 수행하지 않는다.
3. `submission`/`receipt`: 저장된 공개 payload 및 기존 receipt를 조회한다. 동일 submission 재전송도 기존 receipt를 반환한다. 마감·close 뒤 새 receipt 발행과 기존 서명 조회를 구분한다.
4. `prepare`: snapshot의 각 present client에 전체 입력과 결합된 3-of-4 receipt QC를 요구한다. 자신이 receipt를 발행한 입력의 누락·교체를 거부한다. Subset/empty snapshot은 로컬 마감 뒤에만 확정하며, 등록 client 전원의 입력과 QC를 확보하면 조기 close할 수 있다.
5. Receipt 저장과 close/입력 lock/QC 보존/입력 vote 저장을 같은 SQLite write transaction으로 직렬화한다. Clock을 DB lock 획득 뒤 읽어 lock 대기 중 만료된 요청도 거부한다. Vote·receipt는 저장이 완료되기 전에 외부로 반환하지 않는다.
6. 직접 Rep4 runner와 공식 Flower v2 전원 제출 경로에 연결했다. Native/config/committee의 version, collection window와 backend pin도 대조한다. Flower 독립 검증기는 각 receipt QC를 선택된 전체 signed 입력에 다시 결합해 검증한다.

Default window는 60000ms, 직접 작은 fixture는 1000ms다. Window는 세션 시작 전에 1~3600000ms 중 선택한다. 현재 Flower는 학습 전에 수집을 열므로 학습과 업로드를 포함할 충분한 시간을 선택해야 한다. 절대 deadline은 로컬 값이며 동일한 collection hash는 context·parent·계약·window 길이에 묶인다. Clock 보호와 durable storage/rollback 방지는 운영 전제다.

## 수신증명 누락·교체 방지의 범위

Receipt signer 집합을 \(Q_R\), snapshot vote 집합을 \(Q_M\)라 하면

\[
|Q_R\cap Q_M|\ge3+3-4=2>f_{agg}=1.
\]

공통 정직 aggregator는 receipt를 먼저 저장했다면 그 입력을 누락·교체하는 투표를 거부한다. Close 투표를 먼저 저장했다면 새 receipt를 거부한다. Atomic 전이 때문에 동시 요청에서도 같은 규칙이 적용된다. 따라서 동일 입력에 대한 3명 receipt와 그 입력을 누락·교체한 3명 input vote가 양립할 수 없다.

반대로 마감 후 receipt 없이 받은 payload를 snapshot에 넣는 것도 각 present 입력의 QC 조건으로 거부한다. 다른 party에서 전체 payload와 유효 QC를 받아 자기 마감 후 투표하는 것은 허용하되 새 receipt를 발행하지 않는다.

서버에만 도착한 입력에는 포함 보장이 없다. 1~2명만 receipt를 가진 상태에서 재전파가 실패하면 확정이 중단될 수 있다. 로컬 마감은 글로벌 부재 증명이 아니며 이 구조는 모든 client의 참여 공정성이나 BFT liveness를 보장하지 않는다. Native는 여전히 네 aggregator의 실행을 필요로 한다.

## 검증 결과

| 항목 | 결과 |
|---|---|
| Python 관련 회귀 | 291 passed, 기존 Typer/Click deprecation warning 2개 |
| 그중 수집 상태기계 검사 | 34개: 정상 수신, 누락·교체, partial/변조, 마감·재시작, RPC, 두 DB 연결의 receipt/close 경쟁 등 |
| v2 실제 Rep4 | D=65, 16개 제출 패턴을 포함한 21라운드, 정수 결과·모델 일치 |
| v1 실제 Rep4 회귀 | D=65, 3라운드 통과 |
| 공식 Flower/Ray v2 | D=65 합성 fixture 3라운드, receipt QC 12개 독립 검증 |
| Flower 결과 | r1 count=4, r2 count=2, r3 abort; 정확한 SUM·모델·중복 적용 거부 |
| 실행 후 public ledger 대조 | 24라운드 × 4 party = 96개 closed/decided 상태·payload digest·저장 QC 일치 |
| 키 등록·컴파일 | 각 실행에서 client별 1회 등록, 동일 native 세션 유지, compile 1회 |

Receipt QC의 2명 서명·중복 signer·client signer·입력/context 변조를 거부했다. 3명 receipt를 받은 입력을 coordinator가 누락할 때 3명 정직 guard가 거부해, 다른 정직 1명과 악성 최대 1명을 합해도 input quorum을 만들 수 없음을 검사했다. Lock 대기 중 시간을 마감 뒤로 이동한 시험과 실제 서로 다른 SQLite 연결의 receipt/close 경쟁도 통과했다. 저장 완료한 receipt 조회는 마감·close 뒤에도 동일한 결과를 반환했다.

새 기능은 모두 fresh 세션/키와 새 출력 경로에서 검증했다. 이전 5라운드 FMNIST 및 단계 0/1 자료를 덮어쓰지 않았다. 이번 Flower 시험은 실제 FMNIST 재학습이 아닌 65좌표 합성 fixture다. 기존 native 회로는 이번 단계에서 변경하지 않았다.

## 시간·통신량

| 실행 | Compile | 실행 구간 | Native Global 누적 |
|---|---:|---:|---:|
| v2 직접 Rep4 21라운드 | 7.182초 | 25.782초 | 28.165 MB |
| v1 직접 Rep4 3라운드 | 5.980초 | 2.540초 | 4.12635 MB |
| 공식 Flower v2 3라운드 | 6.280초 | ServerApp counter 6.496초 | 4.14499 MB |

직접 v2 실행 구간에는 subset 확정을 위한 로컬 마감 대기가 포함되므로 순수 MPC 계산 시간으로 해석하지 않는다. Native Global은 setup 포함 세션 전체 누적이고 정확한 setup 제외 round별 비용은 아직 계측하지 않았다. Flower masked reply의 application JSON은 26792 bytes지만 새 receipt/prepare/query RPC 전체와 transport framing을 포함하지 않는다. 이 값으로 전체 프로토콜 통신량이나 성능 개선을 주장하지 않는다.

## 재현

새 output 경로로 WSL 저장소에서 실행한다.

```bash
source .venv/bin/activate
python -m experiments.run_seed_mpc_certified \
  --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 \
  --dimension 65 --snapshot-version 2 --participation \
  --collection-window-ms 1000 --output .cache/v2-collection-new.json

python -m experiments.run_seed_mpc_flower \
  --output .cache/v2-collection-flower-new \
  --mode fixture --dimension 65 --rounds 3 \
  --snapshot-version 2 --collection-window-ms 60000
```

[공개 검증 요약·소스/자료 SHA256](seed-mpc-v2-collection-2026-10-11/summary.json), [실제 Rep4 실행](seed-mpc-v2-collection-2026-10-11/participation.json), [Flower 공개 transcript](seed-mpc-v2-collection-2026-10-11/flower-results.json), [독립 검증](seed-mpc-v2-collection-2026-10-11/flower-verification.json), [영속 상태 대조](seed-mpc-v2-collection-2026-10-11/durable-state-verification.json), [JUnit](seed-mpc-v2-collection-2026-10-11/unit-tests.xml)을 보존했다. Flower 공개 committee 자료에는 서명 검증용 공개 identity·등록 계약만 있고 private keys는 없다. Client seed/raw audit, secret shares와 private input/TLS/signing files는 export하지 않았다.

## 다음 구현과 남은 한계

다음은 단계 3의 Flower timeout·부분 reply 분류, 전원 ACK 없이 진행하는 commit, 누락 결정 chain을 검증하는 client 복귀다. 현재 Flower는 v1/v2 모두 네 client의 reply와 ACK를 요구한다. 수신증명 조회 API는 준비됐지만 ClientApp이 receipt를 직접 확인하는 사용자 흐름도 다음 통합 범위다.

등록 도중 dropout, committee 변경, native secret-share 복구와 full BFT liveness는 현재 범위 밖이다. 역할 격리·악성 native 경로·등록부터 abort까지 합성 보안 증명도 미완료다. 같은 WSL/UID에서의 시험은 기능 검증이며, 공개 합계·count에서 가능한 역추론을 제거하지 않는다. Flower Hub 설정·게시를 수행하지 않았다.
