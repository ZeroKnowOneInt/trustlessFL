# Seed-MPC v2 제출 비트·미제출 회로 검증

작성일: 2026-10-11. [다음 구현 계획](../seed-mpc-next-implementation-plan.md)의 단계 0/1을 구현·검증했다. 실제 client dropout의 Flower 마감·수신증명·복귀 경로는 아직 구현하지 않았다.

## 변경 사항

- v1 계약·등록·snapshot 경로를 보존하고 명시적인 v2 등록/계약/snapshot/vote를 추가했다. v2에도 기존 signed wire encoder를 사용하며 등록과 snapshot은 버전별로 구분한다.
- v2에는 전체 등록 slot 순서의 canonical 정수 presence 비트와 absence marker가 있다. Present slot은 완전한 signed D좌표 입력을 요구한다. Absent slot에 payload가 있으면 거부한다.
- Runtime 입력은 `[version=2, round, SHA256의 4개 word, presence N개, slot별 padded wire]`다. Absent wire는 canonical 0 framing이며 실제 0 업데이트로 해석하지 않는다.
- Native는 version/presence/hash/Y를 네 party의 full-width 사본 검사에 넣고 presence의 0/1을 검증한다. Absent slot의 nonzero wire도 거부한다. Sanitization과 최종 accept 비트에 presence를 적용해 합계와 인원을 모두 제외한다.
- 비밀 좌표·global norm·선택 비트를 직접 공개하지 않고 기존 인증 출력과 exactly-once 모델 갱신 경로를 유지한다. Result count가 제출자 수보다 클 수도 없다.
- 공식 MP-SPDZ 0.4.3 archive SHA256을 확인하고 주요 소스 디렉터리의 616개 소스 파일을 archive와 대조했다. 실행 native binary가 archive의 `bin/Linux-adx/rep4-ring-party.x`와 일치함을 확인했다. Pin을 재검증하고 임의 flags 없이 고정 malicious Rep4 argv로 실행한다. 소스·binary·archive 변경과 self-consistent 가짜 pin을 거부한다.
- 새 certified runner와 새 Flower staging의 execution/config hash에 backend pin을 결합한다. 기존 archive를 수정하지 않는다. 공식 prebuilt binary를 사용하므로 upstream의 정확한 빌드 명령까지 확인했다고 주장하지 않는다.

## 실제 검증

| 항목 | 결과 |
|---|---|
| Python 관련 회귀 | 250 passed |
| v2 실제 Rep4 | D=65, 21라운드, 독립 정수 결과·모델 일치 |
| 공개 제출 패턴 | 4명 기준 16개 전부 |
| 추가 산술 사례 | 실제 0 업데이트, cross-chunk norm 초과, 마지막 좌표 범위 초과, ±80000 SUM, 인원 부족 abort |
| 키 등록·컴파일 | 각 client 1회 등록, native 세션 1개, compile 1회 |
| v2 compile 시간 | 6.632초 |
| v2 native 시간 | 9.722초: 등록 완료 대기와 21라운드 등 runner 구간 |
| v2 native Global 통신 | 28.165 MB: setup 포함 전체 누적, round별 setup 제외 비용 아님 |
| v1 실제 Rep4 회귀 | D=65, 3라운드 통과 |
| 공식 Flower/Ray v1 회귀 | D=65 합성 fixture 3라운드; SUM/count·모델·abort·재전송 검증 통과 |

Native fault 사례 7개를 각각 새 세션으로 실행했다. 모두 result certificate 0개, 모델 갱신 0회였다.

1. 한 party의 presence 불일치.
2. 한 party presence의 32번 bit 변조: 낮은 bit만 비교하는 검사를 방지.
3. 모든 사본에 동일한 presence=2: 일치하더라도 canonical bit가 아니므로 거부.
4. Absent slot의 nonzero dummy wire.
5. v2 회로에 stream version=1 전달.
6. 한 party의 input digest 상위 bit 변조.
7. 등록 handle/descriptor digest 불일치.

등록 오류는 실행 예약 전에 거부한다. 나머지 실행 중 오류는 예약 상태가 영속되며 불확실한 round의 재실행을 거부했다. 이 시험은 public stream/등록 입력 변조에 대한 실제 native 거부 검증이다. 임의로 수정된 악성 native party의 모든 selective-failure 공격을 검증한 것은 아니다.

16개 제출 패턴에서 반복 부재·복귀에 해당하는 slot 변화가 있어도 같은 key로 새 round mask가 정확했다. 이는 회로·인증 상태 경로의 검증이며 실제 오프라인 Flower client의 catch-up 검증은 아니다.

Flower 첫 시도는 가상환경의 `flwr`/`flower-superlink`가 PATH에 없어 학습 실행 전에 중단됐다. 종료·정리 후 PATH를 설정하고 별도 fresh 세션에서 정상 완료했다. 실패한 디렉터리의 seed/native 세션을 재사용하지 않았다. 이번 Flower 회귀는 FMNIST 재학습이 아닌 65좌표 합성 fixture다.

## 재현

WSL 저장소에서 가상환경을 활성화한 뒤 실행한다. `--output` 파일·디렉터리는 새 경로를 사용한다.

```bash
source .venv/bin/activate
python -m experiments.run_seed_mpc_certified \
  --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 \
  --dimension 65 --snapshot-version 2 --participation \
  --output .cache/v2-presence-new.json
```

Fault는 위 명령에 `--fault presence-highbit` 등의 옵션을 추가한다. 지원 옵션은 runner의 `--help`에 있다. v1 회귀는 `--snapshot-version 1`로 두고 `--participation`을 제거한다.

```bash
python -m experiments.run_seed_mpc_flower \
  --output .cache/backend-flower-new \
  --mode fixture --dimension 65 --rounds 3
```

[공개 검증 요약·소스/자료 hash](seed-mpc-v2-presence-2026-10-11/summary.json), [실제 v2 실행·인증 자료](seed-mpc-v2-presence-2026-10-11/participation.json), [backend pin](seed-mpc-v2-presence-2026-10-11/backend-pin.json)에 기록을 보존했다. Client key·private identity·private input 파일은 export하지 않았다.

## 남은 범위

다음 구현은 수신증명·마감·입력 확정, Flower의 가변 reply/비차단 commit 및 복귀 chain 동기화다. 현재 제품 Flower 경로는 여전히 네 client 전원 제출·ACK를 요구한다. 역할 격리, 전체 등록/변환/출력/abort 합성 증명, 세션 간 재질의 통제와 setup을 분리한 round별 통신량 계측도 남아 있다.

