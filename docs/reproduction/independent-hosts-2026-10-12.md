# 독립 호스트 실행 경로 구현·검증

2026-10-12. WSL `Ubuntu-24.04`, 브랜치 `work/aion-private-bound-no-wrap`.
[역할별 실행 절차](../seed-mpc-independent-hosts.md).

단계 4의 네트워크 실행 경로를 구현했다. A0는 Flower 서버와 MPC party 0을,
A1~A3는 각자의 MPC party를, client는 자신의 데이터·키로 학습을 실행한다.
이번 검증은 한 WSL의 Docker에서 역할별 filesystem/network namespace를 분리했다.
실제 네 독립 기관이나 물리 호스트에서 운영한 결과로 해석하지 않는다.
Flower Hub 게시·계정 연결·publisher 설정은 수행하지 않았다.

## 구현과 신뢰 경계

- `trustlessfl-distributed` CLI: 로컬 키 생성, 공개 계획, 운영자 승인, client 등록,
  공개 등록 확정, 자기 역할 binding, aggregator/Flower/client 실행.
- 각 역할에서만 개인 키와 seed를 생성한다. A0가 모든 역할의 비밀을 provisioning하지 않는다.
  각 aggregator는 client의 seed 4개 중 자기 slot을 제외한 3개를 수신자용 암호문으로 받는다.
  A0는 전체 masked update를 받지만 마스크 전체를 생성할 seed를 보유하지 않는다.
- RPC는 mTLS, 실제 peer fingerprint 확인, A0 제어 인증을 사용한다. Native MPC는
  승인된 호스트 목록과 각 역할의 TLS 키로 연결한다. Control/AppIO는 loopback에 둔다.
- 모두가 동일한 모델·정책·주소·운영자 키·앱 소스를 승인한다. 운영자마다 자기 승인 backend로
  회로를 독립 컴파일해 공개 bytecode와 대조한다. 단순한 A0 artifact hash 확인으로 대체하지 않는다.
- Client는 자신의 로컬 모델 소스를 명시적으로 승인한다. Client 소유 앱 guard는 Flower FAB를
  설치하기 전에 승인된 package bytes·entrypoint·파일 목록·CONTENT hash를 검사한다.
  A0가 변경한 ClientApp, 추가 실행 파일, 경로 탈출, 비밀 파일 hash 조회와 실행 중 dependency
  설치를 거부한다. 실제 ClientApp은 로컬 승인 패키지에서 가져온다.
- 복귀 client의 새 Flower node ID를 fresh challenge 서명으로 논리 client ID에 연결한다.
  중간 결과 인증서를 확인해 모델을 따라잡는다. 이미 시작한 불확실한 training round를 재계산하지 않는다.

기존 active Rep4, holder 사본 일치 검사, single mask, 정적 좌표·전체 L2 검사,
정확한 mod-2^16 마스크 제거·signed 복원·넓은 정수 SUM을 유지한다.
Aggregator는 고정 4명이고 세션 전체에서 악성·공모는 최대 1명이다.
두 aggregator의 공모, 집계 출력에서의 개인 기여 역추론, 전체 FL composition 보안은
이번 호스트 분리로 해결되는 문제가 아니다. 공개 키와 계약 fingerprint는 운영자끼리
인증된 채널에서 확인해야 한다. Client 모델 plugin은 승인한 로컬 코드이며 sandbox가 아니다.

## 실제 실행 결과

공식 Flower 1.36.0의 SuperLink/SuperNode와 MP-SPDZ 0.4.3 active Rep4를 사용했다.
Simulation/Ray 경로가 아니다. 모델은 6개 feature, hidden 5, 3-class MLP이며 파라미터는
53개다. Client마다 합성 학습 데이터 64개, 공개 평가 데이터 96개를 사용했다.
참조 계산은 알려진 합성 데이터 seed로 데이터를 별도로 생성하고 재학습했다.
실제 client의 seed·키·학습 데이터 파일을 참조 계산 입력으로 읽지 않았다.

| 시험 | Client / aggregator | Round별 presence | 통과 인원 | 정수 SUM·모델 | 인증서·수신증명 재검증 |
|---|---|---|---|---|---|
| 이탈·새 node ID 복귀 | 4 / 4 | `1111 → 1110 → 1111` | `4 → 3 → 4` | 모든 round 정확히 일치 | 통과 |
| 최종 wheel 실행 | 2 / 4 | `11 → 11` | `2 → 2` | 모든 round 정확히 일치 | 통과 |

첫 시험에서는 C3 컨테이너를 round 1 제출 후 종료했고 round 2의 native CHECK 뒤 재시작했다.
C3는 round 3에 새 Flower node ID로 인증·재참여했다. 최종 wheel 시험은 FAB CONTENT 검사까지
보강한 패키지를 새 세션에서 설치한 결과다. 이 최종 패키지로 4-client 이탈 시험을 다시
실행한 것은 아니다. 두 시험 모두 raw 업데이트 audit은 0개이며 A1의 A2 제어 RPC는 거부됐다.

각 컨테이너에는 자신의 native 개인 키 `Pp.key` 또는 `Ci.key`만 있었다.
Aggregator workspace에는 client 개인 설정이 없고, client workspace에는 aggregator 개인 설정이 없다.
다른 역할 workspace 및 Docker socket 접근도 차단됐다. 단, 호스트의 Docker 관리자는
모든 컨테이너를 통제할 수 있으며 실제 배포에서 서로 독립한 운영자를 대체하지 않는다.

이탈 시험 전체 실행은 **364.364초**, 최종 패키지 시험은 **231.705초**였다.
이 시간에는 등록·계획·승인·실행·참조 검증이 포함되며 MPC 한 round의 지연시간이 아니다.
합성 평가 정확도는 각각 초기 35.4167%에서 41.6667%, 39.5833%가 됐다.
이는 학습 연결 확인용이며 FMNIST 정확도나 poisoning 완화 성능 결과가 아니다.

마지막 commit ACK는 비동기 상태이므로 서버 종료 시 client ledger head가 마지막 결과보다
뒤처질 수 있다. 이탈 시험 종료 기록의 C3 ACK counter는 0이었지만 C3의 round 3 참여와
결과 체인 동기화는 실제 제출·정수 참조·인증서 검사로 확인했다. ACK 도착을 round 성공 조건으로
해석하지 않는다. Native/aggregator 중단 후 같은 seed로 재실행하지 않으며 새 세션이 필요하다.
초기 roster 미접속, 네트워크 DoS, 악성 aggregator의 MPC 중단에 대한 전체 BFT liveness는 제공하지 않는다.

## 회귀 검사와 수정 사항

```bash
.venv/bin/python -m pytest -q tests/test_seed_mpc_*.py tests/test_rep4_candidate.py
```

**490 passed**, 26.49초. Click/pathspec의 기존 dependency deprecation warning 82개가 있었다.
실제 mTLS 연결과 잘못된 인증서·fingerprint 거부, public plan·모델·회로·enrollment 변조,
독립 컴파일 대조, public 파일 복사 목록, native active/TLS 옵션, 새 node ID challenge,
FAB 코드·메타데이터 검사 및 공식 Flower FAB builder와의 호환성을 포함한다.
Native 실행 두 시험은 이 unit/regression 검사와 별도다.

이전 실패 시도를 성공 결과로 포함하지 않았다.

- 최초 runner가 종료 직전 모든 client의 마지막 ACK를 요구해 실패했다. 이미 완료된 두 round는
  별도 정수 참조·인증서 재검증에 일치했으며 runner의 성공 조건을 인증된 commit으로 수정했다.
- 컨테이너 pause/기존 node ID 복귀 시험은 재참여하지 못했다. Fresh identity challenge와
  새 node ID 발견·매핑을 추가한 뒤 실제 종료·재시작 시험에서 `4 → 3 → 4`를 확인했다.
- 최종 FAB 검사에서 CONTENT 크기 필드를 byte로 해석해 client가 올바른 FAB를 거부했다.
  Flower의 bit 단위에 맞춰 고쳤고 공식 builder 회귀 검사와 최종 wheel 실행 모두 통과했다.

## 재현과 공개 기록

역할별 실제 호스트 명령은 [실행 문서](../seed-mpc-independent-hosts.md)에 있다.
Docker 검증은 wheel만 포함한 build context와
[검증 이미지 Dockerfile](../../deployment/seed-mpc/Dockerfile.distributed-validation)을 사용한다.
이 Dockerfile은 이전 단계의 검증 base에서 backend를 준비·확인한다.
실제 위 시험은 이전 단계에서 source build·승인한 같은 backend를 포함한 로컬 검증 이미지를
사용했다. 따라서 서로 다른 OS/toolchain 네 곳의 독립 source build를 검증했다고 주장하지 않는다.

```bash
.venv/bin/python experiments/validate_seed_mpc_distributed.py \
  --image trustlessfl-distributed-validation:final-v2 \
  --output .cache/my-independent-host-validation --clients 4 --dropout
```

이 명령은 전용 bridge와 역할별 컨테이너를 생성하고 종료 후 자신이 만든 컨테이너·network를 정리한다.
새 output directory를 사용한다. Docker image는 로컬에만 준비했으며 registry에 게시하지 않았다.

공개 기록은 [4-client 이탈·복귀 결과](independent-hosts-2026-10-12/dropout-rejoin.json),
[최종 패키지 결과](independent-hosts-2026-10-12/final-package.json),
[검증 artifact hash 목록](independent-hosts-2026-10-12/manifest.json)에 있다.
개인 키·seed·학습 데이터·native input·SQLite client 상태는 공개 기록에 복사하지 않았다.
원본 역할별 workspace는 로컬 `.cache` 검증 자료이므로 배포 bundle이나 공개 저장소에 포함하지 않는다.

## 후속 패키지 검증

같은 날 후속 작업에서 기존 final-v2 wheel의 4-client 3라운드 이탈·복귀를 재시험해
4→3→4 및 정수 합·모델·인증서 일치를 확인했다. 이어 client native 설치를 제거한 새 wheel도
MLP 4→3→4와 CNN 2라운드를 통과했다. [후속 결과와 패키지 안내](package-validation-2026-10-12.md).
