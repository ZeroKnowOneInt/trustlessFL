# 최신 Seed-MPC 구현 이후 작업 계획

작성일: 2026-10-11. WSL `/home/hacho/@WSL-Projects/trustlessFL`.
브랜치: `work/aion-private-bound-no-wrap`.
기준: [현재 프로토콜](aion-seeded-components-protocol.md),
[공개 비교·packing 검증](reproduction/public-packed-2026-10-11.md).
이 문서는 과거 secret-AES 기준의 다음 구현 계획 이후 상태를 반영한다.

## 1. 현재 완료 범위

- 고정 aggregator 4명, 최대 악성 aggregator 1명의 Rep4.
- Client별 seed 4개의 수신자별 암호화 등록, 로컬 component 확장, single mask.
- Component의 세 holder 사본을 악성 보안 비밀 입력하고 비밀 상태에서 일치 검사.
- 정확한 mod-2^16 마스크 제거, signed 복원, 정적 좌표/global norm 검사, 넓은 ring SUM.
- 제출 수신증명, 확정 snapshot, 입력/결과 인증서, 영속 lock, client dropout·복귀 동기화.
- 공개 wire/header/tag/presence의 인증된 공개 비교, 대형 모델의 SIMD lane 64 기본값.
- 초기 setup/각 round native 송신 counter와 application/RPC 계측 분리.
- 최신 Python 회귀 315개, input fault 12건, 역할 격리 fixture 3라운드.
- 최신 전체 FMNIST/LeNet5 실제 학습 **1라운드**: 기준 재학습·SUM·모델·평가 일치,
  accuracy 74.84%, native round 345,574,822 B, native setup 33,308 B.

과거 secret-AES의 전체 학습 5라운드와 dropout 시험을 최신 packing 버전의 5라운드
완료 근거로 사용하지 않는다. 현재 component는 native에 다시 비밀 입력하며,
기본 입력 경로는 stock private input이다. 후속 선택형 direct import 구현은
[직접 share 연결 문서](aion-direct-rep4-import-protocol.md)와 검증 기록을 따른다.
Direct import에도 holder digest와 checked 상태 합의 통신이 필요하다.
[후속 검증](reproduction/direct-rep4-import-2026-10-11.md)은 Python 332개, 변조 9건,
작은 dropout 10라운드·격리 3라운드, 전체 FMNIST 1라운드를 통과했고
round native 274,113,190 B를 확인했다. 최신 전체 학습 5라운드는 여전히 후속 과제다.

사용자 지시에 따라 잔여 비용 계측보다 모델 범용화를 먼저 구현했다.
[사용자 모델·정적 정책·compile cache](seed-mpc-user-models.md)는 PyTorch 분류 모델 두 차원과
새 세션의 cache hit, 기존 FMNIST/fixture 회귀를 통과했다. 관련 테스트 363개다.
모델 범용화 첫 검증은 client 4명이었다. 후속 사용자 경로에서 client N 설정을 구현했으며 임의 학습 hook과 변동 buffer 지원은 남아 있다.
[검증 기록](reproduction/user-models-2026-10-11.md)을 참고한다.

사용자용 로컬 실행은 [역할별 설정과 audit 없는 CLI](seed-mpc-user-runtime.md), client N 설정까지 구현했다. Wheel 외부 실행과 MLP/CNN 2라운드 검증이 통과했다. Backend 설치·실행 자동화는 [후속 구현](seed-mpc-backend-setup.md)으로 추가했다. 독립 host 배포는 아직 남아 있다.

## 2. 유지할 계약

Committee는 변경하지 않고 aggregator 수 4명과 악성 허용 최대 1명을 유지한다.
클라이언트의 SGD 수행·마스크 생성 의도는 증명하지 않는다. MPC에서 복원되는 canonical
입력의 좌표 범위와 global norm을 검사한다. Client ZKP는 추가하지 않는다.
좌표 bound B, norm threshold T, scale S, modulus Q는 세션 전에 확정하는 정적 정책이다.

Carry가 포함된 wire는 `(y-mask) mod Q`로 복원한다. `2B<Q`와 signed 정수 해석,
`DB²`, `N*B` 및 비교 회로 폭의 backend 용량 검사를 계속 요구한다.
최종 SUM은 wire modulus Q에서 계산하지 않는다.
공개 출력은 기존 context/제출집합/인증자료 및 SUM/count/abort 범위를 유지한다.

Norm 이내 악성 update와 실제 학습 수행 증명은 추가 방어 목표에 포함하지 않는다.
Aggregator 2명 공모, committee 교체, 무조건적인 MPC 가용성도 현재 계약에 추가하지 않는다.
Flower Hub 관련 계정·게시 설정은 로컬 검증 이후 사용자의 별도 게시 지시가 있을 때 수행한다.

## 3. 실행 순서

| 순서 | 성격 | 작업 | 완료 기준 |
|---|---|---|---|
| 0 | 검증·일부 runner 구현 | 최신 버전의 정상/전체 모델 dropout 다중 라운드 | 계획된 실제 학습 완료와 매 round 정확한 정수 SUM·모델·체인 일치 |
| 1 | 계측 구현 | 잔여 비용의 단계별 분리 | native 총 counter와 stage 합계 대조, 전처리·공개/비밀 연산 비용 구분 |
| 2 | 설계·native 구현 | Seed 기반 Rep4 share 직접 연결 | component 재입력 제거와 악성 일관성 보장, 작은 native fault 회귀 후 전체 모델 대조 |
| 3 | 조건부 최적화 | Binary/arithmetic 변환·norm·선택 비용 개선 | 동일 정책/입력/보안에서 실측 절감, 전체 norm과 넓은 SUM 유지 |
| 4 | 범용화 일부 완료 | Model schema·정적 policy·compile cache·client N 구현 | D/N 변경·폭 검사·새 세션 cache 재사용 검증 |
| 5 | 운영 구현 | 재시작 정책·다중 호스트 실행·로컬 사용 패키지 | 불확실한 round 재실행 금지, 독립 역할 실행, 재현 가능한 로컬 사용 |

보안 검토와 악성 native 회귀는 단계 2/3/4의 변경마다 함께 수행한다.
사용자 지시에 따라 긴 5라운드 검증보다 direct share 연결을 먼저 진행한다.
기존 345,574,822 B 전체 학습 1라운드를 기준선으로 보존하고, 작은 회로/fault 검증 뒤
전체 모델 1라운드로 비교한다. 다중 라운드 학습과 단계별 계측은 후속 과제로 남긴다.
단계 3은 계측으로 비용 효과가 확인될 때 수행한다.

## 4. 단계 0: 최신 구현의 다중 라운드 기준선

실제 전체 FMNIST/LeNet5 정상 5라운드를 새 세션에서 실행한다.
각 round의 전체 제출/통과 여부, 독립 양자화·정수 SUM/count·모델·평가,
등록 1회/round counter 재사용 금지, setup과 round별 송신량을 검증한다.
전원 미제출로 정책 abort한 실행을 정상 학습 5라운드 완료로 표시하지 않는다.

전체 학습 mode에 고정 dropout/복귀 일정 옵션과 이에 맞는 reference 검증을 연결한다.
기존 작은 dropout-fixture의 처리 로직을 재사용하되, 실제 학습 update와 client의 인증 head에
맞춰 비교한다. 예시 일정은 r1 전원, r2 C3 부재, r3 C2/C3 부재,
r4 C3 복귀 및 C1 업로드 후 ACK 부재, r5 전원 복귀다.
학습 결과는 해당 일정의 reference와 비교하며 정상 5라운드의 accuracy와 같아야 한다고 요구하지 않는다.

이 작업은 새 필터 기능보다 최신 최적화의 장기 실행·seed 재사용·dropout 회귀 확인이 목적이다.
수정/실행 대상은 Flower runner, client/server app의 시험 일정 연결과 reference verifier다.

## 5. 단계 1: 무엇이 345.57 MB를 만드는지 분리

현재 round 단위 counter에서 다음 비용을 구분하는 계측을 추가한다.

1. 공개 입력의 Rep4 입력·opening·CHECK·equality.
2. Component 비밀 입력과 세 사본 일치 검사.
3. Binary 마스크 제거와 좌표 범위 검사.
4. Binary→arithmetic 변환 및 global norm 누적.
5. Acceptance 계산·선택·최종 SUM/opening/CHECK.

Live preprocessing은 실제 발생 구간에 포함한 수치와 분류를 함께 기록한다.
여러 연산에 걸친 배치·전처리를 근거 없이 특정 함수의 고유 비용으로 나누지 않는다.
새 timer/컴파일 경계가 batching을 바꾸는 경우 원래 baseline과의 차이를 별도로 기록한다.
계측은 고정된 공개 처리 크기에만 의존하고 개인 norm/선택 bit/seed/component 값을 기록하지 않는다.

완료 기준은 같은 실행의 setup+stages+shutdown과 native 전체 송신 합계의 일치,
D 및 client 수 변화에 따른 비용 구성 표다. 직접 share 연결의 예상 절감을
전체 round 비용과 혼동하지 않는다.

## 6. 단계 2: Component 재입력을 제거하는 native 연결

현재 한 좌표의 component 4개를 각각 holder 3명이 입력하므로 총 12개의 component 입력이 생긴다.
목표는 holder의 등록 seed로 생성한 component를 native Rep4 binary share로 직접 연결하여
동일 값을 일반 private input으로 다시 공유하는 과정을 제거하는 것이다.

먼저 interface와 보안 조건을 문서화하고 다음을 구현한다.

- Rep4 component 순서·lane packing·bit/word 순서·tail padding의 명시적인 native 입력 형식.
- 등록 handle, execution/policy, session/round/block과 연결된 로컬 생성/입력 계약.
- 악성 party의 실제 native share 불일치를 검출하는 holder 일관성 절차.
- 검출·CHECK 완료 전 허용되지 않은 update/mask 출력이나 결과 인증이 발생하지 않는 경계.
- 별도 native build, patch/source/compiler/binary/shared-library hash pin과 재현 가능한 빌드.
- 현재 stock private-input 경로를 대조군으로 유지하는 명시적 backend 선택.

**파일에서 raw share를 읽는 기능만 추가해서 완료로 보지 않는다.**
Host가 seed/파일 hash를 확인하는 것만으로 악성 native share를 인증했다고 보지 않는다.
Seed/component를 공개하거나 component hash를 무분별하게 외부에 공개하는 검사도 채택하지 않는다.
개인 입력의 ZKP를 클라이언트에게 요구하는 구조로 변경하지 않는다.

정상/미제출/복귀, holder 한 명의 값 변경·누락·프레임 불일치,
마지막 chunk와 양 끝 signed 값, global norm, SUM/count/abort를 작은 회로에서 검증한다.
이후 동일 FMNIST workload의 정수 SUM·모델·평가 및 setup/round 비용을 대조한다.
절감량은 해당 완료 실측 전에 수 MB 수준 등으로 약속하지 않는다.

## 7. 단계 3: 남은 계산 비용 최적화

계측에서 비중이 확인된 binary/arithmetic 변환, norm 곱셈/합산,
acceptance와 SUM batching을 순서대로 검토한다.
현재 이미 쓰는 Rep4 local-share conversion 옵션 `-Z4`를 새 개선으로 중복 제안하지 않는다.

좌표 bound와 global norm을 함께 유지한다. Chunk별 norm 검사로 global norm을 대체하지 않는다.
비밀 통과 여부에 따라 외부 로그·메시지 길이·실행 분기가 달라지는 최적화는 채택하지 않는다.
검사 생략이나 semi-honest backend 전환으로 감소한 비용은 같은 계약의 최적화로 인정하지 않는다.

수정된 회로는 정수 참조·fault 회귀를 먼저 통과시키고, 전체 차원/학습 counter를 비교한다.

## 8. 단계 4: Client 수와 모델 범용화

Aggregator 수는 4로 고정하되 client 수를 runner, provisioning, TLS 등록,
Flower node mapping, 입력 slot, 데이터 분할, verifier 전반에서 설정값으로 옮긴다.
사용자 경로의 provisioning/TLS/Flower mapping/검증에서 client N을 사용하도록 구현했다. 기존 실험 벤치마크의 4-client fixture는 비교를 위해 유지한다.
4개 component 및 4개 aggregator를 뜻하는 상수와 client 수를 뜻하는 상수를 구분한다.

Client 수 증가 시 `N*B`, count/SUM 비교 폭과 minimum_accepted를 다시 검증한다.
Client N=4/8/16의 실제 Flower 2라운드와 각각 4라운드 native dropout/wrap/boundary 검증을 순차 완료했다. [재현 기록](reproduction/client-counts-2026-10-11.md)을 참고한다.
고정 registered slot의 라운드별 presence와 bound 검사 계약은 유지한다.

모델 adapter에는 parameter 이름/shape/dtype/flatten 순서와 buffer 처리 계약을 추가한다.
D, B, T, S, Q를 모델 preset/정적 정책에서 선택하고 session hash에 고정한다.
정상 update를 지나치게 제외하는 threshold는 별도 사전 calibration에서 확인하며,
실행 중 제출값으로 threshold를 바꾸지 않는다.

동일 회로 재사용은 D/N/정책/처리 크기/backend/compiler/source hash가 맞을 때만 허용한다.
현재 한 세션 안에서는 round마다 컴파일하지 않는다.
Flower staging에는 선택형 agreed runtime client port와 content-addressed compile cache를 구현했다.
캐시 recipe는 port 외 config/source/backend pin을 포함하고, 실행 hash는 실제 port 및 모델 계약까지 고정한다.
동일 모델의 새 세션 compile 0회와 다른 D의 cache miss를 실제 Flower/MPC로 검증했다.
Client N 설정과 audit 없는 로컬 서비스 wrapper를 구현했다. 독립 host 실행 경로는 아래 단계 5에서 추가했다. 임의 학습 hook·변동 buffer와 실제 네 독립 운영자 배포까지 완료된 것으로 확대하지 않는다.

## 9. 단계 5: 운영과 로컬 사용 준비

Client 등록 ledger와 마지막 인증 모델을 기준으로 coordinator/client 복구 정책을 구현한다.
새 Flower node ID에서도 기존 client identity를 인증해 mapping하는 복귀 경로를 추가한다.
SQLite head 복구를 native MPC의 비밀 상태 복구와 혼동하지 않는다.
진행 중 native가 죽으면 해당 세션을 명시적으로 실패시키고, 마지막 확정 모델에서
fresh session/등록으로 다시 시작하는 정책부터 구현한다. 불확실한 round를 같은 mask로 재실행하지 않는다.
고정 committee의 identity·구성은 유지한다.

2026-10-12: 로컬 경로 외에 독립 호스트용 `trustlessfl-distributed`를 구현했다.
각 역할의 로컬 키·데이터·seed 생성, 승인된 public bundle, 독립 회로 컴파일 대조,
호스트 주소와 native TLS, mTLS RPC, client 소유 앱 코드 검사, fresh challenge 기반
새 Flower node ID 재참여를 연결했다. 별도 Docker filesystem/network namespace에서
4-client 3라운드의 4→3→4 재참여와 최종 wheel 2-client 2라운드를 검증했다.
[실행 절차](seed-mpc-independent-hosts.md), [결과와 검증 범위](reproduction/independent-hosts-2026-10-12.md).
같은 Docker 관리자 아래의 시험이며 실제 네 독립 운영자의 물리 호스트 배포는 미검증이다.
Transport 인증과 호스트 분리는 산술·MPC 검증이나 전체 FL 프라이버시 증명을 대신하지 않는다.

로컬 사용 패키지는 dependency/build pin, CLI/config 예제, 실행/오류/종료 절차,
private 파일과 공개 artifact 분리, 모델/정책 선택 안내를 포함한다.
Test-only raw audit/fault injection은 일반 사용 경로와 구분한다.
Flower Hub publisher·게시·계정 연결 설정은 지금 만들지 않는다.

## 10. 보안 검토의 완료 수준

기존 작은 native 시험에는 산술·binary 곱셈 share 및 opening 변조가 포함돼 있다.
최신 경로의 모든 변환/selection/최종 비밀 SUM opening을 검증한 것으로 확대 해석하지 않는다.
새 native 연결/회로 변경에서는 해당 계산 경계에 직접 변조를 넣고 실제 네트워크 transcript,
중간 공개값, abort와 결과 인증을 점검한다. Python 입력 fault만으로 native message 검증을 대신하지 않는다.

문서에는 등록→로컬 PRG→Rep4 input/share→변환→검사→출력/abort의 합성 전제를 적는다.
허용된 SUM/count/abort로부터의 역추론과 최소 통과 인원이 정직한 기여 2명을 보장하지 않는 점은
출력 계약에 계속 포함한다. Test 통과, backend의 보안 전제, 전체 구성의 formal proof를 구분한다.

## 2026-10-12 패키지 검증 갱신

독립 client 등록 통신을 패키지에 넣어 MP-SPDZ·compiler·Ray 설치를 제거했다.
새 Ubuntu client image에서 MLP 53좌표/4-client 3라운드의 4→3→4 복귀와
CNN 435좌표/2-client 2라운드를 실제 Flower/Rep4로 검증했다. 정수 합·모델·인증서는
모든 round 일치했고 회귀 508개, pip check, uv lock --check가 통과했다.
[설치·실행 안내](seed-mpc-package-guide.md), [패키지 결과](reproduction/package-validation-2026-10-12.md).
실제 네 독립 운영자 배포, 전체 FL composition 보안, FMNIST poisoning 성능과 Hub 게시는 별도 단계다.
