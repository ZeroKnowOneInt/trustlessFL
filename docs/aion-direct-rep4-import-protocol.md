# Seed component를 Rep4 share로 직접 연결하는 경로

작성일: 2026-10-11. WSL `trustlessFL`, `work/aion-private-bound-no-wrap`.

이 경로는 [seed component 프로토콜](aion-seeded-components-protocol.md)의 매 chunk 입력을
대체하는 선택형 최적화다. 기존 `stock-private-v1` 경로는 보존한다.
`holder-checked-direct-v1`은 별도 hash-pinned native build에서만 실행한다.
등록·snapshot·정적 bound·결과 인증·영속 lock은 기존 계약을 적용한다.

## 1. Share의 구조

Client i가 독립적인 128-bit seed 네 개를 등록한다. Aggregator P_p는 p를 제외한
세 seed를 수신자별 암호화 packet으로 받는다. 동일 seed의 세 holder는 최초 등록 때
기존 악성 보안 MPC 입력으로 128-bit 값의 일치 여부를 검사한다.

등록 context에 session, epoch, client, handle, policy, execution이 포함되고,
HKDF namespace와 AES counter의 round/block 구분을 유지한다. 각 좌표에서:

```text
c[i,j,r,k] = PRG(seed[i,j], registration_context, round=r, coordinate=k)
m[i,r,k]   = c[i,0,r,k] XOR c[i,1,r,k] XOR c[i,2,r,k] XOR c[i,3,r,k]
y[i,r,k]   = (u[i,r,k] + m[i,r,k]) mod Q, Q=65536
```

네 component의 XOR 자체가 binary replicated secret sharing이다.
P_p는 c_p를 알지 못하고, c_j(j!=p)만 local Rep4 share에 넣는다.
Absolute component j의 local slot은 `(j-p mod 4)-1`이다.
각 coordinate는 16-bit secret word이며, circuit에서 기존 SIMD bit transpose를 적용한다.

기존 경로는 component마다 세 holder가 다시 일반 private input을 수행하고 비밀 사본을
비교했다. 새 경로는 이미 분산되어 있는 세 component를 local share register에 연결한다.
seed의 재공유, mask/component 공개, client ZKP는 추가하지 않는다.

## 2. Native 입력과 일관성 검사

컴파일러는 실제 party 0..3 밖의 reserved `INPUTB` source 4로 C개 word를 한 번에 요청한다.
새 native importer만 이를 해석한다. 일반 source 0..3은 기존 MP-SPDZ 입력으로 처리한다.
C는 현재 lane64에서 최대 512 좌표다. 실행은 active Rep4, party 4명, main thread로 제한한다.

Local FIFO 순서는 client → chunk → absolute component 오름차순(자기 component 제외)
→ chunk 좌표 오름차순이다. 매 호출마다:

1. 세 local component chunk를 임시 `pending`에 읽고 canonical 16-bit 입력인지 검사한다.
2. 각 held component j에 대해 domain, import sequence, width, C, j와 packed word의
   BLAKE2 digest를 계산한다. Sequence는 process-local 단조 counter이며 소진 시 거부한다.
3. digest는 해당 component의 다른 두 holder에게만 전달한다. 두 party 사이에서는
   둘이 함께 보유한 두 component digest, 64 bytes를 교환한다.
   Component j를 모르는 P_j에게 digest를 전달하지 않는다.
4. 각 party가 받은 digest를 자기 값과 대조한다. 길이·값·canonical 입력 오류가 있으면 bad=1이다.
5. `(sequence, C, width, bad)` 17-byte 상태를 broadcast하고 **즉시 `Check_Broadcast()`**한다.
   상태가 불일치하거나 어느 party라도 bad=1이면 중단한다.
6. 모든 검사가 끝난 뒤에만 `pending`을 secret registers로 옮긴다.

네 party 중 최대 한 명이 악성이면 component마다 정직한 holder가 최소 두 명 존재한다.
정직한 holder들은 자신이 받은 값들을 직접 대조한다. 다른 digest/status를 선택적으로
보내는 행위는 holder 비교 또는 즉시 broadcast 검증으로 차단한다.
이 설명은 충돌 저항성과 backend/channel의 기존 보안 가정을 전제로 한다.

digest는 수신자가 이미 아는 component에 대해서만 보내므로, 부족한 component를
알려 주는 추가 공개 hash를 만들지 않는다. 외부 출력에는 일관성 실패에 따른 abort가
추가된다. 이를 무조건적인 무누출이나 완성된 합성 보안 증명으로 표현하지 않는다.

등록 context를 C++ digest에 직접 다시 넣지는 않는다. 고유 registration namespace,
승인된 실행 hash/config, 확정 snapshot 순서와 process 내 sequence가 함께 연결을 제공한다.
같은 비밀 상태의 process 재시작·재질의는 지원하지 않는다.

## 3. Carry/wrap와 바운더리 검사

직접 연결은 mask의 입력 방식만 바꾼다. 산술은 기존 식 그대로다.

```text
z = (y - m) mod Q
u = z                 if z < Q/2
    z - Q             otherwise
valid_coordinate = (-B <= u <= B)
valid_client = every real coordinate valid AND sum_k u[k]^2 <= T
U[k] = sum_i valid_client[i] * u[i,k]
a = sum_i valid_client[i]
```

Wire에서 발생한 carry는 mod-Q subtraction으로 제거된다. `2B<Q`이면 허용 범위에서
canonical signed 복원이 유일하다. 무제한 원래 정수나 실제 SGD 수행을 증명하지 않는다.
좌표를 안전한 값으로 바꾸더라도 전체 invalid bit를 유지하여 client가 잘못 통과하지 않게 한다.
Global norm을 chunk별 norm으로 대체하지 않는다.

최종 SUM은 Q에서 더하지 않고 검증된 넓은 arithmetic ring에서 계산한다.
`DB²`, `N*B`, norm·합·count 비교 폭의 용량 검사는 그대로 필수다.
현재 D61706/N4/B20000에서 최대 좌표 합 ±80000도 정확히 보존한다.
Padding은 실제 coordinate와 구분하고 공개 wire의 nonzero padding을 거부한다.

## 4. 신뢰·출력 계약과 한계

고정 committee에서 세션 전체 악성·공모 aggregator 집합이 최대 1명인 전제와
private/authenticated channel 전제를 유지한다.
현재 실행은 신뢰하는 host의 loopback이다. 다중 host 운영 검증은 별도 작업이다.
두 aggregator가 공모하면 seed 네 개를 합칠 수 있으므로 보호 범위 밖이다.
클라이언트의 입력은 bound/global norm으로 검사하며 학습 수행·마스크 생성 의도는 증명하지 않는다.

공개되는 aggregate SUM/count/abort와 기존 context/집합/인증 자료는 이전과 같다.
개인 seed/component/update/norm/통과 bit를 직접 공개하지 않는다.
SUM/count에서 개인 기여나 통과 bit가 추론될 수 있는 출력 누출은 여전히 존재한다.
minimum_accepted=2가 정직한 client 둘을 보장하지 않는다.

악성 party가 검사 이후 local share를 바꾸는 행위는 이후 active Rep4 연산/공개 검사의
대상이다. Native fault 회귀는 지정된 경계의 차단을 확인하며 모든 악성 실행의 증명은 아니다.
영속 ledger는 native 비밀 상태 복구를 대신하지 않는다. Abort와 가용성 보장은 구분한다.

## 5. 빌드와 실행

공식 MP-SPDZ와 observer build를 보존하고 새 디렉터리에 빌드한다.
Source patch를 공식 0.4.3 archive에서 다시 유도하고 승인 build manifest를 repository hash로
고정한다. Binary, libSPDZ, 실제 loader 의존성, CONFIG와 source inventory를 검증한다.
임의 loader override와 승인되지 않은 native build는 실행 전에 거부한다.

```bash
cd /home/hacho/@WSL-Projects/trustlessFL
.venv/bin/python -m experiments.build_seed_mpc_direct --jobs 1

# 승인 hash는 자동 갱신하지 않는다. 다른 build는 검토 후 명시적인 재고정이 필요하다.
PATH="$PWD/.venv/bin:/usr/local/bin:/usr/bin:/bin" .venv/bin/python -m experiments.run_seed_mpc_flower \
  --output .cache/my-direct-fixture \
  --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3-direct-rep4-v1 \
  --component-input holder-checked-direct-v1 \
  --mode fixture --rounds 3 --snapshot-version 2 --chunk-blocks 64 --communication-meter
```

기본 `--component-input stock-private-v1`은 기존 입력 경로다.
선택형 importer의 효과는 동일 정책·처리 크기의 실제 counter로 비교한다.
검증·측정은 [직접 연결 검증 기록](reproduction/direct-rep4-import-2026-10-11.md)에 정리한다.


## 6. 다른 Linux/WSL 환경의 source build

2026-10-12 [설치 자동화](seed-mpc-backend-setup.md)는 공식 archive와 동일 observer/checked-import 패치를 고정한 뒤 해당 운영자가 직접 빌드한 결과를 로컬 승인 registry에 등록하는 추가 경로다. 이전 고정 build manifest hash는 유지한다. 새 source build도 전체 source/config/binary/library를 검증하며, installation/deployment의 자체 manifest만으로 승인하지 않는다. OS 계정의 비공개 registry와 신뢰하는 installer·toolchain을 전제로 한다. 임의 loader override나 보안 flag는 허용하지 않는다. 독립 host role provisioning과 전체 합성 보안 증명은 별도다.
