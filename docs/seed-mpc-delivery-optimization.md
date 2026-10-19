# V2 결과 전달·검증 비용 개선

2026-10-12의 구현은 서버가 ACK를 늦게 회수해 확인한 client head가 0에 머물고, 이후 모든 결정 이력을 재전송하던 문제를 수정한다. 정적 좌표/global L2 검사, single mask 제거, Rep4 회로, QC 3-of-4, 정수 SUM/count 출력과 공모 가정은 바꾸지 않는다.

## ACK와 head 복구

서버가 확정한 round를 `r`, client별 확인한 round를 `h_i`라 하면 commit/train에는 `records[h_i:r]`를 전달한다. Client는 전체 suffix와 목표 모델을 검증한 뒤 durable 상태를 적용한다. `h_i`는 전달 최적화용 cursor이며 MPC의 입력 선택·accept bit·quorum을 결정하지 않는다.

ACK는 기존처럼 client 서명·session·decision hash·model hash를 검증한다. 응답이 가리키는 head가 서버의 인증된 결정 목록에 있어야 하고 `h_i`는 뒤로 가지 않는다. 지연된 commit의 ACK가 더 최신 head를 보고해도 알려진 인증 head이면 수용한다.

학습 응답을 기다리거나 committee RPC가 실행되는 동안에도 **메인 스레드에서** ACK를 회수한다. RPC는 별도 worker에서 수행하지만 반환 전에 완료/실패를 join하며, Flower Grid를 RPC worker에서 접근하지 않는다. Progress callback이 실패해도 RPC의 완료를 기다려 결과 불확실성을 숨기지 않는다.

Commit TTL은 `max(60초, deployment timeout)`이다. TTL 연장만으로 ACK 유실을 해결한다고 가정하지 않는다. 전달 실패 또는 5초 이상 지연이 있으면 다음 proof를 best-effort으로 요청한다.

\[
P_i=\operatorname{Sign}_{sk_i}(\text{domain},\text{session},\text{node},\text{nonce},h,
  d_h,H(\theta_h)).
\]

여기서 `d_h`는 이미 확정한 result body의 digest이며, round 0에는 genesis digest다.

`query.head`는 새 256-bit nonce를 사용한다. Client는 학습하거나 모델을 변경하지 않고 SQLite의 현재 durable head를 읽어 응답한다. 서버는 요청 node, pinned client 서명, session, nonce와 이미 알려진 결정/모델 hash를 모두 대조한다. Round 0의 genesis head도 허용하지만 cursor를 전진시키지는 않는다. 알려지지 않은 head나 변조된 proof는 전달 확인에 사용하지 않는다.

Client당 recovery query는 최대 하나를 pending으로 유지하며 실패 재시도 사이에는 최소 2초를 둔다. 실패/잘못된 본문은 기록하고 다음 집계로 진행한다. 악성 client가 자신의 저장 상태를 거짓으로 주장해도 다른 client의 cursor나 QC/MPC 판정이 바뀌지 않는다. 다음 train에서 정확한 인증 모델·round를 요구하는 규칙도 유지한다.

ACK/head proof 응답은 모든 client가 보내야 하는 barrier가 아니다. 세션 끝의 drain도 최대 0.5초 best-effort이다. 마지막 ACK가 미확정이어도 서버의 확정 결과가 취소되지 않는다. 오프라인 복귀자는 여전히 필요한 전체 suffix를 받아 검증한다.

## 동일한 입력 snapshot의 검증 재사용

`SeedCommittee.check_manifest`는 다음 두 digest를 key로 하는 최대 2개 entry의 LRU cache를 사용한다.

\[
K=(H(\text{보안 설정}),H(\operatorname{canonical}(\text{전체 manifest}))).
\]

보안 설정에는 contract·registry·policy·session·epoch·clients·handles·snapshot version이 포함된다. 처음 보는 key는 모든 client chunk 서명, context, slot, offset coverage, presence와 canonical 형식을 검증한다. 검증에 성공한 후에만 immutable digest와 frozen `RoundContext`를 저장한다. Mutable manifest나 비밀 mask/seed는 저장하지 않는다.

동일한 canonical 입력을 같은 보안 설정에서 다시 확인할 때만 서명 재검증과 manifest 재구성을 생략한다. 입력·서명·정책·공개키·session이 바뀌면 cache hit가 아니다. SHA-256의 충돌 저항성과 기존 로컬 실행 환경의 무결성을 전제로 한다. Restart/새 인스턴스의 cache는 비어 있다.

**QC 서명 검증, 결과 count/SUM/모델 범위, parent·round 순서, 전체 suffix 사전 검증, durable lock과 exactly-once 모델 적용은 생략하지 않는다.** cache는 MPC나 QC를 대체하는 신뢰 입력이 아니다.

## 검증과 적용 범위

잘못된 ACK 자료형·서명·head·nonce·node·session, cache 내용/설정 변조, 부족한 QC, chain gap과 부분 적용 방지, 지연된 ACK/node 변경, 복귀와 전원 ACK 유실을 테스트한다. 실측 비용과 회귀/실제 dropout 검증 결과는 [개선 전후 보고서](reproduction/flower-cost-improvement-2026-10-12.md)에 기록한다.

모델 크기나 특정 데이터셋에 종속된 분기 없이 Python 전달·검증 경로를 최적화한다. 기존 회로가 유효하면 이 수정 때문에 회로를 재컴파일할 필요는 없다. Native MPC 통신량을 줄이는 변경은 아니다. 독립 물리 호스트에서의 성능·운영 검증은 별도다.

구현: [결과 전달/복구](../trustlessfl/seed_mpc_dropout.py), [서버 progress](../trustlessfl/seed_mpc_server_app.py), [client head proof](../trustlessfl/seed_mpc_client_app.py), [manifest cache](../trustlessfl/seed_mpc_committee.py), [회귀 테스트](../tests/test_seed_mpc_dropout.py).
