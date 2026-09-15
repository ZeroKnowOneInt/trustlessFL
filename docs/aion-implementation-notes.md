# AION 논문 구현 포인트 및 적합성 검토

> 구현 결정 업데이트 (2026-09-12): 사용자가 Flower 서버 1개와 독립 aggregator 여러 개의 논문 재현 구성을 허용했다. 본 문서는 당시 논문 검토 내용이며 아래 P0의 구조 선택은 해결되었다. 실행 가능한 코드의 범위, 원 논문과의 차이 및 남은 항목은 [Flower 구현 현황](./aion-flower-implementation.md)을 따른다.

## 1. 결론

AION의 핵심 아이디어는 장기간 재사용 가능한 client secret과 key-homomorphic PRF(HPRF)를 이용하여 client마다 라운드당 mask를 하나만 적용하고, 여러 client의 mask를 한 번에 복원하는 것이다. 악의적인 참여자에 대해서는 VSS, aggregator 간 BFT, VRF 기반 client sortition, mask 입력 검증 및 비동기 업데이트 처리를 결합한다.

그러나 AION을 현재 프로젝트 요구사항에 그대로 구현할 수는 없다.

- 현재 요구사항: 참여자와 별개인 **하나의 aggregator**, 해당 aggregator도 악의적일 수 있음
- AION: **하나의 training server와 `n`개의 aggregator**로 구성되며, 부분 동기 네트워크에서는 `n >= 3f + 1`개의 aggregator 중 최대 `f`개만 악의적이라고 가정

AION에서 `server`와 `aggregator`는 서로 다른 역할이다. 논문 제목이나 본문의 “single server”는 aggregator가 하나라는 뜻이 아니다. client는 초기화 때 secret을 `n`개 share로 나누어 모든 aggregator에 전달하고, aggregator들은 BFT와 threshold reconstruction을 수행한다. 따라서 `n=1`이고 그 aggregator가 악의적일 수 있다면 유일한 share가 client secret 자체가 되어 개별 mask와 update를 복원할 수 있다.

**구현 착수 전 P0 결정:**

1. 외부에는 하나의 endpoint를 제공하되 내부적으로 독립된 `3f+1` aggregation authority를 허용하여 AION을 구현한다.
2. 물리적·논리적·신뢰 주체 모두 하나인 악의적 aggregator 조건을 유지하고, AION은 아이디어만 참고하여 다른 single-aggregator 프로토콜을 설계한다.

1번에서 내부 node가 모두 같은 운영자와 신뢰 경계를 공유하면 AION의 “최대 `f`개만 타협” 가정을 만족하지 않는다. 현재 [Secure Aggregation 요구사항](./secure-aggregation-requirements.md)의 단일 신뢰 주체 조건을 그대로 유지한다면 2번에 해당한다.

## 2. 논문의 시스템 및 보안 가정

논문 §3과 §8에서 사용하는 기준은 다음과 같다.

| 항목 | AION의 가정 | 구현 영향 |
|---|---|---|
| client 수 | 전체 `N`, 라운드별 `q` | client registry와 라운드별 참여 집합 필요 |
| 중앙 server | 1개 | 학습 task 초기화와 최종 model 저장 담당 |
| aggregator | `n`개 | share 보관, client 조정, mask 복원, model 집계, BFT 담당 |
| 악의적 aggregator | 최대 `f`개 | 부분 동기 BFT에서 `n >= 3f + 1` 필요 |
| 악의적 client | 라운드당 최대 `q - 2`개 | privacy를 위해 적어도 정직한 client 2개 필요 |
| aggregator network | 부분 동기, 정직한 node 간 알려지지 않은 상한 `Delta` 존재 | timeout과 view-change가 필요 |
| client-aggregator network | 비동기 | 늦은 update와 중복 도착을 상태 기계로 처리해야 함 |
| channel | 인증되고 암호화됨 | 상호 인증, 무결성, 기밀성, replay 방지 필요 |
| 암호 가정 | signature 및 encryption 위조·해독 불가 | 검증된 구현과 충분한 security parameter 필요 |

악의적 행위의 범위에는 잘못된 secret sharing, 틀린 mask, model poisoning, dropout, aggregator crash, 거짓 share, equivocation, aggregator-client 공모가 포함된다.

논문의 formal security theorem은 다음 전제를 추가로 둔다.

- HPRF가 안전하고 HPRF output으로 key를 복원할 수 없다.
- BFT가 consistency와 liveness를 제공한다.
- VSS가 correctness와 secrecy를 제공한다.
- 악의적 aggregator와 client 수가 위 임계치를 넘지 않는다.

가용성은 악의적 주체가 임계치를 넘거나 단일 외부 gateway가 요청을 차단하는 상황까지 보장하지 않는다. 안전하게 abort하는 것과 계속 진행하는 것을 구분해야 한다.

## 3. 필요한 암호 및 분산 시스템 구성요소

### 3.1 Verifiable Secret Sharing(VSS)

논문은 설명을 위해 Feldman VSS를 사용한다(§2.1, Algorithm 1·3).

구현 항목:

- client secret `m_i` 생성
- 차수 `t-1` polynomial과 `(t, n)` share 생성
- aggregator마다 서로 다른 `[m_i]_j` 전달
- polynomial coefficient commitment 생성 및 공개
- 각 aggregator의 share verification
- 유효 share `t`개 이상에 대한 Lagrange interpolation
- commitment의 homomorphism을 이용한 aggregated share `[M_r]_j` 검증
- 잘못된 share, commitment 불일치, 중복 share 및 잘못된 node index 거부

AION의 부분 동기 설정에서는 reconstruction threshold가 `t=f+1`이다. field, group, generator, subgroup 검증, element encoding 및 commitment scheme의 정확한 parameter는 논문만으로 production 수준까지 확정되지 않으므로 별도 명세와 test vector가 필요하다.

### 3.2 Key-homomorphic PRF(HPRF)

client `C_i`는 장기 secret `m_i`와 round identifier `r`로 `HPRF(m_i, r)`을 만들고 local update에 더한다. key homomorphism에 의해 client mask의 합을 aggregated key 또는 aggregated mask에서 계산한다(§2.2, §4).

구현 항목:

- 논문이 인용한 LWE 기반 key-homomorphic PRF의 정확한 parameter set 선정
- `HPRF(key, domain-separated round context) -> vector[d]`
- key addition과 output addition의 호환성
- model dimension `d`에 맞춘 deterministic expansion
- round, task, model version, tensor name을 포함한 domain separation
- HPRF approximation error에 대한 DMC/DMR 처리
- CPU/GPU 및 여러 platform에서 동일한 byte-level 결과를 내는 test vector

일반 HMAC, HKDF 또는 보통의 PRG는 key-homomorphic하지 않으므로 대체할 수 없다.

### 3.3 BFT consensus와 threshold certificate

AION은 aggregator 사이에서 stable leader와 두 번의 vote를 사용하는 HotStuff 계열 BFT를 가정한다(§2.3).

합의 대상:

- 초기 valid client set
- 최초 global model
- 라운드별 online/valid client set
- 라운드별 aggregated global model

구현 항목:

- proposal, vote, quorum certificate, commit, view-change
- `n-f`개의 서명을 나타내는 threshold certificate 또는 안전한 aggregate signature
- client가 model과 client-set certificate를 독립 검증하는 기능
- 동일 `(task_id, round_id, phase)`에 대한 상충 proposal 탐지
- 악의적 leader의 무응답 및 잘못된 reconstruction bundle에 대한 view-change
- canonical serialization과 signature domain separation

이 합의는 server가 client별로 서로 다른 model을 보내 target client의 gradient를 고립시키는 model inconsistency attack을 막는 핵심 장치다(부록 A의 gradient isolation 분석).

### 3.4 Verifiable Random Function(VRF)과 CCS

ASR이 aggregated secret을 공개하면 서로 포함 관계인 두 round의 client set 차이로 한 client의 secret을 계산할 수 있다. AION의 Client Concealed Sortition(CCS)은 client들을 독립적이고 겹치지 않는 subset에 배정하여 이를 방지한다(§4.3, Algorithm 4, 부록 E).

구현 항목:

- client의 `m_i`와 연결된 VRF key/public commitment
- BFT가 commit한 `Hash(initial_model || threshold_signature)`를 VRF input으로 사용
- `k = vrf_output mod K`로 subset 결정
- masked update와 VRF output/proof 동시 제출
- aggregator의 proof 및 round/subset membership 검증
- secret sharing이 끝나기 전에 VRF input을 예측·선택하지 못하도록 순서 강제

소수의 고정 silo가 매 라운드 반복 참여해야 하는 cross-silo 환경에서는 겹치지 않는 subset 방식이 부적합할 수 있다. 이 경우 aggregated secret을 노출하지 않는 AMR을 우선 검토해야 한다.

### 3.5 인증, 암호화 및 identity

- server, aggregator node, client별 장기 identity와 역할 분리
- client가 각 aggregator node용 share를 end-to-end 암호화하고 인증
- 하나의 gateway를 쓰더라도 gateway가 다른 node의 share 평문을 보거나 바꾸지 못하도록 recipient binding
- 모든 메시지에 `protocol_version`, `task_id`, `round_id`, `phase`, `sender_id`, `recipient_id`, monotonic sequence 및 payload hash 포함
- key rotation, 폐기, revocation 및 audit policy

## 4. 프로토콜 상태 기계

논문 Algorithm 1·2를 구현할 때 명시적 상태 기계가 필요하다.

```text
INIT_SHARING
  -> INIT_CLIENT_SET_COMMITTED
  -> INITIAL_MODEL_COMMITTED
  -> ROUND_COLLECTING
  -> ONLINE_SET_COMMITTED
  -> MASK_RECONSTRUCTED
  -> GLOBAL_MODEL_COMMITTED
  -> ROUND_COMPLETE | TRAINING_COMPLETE

모든 상태 -> ABORTED
```

상태 전이는 certificate와 threshold를 충족할 때만 허용하며, 같은 메시지의 재전송은 idempotent하게 처리한다. 이전 단계로 되돌아가거나 이미 commit된 client set을 바꾸는 요청은 거부한다.

### 4.1 일회성 초기화

논문 §4.1, Algorithm 1의 구현 순서:

1. 각 client가 무작위 장기 secret `m_i`를 생성한다.
2. client가 `(f+1, n)` VSS를 수행하고 각 aggregator에 share와 commitment를 보낸다.
3. aggregator가 share를 검증하고 유효한 client만 후보 집합에 넣는다.
4. aggregator들이 valid client set과 initial model에 합의한다.
5. client는 BFT certificate가 붙은 initial model을 받은 후에만 학습을 시작한다.
6. ASR을 사용한다면 client가 CCS를 수행하여 자신의 subset/round를 정한다.

장기 `m_i`는 여러 round에서 재사용되므로 memory, swap, crash dump, backup 및 log에 노출되지 않게 보관해야 한다. aggregator의 `[m_i]_j`도 동일하게 민감한 장기 상태다.

### 4.2 라운드별 집계

논문 §4.2, Algorithm 2의 구현 순서:

1. client가 이전 round의 BFT-certified model을 검증한다.
2. local training으로 `x_(i,r)`을 계산한다.
3. `y_(i,r) = x_(i,r) + HPRF(m_i, r)` 또는 scaling을 포함한 MGF 형태를 계산한다.
4. masked update와 필요한 VRF proof를 aggregator에 업로드한다.
5. aggregator가 deadline까지 받은 update를 online set으로 분류한다.
6. MGF를 적용한다면 masked update를 검증하여 valid set을 만든다.
7. aggregator들이 최종 online/valid set에 BFT 합의한다.
8. 각 aggregator가 해당 client들의 share를 더해 `[M_r]_j`를 만든다.
9. ASR 또는 AMR로 전체 mask를 얻는다.
10. masked update 합에서 전체 mask를 빼 global update를 계산한다.
11. 선택적으로 이전 round의 늦은 update를 EMA로 집계한다.
12. aggregator들이 새 global model에 합의하고 certificate와 함께 다음 round client에게 전달한다.

online set이 commit된 뒤에는 update 추가·삭제를 허용하지 않아야 한다. mask reconstruction에 사용한 집합과 masked update 합산에 사용한 집합이 byte-for-byte 동일해야 한다.

## 5. ASR과 AMR 선택

| 항목 | ASR | AMR |
|---|---|---|
| 복원 대상 | aggregated secret `M_r = sum(m_i)` | aggregated mask `HPRF(M_r, r)` |
| 장점 | 단순하고 비용이 낮음 | aggregated secret을 공개하지 않음 |
| 단점 | 서로 겹치는 client set의 차분으로 개별 secret이 노출될 수 있음 | 더 많은 HPRF 값과 오류 검증이 필요함 |
| 반복 참여 | CCS로 겹치지 않는 subset 강제 필요 | client set 중복 허용 |
| 논문상 검증 | commitment로 aggregated share 검증 | `2f+1+z` HPRF share를 모아 polynomial 일치 검사 |

고정된 소수 silo가 여러 round에 반복 참여하는 현재 용도에는, AION 호환 multi-aggregator 구성을 선택한다면 **AMR을 기본 후보**로 보는 것이 타당하다. 다만 다음 사항을 먼저 검증해야 한다.

- 사용하려는 HPRF 구현에서 share에 HPRF를 적용하고 Lagrange 결합하는 연산이 논문 식과 정확히 일치하는가
- 최대 `f`개의 잘못된 HPRF share를 식별하는 Algorithm 5가 선택한 parameter에서 종료하는가
- approximation error와 polynomial consistency 검사가 충돌하지 않는가
- leader가 reconstruction 근거가 되는 share 집합과 proof를 모든 aggregator에 전달하는가

## 6. Masked Gradient Filtering(MGF)

논문 §5, Algorithm 6의 입력 검증은 ZK proof가 아니라 masked update의 norm을 직접 제한하는 경험적 poisoning 방어다.

핵심 계산:

```text
alpha_r = beta * ||x_(r-1)||_inf / h_max
y_(i,r) = x_(i,r) + alpha_r * HPRF(m_i, r)

mu_r = (||x_(r-1)||_2 + alpha_(r-1) * ||HPRF(M_(r-1), r-1)||_inf)
       / (||x_(r-2)||_2 + alpha_(r-2) * ||HPRF(M_(r-2), r-2)||_inf)
b_r = mu_r * b_(r-1)

accept iff ||y_(i,r)||_2 <= b_r
```

구현 항목:

- `beta`, `h_max`, 초기 `b_0/b_1` 및 첫 두 round의 bootstrap 규칙
- 모든 node에서 동일한 norm, rounding, overflow 결과
- `NaN`, infinity, 비정상 shape/dtype, sparse/dense 혼용 거부
- filter 결과를 online set BFT 이전에 결정하고 consensus 대상에 포함
- bound evolution에 사용할 이전 model/mask의 certificate 확인
- dataset/model별 poison ratio, boost rate, mask ratio 재평가

중요한 한계:

- MGF는 제출값의 norm을 제한할 뿐 client가 올바른 local training을 수행했음을 증명하지 않는다.
- 악의적 client가 올바른 HPRF mask를 더했음을 cryptographically 증명하지 않는다.
- 논문의 aggregated-model correctness 서술도 client가 mask를 올바르게 더했다는 조건을 둔다.
- 따라서 “악의적 client가 있어도 정확한 정직 client 합을 항상 얻는다”는 보장으로 해석하면 안 된다. 강한 input correctness가 필요하면 ZK proof, verifiable computation 또는 별도 poisoning defense가 필요하다.

## 7. HPRF 오류와 수치 표현

논문의 LWE 기반 HPRF는 key addition 때 element별 작은 approximation error가 누적된다. §6.1의 DMC/DMR은 이를 decimal 아래 추가 자리로 밀어낸 후 마지막에 잘라낸다.

구현 항목:

- model element의 decimal precision `l_dp` 고정
- round 참여자 수 `q`에 대해 `l_ex = ceil(log10(2q))` 계산
- client가 HPRF element를 `10^(l_dp+l_ex)`로 scale하여 mask 적용
- aggregator도 같은 방식으로 aggregated mask를 scale
- unmask 후 `l_dp` 자리로 deterministic rounding
- 양수·음수, 경계값, 최대 `q`, carry/borrow 및 overflow test

Python `float`에 의존하면 platform별 차이와 비결정성이 생길 수 있다. 실제 구현은 finite-field element와 signed fixed-point encoding을 명세하고, model 합이 modulus를 wrap하지 않는 범위를 증명해야 한다. 논문의 decimal 절단 알고리즘은 test vector로 재현한 뒤 채택한다.

## 8. 비동기 update 처리

논문 §6.2, Algorithm 9의 Expired Model Aggregation(EMA)은 round `r-1`에 늦은 masked update가 round `r`에 도착한 경우 별도 집계한다.

구현 항목:

- late update가 원래의 model version과 round에 binding되어 있는지 검증
- `C_delay`가 privacy threshold `xi >= 2` 이상일 때만 집계
- late subset 전용 aggregated share/mask reconstruction
- `x_r <- x_r + omega * x'_(r-1)`의 scaling factor `omega` 정책
- 한 update를 정상 집계와 late 집계에 중복 반영하지 않는 deduplication
- 허용 지연 round 수, 만료, storage quota 및 삭제 정책

초기 구현에서는 EMA를 제외하고 synchronous core를 먼저 검증하는 편이 안전하다. EMA는 privacy 집합과 model semantics를 동시에 복잡하게 만든다.

## 9. 권장 message와 저장 상태

최소 message 유형:

- `InitShare`: client별 VSS share, commitment, recipient aggregator
- `ClientSetProposal` / `ClientSetCertificate`
- `ModelProposal` / `ModelCertificate`
- `MaskedUpdate`: tensor metadata, masked payload, VRF output/proof, signature
- `AggregateShare`: committed client-set hash, `[M_r]_j`, VSS verification evidence
- `AggregateMaskShare`: AMR용 HPRF share와 node signature
- `ReconstructionBundle`: 사용한 share 집합, 검증 결과, reconstructed mask 식별자
- `AbortEvidence`: 상충 certificate, invalid share 또는 timeout/view 정보

영속 상태:

- 공개: protocol parameters, identity keys, commitments, committed client sets, model certificates
- 민감: client `m_i`, aggregator의 client별 VSS share, 아직 commit되지 않은 round 입력
- 일시적: proposal, vote, uncommitted online set, reconstruction working set

model/update 본문을 log, metric, trace, exception message에 넣지 않는다. 공개 transcript만으로도 client 참여 패턴이 드러날 수 있으므로 metadata 보존 기간을 별도로 정한다.

## 10. 구현 순서

### P0. 구조 결정

- “aggregator 하나”가 단일 외부 endpoint인지 단일 신뢰 주체인지 확정
- AION의 independent aggregator committee를 허용할지 결정
- `N`, 라운드별 `q`, `f`, `n`, 최소 정직 client 수 확정
- ASR+CCS와 AMR 중 선택

이 단계가 끝나기 전에는 AION protocol code를 작성하지 않는다. 현재 조건 그대로라면 security proof가 적용되지 않는다.

### P1. 실행 가능한 수학 명세

- field/group/HPRF/VSS/VRF/signature parameter 확정
- tensor fixed-point encoding과 modulus safety bound 작성
- 각 primitive와 protocol step의 cross-platform test vector 생성
- 공개 정보, 민감 정보 및 삭제 시점 정의

### P2. 암호 primitive와 단위 테스트

- VSS share/verify/reconstruct 및 aggregated verification
- HPRF와 key homomorphism
- DMC/DMR rounding
- VRF prove/verify
- canonical encoding, signature 및 authenticated encryption

prototype이라도 자체 제작 암호를 production 용도로 사용하지 않는다. 사용 가능한 audited library가 없다면 연구용 구현으로 명확히 제한한다.

### P3. 초기화와 synchronous aggregation

- identity 등록과 authorization
- 일회성 VSS 초기화
- round state machine과 idempotent API
- masked update 수집
- committed online set
- ASR 또는 AMR
- unmask 및 certified global model

### P4. 악의적 참여자 대응

- invalid client share 및 malformed update
- invalid aggregator share
- leader equivocation 및 view-change
- model inconsistency/gradient isolation
- aggregator-client collusion threshold
- replay, duplicate, omission, reordering

### P5. 선택 기능

- MGF와 model별 parameter calibration
- CCS 또는 반복 참여용 AMR hardening
- EMA 기반 late update 활용
- dynamic aggregator membership
- 비동기 BFT

## 11. 필수 검증 시나리오

### 암호 정확성

- 임의 client 집합에서 `sum(HPRF(m_i,r))`와 reconstruction 결과가 DMC/DMR 오차 규칙 안에서 일치
- 서로 다른 round의 mask가 독립적으로 보임
- 정확히 threshold 미만의 share로 client secret 또는 aggregated mask를 복원하지 못함
- 잘못된 VSS/ASR/AMR share가 검증에서 거부됨

### 악의적 aggregator

- leader가 client마다 다른 model을 보내면 certificate 검증 실패
- 서로 다른 online set을 제시하면 equivocation 탐지 또는 BFT 미commit
- reconstruction share 변조 시 거부 및 view-change
- result 변조 시 client가 model certificate를 거부
- 최대 `f`개 crash/지연에서 진행하고 `f` 초과 시 안전하게 abort

### 악의적 client

- 잘못된 share/commitment, VRF proof, signature, shape 및 dtype 거부
- duplicate identity와 replay된 update 거부
- MGF 경계값 및 norm 초과 update 거부
- 최대 `q-2` client와 `f` aggregator의 공모 view로 두 정직 client 각각의 update를 구분하지 못함

### 라운드 및 네트워크

- client는 outbound 연결만 사용
- 초기화 시 모든 aggregator 대상 share가 올바른 recipient에게만 복호화됨
- 지연, 중복, 순서 변경 및 재접속에도 상태 전이가 결정적임
- commit 뒤 client set 변경 불가
- late update가 원래 round에만 귀속되고 중복 집계되지 않음

### 수치 및 학습

- 최대 dimension, 최대 client 수 및 최대 update 크기에서 field overflow 없음
- CPU/GPU와 서로 다른 architecture에서 동일한 encoding 및 rounding
- mask 제거 후 허용 오차 안에서 clear aggregation과 일치
- poisoning 실험은 privacy/correctness 테스트와 분리하여 ASR, test error 및 convergence를 측정

## 12. 논문만으로 확정되지 않는 사항

구현 전에 다음을 별도 결정하거나 논문 공개 code와 대조해야 한다.

- production용 LWE-HPRF의 정확한 parameter와 라이브러리
- VSS field와 HPRF key space 사이의 encoding
- threshold signature 및 BFT의 구체 구현
- MGF의 초기 bound와 첫 두 round 처리
- norm 계산 정밀도와 tensor별/전체 model별 bound
- malicious client가 틀린 mask를 적용했음을 검출할 방법
- dynamic membership 시 장기 share refresh와 proactive security
- crash recovery 중 장기 share 및 round secret의 안전한 보존
- 하나의 네트워크 endpoint 뒤에 여러 독립 trust authority를 배치할 수 있는 운영 모델

## 13. 논문 위치별 추적표

| 논문 위치 | 내용 | 구현 대상 |
|---|---|---|
| §2.1 | Feldman VSS | `share`, `verify`, `reconstruct`, aggregated commitment |
| §2.2 | LWE 기반 HPRF | round별 single mask와 homomorphic mask 합산 |
| §2.3 | HotStuff 계열 BFT | client set/model consensus와 view-change |
| §2.4 | VRF | CCS proof와 subset 검증 |
| §3 | system/threat model | 역할, threshold, network, adversary configuration |
| §4.1, Algorithm 1 | initialization | 장기 secret의 일회성 sharing |
| §4.2, Algorithm 2 | aggregation | round state machine 전체 |
| §4.3, Algorithm 4 | CCS | ASR의 multi-round key leakage 방지 |
| §4.4, Algorithm 5 | AMR | aggregated key 비공개 mask reconstruction |
| §5, Algorithm 6 | MGF | evolving masked-update norm filter |
| §6.1, Algorithm 7·8 | DMC/DMR | HPRF approximation error 제거 |
| §6.2, Algorithm 9 | EMA | late update의 privacy-preserving 재사용 |
| §8, 부록 A | security analysis | adversarial 및 collusion test 기준 |
| 부록 D | complexity | aggregator 간 `O(n)`, client-aggregator `O(nq)` 목표 |
| 부록 E | CCS 미사용 위험 | 겹치는 client set 차분 공격 test |
| 부록 G | deployment | dynamic aggregator와 async BFT 확장 |

## 14. 현재 프로젝트에 대한 권고

현재의 “악의적일 수 있는 단일 독립 aggregator”를 변경하지 않는다면 AION 전체를 구현 대상으로 삼지 않는다. 먼저 single-aggregator 환경에서 client 간 end-to-end 암호 메시지를 aggregator가 relay하는 프로토콜, client threshold committee, verifiable public transcript, TEE 또는 homomorphic encryption 등 대체 신뢰 수단을 비교해야 한다.

AION을 채택하려면 요구사항을 “외부 aggregation service는 하나이지만 내부에는 서로 독립적인 `3f+1` aggregation authority가 있고 최대 `f`개만 공모한다”로 변경해야 한다. 그 경우 고정 silo의 반복 참여 특성 때문에 ASR+CCS보다 AMR을 우선 검토하고, synchronous core와 adversarial test를 완료한 뒤 MGF와 EMA를 추가하는 순서가 적절하다.
