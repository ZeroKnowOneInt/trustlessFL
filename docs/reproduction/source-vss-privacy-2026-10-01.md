# 원본 VSS 및 Flower 초기 공유의 비공개성 감사

현재 source 포팅에는 scaled-MGF carry 문제와 독립적인 초기 키 노출이 있다.
아래 결과는 원본 공개 VSS와 현재 source adapter에 한정하며 다른 VSS나
논문 전체의 보안성으로 확대하지 않는다.

`Aion/util/crypto/secretsharing/vss.py::share`는 비밀 다항식의 나머지 계수를
무작위로 뽑지 않고 `f_coeffs.append(i + 1)`로 고정한다. 문턱이 t이면:

```
f(x) = secret + x + 2*x^2 + ... + (t-1)*x^(t-1) mod prime
secret = share_value - sum(j*x^j for j in 1..t-1) mod prime
```

공유 좌표 x, 문턱 t, prime은 공개값이므로 한 share만 받아도 비밀을 정확히
계산한다. threshold=2이면 단순히 `secret = share_value - x mod prime`다.
문턱 이상의 aggregator 공모가 필요하다는 일반 VSS 설명은 이 코드에
적용되지 않는다. blind 다항식의 고정 계수도 이 문제를 막지 않는다.

또한 source `enroll`/첫 `mask` 응답은 `SHARED_MASK.shared_mask`를 평문
outbox로 반환하며 ServerApp이 이를 `deliver-share`로 중계한다. 따라서
현재 서버는 이 응답의 한 share에서 개인 HPRF 키를 계산할 수 있다.
노드별 Context 분리는 서버가 전달받는 메시지 내용을 숨기지 않는다.

감사 코드 `experiments/audit_source_vss_privacy.py`는 hash-pinned 원본
`VSS.share`를 직접 실행한다. threshold 2/3/4, 공개 fixture secret 세 개,
수신 좌표 여섯 개의 총 54개 단일 share에서 모두 원래 비밀을 복원했다.
결과는 `.cache/source-vss-single-share-privacy-20261001.json`이다. 별도
회귀는 실제 learning enrollment 응답에서 같은 노출을 확인한다. 공격에는
private actor state를 주지 않으며 그것은 결과 비교 oracle로만 사용한다.

첫 감사 때 manifest에 원본 고정 계수·평문 중계 한계를 기록했다. 아래 후속
수정으로 새 learning manifest의 기본값은 암호화된 무작위 공유로 변경됐다.
기존 실험 결과와 원본 파일은 바꾸지 않았다.

비공개 키 공유에는 무작위 다항식 계수와 recipient-bound end-to-end
암호화/인증이 모두 필요하다. 원본 HPRF·round 기반 마스크·초기 일회성
공유라는 구조를 유지할 수 있지만, 원본의 고정 계수와 평문 중계까지 그대로
보존하면 그 조건을 만족할 수 없다. 공유 횟수 변경은 필요하지 않다.
이 수정만으로 scaled-MGF carry 모호성이 해결되지는 않는다.

## 학습 경로의 후속 수정

새 synthetic/FMNIST 작업은 `recipient-encrypted-pedersen-v1`을 기본으로
사용한다. `aion_source_sharing.py`가 기존 검증된 연구용 crypto 함수들을
재사용해 초기 HPRF scalar 키를 CSPRNG 다항식과 무작위 blind로 나눈다.
share scalar field는 RFC3526 subgroup ORDER이고 commitment group은
MODULUS다. 원본 HPRF 행렬·키 범위·round 입력은 바꾸지 않았다.

초기 share pair를 pinned recipient X25519 key로 암호화하고 Ed25519
client signature를 붙인다. task·sender·recipient·index·commitment를
결합하고 수신자가 복호화 후 Pedersen verification을 수행한다. Flower에는
공개 commitment와 ciphertext만 반환한다. committee의 aggregate pair도
집계 노드에게 암호화·서명해 보내며, 집계 노드는 선택 members·sender·index·
commitment 합·문턱과 각 share를 검증한 뒤 aggregate key만 복원한다.

singleton key-sum 요청과 같은 라운드의 다른 subset 재공개를 거부한다.
초기 공유 횟수와 이후 추가 mask share 0개 조건은 유지된다. 여러 라운드
subset 차분 공격은 CCS와 별도 합성 문제이며 이 수정으로 해결하지 않았다.
committee가 masked MGF selection을 독립 인증하는 절차도 현재 미완료다.

ones-vector 원본 benchmark와 과거 manifest는 고정 계수 source 계산을
보존한다. audit/legacy 회귀는 이 노출을 계속 기록하며 새 learning 경로의
비공개성과 혼동하지 않는다. 과거 source 실험을 수정된 공유의 결과로
재표시하지 않는다.

개인 transport identity는 node별 파일에 mode 0600으로 저장하고 catalog에는
파일 경로만 넣는다. manifest에는 공개 registry만 넣는다. 실제 배포에서는
각 노드의 파일/관리 권한을 분리해야 한다. 현재 한 OS 사용자 권한의 로컬
Flower simulation에서 server의 임의 파일 접근까지 방지한다고 주장하지
않는다. 키 생성과 public registry pinning은 신뢰하는 provisioning 단계다.

관련 source/encrypted-sharing/official-handler/conditional-MGF/batching 시험
64개가 통과했다. 새 로컬 synthetic 4라운드는 keys 40, extra masks 0,
19회 selected training replay model error 0이었다. 출력은
`.cache/source-encrypted-sharing-synthetic-4round-20261001`이다.

공식 SuperLink/Ray fresh 실행도 4라운드를 완료했다. run ID
16286199186799865493, runtime 26.235321 s, keys 40, extra mask shares 0,
15회 selected training replay model error 0이다. 출력은
`.cache/source-encrypted-sharing-synthetic-4round-official-20261001`이며
manifest와 staged package hash를 검증한 offline verifier가 통과했다.
로컬과 공식 실행은 fresh HPRF 키를 사용하므로 선택 집합이 같다는 주장은 아니다.

이 변경은 고정 계수 share 공격과 Flower 메시지의 평문 share 중계를
수정했다. 작은 scalar HPRF keyspace, private MGF 수치 모호성, 전체 악성
cohort 선택 및 외부 암호 검토까지 완료한 보안 프로파일은 아니다.
