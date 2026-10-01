# AION-ASR 완료 조건과 현재 차단 요인

이 문서는 `aion-asr-research-v2`를 논문과 동등한 보안 구현으로 표시하지 않기 위한 검증 기준이다. 현재 구현은 연구용이다.

## CCS·VRF의 범위

[AION 논문 §4.3, Algorithm 4](https://www.usenix.org/system/files/usenixsecurity25-liu-yizhong.pdf#page=9)는 CCS(Client Concealed Sortition)를 실제 프로토콜 절차로 명시한다. 클라이언트는 VRF 증명을 생성해 참여 subset을 결정하고, 업로드할 때 결과와 증명을 보내며, 집계자는 이를 검증한다. 따라서 단순한 향후 과제 언급은 아니다. 같은 절은 여러 라운드에서 재사용하는 HPRF 키의 합을 서로 다른 참여 집합에서 공개하면 차분으로 개인 키가 노출될 수 있다는 동기를 설명한다.

그러나 논문에 알고리즘이 있다는 사실과 공개 artifact 실험이 이를 실행했다는 사실은 구분해야 한다. 로컬 원본 `Aion`의 Python·Markdown 검색에서는 CCS·VRF 구현을 찾지 못했고, `input_validation/FL_Backdoor_CV/roles/server.py`의 학습 실험은 `random.sample`로 참여자를 선택한다. 이 관찰은 공개된 해당 코드 경로에 한정되며, 저자들의 비공개 구현 존재 여부를 판단하지 않는다.

현재 Flower 실험은 VRF 기반 CCS를 구현하거나 시험하지 않는다. ASR 집계·MGF 학습 실험 자체는 CCS 없이 실행할 수 있지만, 이는 논문의 전체 참여 정책 및 재사용 키 보안 설계 재현을 뜻하지 않는다. 특히 per-round fresh-key MGF 실험은 논문의 one-time secret-sharing 비용 특성도 재현하지 않는다. CCS 도입만으로 MGF 필터링이나 dropout이 만드는 모든 부분집합 공개가 안전해진다고 간주해서도 안 된다.

## LWE-HPRF

2026-10-01 후속 source 감사에서 원본 scalar-key 범위 1..100000과 quantized
업데이트 격자만으로 공개 key-search가 재현됐다. 현재 decimal8 및 finite16
후보의 fixture 각각 2520/2520개 좌표가 키/share를 제공하지 않고 복원됐다.
이는 source `aion-original` scalar artifact의 특정 wire에 관한 결과이며
다른 LWE backend나 논문 전체의 공격 증명은 아니다. 신규 source manifest는
원본 key profile과 `production_privacy=false`를 명시한다.
[공개 탐색 감사와 범위](reproduction/source-keyspace-privacy-2026-10-01.md).

현재 `lwe-reference`는 논문의 이진 행렬 곱과 반올림을 기능적으로 계산하지만, 키 폭은 기본 8이다. [Boneh–Lewi–Montgomery–Raghunathan 정리 5.1](https://crypto.stanford.edu/~klewi/papers/homprf-proc.pdf)의 구성은 `m = n ceil(log q)`와 잡음·출력 모듈러스 조건을 요구한다. 현재 VSS 필드 `q`는 약 2047비트이므로 `m=8`은 정리의 비자명한 `n`에 대응하지 않는다. 이 정리만으로 현재 백엔드의 PRF 보안성을 주장할 수 없다.

기존 연구 백엔드의 32비트 입력은 서로 다른 `(round, block)`을 SHA-256의 앞 32비트로 줄여 만들었다. 실제 같은 task·round에서 block 24581과 47098이 충돌한다. 새 LWE task의 기본값은 이제 `hprf_input_bits=128`로 해석하며, 64비트 round와 64비트 block을 연결해 허용 범위 내에서 충돌 없이 인코딩한다. 기존 32비트 task는 명시적으로 `hprf_input_bits=32`를 지정해야 하며 설정 해시가 새 task와 달라 인증서를 혼합할 수 없다. artifact 백엔드의 기존 기본값은 유지한다. 이는 입력 충돌만 제거하며 SHAKE에서 도출한 공개 행렬의 분포, 키 폭, LWE 가정 또는 PRF 보안을 입증하지 않는다.

`trustlessfl/lwe_parameters.py`는 이 정리의 **필요한 형태·잡음 상한**을 정확한 정수 연산으로 검사한다. 원본 AION artifact `HPRF/init.py`의 설정은 `n=128`, `m=512`, `q` 259비트다. 따라서 정리의 요구 폭은 `128×259=33152`로, 공개 artifact의 `m=512`도 이 정리를 그대로 적용할 수 없다. 이 검사는 보안성 증명이 아니라 부적합 설정을 찾아내는 gate다.

같은 [BLMR 원 논문](https://crypto.stanford.edu/~klewi/papers/homprf-proc.pdf) §2는 인용한 Regev 환원에 `q > 2√n/α`가 필요하다고 설명한다. 새 정수 검사 `regev_window_possible()`은 정리 5.1의 `α·m^ℓ·p ≤ 2^-target`과 이 조건을 동시에 만족할 **α 구간의 존재 여부만** 판정한다. `n=128`, `ℓ=32`, `p=2^128`, `target=128`이면 해당 구간을 갖는 `q`는 최소 793비트여야 하고 `m=n⌈log₂q⌉`는 최소 101,504다. 이 폭에서 두 이진 `m×m` 행렬의 원시 비트만 약 2.40 GiB다. 따라서 현재 P-192 연구 백엔드는 이 *특정 충분조건 조합*을 만족할 수 없다. 이는 다른 LWE 가정·구성의 불가능성 증명이나 128비트 보안 추정이 아니다.

충돌 없는 `ℓ=128` 설정을 같은 **충분조건 조합**으로 평가하면 `q`가 최소 2610비트, `m`은 최소 334,080이며 두 행렬의 원시 비트만 약 25.99 GiB다. 따라서 입력 인코딩만 개선해 현재 구현을 보안 프로파일로 승격할 수는 없다. 이 수치는 독립적인 공격 비용 추정이나 최적 파라미터 선택이 아니다.

완료 기준: 독립적인 구체 보안 파라미터 선택, 해당 파라미터의 키·행렬·입력 분포 구현, 정확성과 성능 시험, 외부 암호 검토. 이름만 LWE인 경량 행렬 백엔드를 운영 보안으로 승격하지 않는다.

구체 보안성을 산정할 때는 [Lattice Estimator](https://github.com/malb/lattice-estimator)처럼 공격 비용을 추정하는 도구가 필요하다. 추정치만으로 구현 검증이나 외부 감사를 대체하지는 않는다. 또한 2047비트 VSS 필드를 HPRF 모듈러스로 그대로 쓰면 정리의 최소 `m`부터 약 2047이므로, 단순히 `hprf_width` 상한만 높이는 변경으로는 현실적인 128비트 보안 파라미터를 얻지 못한다. 현재 `lwe-192-reference`는 VSS와 HPRF 모듈러스를 분리하고 집계 키 변환을 시험하는 선행 단계이다. 폭 8은 P-192에서도 정리 조건 `m=n⌈log q⌉`을 충족하지 않으며, 보안 파라미터 선택은 아직 남았다.

## MGF와 modular mask

[AION 논문 Algorithm 6](https://www.usenix.org/system/files/usenixsecurity25-liu-yizhong.pdf)은 실수형 `y = x + α HPRF(m,r)`의 L2 norm을 제한한다. 기본 wire는 `y = x·padding + h (mod 2^128)`이다. 이 잔여값의 norm은 실수형 `y`의 norm이 아니다. 예를 들어 `-1 mod 2^128`은 정상적인 작은 음수임에도 unsigned norm으로는 `2^128-1`이 된다.

반대로 HPRF 출력을 실수 범위로 단순 축소해 더하면 집계 복원에도 문제가 생긴다. 모듈러스 16에서 두 마스크가 각각 10이면, 개별 마스크 합은 20이지만 집계 키의 출력은 `20 mod 16 = 4`이다. 차이 16은 논문의 반올림 오차 `±1`이 아니므로 DMC/DMR만으로 제거되지 않는다. 축소·반올림·carry의 안전한 집계 방법과 privacy 분석이 먼저 필요하다.

선택형 `mgf_beta` 모드는 signed fixed-point wire를 별도로 사용한다. client는 매 라운드 새 HPRF 키를 Feldman VSS로, 실제 양자화한 bounded mask를 Pedersen VSS로 공유해 aggregator별로 암호화한다. Flower는 공개 masked vector의 L2 norm으로 후보를 걸러내며, aggregator가 각자 받은 두 종류의 share를 검증한 뒤 roster에 투표한다. 인증된 roster에 든 client의 mask share만 합산·복원해 masked sum에서 빼고, 합계 HPRF 키는 ASR로 복원해 다음 bound의 mask 항에 사용한다. `alpha`·`bound`·이전 norm 항은 모델 인증서에 포함하며, 정수/유리수 연산으로 다음 값을 결정한다. 첫 라운드의 값은 공개 manifest에서 명시적으로 부트스트랩해야 한다. 기본 모듈러 wire와 이 bounded wire를 섞지 않는다.

기존 Feldman 공개 commitment는 작은 mask 값을 전수조사로 드러낼 수 있으므로 bounded mask share에는 Pedersen commitment를 사용한다. 현재 직접 Party 시험은 3종 연구 HPRF 백엔드에서 2라운드 필터·복원을, Flower ProcessGrid 시험은 악성 masked update 배제와 `hotstuff=true` 동시 사용을 검증한다. Roster 잠금 전 `mgf_admit` 정족수는 client별 서명·norm·수신자별 암호화 share를 독립 검증한다. 따라서 깨진 share를 낸 client 하나가 정상 client 2명의 라운드를 중단하지 않도록 Flower와 P2P 양쪽에서 배제할 수 있다. 선택형 peer inbox는 새 signed update를 보관하고, `hotstuff=true`일 때 Flower 중단 후 유효한 client 업데이트 2개 이상으로 동적 roster를 합의해 집계를 마치는 TCP 시험을 통과한다. 유효한 roster의 aggregate mask는 복원된 HPRF 합계 키의 출력과 대조하며, 출력 링의 carry 및 반올림 오차를 허용한다. 개별 client가 잘못된 mask를 제출해 합계가 어긋나면 최종화를 거부한다. 초기 등록과 달리 MGF의 HPRF 키는 매 라운드 새로 생성하므로 이전 라운드 합계 키와 차분되지 않는다. EMA와 legacy privacy group 모드는 이 새 경로와 현재 함께 사용할 수 없다.

더 근본적으로 bounded mask `0≤m≤α`에 대해 가능한 입력 `x₀`와 `x₁`의 차이가 `α`보다 크면 공개되는 `y=x+m`의 지지집합이 겹치지 않아 두 입력을 완전히 구별할 수 있다. 1차원 정수 예제(`x=-1` 대 `x=1`, `α=0.2`)를 회귀 시험으로 고정했다. 이는 암호화된 share나 hiding commitment로 해결되지 않으며, MGF용 작은 mask가 어떤 입력 프라이버시 보장을 제공하는지 별도의 제한·증명이 필요하다는 뜻이다. 집계 일치성 검사는 여러 client의 오류가 상쇄되는 경우를 구분하지 못한다. 악성 client가 서명한 Pedersen mask share가 자신의 HPRF 키에서 정확히 생성됐다는 개별 증명, 두 생성자의 이산로그 관계와 암호 구현의 외부 검토도 남았다. 그러므로 새 wire는 **MGF 기능 경로**이지 논문과 동등한 프라이버시·악의적 client 보안 증명이 아니다. per-coordinate 암호화/VSS는 논문의 경량 MGF 통신량보다 크며, 큰 모델에서의 성능도 아직 검증되지 않았다.

완료 기준: HPRF 보안 프로파일과 bounded mask의 privacy 모델, client별 mask-key 관계 증명 또는 동등한 악성 입력 무결성 보장, 동적 cohort의 P2P roster 복구 및 EMA와의 합성, 대규모 모델 성능·외부 암호 검토.

### 마스킹된 classifier의 percentile 선택 경로

`aion_mgf_beta --mgf-projection --mgf-percentile`은 classifier 840개 좌표의 마스킹된 검사 값으로 순위를 계산한다. 첫 3라운드에는 10번째 백분위 값으로 초기 threshold를 정하고, 선택 수를 cohort의 최소 10%·최대 80%로 제한한다. q=100이면 10~80명이며, 작은 기능 시험에서는 안전한 집계를 위해 최소 2명을 사용한다. 이 경로는 `oracle_classifier` 평문 필드를 만들지 않는다.

client는 검사 벡터와 전체 update body의 hash를 함께 서명한다. 집계자는 후보 서명·round·parent를 확인하고 동일한 선택을 재계산한 뒤, 다른 선택을 제안한 roster를 거부한다. 선택된 업데이트의 서명된 검사 벡터와 hash도 검증한다. 이는 **전송된 메시지 사이의 결합**이며, 개별 client의 검사 값이 실제 학습 결과와 올바른 HPRF mask로 생성됐다는 영지식 증명이 아니다. 기존 합계 projection 일치성 검사는 그대로 적용된다.

`--mgf-percentile`만 켠 기존 경로는 4라운드부터 현재 인증된 bounded-MGF bound를 사용한다. 새 `--mgf-artifact-bound` 경로는 아래의 전체 후보 mask norm과 두 과거 norm을 사용한다. 또한 후보 목록의 hash를 인증해도 coordinator가 후보를 누락하지 않았다는 보장은 생기지 않는다. 공식 실험 verifier는 staged schedule과 후보 집합의 일치를 추가 검사하지만, 이것은 실행 후 검사이지 온라인 Byzantine reliable broadcast가 아니다. 선택된 client의 share 검증에 실패하면 이 경로는 라운드를 중단하고, 몰래 다른 client로 대체하지 않는다.

무작위 순서의 20명 cohort로 Flower 메시지 기반 process pool에서 4라운드 선택·staged update 전달·모델 복원 테스트를 통과했다. [공식 SuperLink/Ray의 N=500/q=100 공격 1라운드](experiments/fmnist-flower-masked-percentile-paper-scale-one-round-2026-09-30/report.md)도 후보 100명 중 정상 client 10명을 선택하고 모델·roster 인증서와 후보 집합을 검증했다. 이는 다중 라운드 방어 성능 결과가 아니다.

TCP recovery 시험에서도 percentile 옵션을 활성화한 2-client 경로가 Flower와 최초 리더 중단 후 나머지 aggregator의 HotStuff commit·모델 결정을 완료했다. 이 작은 cohort 시험은 q=100의 공격 방어나 부분 동기 환경에서의 전체 진행 보장 증명이 아니다.

후속 단계로 `mgf_cohort_vote`·`mgf_cohort_share`·`mgf_cohort_norm` RPC를 추가했다. client가 compact probe 안의 ASR key material에도 서명하며, aggregator는 전체 후보의 key share 합을 수신 aggregator별로 암호화해 전달한다. 각 aggregator 내부에서 합계 키를 복원해 HPRF mask의 최대값을 계산하고 norm만 서명해 반환한다. Flower coordinator에는 이 단계의 복호 가능한 합계 key share를 전달하지 않는다. 후보 집합은 라운드당 하나로 잠그고 worker 재시작 후에도 다른 집합의 복원을 거부한다. **share 공개 전에 동일 후보 집합의 n-f 승인 인증서를 요구**하므로 coordinator가 honest aggregator에게 서로 다른 후보 집합을 질의해 합계 키를 차분하지 못하도록 한다. 여러 복원 집합의 차분으로 단일 client 키가 드러나는 작은 시험을 피하려고 후보 수는 2명 또는 10명 이상으로 제한했다.

새 RPC는 세 HPRF 연구 backend와 Flower process pool의 암호화·복원·변조 거부·지속 잠금 시험을 통과했다. `--mgf-artifact-bound`를 켜면 Flower workflow와 P2P 복구가 승인·암호화 share 전달·norm 인증 단계를 수행하고, roster에 norm 인증서를 포함한다. 첫 3라운드에는 실제 percentile threshold를 다음 상태에 저장한다. 4라운드부터 `b = (norm_latest + mask_linf_current) / (norm_older + mask_linf_previous) * b_previous`를 계산하며, 집계 후 최근 두 norm과 다음 alpha를 인증된 모델 상태에 저장한다. norm과 threshold는 고정소수점·12자리 십진 연산을 사용하므로 원본 float32 실행과 비트 단위 동일성을 주장하지 않는다.

20명 후보의 4라운드 Flower process pool 시험은 마스킹된 동일 입력과 동일 cohort mask norm을 원본식 `ArtifactMGF` 대조 구현에도 넣어 threshold·선택 집합·norm history를 비교했다. 추가 TCP 시험은 artifact-bound를 켠 2-client 경로가 Flower와 최초 리더 중단 후 commit을 완료함을 확인했다. 원본의 난수·행렬·모듈러스와 현재 연구 HPRF는 다르며, 이 시험은 원본의 모든 실험 결과나 프라이버시 보장을 재현한 증거가 아니다. 위 공식 q=100 결과는 이 RPC가 도입되기 전 실행이며 4라운드 이후 bound 검증으로 재사용하지 않는다.

[공식 Flower N=100/q=20의 공격 포함 4라운드](experiments/fmnist-flower-masked-artifact-bound-four-round-2026-09-30/report.md)도 완료하고 저장된 모델 변화로 norm history와 alpha를 다시 검증했다. [동일 조건 무방어 비교](experiments/fmnist-flower-masked-artifact-bound-comparison-2026-09-30/report.md)는 checkpoint·입력·분할·참여·실제 training catalog 조건을 비교한 뒤 양쪽 실행을 재검증했다. 단일 seed·축소 조건이며 보안 증명이나 q=100의 장기 성능 결과가 아니다.

## HotStuff liveness

정상 경로는 Flower `ServerApp`가 조정하며, 선택형 P2P 경로는 전달된 update나 영속 proposal의 합의를 coordinator 중단 후에도 마칠 수 있다. 현재 서명된 view-change는 유한 model view 체인에 한정되며, 부분 동기 네트워크에서의 HotStuff 진행 보장이 아니다.

추가된 `PeerParty.recover_roster()`는 aggregator 정족수가 이미 독립 검증·잠근 roster 인증서를 P2P로 복구하고, leader-view 모드의 추가 roster commit 정족수도 모은다. `finish_pending_roster()`는 이 인증서로 aggregate share를 방출하고 모델 제안·commit·decision까지 완료한다. leader-view 모드에서는 인증된 roster와 로컬 잠금이 일치하는 model timeout 투표만 peer에게 허용하고, 다음 리더 제안을 view-change QC로 인증한다. `aion-peer`가 roster 발견 후 설정된 대기 시간 뒤 자동 재시도한다. 두 모드 모두 `finish_pending_model()`은 모델 제안 정족수가 이미 영속 저장된 경우 제안 QC·commit·decision을 마친다.

고정 전체 cohort·비-EMA·비-leader-view 모드에서는 선택형 Flower ClientApp 이중 전달과 `prepare_from_inbox()`가 roster 이전 장애도 처리한다. 서로 다른 client의 전달 정족수가 달라도 `synchronize_inbox()`가 원본 client 서명을 검증하며 업데이트를 조회하고, 준비 요청에서 나머지 peer로 중계한다. 부분 inbox 재시작·한 aggregator 장애·후속 라운드 진행을 TCP 시험으로 검증했다. MGF에서는 `hotstuff=true`일 때에만 동적 roster의 peer 복구를 허용하고, Flower와 최초 리더가 멈춘 사례를 TCP 시험으로 검증했다. client equivocation에 대한 reliable broadcast, 공정한 동적 roster 선택, 다음 라운드의 자율 학습 시작은 남아 있다. 영속 high-QC/lock 규칙은 아래 선택형 `hotstuff=true` 모드에만 적용된다.

Inbox anti-entropy는 필요한 원본 client 서명을 모두 영속 저장하면 응답하지 않는 나머지 peer 요청을 취소한다. 이로써 한 peer의 지연이 완료된 update 집합의 roster 준비를 막지 않도록 회귀 시험을 추가했다. MGF에서는 norm-valid 후보가 2개여도 그중 하나의 share가 입장 정족수에서 탈락할 수 있다. 이때 모든 peer 인벤토리를 유한 timeout까지 다시 조회한 뒤 입장을 재검사하며, 다른 peer에만 있던 정상 client를 찾아 roster를 완료하는 TCP 시험을 추가했다. 이는 누락된 client 업데이트 자체를 생성하거나 Byzantine client의 상충 서명을 해결하는 기능은 아니다.

MGF 입장 투표도 서명된 `n-f` 인증서가 모이면 남은 피어 요청을 취소한다. 집계 share 전송은 먼저 sender·roster 문맥이 맞는 `n-f`개의 응답만 수집한다. `n≥3f+1`에서 이 집합에는 최소 `f+1`개의 정상 share가 있으므로, 뒤이은 `Party.finalize`의 Feldman/Pedersen VSS 검증과 문턱 복원을 거칠 수 있다. 하나의 무응답 피어 때문에 이미 충분한 집계 share를 기다리지 않는 단위 시험을 추가했다. 이 단계는 서명·문맥만 검사하므로, VSS를 검증하는 최종화 단계를 건너뛰어서는 안 된다.

새로운 `hotstuff=true` 모드는 `leader_views`와 동시에 켤 수 없다. Basic HotStuff의 prepare→pre-commit→commit 투표, 슬롯별 영속 prepare-QC와 잠금 QC, 최고 QC를 이어받는 new-view, 노드 자신의 타이머가 만료된 뒤 발행하는 timeout 투표와 그 정족수 인증서를 Flower 및 P2P 경로에 연결했다. roster/모델 인증서는 해당 commit-QC를 반드시 포함한다. 잠금 뒤 리더가 사라진 view에서 준비된 값을 후속 리더가 복구하고, Flower 중단 뒤 첫 peer 리더가 없어도 결정하는 시험을 추가했다. 높은 view에서 드라이버가 1초 상한으로 view 타이머를 만료 처리하던 실패를 수정했다. 피어 자신의 영속 지수형 타이머가 timeout 서명을 제한하며, 드라이버는 그동안 다른 peer의 인증된 높은 view/결정 상태를 주기적으로 확인한다. view 3의 실패·회복과 대기 중 타 peer 진입을 회귀 시험으로 검증했다. 더 많은 임의 장애 스케줄, 모든 정상 peer의 동시 pacemaker, 프로세스 재시작 및 부분 동기 조건에서의 진행을 포괄적으로 검증해야 한다. 현재 드라이버는 한 호출당 aggregator 수만큼 view를 시도한 후 재호출에 의존하며, 외부 보안 검토 없이 전체 HotStuff 진행 보장을 주장하지 않는다.

추가로 드라이버의 재시도가 이미 경과한 영속 피어 view 타이머를 새로 시작하지 않도록 했다. 실패한 view에서 서명된 timeout 투표를 곧바로 요청하고, 아직 타이머가 끝나지 않은 피어의 거절은 유한 시간 동안 재시도한다. 피어가 실제 타이머 만료 전에는 투표하지 않는 검사는 유지한다. 이미 만료된 view에서 드라이버가 별도 sleep 없이 다음 view에 진입하는 단위 시험을 추가했다. 이는 모델 pre-commit 단계 이후의 간헐적인 TCP 진행 지연을 줄일 수 있지만, 그 실행의 유일한 원인을 확정하거나 부분 동기 liveness를 증명하는 근거는 아니다.

각 피어는 prepare/pre-commit/commit 투표와 함께 해당 리더의 원본 서명 제안을 영속 저장한다. 새 `recover` 조회는 현재 view의 제안과 prepare QC를 별도 서명으로 보고하며, 드라이버가 제안의 리더 서명·new-view 정족수·prepare QC를 재검증한 뒤 동일 view의 멱등 투표를 다시 모은다. pre-commit 투표 직후 드라이버를 취소한 단위 시험에서 새 view timeout 없이 같은 view의 commit-QC와 결정을 복구했다. 악성 MGF client를 배제하는 TCP 복구 실행도 재검증했다. 이는 누락된 개별 투표를 새로 만들어내지 않으며, 임의 네트워크 스케줄에서 모든 정상 피어가 결국 결정한다는 증명은 아직 아니다.

P2P 상태 조회는 보통 첫 정족수 응답에서 끝난다. 빠른 구 view 정족수가 더 높은 view에 진입한 느린 정상 노드를 가릴 수 있으므로, 구 view timeout 정족수 생성에 실패한 경우에는 요청별 유한 timeout까지 전체 상태를 다시 읽고, 인증된 높은 view의 timeout QC에 합류한다. 상태 조회마다 응답하지 않는 Byzantine peer의 timeout을 기다리던 지연을 줄이면서 높은 view 복구를 유지하는 회귀 시험을 추가했다. 사이드카의 자동 복구 작업이 예외로 종료되거나 예기치 않게 반환되면 이제 서비스도 실패를 표면화하며, 정상 서비스인 척 무한 대기하지 않는다. 이는 분산 pacemaker의 전체 진행 증명은 아니다.

모델·roster의 영속 proposal/commit/decision 인증서 수집은 유효한 서명 정족수가 모이면 남은 네트워크 요청을 취소한다. 이전에는 결정에 필요한 모든 정상 피어가 응답한 후에도 무응답 피어의 지수형 요청 timeout을 기다릴 수 있었다. MGF+HotStuff TCP 복구를 반복 실행했을 때 100초 제한에 걸린 사례가 있었고, 그 실행의 영속 상태에는 정상 피어 세 곳의 동일한 결정과 모델 제안이 남아 있었다. 변경 후 해당 시나리오와 무응답 피어 단위 시험을 다시 통과시켰지만, 이 대기가 그 실패의 유일한 원인이었는지는 아직 입증하지 못했다. 이는 장애 스케줄 전체를 검증한 결과가 아니다.

2026-09-29 전체 테스트에서는
`test_hotstuff_peer_continues_after_flower_and_initial_leader_stop[False-True-False]`가
100초 동안 roster 결정을 만들지 못해 실패했다. 세 정상 peer의 자동 복구
진단에 `prepare-from-inbox: HotStuff driver exhausted views; durable QCs retained`가
기록됐다. 같은 케이스의 직후 단독 재실행은 43.5초에 통과했다. 따라서
현재 MGF+HotStuff 자동 복구에는 부하 또는 메시지 순서에 따른 간헐적 진행
실패가 남아 있으며, 단독 통과를 전체 진행 보장의 근거로 사용하지 않는다.
드라이버의 마지막 view 시도 뒤에도 다른 peer의 서명된 결정 QC가 이미
생겼을 수 있어, 소진 오류를 반환하기 전에 전체 peer 상태를 한 번 더 조회해
기존 정족수 검증을 거친 결정만 반환하도록 했다. 해당 경쟁 단위 시험과
HotStuff P2P 복구의 네 변형이 통과했고, 후속 전체 테스트는 209개 통과·
11개 건너뜀으로 끝났다. 그래도 한 번의 전체 통과로 간헐적 실패의 모든
원인을 제거했거나 일반적인 진행성을 입증한 것은 아니다.

정족수에서 응답을 멈추므로 나중에 돌아온 네 번째 peer의 서명이 기존 결정 인증서에 자동으로 합쳐지지는 않는다. 이미 유효한 결정 인증서는 재서명 없이 별도 `decision-qc` 메시지로 설치할 수 있다. 추가된 `decision-proof` 조회는 복귀한 peer가 다른 aggregator에 저장된 모델·commit·decision 인증서를 요청하고, 모든 서명 및 자신의 로컬 준비 상태를 검사한 뒤 설치한다. 로컬 제안 복구가 실패했을 때 자동 복구 작업이 이 조회를 시도하며, 재투표가 불가능한 TCP 회귀 시험에서 복귀 피어의 결정 상태가 따라잡는 것을 확인했다. 로컬에서 독립 검증·준비하지 않은 모델을 이 경로로 받아들이지는 않으며, 모든 장애 스케줄의 지속적 anti-entropy 또는 전체 HotStuff 진행 보장을 의미하지 않는다.

영속 view timer에는 Linux boot ID를 함께 저장한다. 같은 부팅 세션에서 Flower worker 또는 P2P sidecar 프로세스만 재시작하면 `monotonic` 타이머를 유지하고, OS 재부팅으로 clock epoch가 바뀌면 타이머를 다시 시작한다. 단순히 현재 `monotonic` 값이 저장값보다 크다는 이유만으로 재부팅 전 타이머를 만료 처리하지 않는다. boot ID를 읽을 수 없는 플랫폼에서는 영속 HotStuff 타이머를 안전하게 해석할 수 없어 모드를 거부한다. 이는 timer 복구의 정확성 보강이지 임의의 부분 동기 스케줄에 대한 진행 증명은 아니다.

완료 기준: aggregator 사이의 독립적인 네트워크 경로와 영속 pacemaker, timeout/new-view 인증서, 안전한 lock/high-QC 규칙, 두 단계 commit, 리더·coordinator 실패 및 재시작 시험. Flower는 학습 인터페이스로 남길 수 있지만 합의 메시지의 유일한 전달자는 될 수 없다.

설계 시 AION §2.3의 안정된 리더에서 두 투표 라운드를 사용하는 변형과 [Basic HotStuff §4](https://arxiv.org/pdf/1803.05069)를 구분해야 한다. Basic HotStuff의 세 투표 단계 중 pre-commit을 단순 삭제하면 해당 논문 §4의 비진행 실행이 가능하다. 따라서 두 단계 정상 경로를 유지하려면 대응하는 view-change·동기화 가정까지 명시하고 검증해야 하며, 유한 leader rotation만으로 이를 충족했다고 표시하지 않는다.

원본 AION artifact의 `bft_view.py`를 그대로 이식하는 것도 완료 조건을 충족하지 않는다. 그 코드는 view-change 정족수를 `n//2+1`로 계산하고 `_get_prepared_messages()`가 빈 목록을 반환하므로, 이 저장소의 `n≥3f+1`, `n-f` 인증서 및 lock 복구와 동등하지 않다.
