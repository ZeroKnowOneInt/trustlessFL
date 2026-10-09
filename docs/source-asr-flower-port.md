# 원본 Aion-ASR의 Flower 통신 포팅

2026-10-01 사용자 확인에 따라, 신규 bounded-MGF 복원 설계가 아니라
**원본 ASR 함수와 메시지 흐름을 Flower로 실행하는 경로**를 추가했다.
이 경로는 기존 연구용 `Party` 프로토콜과 분리되어 있다.

후속 공개 key-search 감사에서 작은 원본 scalar key domain과 quantized
업데이트 표현의 입력 비공개성 문제가 재현됐다. 신규 manifest의
`key_profile.production_privacy=false` 및 scope에 표시하며, 원본 재현용
경로를 보안 구현으로 표시하지 않는다. 초기 VSS와 추가 share 0 조건은 유지한다.
[키 범위·wire 비공개성 감사](reproduction/source-keyspace-privacy-2026-10-01.md).

## 현재 연결된 경로

최신 paper-scale 실행은 `scale_source=quantized-sum`으로 다음 scale/history의
update와 mask를 모두 selected SUM 단위로 계산한다. 학습 모델에 적용할 때만
selected mean을 사용한다. 과거 mean/mask-SUM 혼용 profile은 legacy로 보존하며,
이 보정 후에도 실제 Flower 복원의 carry ambiguity는 남아 있다.
[독립 DMC/DMR 대조와 새 실행](reproduction/paper-mapping-and-sum-units-2026-10-02.md).

| 원본 | Flower 연결 |
| --- | --- |
| `param.choose_committee` | 원본 ChaCha20 함수로 committee 선정, 공개 설정에 순서/seed 고정 |
| `SA_ClientAgent.sendVectors` | 각 client의 ClientApp에서 원본 함수 실행, `VECTOR` 전송 |
| `share_mask_seed` / `VSS.share` | 첫 라운드에만 원본 키 share를 committee client들에게 전달 |
| `SA_AggregatorAgent.MMF` / `report_process` | 별도 aggregator ClientApp에서 원본 norm 필터와 모듈러 합산 |
| `get_sum_shares` / `sum_shares` | 원본 committee client들이 선택 집합의 기존 share를 합산 |
| `VSS.reconstruct` / `reconstruction_process` | aggregator가 합계 키와 원본 HPRF로 집계 복원 |
| `BFTProtocol.prepare/precommit/commit` | committee의 Flower 메시지 교환으로 정상 경로 실행 |

클라이언트들이 share 보유자 역할도 맡는 원본 구성을 유지한다.
ServerApp는 메시지 라우팅과 단계 실행을 담당한다.
큰 cohort의 masked VECTOR 묶음은 최대 약 8 MiB 단위의 Flower
`stage-vectors` 메시지로 나눈다. aggregator ClientApp은 실제 수신한
masked envelope만 node-local `masked-inbox`에 저장하고, 최종 `select`
요청의 sender/digest 참조를 검증해 원본 필터에 전달한다. 서버가 다른
client의 로컬 평문 업데이트 파일을 읽어 전달하는 IPC 우회가 아니다.
작은 cohort는 기존 inline 메시지 경로를 유지한다.
현재 참조 인덱스는 한 라운드만 Context에 유지하지만, 수신 ciphertext
파일은 실험 감사용으로 라운드별 보존한다. 100명·61,706좌표에서는
라운드당 약 120 MiB이므로 장기 실행의 저장 공간을 고려해야 한다.
공식 로컬 Ray 실험의 경로는 공유 파일시스템 위에 actor별 namespace로
분리되어 있다. 독립 장비 배포에서는 aggregator의 영속 node-local
저장소와 worker 재시작 시 접근성을 별도로 구성해야 한다.
초기 참여자 확인, 라운드별 온라인 참여자 확인, 최종 `FINAL_SUM`에 각각
서명된 prepare→precommit→commit 투표를 모은다.
최종 모델 commit의 서명·문맥·고유 투표자 정족수도 별도로 검증한다.

**라운드별 새 키 또는 좌표별 mask share를 생성하지 않는다.**
기존 bounded-MGF 경로의 추가 share를 지운 것이 아니라, 그 경로를 통하지 않는
원본 키 공유·필터·복원 실행을 만든 것이다. 과거 코드와 결과는 보존한다.

## 원본 계산 보존

입력으로 받은 원본 트리는 수정하지 않는다. 실행별 새 directory에 필요한
소스를 복사하고 SHA-256을 manifest에 기록한다. AST를 통해 필요한 원본
메서드를 추출하여 실행하므로 필터와 VSS를 새 수식으로 재작성하지 않는다.
HPRF는 이미 원본 출력 전체와 대조한 `OriginalAionHPRF` 어댑터를 사용하며,
실제 저장된 initialization/matrix, 출력 링과 반올림을 유지한다.
원본의 상대 파일 경로와 simulator의 `sendMessage`만 어댑터에서 연결한다.

원본 ASR `MMF`의 최소 30%·최대 80% 선택과 inclusive threshold를 유지한다.
이것은 별도 학습 실험 `roles/aggregation_rules.py::aion`의 최소 10% 필터와
구분된다. 두 필터를 같은 구현이라고 표시하지 않는다.

학습 수치 복원과 norm 필터의 유효성은 별개다. 현재 10 client·소수 6자리·
max_abs 100 설정에서 인코딩된 업데이트 항의 좌표별 상한은
`100 × 10^6 × padding(100) = 10^10`이고, HPRF 출력 링은 약 `1.476 × 10^19`다.
따라서 norm을 측정하는 표현은 학습 업데이트에 맞춰 작게 조정된 bounded mask가
아니다. 이 규모 차이는 공격 실패를 해석할 때 고려해야 하며, source MMF 선택을
논문의 classifier MGF 재현이라고 주장할 수 없는 추가 이유다. 수치 규모에서
도출한 설명이며, 모든 seed·공격에 대한 실패 증명은 아니다.

## 다중 노드 연결에 필요한 BFT 보정

다음은 source 계산 함수의 교체가 아니라 BFT 연결부의 명시적인 보정이다.

- 2026-10-02부터 새 manifest의 `selection_consensus=post-filter-bft-v1`은
  필터를 먼저 실행하고, 통과한 집합을 첫 번째 BFT의 합의 대상으로 쓴다.
  합계 키 share 제공은 해당 round/명단의 commit 인증서가 있을 때만 허용한다.
  Paper-MGF 위원회는 자신의 signed filter replay 결과와 다른 명단에 투표하지 않는다.
  과거 manifest의 수신 집합 BFT 의미는 보존한다.
  [변경과 검증](reproduction/post-filter-bft-2026-10-02.md).
- 새 paper-MGF manifest의 `aggregation_validation`은 선택 합계 키 opening을
  초기 VSS commitment와 대조하고, 위원회가 masked SUM·복원 모델·mask norm·
  다음 scale/history를 재계산한 뒤 모델 BFT에 투표하도록 한다. 다음 round도
  자신이 검증하지 않은 history를 인증서만 보고 신뢰하지 않는다. 추가 client
  key/mask share는 없으며 aggregate opening은 public model/history에 넣지 않는다.
  [검증과 공식 10-round 실행](reproduction/source-aggregate-validation-2026-10-02.md).
- 원본 검증은 수신자의 자기 공개키를 썼다. sender별 공개키를 Flower에서
  수집·고정하고, 해당 sender 키로 원본 서명 검증 함수를 호출한다.
- `Message` 객체 대신 공개 payload digest를 합의 값으로 전송한다.
  모든 노드가 같은 값을 hash/서명할 수 있게 하는 직렬화 연결이다.
- `_check_consensus`는 서로 다른 값의 개수를 투표 수처럼 셌다.
  동일 값의 서로 다른 commit sender 수를 `n-f`와 비교한다.
- 실제 참여하는 committee 크기로 `n/f`를 설정하고, 동일 sender의
  중복 메시지를 정족수에 다시 세지 않는다. 슬롯별 sequence를 분리한다.
- cwd의 `pki_files` 대신 node-local Flower Context에 개인 키와 상태를 보관한다.
  원본 소스 directory에 키를 쓰지 않는다.

이는 정상 경로의 서명·투표 연결이다. 원본 view-change/checkpoint 및 임의
장애 상황의 복구는 이 어댑터에서 아직 포팅하지 않았다.
기존 연구 경로의 HotStuff 장애 시험을 이 경로의 검증으로 전용하지 않는다.

## 실행

```bash
uv sync --extra author-asr
uv run aion-author-asr \
  --source ../Aion --output .cache/NEW-author-asr-port \
  --clients 10 --committee 4 --dimension 8 --rounds 20
```

캐시 의존성 환경에서는 다음 명령으로 같은 CLI를 실행한다.

```bash
PYTHONPATH=.cache/author-asr-deps:.cache/flower-deps:.cache/torch-deps:. \
  python3 -m experiments.run_author_asr_flower \
  --source ../Aion --output .cache/NEW-author-asr-port --rounds 20
```

output은 존재하지 않는 새 경로여야 한다.
이 명령은 실제 Flower ClientApp/ServerApp/Message 직렬화를 사용하는 독립
프로세스 ProcessGrid 실행이다. 공식 SuperLink/Ray 실행이나 원격 네트워크
성능 측정으로 표시하지 않는다.
기존 ServerApp도 `aion-source-manifest` run config가 있으면 이 경로로 분기한다.
배포 시 각 노드에 `aion-source-manifest`와 `aion-source-id`를 지정해야 한다.

## 공식 Flower SuperLink/Ray 실행

`experiments.run_source_asr_official`은 준비된 실행의 공개 workload 설정만
사용하여 새 task·committee·source snapshot을 만든다. 이전 Context, 개인 키,
mask seed, VSS share를 가져오지 않는다. Flower simulation의 `partition-id`를
actor 설정에 대응시키며 Ray worker가 바뀌어도 개인 상태는 node별 Context에
남는다. node catalog·manifest·staged Python package·실행 설정의 hash를 기록하고
재검증한다. FMNIST 평가 입력도 새 manifest에 hash로 고정한다.

```bash
PATH="$PWD/.cache/flower-deps/bin:$PATH" \
PYTHONPATH=.cache/author-asr-deps:.cache/flower-deps:.cache/torch-deps:. \
  python3 -m experiments.run_source_asr_official \
  --prepared .cache/author-asr-fmnist-attack-four-round-20261001 \
  --output .cache/NEW-source-official --workers 2
```

`--rounds 20`으로 실행 길이를 바꿀 수 있다. 공격 일정은 기본적으로 prepared
설정을 유지하며, 예를 들어 `--attack-rounds 1 4 7 10`으로 명시적으로 바꿀 수
있다. 기존 결과·입력 manifest는 수정하지 않는다. 이 경로도 로컬 simulation이며
원격 P2P 네트워크 성능이나 논문 방어 성공을 의미하지 않는다.

Ray의 Context 직렬화가 라운드 수에 비례해 커지지 않도록 큰 응답 재시도 cache는
현재 라운드만 보관한다. 지난 요청은 digest만 남기고 재실행하지 않으며, 일치하는
지난 라운드 재시도도 만료 오류로 거부한다. 현재 라운드의 동일 요청은 같은 응답을
반환한다. VSS share와 개인 키는 이 cache 정리 대상이 아니다. 이 정책은 원본
계산 변경이 아니라 포팅의 상태 보관·재시도 범위 변경이다.

## 동적 참여

학습 CLI의 `--clients 100 --participants 10`은 모집단 100명 중 각 라운드의
10명만 실제 학습·마스킹하도록 한다. 나머지는 학습 요청을 받지 않는다.
원본 학습 실험의 개별 참여자 포함 규칙을 별도 seeded RNG로 재현한다.
공격 라운드에는 지정 공격자를 포함하고, 비공격 라운드에는 benign 모집단에서
추출한다. 전체 저자 RNG transcript 또는 논문의 CCS/VRF 구현은 아니다.

마스크 키·원본 VSS share는 전체 모집단에 대해 학습 전 한 번 초기화한다.
따라서 100명·committee 4명에서는 첫 share 전달이 400개다. 기존 고정 10명의
40개와 혼동하지 않는다. 이 upfront population 초기화 비용도 기록한다.
재참여자는 새 키나 좌표별 mask share 없이 직전 라운드의 commit을 검증하고
현재 모델에서 학습한다. 라운드를 건너뛴 참가자를 강제로 재학습하지 않는다.
선택 집합·온라인 commit·재학습 검증은 staged cohort에 묶인다.

```bash
PYTHONPATH=.cache/author-asr-deps:.cache/flower-deps:.cache/torch-deps:. \
  python3 -m experiments.run_author_asr_flower \
  --output .cache/NEW-source-dynamic --workload fmnist \
  --fmnist-inputs PATH_TO_STAGED_INPUTS --clients 100 --participants 10 \
  --committee 4 --workers 4 --rounds 4 --attack-clients 2 --attack-rounds 1 4
```

32노드를 초과하는 로컬 CLI는 기본으로 worker 4개를 사용한다. 논리 노드별
Context는 분리하지만 worker를 공유하므로 프로세스 격리 보장은 아니다.
공식 Flower staging도 participation 설정을 보존하며 라운드 길이 또는 공격
일정을 바꾸면 같은 참여 규칙으로 새 schedule을 생성한다.
현재 MMF의 마스크 규모 문제와 고정 키 차분 노출은 동적 참여 추가로 해결되지 않는다.

## 검증과 현재 범위

4·20라운드에서 원본 함수를 직접 호출한 결과와 Flower 실행의 선택 집합,
threshold, 복원 벡터 전체를 대조한다. 첫 라운드의 키 share 전달 수는
10 client × 4 committee = 40이며, 이후 라운드에는 추가 키 share가 없고
mask share는 전 라운드에서 0개다. commit 서명도 독립 대조한다.
중복 투표, 변조된 합의 값, source hash 변경, share 수신자 오류,
키 공유 재실행·요청 재시도 및 기존 ServerApp 분기를 시험한다.

**기본 `ones` 모드는 원본 `ones + float64 HPRF`를 유지한다.**
추가 `--workload synthetic|fmnist`는 실제 학습 업데이트를 위한 수치 어댑터다.
원본 float64 마스크에 작은 업데이트를 더하면 정밀도가 소실되므로, 학습 모드는
고정 소수점 정수로 인코딩하고 원본 HPRF 마스크를 정수로 더한다. 원본 MMF의
norm 계산에만 float64를 사용하고, 집계는 정수로 유지한다. 복원할 때는
부호 있는 양자화 합계를 먼저 디코딩한 뒤 선택 인원 수로 나눈다.
원본 `reconstruction_process`의 floor division을 그대로 학습에 쓰지 않는다.
따라서 학습 모드는 원본 ones workload와의 완전 동일성이 아니라 명시적인
수치 포팅이며, 별도 학습 artifact의 classifier MGF로 바꾼 것도 아니다.

학습 client는 이전 모델의 commit을 검증한 뒤 로컬 학습·마스킹을 수행한다.
개별 평문 업데이트나 classifier를 aggregator로 보내지 않는다. 첫 라운드 키
share를 이후에도 사용하고, 좌표별 mask share를 추가하지 않는다. 이것은 통신
형태에 대한 확인이지 키 재사용의 암호학적 안전성 증명은 아니다. 원본 VSS의
고정 다항식 계수 등 실험용 설정도 남아 있어 운영용 보호 구현으로 사용하면 안 된다.

VSS prime은 명시적인 2048-bit 공개 prime, committee seed는 새 32-byte 값이다.
이는 원본이 허용하는 실행 입력을 고정하는 것이며 원본 전역 RNG의 동일
난수열 재현을 의미하지 않는다. `tests/test_author_asr_flower.py`의 고정
committee fixture는 대조용이며 CLI 기본은 원본 ChaCha20 선정이다.

원본 ones CLI 실행 입력/결과:
`.cache/author-asr-source-complete-normal-twenty-round-20261001`.
20라운드 완료, 키 share 전달 40개, 추가 mask share 0개, 최종 합의 완료를 확인했다.
최신 관련 회귀 실행은 source-port 시험 11개를 포함한 38개 통과(68.50초)였다.
전체 저장소 테스트를 이번 변경 이후 모두 다시 실행한 것은 아니다.

## 실제 학습 실행과 결과

이미 준비된 저자 분할 FMNIST 입력을 사용한다. 아래 output은 새 경로여야 한다.

```bash
PYTHONPATH=.cache/author-asr-deps:.cache/flower-deps:.cache/torch-deps:. \
  python3 -m experiments.run_author_asr_flower \
  --source ../Aion --output .cache/NEW-source-fmnist \
  --workload fmnist --fmnist-inputs PATH_TO_STAGED_INPUTS --rounds 4

PYTHONPATH=.cache/author-asr-deps:.cache/flower-deps:.cache/torch-deps:. \
  python3 -m experiments.verify_source_learning \
  --run .cache/NEW-source-fmnist --inputs PATH_TO_STAGED_INPUTS
```

공격 실행에는 `--attack-clients 2 --attack-rounds 1 4`를 추가한다.
검증기는 선택된 클라이언트를 다시 학습하여 전체 양자화 평균과 모델을 비교하고,
원본 BFT의 정상 경로 commit 서명도 독립 검증한다. MGF 선택의 타당성이나
입력 비공개성을 증명하는 검증기는 아니다.

[실제 4라운드 보고서](experiments/fmnist-source-asr-fixed-key-four-round-2026-10-01/report.md):
정상 실행 정확도 88.46%, 공격 실행 정확도 14.84%이며 두 실행의 집계 재검증
오차는 0이다. 키 share는 각각 처음 40개, 추가 mask share는 0개였다.
공격자 1이 원본 MMF에서 제거되지 않았으므로 논문 공격 방어 재현은 완료되지 않았다.

[공식 Flower의 새 소스 경로 검증](experiments/fmnist-source-asr-official-2026-10-01/report.md)에서는
합성 4라운드 및 실제 FMNIST 공격 4·20라운드 실행을 별도로 기록한다.
