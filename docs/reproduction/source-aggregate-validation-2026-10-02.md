# 선택 합계 키·마스크 norm·모델의 위원회 재검증

후속으로 실제 FMNIST 정상 4라운드의 모델 오차 0을 검증했다. 별도
공격 작업은 3라운드 carry 모호성으로 실패했으며 전체 완료로 세지 않았다.
[실제 학습·공격과 스케일링 범위 대조](source-aggregate-fmnist-2026-10-02.md).

## 변경 이유와 현재 범위

이전 source paper-MGF 경로는 위원회가 signed masked VECTOR로 필터 결과를
독립 재계산한 뒤 key sum share를 제공했다. 하지만 모델 BFT에는 aggregator가
만든 `FINAL_SUM` digest만 전달했고, 이전 MGF history는 그 commit 인증서가
있으면 신뢰했다. BFT 인증서는 합의의 증거이지 수치 계산의 정확성 증거가 아니다.

새 paper manifest의 `aggregation_validation=aggregate-key-opening-replay-v1`은
모델 BFT **전에** 각 위원회 노드가 집계와 수치 메타데이터를 재계산하도록
한다. 원본 HPRF·마스크 스케일링·일회성 키 공유·conditional quantized-lift는
유지한다. 추가 개별 key share, 좌표별 mask share, 개별 plaintext 전달은 없다.
새 단계는 Flower 메시지로 실행하며 P2P sidecar는 추가하지 않았다.

이는 검증을 생략했던 부분의 보강이다. 원본/논문과 완전히 같은 새 프로토콜,
carry 모호성의 일반 해법, 범위 증명, 생산 보안 또는 HotStuff 전체 진행
보장이라고 주장하지 않는다. 실제 FMNIST 방어 실험의 완료 증거도 아니다.

## 실제 흐름

1. 위원회가 client-signed masked VECTOR와 인증된 이전 모델을 검증하고,
   MGF 선택 명단·masked SUM을 node-local Context에 고정한다.
2. BFT①가 해당 필터 통과 명단을 commit한 뒤, 기존 one-time key share의
   선택 합계만 제공한다. 동일 round에 다른 subset의 key release는 계속 거부한다.
3. aggregator는 기존 aggregate Pedersen share에서 합계 키와 **합계 blinding**을
   함께 복원한다. 새 클라이언트 share를 생성하는 것이 아니다.
4. aggregator가 이 합계 opening과 제안 `FINAL_SUM`을 위원회에 보낸다.
   각 위원회는 자신이 초기 공유에서 보관한 selected client commitment들을
   곱하고, opening의 `g^key * h^blind`가 합계 constant commitment와 같은지 확인한다.
5. 위원회가 자신이 보관한 masked SUM과 인증한 이전 상태를 사용하여
   복원·selected mean·누적 모델·실제 decimal mask SUM norm·다음 scale·history
   term을 다시 계산한다. 제안 body 전체 digest가 일치할 때만 승인한다.
6. BFT② 투표자는 자신에게 그 round/body의 검증 기록이 있어야 투표한다.
   다음 round MGF도 BFT 인증서뿐 아니라 자신의 이전 검증 기록과 body 일치를 요구한다.

Opening은 ASR에서 이미 허용한 **선택 합계**에 한정한다. 개별 키 또는
개별 blinding을 열지 않는다. 공개 결과·모델 body·검증 receipt에는 opening을
넣지 않는다. 위원회에 전달하는 합계 key/blind witness가 추가된 것은 명시적인
adapter 차이이며, CCS 없는 여러 subset/round의 합계 공개 위험을 해결하지 않는다.

검증용 snapshot에는 선택된 masked SUM과 공개 이전 모델만 추가 보관한다.
각 클라이언트의 업데이트를 unmask하거나 새로운 coordinate share를 요구하지 않는다.
`recover()`가 ambiguous/no-candidate/precision을 반환하면 승인·모델 투표를
진행하지 않고 실패한다. 틀린 복원값을 선택하거나 plaintext 경로로 fallback하지 않는다.

## 새 구현과 기존 결과 호환

- `trustlessfl/aion_source_aggregate.py`: profile 검사, 초기 commitment에
  대한 합계 opening 검증, local numeric replay, model/history 투표 gate,
  signed receipt 검증.
- `crypto.pedersen_reconstruct_pair` / `pedersen_verify_opening`: 기존 share로
  constant-term secret/blind를 복원·검증한다. 기존 key-only API는 유지한다.
- source selection: 새 profile에만 local masked SUM·이전 모델·이전 norm의
  snapshot을 보관한다. norm은 JSON에 저장 가능한 rational 문자열로 저장한다.
- source workflow/BFT: 검증 action과 서명 receipt를 BFT② 앞에 연결한다.
- offline verifier: 모든 committee receipt의 sender·round·selected set·parent·
  FINAL_SUM digest를 검사하고, vector digest를 selection receipt와 연결한다.

profile이 없는 과거 manifest는 기존 의미로 검사한다. 알려지지 않은 profile은
조용히 legacy로 내려가지 않고 거부한다. 과거 staged package와 결과는 수정하지 않았다.
offline verifier가 공개 receipt를 검증한다고, 기록에 없는 masked VECTOR와
opening을 독립 복원한 것으로 표시하지 않는다. 실제 계산 재검증은 실행 중
committee가 수행하고, 모델 정답은 별도 selected-training replay로 대조한다.

## 공식 Flower 검증

기존 prepared task에서는 공개 workload 설정과 hash-pinned author source만
재사용한다. 새 task/identities/Context를 생성하며 기존 개인 키·share는 가져오지 않는다.

```bash
PATH=/home/jisung/trustlessfl/trustlessFL/.cache/flower-deps/bin:$PATH \
PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m experiments.run_source_asr_official \
  --prepared .cache/source-filtered-bft-paper-mgf-one-round-official-20261002 \
  --output .cache/NEW-source-aggregate-replay --workers 4 --rounds 10

PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m experiments.verify_source_learning --run .cache/NEW-source-aggregate-replay
```

| 실행 | 공식 run ID | 상태 | ServerApp 측 시간 | 초기 key share | 추가 mask share | aggregate 재검증 | 모델 오차 |
| --- | --- | --- | ---: | ---: | ---: | --- | ---: |
| synthetic 1 round | 8428565648600774042 | finished:completed | 18.1675 s | 80 | 0 | 1 round × 4 receipts | 0 |
| synthetic 10 rounds, JSON fix 적용 | 828793332788267566 | finished:completed | 54.5717 s | 80 | 0 | 10 rounds × 4 receipts | 0 |

두 출력은 각각 `.cache/source-aggregate-replay-one-round-official-20261002`,
`.cache/source-aggregate-replay-ten-round-fixed-20261002`다. offline verifier의
selected training replay는 각각 2회·28회이고 모두 모델 오차 0이다. 10-round
선택 인원은 `[2,2,2,3,3,3,3,3,3,4]`다. 두 public results 모두 합계 opening을
포함하지 않는다. CLI exit code가 아니라 실제 `run-status.json`의
`finished:completed`와 결과/서명/재학습 대조를 완료 근거로 썼다.

초기 10-round task `7357352599758813845`와 2-round 진단 task는 1 round
commit 후 `authorize-selection`에서 실패했다. 새 snapshot에 `Fraction`
객체를 남겨 round 2부터 Flower의 canonical JSON 저장이 실패한 결함이었다.
이를 rational 문자열로 수정하고 round-two state 직렬화를 회귀 시험에 넣었다.
실패한 task와 terminal failure 기록은 보존했고 완료로 집계하지 않았다.
수정본은 새 task로 검증했으므로 이전 task와 동일 키/난수 실행이라는 주장은 아니다.

## 검증한 실패 조건

잘못된 key/blind 또는 selected commitment, 승인되지 않은 key release,
변조된 모델/합계/next norm/mask norm/bound/history term, 다른 round·task,
미검증 모델의 BFT 투표, BFT 인증서만 있는 미검증 과거 metadata,
다른 vectors/parent에 대한 receipt, 누락·중복·위조 receipt를 거부한다.
소수 격자와 mask bound 안에 실제 ambiguity가 남는 fixture는 그대로 실패한다.

공개 오류는 닫힌 enum 값만 반환한다. `history-unverified`,
`model-unverified`, `selection-mismatch`에는 key·blinding·좌표값이나 원본
exception text를 포함하지 않는다. 일반 오류와 기존 numeric failure도 기존
sanitized 응답을 유지한다.

최종 관련 회귀는 **199개 통과, 86.16초**다. 아래 범위에 새 집계 검증,
round-two JSON 저장, 오류 메시지 비공개성, 기존 선택/VSS/BFT/공식 staging
검사를 포함한다. 별도로 원본 HPRF·기존 AION core와 새 검증 파일을 묶은
118개도 통과했다. 두 실행은 중복된 시험을 포함하므로 숫자를 합산하지 않는다.

```bash
PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m pytest -q \
  tests/test_source_aggregate_validation.py tests/test_source_selection_authorization.py \
  tests/test_source_paper_numeric.py tests/test_pedersen.py \
  tests/test_scaled_ring.py tests/test_paper_dmc.py tests/test_source_filtered_bft.py \
  tests/test_source_encrypted_sharing.py tests/test_source_asr_official.py \
  tests/test_source_asr_dynamic.py tests/test_source_masked_inbox.py tests/test_source_vss_privacy.py
```

`compileall`과 `git diff --check`도 통과했다. 저장소 전체 테스트를 이번
변경 이후 다시 실행한 것은 아니다. 이전 공식 paper-MGF 1-round 결과는
read-only API로 재검증하여 모델 오차 0을 확인했고, 원래 결과 파일은 보존했다.

## 아직 남은 핵심

이 실행에서 집계·norm을 정확하게 재검증했다는 것과, 모든 실제 학습 round의
scaled-mask 복원이 유일하다는 것은 다르다. 기존 commensurate-scale 반례와
이전 공식 학습의 carry ambiguity는 여전히 유효하다. 이번 합계 opening은
합계 키의 진위를 증명할 뿐 누락된 carry를 제공하지 않는다. scalar HPRF
key-domain privacy, CCS, malicious-client 입력 증명, Byzantine progress 등도
이번 수정의 완료 범위가 아니다. 전체 목표는 계속 미완료다.
