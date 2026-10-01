# Aion의 Flower 포팅: 진행 상황 스냅샷

2026-10-01. 이 문서는 현재 구현과 실패 결과까지 보존하기 위한 브랜치의
상태 요약이다. **연구용 포팅이며 전체 목표는 미완료다.** 이전 성공 실험을
새로운 private MGF 경로의 성공 또는 보안 증명으로 재분류하지 않는다.

## 목표

저자 공개 구현을 최대한 활용하여 다음 경로를 Flower에서 실행한다:

client 로컬 학습 → 초기 일회성 키 공유 → 기존 키와 round로 HPRF 마스킹
→ Flower로 masked-vector 전달 → masked MGF 선택 → 선택 집합의 key sum만
복원 → 집계 마스크 제거 → 글로벌 모델 갱신.

추가 per-round/per-coordinate mask share, 서버의 개별 plaintext update,
개별 키 탐색으로 복원을 우회하지 않는다. 목표와 변경 이력은
[포팅 목표 문서](../aion-author-port-goal.md)에 있다.

## 경로별 상태

| 경로 | 확인된 범위 | 완료로 해석하면 안 되는 부분 |
| --- | --- | --- |
| 원본 `aion_source_asr` | 원본 HPRF·MMF·복원 함수, 일회성 키 공유, Flower 통신, 실제 학습 평균 검증 | MMF는 학습 artifact의 classifier MGF와 다르며 공격 방어 재현 실패 |
| 저자 학습 artifact MGF 대조군 | FMNIST/LeNet5, N=500/q=100, 공식 Flower 60라운드와 원본 MGF 수식 대조 | 서버가 평문 업데이트를 보고 마스킹·평균하므로 private secure aggregation이 아님 |
| 이전 bounded/projection MGF 실험 | 마스킹된 classifier 선택 및 전체 모델 집계, 일부 HotStuff 연결 실험 | 경로에 따라 추가 share·매 라운드 키 공유·oracle 등이 있어 현재 목표와 다름 |
| 최신 `paper-quantized-mgf` | client 마스킹, 초기 encrypted sharing, signed-vector와 committee replay, 조건부 carry 복원 | synthetic 1라운드 통과; 공식 10라운드 시도는 4라운드 실패. 보안 미검증 |

[원본 ASR 실행](../source-asr-flower-port.md),
[학습 artifact 60라운드](../experiments/fmnist-author-artifact-pop500-2026-10-01/report.md),
[이전 client-MGF 범위](../paper-client-mgf-port.md)를 구분해 읽어야 한다.

## 현재까지 구현한 것

- Flower `ClientApp`/`ServerApp`/`Message` 기반 실행과 공식 SuperLink/Ray
  실행 도구. 큰 masked-vector는 bounded batch로 보내며 노드별 inbox를 쓴다.
- 저자 소스 hash 기록, 원본 HPRF·학습 SHPRG 수치 차등 검증, 학습
  checkpoint/분할/공격 metadata 및 선택된 학습의 오프라인 재계산.
- 새 source learning 작업의 randomized Pedersen VSS, X25519 기반
  수신자별 암호화, Ed25519 서명. 원본 VSS의 고정 계수·평문 share 중계와
  구분하며, 초기 키 share만 공유하고 추가 mask share는 보내지 않는다.
- 최신 paper 경로에서 client가 task/round/parent/scale을 포함한 masked
  VECTOR에 서명한다. 위원회도 동일 입력을 Flower로 받고 필터를 재계산해
  선택 명단이 맞을 때만 key-sum share를 제공한다. Signed receipt를
  실행 history와 verifier에 연결했다.
- Singleton 및 동일 round의 다른 subset key release 거부, wire 변조·서명·
  context 검증, 실패 category의 공개 안전 기록, 공식 Flower의 실제
  `finished:completed` 상태 확인. CLI exit 0만으로 성공 판정하지 않는다.

[공유 수정](source-vss-privacy-2026-10-01.md)과
[선택 인증](source-selection-authorization-2026-10-01.md)에 세부 범위가 있다.

## 최근 실제 검증

1. Hardened **unscaled source** 공식 synthetic 4라운드: 초기 key share 40건,
   추가 mask share 0건, 선택된 학습 15회 재계산, model error 0.
   이는 scaled-MGF의 4라운드 성공이 아니다.
2. 최종 signed-receipt **scaled-MGF** 공식 synthetic 1라운드: 20명 client,
   committee 4명, 차원 8, key share 80건, 추가 mask share 0건,
   signed receipt 4개, 선택된 2명의 재학습과 model error 0.
3. 같은 목표의 fresh 공식 **10라운드 시도**: 1–3라운드 commit 후
   4라운드 `reconstruct`가 `ambiguous`로 실패했다. `results.json` 없이
   `failure.json`을 기록했고 Flower 상태도 `finished:failed`다.
   실행 시간은 약 30.96초다. [실패 분석](source-authorized-long-run-2026-10-01.md).

실행 캐시와 private identities는 Git에 포함하지 않는다. 성공/실패 run ID,
조건, 검사 범위는 위 개별 보고서에 기록되어 있다. 테스트 통과가 실패한
10라운드 학습의 성공을 뜻하지는 않는다.

스냅샷 준비 시 아래 최신 수치·선택 인증·공식 실행 판정·저자 소스 감사
회귀를 함께 다시 실행해 **92개 통과**(11.58초)를 확인했다:

```bash
PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m pytest -q \
  tests/test_source_paper_numeric.py tests/test_source_asr_official.py \
  tests/test_endpoint_flower.py tests/test_source_selection_authorization.py \
  tests/test_masked_mgf_collision.py tests/test_aion_original_shprg.py \
  tests/test_author_mgf_dataflow.py tests/test_aion_author_source_audit.py \
  tests/test_author_numeric_coverage.py tests/test_source_identity.py
```

`compileall`과 staged diff whitespace 검사는 통과했다. 전체 suite도 시도했으나
제한된 샌드박스에서 localhost bind 실패가 발생해 중단했다. 별도 첫 P2P
시험에서도 같은 bind 실패를 확인했다. 따라서 이번 스냅샷을 전체 suite
통과로 표시하지 않는다. 해당 P2P 시험 1개는 localhost 소켓을 허용한
환경에서 재실행해 통과했다(0.33초). 위 `.cache` 경로는 이 작업 환경의 의존성 경로이며
Git에 포함되지 않는다. 새 환경에서는 프로젝트 의존성을 먼저 설치해야 한다.

## 남은 핵심 문제

**Scaled-HPRF carry:** 원본 HPRF의 준동형성은 출력 링에서 성립한다.
실수 스케일링 후 개별 마스크의 정수 대표값 합에는 출력 modulus의 carry가
남으며, 합계 키만으로 항상 결정되지 않는다. 조건부 decoder는 양자화와
물리적 mask bounds를 만족하는 합이 하나일 때만 복원한다. 실제 실패 run의
다음 mask period는 160 model quanta여서 여러 후보가 남았다.

현재 입력 표현에서 서로 다른 plaintext sum이 같은 masked numeric 입력과
key sum을 만드는 [반례](../mgf-key-sharing-reduction.md)도 있다. 개별 VSS
commitment까지 같은 전체 transcript의 반례나 모든 HPRF의 불가능성 주장은 아니다.

**개별 업데이트 비공개성:** 원본 scalar keyspace `1..100000`의 공개 탐색
위험은 남아 있다. 고정 VSS 계수 문제를 수정했다고 이 문제가 사라지지는
않는다. Exact/high-precision wire 후보는 수치 복원에 성공해도 공개 입력으로
개별 업데이트가 드러나는 반례가 있어 채택하지 않았다.
[키 공간 감사](source-keyspace-privacy-2026-10-01.md),
[정밀도 후보 기각](author-scale-wire-privacy-2026-10-01.md).

**합의·프로토콜 보장:** 위원회의 selection replay는 이전 aggregate norm의
계산 자체를 증명하지 않는다. Across-round cohort 누출, 임계 수 이상의
공모, CCS/VRF, EMA late-update, 모든 부분 동기 상황의 HotStuff 진행 보장,
HPRF의 보안 증명은 완료했다고 주장하지 않는다. 같은 OS 사용자의 로컬
simulation도 실제 배포의 trust-domain 격리를 증명하지 않는다.
[보안 완료 기준](../security-completion-criteria.md).

## 저자 코드 확인의 결론

저자 코드는 **존재한다**. 공개 자료에 구현이 전혀 없다고 표현하면 틀린다.
확인한 E1은 ASR protocol simulation, E2는 중앙 학습·MGF 평가다. E2는
개별 mask 합을 사용하고 선택된 평문 업데이트를 평균한다.
[데이터 흐름 대조](author-mmf-mgf-dataflow-2026-10-01.md).

후속 읽기 전용 조회에서는 [Zenodo v1–v5](https://zenodo.org/records/15870338)의
Python 파일 목록과 버전별 핵심 8개 파일을 대조했다. HPRF, 학습 SHPRG,
`aggregation_rules.py`, `server.py`의 해당 파일 내용은 버전 간 동일했다.
이는 전체 archive의 모든 파일을 동일하다고 검증했다는 뜻이 아니다.
확인한 공개 코드에서 client-scaled MGF와 sum-key-only 복원을 결합하는
대표값/carry 규칙은 찾지 못했다. 비공개 또는 미발견 코드의 부재를 증명하지 않는다.
[공식 artifact 설명](https://www.usenix.org/system/files/usenixsecurity25-appendix-liu-yizhong.pdf),
[기존 소스 대조](source-identity-2026-10-01.md).

## 다음 작업

우선 저자의 실제 결합 wire·대표값/carry 처리 규칙을 확보해 현재 반례와
실제 다중 라운드에 대조해야 한다. 확보하지 못하면 사용자와 범위를 합의한
별도 HPRF/wire 설계가 필요하며, 이는 원본 포팅과 구분해야 한다.
검증되지 않은 새 설계를 안전한 해결책이라고 가정하지 않는다.

수치 정확성과 개별 업데이트 비공개성을 함께 검증한 뒤에야 같은
client-masked 경로의 다중 라운드와 FMNIST 공격 대조를 확장한다.
중앙 평문 baseline이나 추가 share 경로로 현재 목표의 완료를 대체하지 않는다.
