# 원본 ASR-MMF, 학습 artifact MGF, 논문 MGF의 데이터 흐름 대조

## 결론

공개 저자 트리에는 서로 다른 두 실행물이 있다.

1. `agent/Aion`의 ASR simulator는 클라이언트가 원본 HPRF로 전체 벡터를
   마스킹하고 첫 라운드에 키를 VSS로 한 번 공유한다. aggregator는 받은
   masked vector를 MMF로 필터링하고 선택된 합에서 aggregate-key HPRF를
   제거한다.
2. `input_validation/FL_Backdoor_CV`의 학습 artifact는 서버 함수가 이미
   보유한 평문 local update에서 classifier weight를 뽑고, 서버가 생성한
   SHPRG seed/mask를 더해 selection만 수행한 뒤 선택된 **평문 전체
   update**를 평균한다.

따라서 공개 학습 artifact의 방어 곡선은 논문 Algorithm 6의 비공개
end-to-end network 구현 증거가 아니다. 반대로 ASR simulator는 실제
학습 artifact의 classifier MGF와 같은 필터가 아니다. 이 차이를 하나의
구현으로 합쳤다고 주장하지 않는다.

## 재현 가능한 소스 감사

[`experiments/audit_author_mgf_dataflow.py`](../../experiments/audit_author_mgf_dataflow.py)는
저자 파일을 실행하지 않고 AST와 source segment를 검사한다. 결과는
`.cache/author-mgf-dataflow-audit-20261001.json`에 저장했다.

```bash
PYTHONPATH=.cache/author-asr-deps:.cache/flower-deps:.cache/torch-deps:. \
python3 -m experiments.audit_author_mgf_dataflow \
  --source ../Aion \
  --output .cache/author-mgf-dataflow-audit-20261001.json
```

확인한 항목은 다음과 같다.

- ASR client의 원본 HPRF 생성, 첫 라운드에만 `share_mask_seed`,
  `masked_vector` 전송
- ASR aggregator의 network masked-vector MMF 입력, 선택 합의 mod-p 처리,
  aggregate-key HPRF 생성 및 제거
- ASR MMF의 최소 30%, 최대 80%, inclusive `<=` 경계
- 학습 `aion()`의 평문 `model_updates` 입력, 함수 내부 seed 생성,
  `last_layer_updates + vector` selection 입력
- 학습 `aion()`의 `client_sum_hprg` 호출과 선택된 평문 update 평균
- launcher의 최소 10%, 최대 80%, `searchsorted` left 경계
- 학습 `aion()` 함수 안에 HPRF/DMC/DMR 참조가 없다는 사실

15개 조건이 모두 통과했고, 감사 자체 회귀 시험도 통과했다. 네 원본 파일의
SHA-256과 다섯 함수의 location-independent AST hash를 결과에 기록했다.
이는 공개 snapshot의 구조적 증거이며 전체 프로그램의 보안 증명은 아니다.

## 논문과 두 공개 경로의 대응

논문 본문의 [Algorithm 6–8](https://www.usenix.org/system/files/usenixsecurity25-liu-yizhong.pdf)은
클라이언트가 `alpha_r * HPRF(m_i,r)`를 단일 마스크로 붙이고, aggregator가
masked gradient 자체를 norm-filter한 뒤 aggregate-key HPRF를 제거하고
지정 소수 자릿수로 반올림하는 흐름이다.

| 항목 | 논문 Algorithm 6–8 | ASR simulator MMF | 학습 artifact `aion()` |
| --- | --- | --- | --- |
| 전송/함수 입력 | client scaled-HPRF masked gradient | client unscaled-HPRF masked full vector | server-held plaintext updates |
| validation mask | `alpha_r * HPRF(m_i,r)` | raw original HPRF | 별도 SHPRG, server-generated seed |
| selection 좌표 | masked gradient | 전체 simulator vector | classifier weight 840좌표 |
| 초기 선택 | 알고리즘에 percentile bootstrap 미기재 | 첫 3회 30% rank | 첫 3회 10% rank |
| 최대 선택 | 알고리즘에 80% clip 미기재 | 80% | 80% |
| bound 경계 | inclusive `<=` | inclusive `<=` | `searchsorted(left)`, 사실상 `<` |
| 집계 | masked sum - scaled aggregate HPRF | mod-p masked sum - aggregate HPRF | selected plaintext mean |
| 일회성 VSS | 명시 | 존재 | 해당 없음 |
| DMC/DMR | Algorithm 7/8 | 별도 mod-p integer 처리 | 없음 |

논문은 beta=0.2를 설명하지만 공개 `attack3_fmnist.py` launcher는
`weight=0.1`을 사용한다. launcher는 population 500, per-round sample 100,
adversaries 20, resumed checkpoint 300, retraining 60 rounds, poison
probability 0.5도 지정한다. 현재 500/100 실험은 이 설정의 축소 실행이며,
라운드 수와 공격 일정 차이를 각 결과에 명시한다.

## 현재 Flower 경로의 의미

- `aion_source_asr`: 왼쪽 ASR simulator 경로. client masking, 원본 HPRF,
  one-time VSS, source MMF를 유지한다. 500/100 공식 Flower 4라운드까지
  모델 재계산 오차 0으로 검증했다.
- `--author-mgf`의 plaintext `mgf`: 오른쪽 학습 artifact를 보존한 ML
  대조군. 방어 곡선 재현에 사용하지만 secure aggregation이라 부르지 않는다.
- `aion_mgf_oracle`: 원본 HPRF 집계와 artifact selection을 대조하기 위해
  classifier를 공개하는 명시적 oracle이며 one-time-sharing 재현이 아니다.
- `--paper-quantized-mgf`: 논문 수치식을 추가 share 없이 시험하는 조건부
  adapter다. 공개된 원본 HPRF에서 modular carry lift가 모호한 라운드를
  실패 처리하므로 완성된 저자 protocol이라고 부르지 않는다.

즉, 공개 저자 구현을 최대한 보존하는 현재 목표에서 올바른 처리는 두
artifact를 억지로 동일시하는 것이 아니라 각각 포팅·검증하고, 공개 소스에
없는 scaled-HPRF MGF wire를 새 암호 프로토콜인 것처럼 보충하지 않는 것이다.
