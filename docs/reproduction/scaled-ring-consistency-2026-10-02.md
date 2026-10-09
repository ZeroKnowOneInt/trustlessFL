# 원본 HPRF의 스케일링된 모듈러 공간 재검증

## 결론

스케일링 자체가 준동형성을 깨는 것은 아니다. 같은 계수 `lambda`를
적용하면 원본의 `mod p` 관계는 `mod (lambda*p)` 관계로 옮겨진다.
다만 그 잔여값을 실제 학습의 정수/실수 **합계**로 복원하려면 독립적인
허용 범위와 HPRF·전송 반올림 오차 조건이 필요하다. 모듈러 관계가 맞는
것만으로 scaled-MGF 전체 경로가 완성되는 것은 아니다.

이번에는 이 제안을 원본 저장 HPRF 행렬·초기화 파일로 직접 검증했다.
추가 mask share, 클라이언트 키 탐색, 평문 업데이트의 서버 전달은 추가하지
않았다. 새 함수는 수치 참조·감사용이며 현재 Flower wire와 MGF 필터는
변경하지 않았다. 조건부 성공을 전체 목표의 완료로 표시하지 않는다.

## 연산과 복원 조건

좌표별 원본 관계를 `sum(h_i) = H(sum(k_i),r) + c*p + e`라고 쓰면,
`PaperDMC`의 유효 계수 `lambda=coefficient/denominator`에 대해:

```text
P = lambda*p
sum(y_i) - lambda*H(sum(k_i),r) = sum(x_i) + c*P + lambda*e
```

`mod P`를 적용하면 캐리 항은 사라진다. 그러나 실수 합계 `X`와 `X+P`는
같은 잔여값이다. 이번 centered lift가 보장하는 조건은 독립적인 좌표별
SUM bound `B`에 대해 `B + E < P/2`이고, 양자화 반 간격보다 `E`가 작아야
한다. `n`명을 선택하고 wire를 소수 자릿수 `D`로 반올림하면 보수적 오차는:

```text
E = coefficient*(n-1)/D + n/(2*D)
```

정확한 유리수 wire에서는 마지막 전송 반올림 항을 제외한다. 이 bound는
시험 입력의 명시적 조건이며, MGF 통과나 이전 글로벌 모델의 norm에서
자동으로 보장되는 범위가 아니다. 악성 클라이언트가 범위를 지킨다는 증명도
아니다. 복원 후 bound 검사만으로 모든 overflow alias를 검출할 수는 없다.

`trustlessfl/paper_dmc.py`에 다음을 보강했다.

- `residual_modulo`: 스케일링된 출력 공간의 잔여값을 명시적으로 계산한다.
  반환값을 평문 합계 또는 MGF 입력으로 오인하지 않도록 계약을 명시했다.
- `remove_centered`: 실제 selected count와 decimal-wire 반올림 오차를
  검사하고, 복원된 값이 독립 bound 밖이면 거부한다. 기존 호출 방식은 유지한다.

## 재현 실행

```bash
PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m experiments.audit_scaled_ring \
  --rounds 10 --clients 20 --dimension 840 \
  --run .cache/source-filtered-bft-paper-mgf-one-round-official-20261002 \
  --output .cache/scaled-ring-public-flower-range-20261002.json
```

감사는 공개 fixture 키만 사용한다. 성공 사례의 좌표별 SUM bound는
`P/4=0.005`, 이전 공개 norm은 0.1, beta는 0.2, `P=0.02`다.
전체 집합·절반 집합·라운드별 변동 부분집합을 각각 검사했다.

10라운드·20명·840좌표에서 exact/decimal 표현 각각 **25,200좌표가
정확히 복원**됐다. 비교한 25,200좌표 모두 nonzero carry가 있었고,
centered HPRF 작은 오차의 최대 절댓값은 3이었다. 이것은 실제 FMNIST
학습 검증이 아니라 독립 범위를 지키는 fixture의 수치 검증이다.

동일 감사를 라운드 참여자 100명·60라운드·840좌표로 확대했다.

```bash
PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m experiments.audit_scaled_ring \
  --rounds 60 --clients 100 --dimension 840 \
  --output .cache/scaled-ring-60round-q100-840-20261002.json
```

exact/decimal 각각 **151,200좌표 모두 정답과 일치**했다. 비교한 모든
151,200좌표에 nonzero carry가 있었고, centered 작은 오차의 최대 절댓값은
2였다. 두 규모 모두 추가 mask share는 0개다. 이 60라운드는 수치 fixture
감사이며 Flower의 60라운드 학습 또는 실제 학습 범위의 보장을 뜻하지 않는다.

## 전송 벡터까지 mod P로 줄이는 방식은 채택하지 않음

새 감사는 동일한 개별 키 두 개를 그대로 두고 평문 합계가 각각 `0`과
`0.02`인 두 입력을 만든다. 일반 decimal masked VECTOR는 서로 다르지만,
각 VECTOR를 `mod 0.02`로 줄이면 같아지고 필터 결과도 같아진다.
이 경우 키·키 commitment까지 바꿀 필요 없이 업데이트가 alias된다.
이것은 **제안된 modulo-only wire 변환**의 반례이며 기존 wire가 이미
이 형태라는 주장이나 모든 가능한 암호 프로토콜의 불가능성 주장이 아니다.

norm도 보존되지 않는다. 실제 원본 마스크에 업데이트 `5*P`를 더한 fixture는
일반 masked norm에서 `b=2*P`를 초과한다. 하지만 VECTOR를 mod P로 줄이면
같은 입력이 필터를 통과한다. 따라서 전송값을 줄이는 변경은 논문
Algorithm 6의 일반 L2 판정과 같다고 표시할 수 없다.

## 기존 공식 Flower 공개 결과의 범위 대조

`audit_public_history`는 기존 `manifest.json`, `results.json`, hash-pinned
HPRF setup만 읽는다. 개인 키·node state는 읽지 않고 기존 결과도 수정하지
않는다. 기존 학습 결과의 참 여부를 검증하는 도구는 별도의
`experiments.verify_source_learning`이며, 이번 검사는 공개된 결과의
centered-range 전제를 대조한다. public SUM을 런타임 복원 oracle이나
사후 bound 생성에 사용하지 않는다.

검사 대상은 BFT 수정 후 완료된 공식 Flower synthetic 1라운드:
`.cache/source-filtered-bft-paper-mgf-one-round-official-20261002`다.

| 항목 | 관측값 |
| --- | ---: |
| 선택 인원 | 2 |
| 공개 selected SUM의 L-infinity | 0.002199 |
| 스케일링된 주기 P | 0.0024694 |
| 반주기 P/2 | 0.0012347 |
| 중심 구간 변환으로 달라지는 공개 SUM 좌표 | 3 / 8 |

기존 조건부 quantized-lift가 복원에 성공한 이 결과에서도 단순 centered
lift의 충분조건은 성립하지 않는다. 따라서 그 성공 경로를 centered lift로
무조건 교체하면 안 된다. 결과 JSON에는 원본 manifest/results의 SHA-256을
함께 기록한다.

## 남은 완료 조건

현재 목표는 그대로 client masking → Flower masked VECTOR → 논문식 MGF →
선택 key sum만 복원 → 올바른 학습 합계 복원이다. 추가 mask share나
서버-held individual plaintext를 우회로로 쓰지 않는다.

스케일링된 모듈러 연산의 일관성은 확인했다. 다음은 실제 학습 범위에
적용 가능한 유일한 lift 규칙과 MGF norm/history의 의미를 함께 정당화해야
한다. 이전 norm만으로 SUM bound를 임의 선언하거나, overflow를 틀린 값으로
복원하거나, MGF가 보는 대표값을 바꿔 통과한 시험으로 완료를 주장하지 않는다.

## 회귀 검증

새 scaled-ring 시험과 기존 수치·Flower ASR·encrypted sharing·MGF selection
authorization·post-filter BFT 시험을 묶어 **148개 통과, 56.94초**를 확인했다.
첫 숫자 예제는 모듈러 관계 설명만 검증하며, 작은 toy modulus의 오차 조건이
두 자리 소수 복원을 보장한다고 가정하지 않는다. 원본 HPRF 복원 성공은
별도의 실제 저장 행렬 fixture로 검사한다.

```bash
PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m pytest -q \
  tests/test_scaled_ring.py tests/test_paper_dmc.py \
  tests/test_source_paper_numeric.py tests/test_masked_mgf_collision.py \
  tests/test_author_scale_precision.py tests/test_source_filtered_bft.py \
  tests/test_source_selection_authorization.py tests/test_source_encrypted_sharing.py \
  tests/test_source_asr_dynamic.py tests/test_source_asr_official.py
```

이번 변경 이후 저장소 전체 테스트를 모두 다시 실행한 것은 아니다.
수정한 Python의 compileall과 `git diff --check`는 통과했다.
