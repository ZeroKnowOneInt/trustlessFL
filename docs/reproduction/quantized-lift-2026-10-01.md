# 추가 share 없는 조건부 quantized-lift 복원

## 범위

`PaperDMC.remove_quantized_lift`는 원본 HPRF의 작은 반올림 오차와 유한한
carry 후보를 분리하고, 모델의 알려진 양자화 격자에 맞는 SUM 후보를 찾는다.
개별 키·개별 업데이트를 추정하거나 재공유하지 않는다. **새 수치 어댑터이며
논문 Algorithm 8 그대로인 저자 구현이라고 주장하지 않는다.**
후보가 하나일 때만 반환하고, 여러 개면 fail-closed한다. 암호 보안 증명이나
악성 클라이언트의 올바른 마스킹을 검증하는 증명은 아니다.

원래 `remove_centered`는 SUM 범위가 mask 주기의 절반보다 작아야 한다는
충분조건만 확인했다. 이 조건이 실패한다고 모든 양자화 기반 복원까지
불가능한 것은 아니다. 새 어댑터는 그 구분을 실제 계산으로 확인한다.

## 수치 조건

모델 quantum을 `delta=10^-l_dp`, 유효 mask 계수를 `a=coefficient/D`,
원본 HPRF modulus를 p라 하면 aggregate residual은
`X + c*a*p + a*e`다. X는 delta 격자 위에 있다.
`-1 <= c <= selected_count` 후보를 시험하고, 해당 candidate를 모델
정밀도로 반올림한 값과의 거리가 허용 오차 이내인지 검사한다.

실수 wire를 무한 정밀도로 가정하지 않았다. `mask_decimal_wire`는 DMC
precision으로 단일 masked view를 양자화하고, 복원에서는 client wire
반올림의 합산 오차 `selected_count/(2D)`도 포함한다. 합산 HPRF는 wire로
전달하지 않고 aggregator에서 생성하므로 해당 값의 전송 반올림 항은 없다.
허용 오차가 모델 quantum의 절반 이상이면 복원을 거부한다.

격자·mask 주기가 정수배로 겹치거나, 여러 carry 후보가 허용 오차 안에
들면 실패한다. 초기 L∞=0.1, beta=0.2인 사례는 여전히 모호하다.
이것을 임의 carry 선택·개별 평문 수집·추가 share로 우회하지 않는다.

## 검증

```sh
PYTHONPATH=.cache/author-asr-deps:.cache/flower-deps:.cache/torch-deps:. \
python3 -m experiments.audit_quantized_lift \
  --public-history .cache/author-asr-official-fmnist-bounded-state-four-round-20261001/results.json \
  --output .cache/quantized-lift-public-history-20261001.json
```

실행 완료. 공개 fixture 키·양자화 업데이트로 20라운드, **32좌표**, 선택
규모 2/4/10을 비교했다. 앞선 840좌표 감사와 별도의 시험이다. 기존 학습
결과에서 공개 aggregate mean만 읽어 초기·후속 스케일 후보를 구성했다.
실제 학습을 재개하거나 이전 클라이언트의 비밀 키·share를 읽지 않았다.
해당 mean이 원본 fixed-point SUM/count 격자와 일치하는지도 검사했다.

| 스케일 후보 | 선택 2명 | 선택 4명 | 선택 10명 |
|---|---|---|---|
| bootstrap L∞=0.1 | 0/20, 모두 모호성 거부 | 0/20, 모두 모호성 거부 | 0/20, 모두 모호성 거부 |
| L∞=0.012347 | 20/20 정확 | 20/20 정확 | 0/20, 모두 모호성 거부 |
| L∞=0.012347/3 | 20/20 정확 | 20/20 정확 | 15/20 정확, 5회 모호성 거부 |
| 기존 공개 r1~r4 mean 각각 | 각각 20/20 정확 | 각각 20/20 정확 | r1~r3 각각 0/20; r4 12/20 |
| 기존 공개 r1~r4 SUM 각각 | 각각 20/20 정확 | 각각 20/20 정확 | 각각 0/20, 모두 모호성 거부 |

모든 profile에서 잘못된 값을 성공으로 반환한 라운드는 0이다. 실패한
라운드는 성공률 분모에서 제외하지 않았다. 공개 history 기반 스케일은
이 어댑터로 실제 학습한 결과가 아니라 **복원 가능성 평가용**이다.

부호 있는 HPRF 대표값 변경, 평균 먼저 계산, 소수 3/6/9/12자리 변경만으로
기존 모호성 반례가 없어지지 않는 시험도 추가했다. 관련 3개 test module
전체는 **48 passed, 0.40s**다.

## 외부 원본 경로 확인

[논문 부록](https://www.usenix.org/system/files/usenixsecurity25-appendix-liu-yizhong.pdf)의
`aionaion/input_validation:latest`와 `aionaion/gradattack:latest`를 직접 확인했다.
2026-10-01 조회에서 두 Registry manifest는 모두 HTTP 404
`MANIFEST_UNKNOWN, unknown tag=latest`였고, 인증된 공개 pull 조회의
`tags/list`는 HTTP 200, 빈 tags 목록이었다. 컨테이너를 실행하거나 설치하지
않았다. 이는 현재 공개 태그를 얻지 못했다는 관측이지 비공개/과거 이미지나
모든 저자 코드를 확인했다는 주장이 아니다.

## 남은 작업

조건부 small-mask 복원이 가능하다는 증거를 얻었지만 초기 스케일과 일부
후속 스케일에서 계속 모호하다. 아직 안정적인 end-to-end Flower 학습
경로로 채택하지 않았다. 성공 사례만 골라 전체 논문 재현 완료로 표시하거나
기본 스케일을 임의로 바꾸지 않는다. 공개 초기 모델의 실제 수치와 표현
규칙을 대조하여 bootstrap까지 복원 가능한지를 확인해야 한다.
