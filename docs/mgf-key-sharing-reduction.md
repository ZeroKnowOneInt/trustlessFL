# MGF 일회성 키 공유와 추가 share 제거: 재현 가능한 제약

2026-10-01. 현재 single-view MGF에서 두 변경을 단순히 활성화하지 않는 이유와
완료 조건을 기록한다. 기능 검증 통과와 논문 통신량 재현을 구분한다.

## 추가 mask share를 삭제할 수 없는 구체적인 입력

저자 `Aion/agent/Aion/HPRF`의 실제 initialization/matrix를 사용했다.
공개 합성 키, HPRF 입력 1, decimals=3, mask amplitude=0.2에서:

| 개별 키 | 합계 키 | 개별 bounded mask의 정수 합 |
| --- | ---: | ---: |
| 1, 19 | 20 | 41 |
| 4, 16 | 20 | 241 |

합계 키 20의 bounded HPRF 출력은 41이다. 차이 200은 출력 링을 실수 범위로
스케일링한 뒤 남은 carry이며, DMC/DMR의 작은 반올림 오차로 취급할 수 없다.
첫 경우의 업데이트 합이 정수 200, 둘째 경우가 0이면 두 경우의 masked 합은
모두 241이다. **합계 키와 masked 합만 이용하는 현재 decoder는 두 정답을
구분할 수 없다.** 이 예는 다른 암호 구성이나 carry 정보를 포함한 새 protocol의
불가능성을 주장하지 않는다.

원본 `SA_ClientAgent.sendVectors()`는 처음 한 번 키를 공유하지만, 실제 전송은
`ones + HPRF`이고 bounded amplitude 스케일링을 적용하지 않는다.
`SA_Aggregator.reconstruction_process()`는 원본 출력 링에서 모듈러 차를 낸다.
그 경로를 그대로 연결하는 것만으로 현재 signed bounded norm 필터와 정확한
학습 평균이 동시에 유지되지는 않는다. 원본 코드에는 이 bounded carry의
복원 경로를 찾지 못했다.

완료 조건은 다음 중 하나다:

- 논문 MGF의 수치 표현과 HPRF 집계 연산을 일관되게 재현하고, 추가 mask
  share 없이 carry/양자화 오차가 허용 오차 안으로 복원됨을 검증한다.
- 필요한 carry 정보를 안전하게 제공하는 별도 프로토콜을 설계하고, 그 비용과
  입력 정보 노출을 명시한다. 이는 논문의 무추가-share 구현과 구분한다.

현재 정확한 집계 경로의 Pedersen mask share를 삭제하거나, 평문 mask를
공개하거나, 모듈러 결과를 실수 결과인 것처럼 해석하지 않는다.

## 매 라운드 새 키를 고정 키로 바꾸는 문제

현재 MGF는 라운드별 참여와 필터 후 선택 집합을 바꿀 수 있다.
공개 합성 키가 c0=101, c1=202, c2=303일 때, 한 라운드에서 세 명의
합계 키 606, 다른 라운드에서 c0/c1의 합계 키 303을 같은 관찰자가 알게 되면
차분으로 c2의 키 303을 얻는다. 예를 들어 합계 키를 복원하는 집계자가 이에
해당하며, 모델 인증서에 개인 키가 직접 들어간다는 뜻은 아니다.
둘 다 최소 2명이라는 조건을 만족한다.
반복 사용한 키가 드러나면 해당 키로 생성한 다른 라운드 마스크도 계산할 수 있다.

따라서 one-time sharing 완료에는 공개하는 합계 키들의 집합 관계를 통제하는
참여/선택 정책 또는 동일한 노출을 막는 별도 프로토콜이 필요하다.
CCS 이름의 옵션을 켜는 것만으로 dropout과 MGF의 선택 집합까지 안전하다고
가정하지 않는다. 기존 비-MGF privacy group은 whole-group 선택 제약을
사용하지만, 이를 그대로 적용하면 현재 개별 클라이언트 norm 필터 실험이 바뀐다.

고정 키를 강제로 사용하는 비교 실험은 만들 수 있으나, 이 차분 노출을 해결한
구현으로 표시할 수 없다. 현재 기본 경로는 fresh key를 유지한다.

## 회귀 시험

`tests/test_paper_mgf_original.py`의
`test_original_sum_key_does_not_determine_bounded_mask_sum`이 원본 artifact로
첫 반례와 동일 masked 합의 모호성을 확인한다.
`test_reused_sum_keys_expose_client_key_for_nested_selected_rosters`는 합성 키로
두 번째 공개 패턴을 확인한다. 실제 실험의 개인 키/gradient를 읽거나 출력하지 않는다.

새 single-view의 여러 라운드 학습 검증은 별도 성능/정확성 결과다.
여러 라운드가 통과해도 위 두 프로토콜 변경이 완료됐다는 의미는 아니다.
