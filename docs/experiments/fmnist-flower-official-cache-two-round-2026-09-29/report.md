# Flower N=500/q=100: 공개 마스크 열 캐시 변경 후 2라운드

`artifact` 마스크 backend의 공개 행렬 열 캐시를 8,192개에서 65,536개로
확대한 뒤, Flower 1.36 SuperLink/Ray CPU에서 FMNIST/LeNet5,
N=500, q=100, aggregator 8개, 악성 client 20명, seed 0의
기본 확률 추첨 첫 2라운드를 새로 실행했다. 두 라운드 모두 공격 라운드다.
`aion_mgf_oracle`과 평문 MGF는 매 라운드 같은 client 10명을 선택했고,
악성 client는 선택하지 않았다. 두 경로의 최종 정확도는 88.59%,
ASR은 0.390625%; 두 모델 이력의 최대 좌표 차이는 `5.1343e-07`이다.

이번 AION 모델의 0–2라운드 이력은 [캐시 변경 전 10라운드 실험](../fmnist-flower-official-default-rng-ten-round-2026-09-29/report.md)의
같은 구간과 **좌표별로 완전히 일치**했다. 해당 실험의 첫 두 `train` 요청
시간은 40.79초와 52.74초, 이번 실행은 38.10초와 50.60초였다.
합계는 93.54초에서 88.71초로 약 5.2% 낮았다. 별도 Flower 실행의
관찰값이므로 이를 통제된 벤치마크나 60라운드의 예상 단축률로 해석하지 않는다.

[해시 연결된 실행 결과](results.json)에 provenance와 모델·결과 해시를 기록했다.
원시 실행은 `.cache/fmnist/official-cache-two-round-seed0/`에 보관한다.
MGF는 앞선 실험과 같이 classifier 평문 좌표를 coordinator에 공개하는
`oracle` 경로이며 보안 MGF 완료를 의미하지 않는다.
