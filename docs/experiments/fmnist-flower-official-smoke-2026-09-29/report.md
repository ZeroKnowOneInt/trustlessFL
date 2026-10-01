# FMNIST AION-ASR: 공식 Flower Runtime 첫 연결 검증

2026-09-29 작업트리의 `experiments.run_fmnist_official`로 N=q=4,
aggregator 4개, 정상 학습 1라운드를 실행했다. 기존 로컬 `ProcessGrid`가
아닌 `flwr run`/SuperLink/Ray simulation에서 `ServerApp`과 `ClientApp`을
각각 별도 FAB로 실행했다. AION과 평문 양자화 대조군은 독립 Flower run이다.

| 경로 | Flower run ID | 최종 정확도 | 최종 TER | 최종 ASR |
|---|---:|---:|---:|---:|
| AION-ASR | 10579703437179788398 | 88.75% | 11.25% | 0.390625% |
| 평문 양자화 | 3406760831158273559 | 88.75% | 11.25% | 0.390625% |

초기 checkpoint의 정확도는 88.56%였다. 두 경로의 매 라운드 모델
최대 절대 오차는 **0**이며, 저장된 NPZ 모델 파일의 SHA-256도 둘 다
`628f55850cafa1f70fe614c1cd81c18f1595f11f74eabcc4fa14a17a0e819d76`이다.
AION 결과에는 genesis와 round 1의 aggregator 4/4 인증서가 기록됐다.
Flower 1.36.0, Ray 2.55.1, PyTorch 2.4.0+cpu, NumPy 2.5.3을 사용했다.

원시 실행 디렉터리는 `/tmp/trustlessfl-fmnist-official-smoke-20260929`이며
`verification.json`으로 모델·지표를 다시 확인했다. `/tmp`가 지워지면
재실행이 필요하므로 이 보고서만으로 제3자가 원시 로그를 검증할 수는 없다.
4명 정상 1라운드 검증을 N=500/q=100, 공격, MGF, 60라운드 또는
보안성 검증으로 확대 해석하지 않는다. N=500/q=100의 별도 공식 Runtime
[첫 공격 라운드 결과](../fmnist-flower-official-paper-scale-2026-09-29/report.md)가
있지만, 그 결과도 60라운드 곡선의 대체 증거는 아니다.

후속 선택형 `--hotstuff` 공식 Runtime 소규모 검사에서는 별도 AION run
`16188319175817602794`의 round 1 모델에 HotStuff `commit` QC가 기록됐고,
평문 양자화 run `8679907680275491594`와 모델 최대 절대 오차가 0이었다.
원시 실행은 `/tmp/trustlessfl-fmnist-official-hotstuff-fixed-20260929`에 있으며
`verification.json` SHA-256은
`664f21b735a950fcb1bc64789a69681f3227d64d24860e2bdb5164fe4f7c8a77`이다.
이 검사는 정상 4명 1라운드의 Flower 연결 확인이지 부분 동기 장애에서의
전체 진행 보장 검증은 아니다.
