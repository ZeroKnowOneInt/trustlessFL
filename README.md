# TrustlessFL — AION-ASR on Flower

## 최신 상태 (2026-10-01)

현재는 **저자 Aion 구현을 활용한 Flower 연구용 포팅**이며, 논문 전체의
비공개 MGF나 production-secure 구현의 완성본은 아닙니다.
[진행 상황·검증 결과·남은 작업 요약](docs/reproduction/aion-flower-status-2026-10-01.md)을
먼저 참고하세요. 아래 내용은 서로 다른 시점과 실험 경로의 기록입니다.

최신 목표는 클라이언트 마스킹·일회성 키 공유·추가 mask share 없는
scaled-MGF입니다. 서명된 masked-vector 전달과 위원회별 선택 검증을 연결했고
공식 Flower synthetic 1라운드는 통과했지만, 10라운드 시도는 3라운드 commit 후
4라운드 복원 모호성으로 실패했습니다. 원본 ASR 집계 성공이나 중앙 평문
MGF의 60라운드 결과를 이 목표의 완료로 취급하지 않습니다.

## 이전 구현·실험 기록

사용자 확인에 따라 [원본 Aion-ASR의 Flower 통신 포팅](docs/source-asr-flower-port.md)을
별도 경로로 추가했습니다. 원본 키 공유·MMF·복원 함수를 실행하며,
첫 라운드 키 share를 재사용하고 추가 mask share는 없습니다.
아래 bounded-MGF 학습 실험과 구분되는 경로입니다. 원본 합성 workload 외에
실제 FMNIST 학습도 연결했습니다. [4라운드 검증](docs/experiments/fmnist-source-asr-fixed-key-four-round-2026-10-01/report.md)에서
집계 오차는 0이었으나 원본 ASR MMF의 공격 방어는 실패했습니다.
이를 논문 MGF의 공격 방어 재현으로 취급하지 않습니다.
새 소스 경로의 [공식 Flower SuperLink/Ray 실행과 20라운드 재검증](docs/experiments/fmnist-source-asr-official-2026-10-01/report.md)도
완료했습니다. 전체 모델 오차는 0이지만 공격 방어는 미완료이며, 활성 목표로 계속 진행합니다.
후속 [100명/10명 동적 참여 검증](docs/experiments/fmnist-source-asr-dynamic-2026-10-01/report.md)도
로컬·공식 Flower에서 완료했습니다. 재참여자는 기존 키/share를 유지합니다.

새 [single-view MGF의 공식 Flower 공격 4라운드](docs/experiments/fmnist-flower-original-single-view-mgf-four-round-2026-10-01/report.md)를
완료했습니다. 검사 좌표의 중복 masked 표현 없이 정확도 88.60%·공격 성공률
0.390625%였고, 네 라운드 전체 모델의 재학습 양자화 평균 오차는 0이었습니다.
1·4라운드 공격자를 제외했고 후보 40개·선택 8개와 threshold 갱신을 검증했습니다.
일회성 키 공유·추가 share 제거는 [별도 완료 조건](docs/mgf-key-sharing-reduction.md)이 남아 있습니다.

추가 `--mgf-projection --mgf-single-view`는 검사 좌표의 중복 masked 표현을
제거합니다. 해당 좌표는 bounded probe에서만 복원하며,
[구현 범위](docs/paper-client-mgf-port.md)에 설명했습니다.
아래 FMNIST 결과는 이 옵션을 적용하기 전 결과입니다.

이전 dual-view [원본 HPRF·클라이언트 마스킹 MGF·HotStuff의 공식 Flower 4라운드](docs/experiments/fmnist-flower-original-client-mgf-projection-four-round-2026-10-01/report.md)는
정확도 88.60%·공격 성공률 0.390625%였으며, 전체 61,706좌표 모델이
선택된 업데이트의 양자화 평균과 네 라운드 모두 오차 0으로 일치했습니다.
40개 후보의 signed-wire와 4라운드의 threshold 갱신도 확인했습니다.
classifier projection을 쓰는 축소 실험이며 일회성 키 공유는 아직 다릅니다.

논문의 **클라이언트 마스킹 → masked-vector MGF → 선택 집합 합의 → 집계** 흐름에
맞추기 위해 `aion_mgf_beta`에 원본 `aion-original` HPRF를 연결했습니다.
이 경로는 평문 `oracle_classifier`를 전송하지 않습니다.
[구현 범위·실행법·검증](docs/paper-client-mgf-port.md)을 참고하세요.
[새 원본 HPRF·masked MGF·HotStuff의 공식 Flower FMNIST 공격 1라운드](docs/experiments/fmnist-flower-original-client-mgf-projection-one-round-2026-09-30/report.md)는
정확도 88.73%·공격 성공률 0.585938%였고, 선택된 두 업데이트의 양자화 평균과
전체 모델이 오차 0으로 일치했습니다. classifier projection을 쓰는 축소 시험입니다.
기존 아래의 10라운드 결과는 평문 classifier를 공개한 oracle 경로이며,
새 클라이언트 마스킹 경로의 실험 결과로 취급하지 않습니다.

현재 우선 작업은 [저자 Aion 구현의 Flower 포팅](docs/aion-author-port-goal.md)입니다.
최신 [공식 Flower 결합 10라운드](docs/experiments/fmnist-flower-author-reference-hprf-loader-hotstuff-ten-round-2026-09-30/report.md)는
author-loader·원본 HPRF·저자 SHPRG/MGF·HotStuff·저자 소스 기록을 포함합니다.
최종 정확도 88.67%·공격 성공률 0.585938%, 평문 MGF와 모든 라운드 선택
일치를 확인했습니다. classifier 평문 공개 등 연구용 경계는 유지합니다.
원본 ASR HPRF의 파일·계산을 보존하는 `aion-original`과 원본 학습
SHPRG·MGF의 CPU 계산을 보존하는 `--author-mgf`를 구분해 제공합니다.
[저자 SHPRG·MGF 4라운드 실험](docs/experiments/fmnist-flower-author-shprg-mgf-four-round-2026-09-30/report.md)은
평문 학습 경로입니다. 아래의 기존 경량 연구 백엔드 결과를 원본 HPRF
재현 결과로 취급하지 않습니다.

[원본 HPRF·저자 SHPRG/MGF·HotStuff 연결의 공식 Flower 4라운드](docs/experiments/fmnist-flower-author-hprf-shprg-hotstuff-four-round-2026-09-30/report.md)에서는
평문 저자 MGF와 모든 라운드 선택 및 최종 지표가 일치했습니다.
classifier 평문 공개와 매 라운드 키 공유, 고정소수점 인코딩이라는
원본 대비 차이를 보고서에 명시했습니다.

[동일 경로의 공식 Flower 10라운드](docs/experiments/fmnist-flower-author-hprf-shprg-hotstuff-ten-round-2026-09-30/report.md)도
완료·재검증했습니다. 평문 저자 MGF와 모든 라운드 선택이 같았고 최종
정확도 88.88%·공격 성공률 0.78125%였습니다. N=100/q=20의 축소 검증이며
논문 규모·길이 전체 재현이나 비공개 MGF 구현 완료는 아닙니다.

추가 `--training-sampling author-loader`는 원본 DataLoader batch 구성과
중복 없는 poison sampling을 선택합니다.
[공식 Flower 4라운드 대조](docs/experiments/fmnist-flower-author-shprg-loader-four-round-2026-09-30/report.md)로
확인했으며, 기존 10라운드의 legacy sampling 결과와 구분합니다.
[같은 학습 방식의 원본 HPRF·HotStuff 결합 4라운드](docs/experiments/fmnist-flower-author-hprf-shprg-loader-hotstuff-four-round-2026-09-30/report.md)도
완료했고 평문 MGF와 모든 라운드 선택이 일치했습니다. 후보 80회 학습의
실제 sampling metadata와 HotStuff 인증서를 재검증했습니다.

Flower 1.36의 `ServerApp`, `ClientApp`, `Message`, `Grid`를 사용하는 **AION-ASR 연구용 구현**입니다. 서버 1개가 여러 독립 aggregator와 학습 client를 조정합니다. 합성 NumPy 회귀 데이터로 여러 라운드의 집계·학습을 실행할 수 있습니다.

[MNIST 실험](experiments/README.md#mnist-전체-데이터-실험)에서는 전체 학습 60,000장·테스트 10,000장으로 softmax 분류기를 학습하고 일반 집계와 비교합니다.
[공식 Flower FMNIST/LeNet5 10라운드 실험](docs/experiments/fmnist-flower-official-ten-round-2026-09-29/report.md)은 원본 checkpoint·데이터, N=500/q=100, **명시적으로 지정한** model-replacement 공격 라운드 5·7·10으로 AION과 평문 양자화 모델의 매 라운드 오차 0을 확인했습니다. 기본 50% 확률 추첨은 분할 직후의 NumPy 난수 상태를 이어 쓰며, 같은 설정의 10라운드에서는 1·2·5·6·7·10라운드가 선택됩니다. 평문 MGF 대조군은 공격을 걸러냈지만 AION 보안 집계 내부 MGF 방어를 입증하지는 않습니다. 논문 길이의 60라운드 곡선도 아직 실행하지 않았습니다.
[원본식 개별 client 추첨의 MGF→AION-ASR 집계 10라운드 실험](docs/experiments/fmnist-flower-official-oracle-individual-ten-round-2026-09-29/report.md)은 N=500/q=100에서 평문 MGF와 매 라운드 선택·지표가 일치했습니다. 별도의 `aion_mgf_oracle` 모드가 평문 classifier 층을 coordinator에 공개하므로 안전한 MGF 구현으로 해석하면 안 됩니다. [2인 그룹 추첨 결과](docs/experiments/fmnist-flower-official-oracle-mgf-artifact-ten-round-2026-09-29/report.md)도 별도 보존했습니다.
[원본식 기본 확률 추첨 10라운드](docs/experiments/fmnist-flower-official-default-rng-ten-round-2026-09-29/report.md)에서는 공격 라운드 1·2·5·6·7·10으로 두 Flower 경로의 선택·지표가 일치했습니다. 이는 위의 명시적 5·7·10 실험과 다른 참여 일정입니다.
[분할 뒤 Python 난수를 이어 쓴 공격 풀의 10라운드](docs/experiments/fmnist-flower-official-shared-python-rng-ten-round-2026-09-29/report.md)에서도 두 경로의 선택·모델이 일치했습니다. 이전 기본 일정 실행과 모델은 같지만 평가 이미지 풀이 달라 ASR은 0.390625%에서 0.5859375%로 바뀌었습니다.
[공격·동적 참여 실험](docs/experiments/fmnist-flower-dynamic-2026-09-28/report.md)은 node-local model-replacement 학습과 사전 확정된 2인 group 단위의 라운드별 참여를 확인했습니다. 이는 논문의 CCS/VRF 추첨이 아닙니다.

[마스킹된 classifier MGF의 공식 Flower 기능 시험](docs/experiments/fmnist-flower-masked-classifier-mgf-one-round-2026-09-30/report.md)은 `aion_mgf_beta --mgf-projection`으로 평문 classifier 없이 전체 모델을 ASR 집계했습니다. 추가 `--mgf-percentile` 옵션은 첫 3라운드의 percentile 초기화와 최소 10%·최대 80% 선택을 마스킹된 값으로 수행하며, 각 aggregator가 client 서명과 선택 결과를 독립 검증합니다. `--mgf-artifact-bound`까지 켜면 전체 후보 mask norm 인증서와 최근 두 집계 norm을 사용해 4라운드 이후 원본식 threshold를 계산합니다. 기존 percentile 경로의 bound 전이는 그대로 유지합니다. 작은 마스크의 정보 노출 및 악성 client의 개별 mask 일치 증명 한계는 [검증 기준](docs/security-completion-criteria.md#마스킹된-classifier의-percentile-선택-경로)에 명시했습니다.
[N=500/q=100 마스킹 MGF 공격 실험](docs/experiments/fmnist-flower-masked-percentile-paper-scale-one-round-2026-09-30/report.md)은 20명 공격자가 참여한 1라운드에서 정상 client 10명을 선택하고 ASR 집계를 완료했습니다. 정확도 88.55%, 공격 성공률 0.5859375%, 공식 실행 시간 737.34초입니다. 단일 라운드 기능·선택 검증이며 장기 방어 성능이나 논문의 집계 성능 재현을 입증하지 않습니다.
[원본식 threshold의 공식 Flower 4라운드](docs/experiments/fmnist-flower-masked-artifact-bound-four-round-2026-09-30/report.md)와 [동일 조건 무방어 비교](docs/experiments/fmnist-flower-masked-artifact-bound-comparison-2026-09-30/report.md)도 완료했습니다. N=100/q=20, seed 0에서 마지막 정확도·공격 성공률은 MGF 88.82%·1.37%, 무방어 64.92%·46.48%였습니다. 축소된 짧은 실험이며 일반적인 방어 성능으로 확대하지 않습니다.

마스킹 backend와 LWE-HPRF reference는 연구용이며 검증된 보안 구현이 아닙니다. 선택형 MGF·EMA·HotStuff/P2P 복구 경로도 논문의 전체 보안 보장이나 모든 장애 상황을 재현한 것으로 해석하면 안 됩니다. 우선순위와 남은 실험 차이는 [재현 계획](docs/aion-reproduction-plan.md)을 참고하세요.

[마스킹 MGF·원본식 threshold·HotStuff 공식 Flower 4라운드](docs/experiments/fmnist-flower-masked-artifact-bound-hotstuff-four-round-2026-09-30/report.md)도 완료했습니다. N=100/q=20에서 최종 정확도 88.71%, 공격 성공률 1.37%였고 모든 라운드의 commit QC를 검증했습니다. ServerApp 내부 시간은 약 20분 55초입니다. 실행 후 개발한 HotStuff 검증 재사용 최적화는 이 측정에 포함되지 않았습니다.

[검증 재사용 적용 4라운드](docs/experiments/fmnist-flower-hotstuff-validation-reuse-four-round-2026-09-30/report.md)는 최신 코드로 완료·검증했습니다. 최종 정확도 88.52%, 공격 성공률 0.390625%, ServerApp 내부 시간 약 16분 48초였습니다. [같은 학습 조건의 무방어 대조](docs/experiments/fmnist-flower-hotstuff-validation-reuse-comparison-2026-09-30/report.md)는 64.92%·46.48%였습니다. 이는 축소된 단일-seed 학습 결과이며, 서로 다른 암호 마스크의 실행 시간을 엄밀한 speedup으로 표시하지 않습니다.

## 실행

Python 3.12 이상, Linux/WSL 환경에서:

```bash
uv sync
uv run aion-demo --clients 4 --aggregators 4 --faults 1 --rounds 3
uv run pytest -q
uv run flwr build
```

데모는 실제 Flower 앱과 protobuf 직렬화를 사용하며, client 4개와 aggregator 4개를 각각 별도 프로세스에서 실행합니다. 네트워크 대신 로컬 `ProcessGrid`를 쓰므로 Ray, GPU, 외부 데이터셋, 실행 중 인터넷 연결이 필요하지 않습니다. 종료하면 임시 identity와 share 상태도 정리합니다.

구현한 흐름은 client별 일회성 Feldman VSS, X25519/HKDF/AES-GCM share 전달, 라운드별 masking, 서명된 참여 집합 정족수, 검증 가능한 집계 share 복원, DMC/DMR 정수 연산, aggregator별 결과 재계산 및 Ed25519 결과 인증입니다. 기본 모드는 고정 cohort이고, 선택적으로 사전 확정된 privacy group 전체를 라운드별로 선택할 수 있습니다.

[실행 및 배포 가이드](docs/aion-flower-implementation.md), [논문 구현 포인트](docs/aion-implementation-notes.md), [요구사항](docs/secure-aggregation-requirements.md)을 참고하세요.
