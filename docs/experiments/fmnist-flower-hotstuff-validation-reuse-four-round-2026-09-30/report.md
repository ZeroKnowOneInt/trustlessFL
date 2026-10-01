# Flower FMNIST: HotStuff application 검증 재사용 4라운드

최신 코드의 마스킹 MGF·원본식 threshold·HotStuff를 공식 Flower 1.36.0 SuperLink/Ray CPU runtime에서 4라운드 실행하고 사후 검증했다. classifier 평문 대신 마스킹된 840좌표로 선택하며 전체 61,706좌표를 ASR 집계한다.

## 조건과 결과

N=100, q=20, 집계자 4개, CPU worker 4개, 학습 seed 0이다. 공격 client 4명이 라운드 1·4에서 model-replacement 학습을 수행한다. 원본 checkpoint, artifact식 분할·poison RNG와 개별 client 추첨을 사용한다. epoch 2, batch 64, lr 0.001, 공격 steps 120·boost 20·poison batch 6이며 초기 alpha와 beta는 0.1이다.

| 라운드 | 정확도 | 공격 성공률 | 선택 수 | 선택 공격자 수 |
|---|---:|---:|---:|---:|
| 0 | 88.56% | 0.390625% | — | — |
| 1 | 88.23% | 0.390625% | 2 | 0 |
| 2 | 88.30% | 0.390625% | 2 | 0 |
| 3 | 88.38% | 0.390625% | 2 | 0 |
| 4 | 88.52% | 0.390625% | 4 | 0 |

4라운드 threshold는 `0.013825518673`이다. 후보·선택·cohort norm·모델·HotStuff commit 인증서를 검증했고, 저장 모델의 변화에서 norm history와 다음 alpha를 재계산했다. 모든 라운드에 commit QC가 있다. [학습 조건이 같은 무방어 대조군](../fmnist-flower-hotstuff-validation-reuse-comparison-2026-09-30/report.md)도 새로 검증해 비교했다.

## 최적화와 측정 범위

각 집계자가 검증한 정확한 `(slot, value, command)`를 자기 서명 증거로 재사용한다. 다른 수신자·변경된 명령·변조 증거에는 적용하지 않으며, 각 단계의 QC·view·투표 잠금은 계속 검사한다. 같은 입력의 단위 대조에서는 application 검증 호출이 17회에서 4회로 줄었고 제안 및 세 단계 QC는 완전히 같았다. 로컬 검증 증거는 투표 QC로 사용할 수 없다.

ServerApp 내부 총 시간은 1,007.80초(약 16분 48초)다. 초기화·학습·집계·모델 저장을 포함하며 CLI/Ray 기동과 사후 평가·검증은 별도다. 누적 `hotstuff` RPC batch 시간은 375.80초, `hotstuff_candidate`는 123.11초다. 원시 trace는 `results.json`의 `phase_timings`로 보존했다. 순수 암호 CPU 시간이 아니다.

[검증 재사용 전 실행](../fmnist-flower-masked-artifact-bound-hotstuff-four-round-2026-09-30/report.md)은 총 1,255.21초, `hotstuff` 636.34초였다. 이번에 관측 시간은 짧아졌지만, 암호 마스크·선택 client·모델 궤적이 다르고 회귀 테스트도 병행했다. 따라서 엄밀히 통제된 speedup이나 반복 측정의 평균으로 표현하지 않는다. 두 실행 모두 선택 수는 2·2·2·4였으나 같은 선택 집합이라는 주장은 하지 않는다.

## 재현과 한계

[실험 README](../../../experiments/README.md)의 4라운드 명령에 `--hotstuff`를 더하고 새 output 경로를 지정한다. 원시 실행은 `.cache/fmnist/official-masked-artifact-bound-hotstuff-validation-reuse-four-round-seed0`, run ID는 `14172839906824354091`이다. source·provenance·verification·모델·결과 hash는 원시 실행과 이 폴더의 `results.json`에 보존했다.

이는 축소된 단일-seed 정상 합의·공격 실험이지 N=500/q=100 다중 라운드나 60라운드 재현이 아니다. Flower가 합의 메시지를 전달했으며 독립 P2P 장애 복구는 별도 TCP 시험과 구분한다. 검증된 LWE-HPRF, CCS/VRF, bounded-mask privacy, 개별 client의 mask/probe/ASR 일치 증명 및 전체 부분 동기 진행 보장을 달성했다고 주장하지 않는다.
