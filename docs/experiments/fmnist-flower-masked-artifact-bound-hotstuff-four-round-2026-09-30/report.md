# Flower FMNIST: 마스킹 MGF·원본식 threshold·HotStuff 4라운드

공식 Flower 1.36.0 SuperLink/Ray CPU runtime에서 classifier projection, percentile, artifact-bound 및 HotStuff를 함께 켠 공격·회복 4라운드를 완료했다. 사후 verifier가 후보 선택·cohort norm 인증서·모델 인증서·HotStuff commit QC 및 모델 변화에서 재계산한 MGF state를 검사했다.

## 조건과 결과

- N=100, q=20, 집계자 4개, CPU worker 4개, 학습 seed 0
- model-replacement 공격 client 4명, 공격 라운드 1·4
- 원본 FashionMNIST/LeNet5 checkpoint, artifact식 분할·poison RNG, 개별 client 추첨
- local epoch 2, batch 64, lr 0.001; 공격 steps 120, boost 20, poison batch 6
- alpha 0.1, beta 0.1; 첫 3라운드 percentile bootstrap 및 이후 전체 후보 mask norm 기반 threshold
- classifier 840좌표로 마스킹 MGF 선택, 전체 61,706좌표 AION-ASR 집계

| 라운드 | 정확도 | 공격 성공률 | 선택 client 수 | 선택 공격자 수 |
|---|---:|---:|---:|---:|
| 0 | 88.56% | 0.390625% | — | — |
| 1 | 88.42% | 1.7578125% | 2 | 0 |
| 2 | 88.50% | 1.7578125% | 2 | 0 |
| 3 | 88.67% | 1.5625000% | 2 | 0 |
| 4 | 88.71% | 1.3671875% | 4 | 0 |

4라운드 threshold는 `0.012456370388`였다. 모든 라운드 모델의 HotStuff stage는 `commit`이며 집계자 4개의 모델 서명을 확인했다. 짧은 단일-seed 실행으로 일반적인 방어 성능을 주장하지 않는다.

## 시간과 코드 버전

ServerApp 내부 총 시간은 1,255.21초(약 20분 55초)였다. 초기화·학습·집계·모델 저장을 포함하지만 CLI/Ray 기동과 사후 평가·검증은 별도다. `results.json`의 `phase_timings`는 coordinator가 본 RPC batch 경과 시간이며, 병렬 수신자 수를 곱한 CPU 시간이나 순수 암호 시간이 아니다.

주요 누적 구간은 train 291.14초, mgf_admit 119.12초, hotstuff_candidate 110.87초, hotstuff 636.34초다. 이 실행에는 최종 mask 복원의 중복 검증 제거와 수신자별 로컬 MGF 재료 캐시가 포함됐다. 실행 도중 개발한 **HotStuff application 검증 재사용**은 포함되지 않았다. 이후 보강한 미리보기 캐시 불변성도 별도 단위 시험으로 검증했다. 실행 중인 앱 사본에 사후 변경을 주입하지 않았다.

이전 [HotStuff 없는 4라운드](../fmnist-flower-masked-artifact-bound-four-round-2026-09-30/report.md)와는 합의 설정과 최종 선택 수가 다르다. 암호 키·마스크 난수도 학습 seed로 고정하지 않으므로 threshold와 모델 곡선이 같다고 가정하지 않는다. 두 실행의 총 시간을 같은 조건의 최적화 speedup으로 보고하지 않는다.

## 재현과 한계

[실험 README](../../../experiments/README.md)의 4라운드 명령에 `--hotstuff`를 추가하고 새 output 경로를 지정한다. 원시 실행은 `.cache/fmnist/official-masked-artifact-bound-hotstuff-four-round-seed0`, run ID는 `12814322823907988234`다. 모델·원시 결과·provenance·verification hash는 이 폴더의 `results.json`에 있다.

이는 Flower가 합의 메시지를 전달하는 정상 실행이다. Flower 중단 후 독립 P2P 복구는 별도 TCP 시험의 증거로 구분하며, 부분 동기 환경의 전체 진행 보장을 입증하지 않는다. N=500/q=100 다중 라운드, 60라운드 및 여러 seed의 논문 곡선도 아니다. CCS/VRF, 검증된 LWE-HPRF, bounded-mask privacy 및 개별 악성 client의 probe/mask/ASR 일치 증명은 여전히 별도 한계다.
