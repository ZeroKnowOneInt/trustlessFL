# 저자 학습 batch·HPRF·SHPRG/MGF·HotStuff의 공식 Flower 4라운드

`author-loader` 학습 batch 구성을 원본 ASR HPRF, 저자 학습 SHPRG/MGF와
Flower SuperLink/Ray의 HotStuff 집계 경로에 연결해 검증했다.
classifier 840개 좌표는 coordinator에 평문 공개하므로 비공개 MGF가
아니다. 원본 전체 프로그램의 공유 RNG 순서를 재현한 결과도 아니다.

## 조건과 결과

FMNIST/LeNet5 avg_300 checkpoint, N=100/q=20, 집계자 4개/f=1,
CPU worker 4개, seed 0, 4라운드다. 공격 client 4명과 공격 라운드 1·4를
명시했다. 각 경로에 같은 데이터 분할·참여 일정·학습 및 공격 설정을
적용했다. 학습 epoch 2, batch 64, lr 0.001; 공격 120 step,
poison batch 6, boost 20이다.

| 실행 | 최종 정확도 | 최종 공격 성공률 | 평균 공격 성공률 | 평균 테스트 오류 |
|---|---:|---:|---:|---:|
| 원본 HPRF + 저자 MGF + HotStuff | 88.69% | 0.78125% | 0.78125% | 11.335% |
| 평문 저자 MGF | 88.69% | 0.78125% | 0.78125% | 11.335% |
| 양자화 무방어 | 63.50% | 43.945313% | 84.375% | 45.265% |

평균은 checkpoint round 0을 제외한 학습 라운드 1~4 전체에서 계산한다.
최대 공격 성공률은 MGF 경로 0.78125%, 무방어 100%다.
두 MGF 경로는 **모든 라운드에서 같은 client**를 선택했으며 선택 수는
2·2·2·7명이다. 선택된 공격자는 없었다. 최소 선택 수 override도 없다.
모델의 전 라운드·전 좌표 최대 차이는 `1.3784517033358268e-5`이므로
지표가 같아도 모델의 비트 단위 일치를 주장하지 않는다.

| 실행 | Flower run ID | 서버 케이스 측정 시간 |
|---|---|---:|
| 원본 HPRF + 저자 MGF + HotStuff | 9449689145539937009 | 377.342초 |
| 평문 저자 MGF | 15812286347105463946 | 19.982초 |
| 양자화 무방어 | 6503976935421539107 | 28.502초 |

CLI 시작·staging·후속 평가는 위 시간 밖에 있다. 회귀 시험도 병행했으며
순수 암호 연산 benchmark가 아니다.

## 검증과 남은 차이

완료 후 최신 verifier로 다시 검증했다. 원본 HPRF 파일 hash와 실제
public setup, 입력·staged source·config·catalog hash, roster/model
HotStuff 인증서, MGF float32 계산과 모델 변화 norm 이력, 두 필터 경로의
매 라운드 선택 일치를 확인했다.

보안 집계 후보 20명 × 4라운드의 **80회 training metadata** 모두
실제 author-loader 사용·round·partition·참여 일정과 일치했다.
MGF 탈락 후보도 포함한다. Exporter는 이 감사가 빠지거나 candidate
training call 수가 다르면 요약을 거부한다. 키/share/업데이트는 공개하지
않는다. 이는 로컬 시뮬레이션 사후 감사이며 악성 client의 학습 증명이 아니다.

원본 Client.local_train 정상 학습 함수와 로컬 generator를 맞춘 계산
차등 시험, 중복 없는 공격 batch, 옵션 전달 및 상태 감사 등 관련 시험
76개가 통과했다. 원본의 persistent attacker clean index 순서와 전체
Python/Torch 공유 RNG, CUDA bitwise 결과는 동일하게 재현하지 않았다.
전체 회귀 시험도 345개 통과·2개 skip으로 완료했다(394.33초).
그 뒤 보강한 exporter 감사 요구 gate는 관련 선택 시험 38개로 확인했다.
skip은 명시적으로 opt-in하는 GPU 시험이며 CPU 테스트로 대체해 통과한
것으로 표시하지 않는다.

전체 delta의 고정소수점 인코딩, 매 라운드 새 ASR 키/VSS 공유,
classifier 평문 공개, 기존 Flower 연구 포트의 VSS·암호화·합의는 유지한다.
원본 one-time sharing 비용·운영 보안·모든 부분 동기 진행성을 주장하지
않는다. 축소된 4라운드로 논문 규모의 60라운드 성능을 입증하지 않는다.

## 실행

실행 위치는 trustlessFL이며 새 출력 디렉터리를 사용한다.

```bash
PATH="$PWD/.cache/flower-deps/bin:$PATH" \
PYTHONPATH=.cache/flower-deps:.cache/torch-deps:. \
python3 -m experiments.run_fmnist_official --phase all \
  --output .cache/fmnist/official-author-hprf-shprg-loader-hotstuff-four-round-seed0 \
  --modes aion_mgf_oracle mgf quantized --author-mgf \
  --training-sampling author-loader \
  --original-hprf-dir ../Aion/agent/Aion/HPRF --hotstuff \
  --population 100 --participants 20 --aggregators 4 --rounds 4 --workers 4 \
  --attack-clients 4 --attack-rounds 1 4 --cohort-sampling individuals --timeout 600
```

[해시 연결된 결과](results.json), [포팅 기준](../../aion-author-port-goal.md),
[legacy sampling의 결합 10라운드](../fmnist-flower-author-hprf-shprg-hotstuff-ten-round-2026-09-30/report.md),
[author-loader 평문 대조 4라운드](../fmnist-flower-author-shprg-loader-four-round-2026-09-30/report.md)를 참고한다.
