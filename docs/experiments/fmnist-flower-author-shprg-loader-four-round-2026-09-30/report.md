# 저자 DataLoader batch 구성의 공식 Flower 4라운드

원본 Client.local_train의 정상 학습 DataLoader/SubsetRandomSampler와
공격 시 중복 없는 poison 첫 batch·Python sample clean subset을
`--training-sampling author-loader`로 선택했다. 원본 전체 프로그램의
공유 RNG 순서가 아니라 client/round별 분리 RNG를 사용하는 포팅이다.
저자 SHPRG/MGF의 CPU float32 평문 경로와 양자화 무방어 경로를
동일한 설정에서 비교했으며, 이 실행은 원본 HPRF 보안 집계가 아니다.

## 결과

FMNIST/LeNet5 avg_300 checkpoint, N=100/q=20, 집계자 역할 4개,
worker 4개, seed 0, 4라운드, 공격 client 4명, 공격 라운드 1·4다.
정상 local epoch 2, batch 64, lr 0.001; 공격 120 step, poison batch 6,
boost 20이다. 기본 legacy sampling 결과와 섞지 않는다.

| 실행 | 최종 정확도 | 최종 공격 성공률 | 평균 공격 성공률 | 평균 테스트 오류 |
|---|---:|---:|---:|---:|
| 저자 SHPRG/MGF | 88.69% | 0.78125% | 0.78125% | 11.335% |
| 양자화 무방어 | 63.50% | 43.945313% | 84.375% | 45.265% |

평균은 checkpoint round 0을 제외한 라운드 1~4 전체에서 계산했다.
MGF 선택 수는 2·2·2·7명이며 선택된 공격자는 없었다. 최소 선택 수
override는 사용하지 않았다. 단일 seed의 짧은 기능 시험이며 일반적
방어 성능이나 논문 전체 곡선을 입증하지 않는다.

| 실행 | Flower run ID | 서버 케이스 시간 |
|---|---|---:|
| 저자 SHPRG/MGF | 11015433626334430147 | 18.258초 |
| 양자화 무방어 | 5008106948496920694 | 26.513초 |

위 시간에는 CLI 시작·staging·실행 후 평가가 포함되지 않는다.

## 검증 및 시행착오 보존

원본 Client.local_train을 AST로 분리해 실행한 정상 학습 차등 시험에서
동일한 로컬 generator를 제공했을 때 모든 업데이트 좌표가 정확히
일치했다. 공격 batch의 poison/clean 중복 방지와 결정성, Flower 평문
핸들러의 옵션 전달을 시험했다. Exporter의 잘못된 첫 실행 거부 시험을
포함한 관련 회귀 시험 44개가 통과했다.
CUDA 수치 및 shared-global RNG 동등성을 주장하지 않는다.

첫 실행 `official-author-shprg-loader-four-round-seed0`은 별도 평문
핸들러가 sampling 옵션을 전달하지 않아 실제로 legacy를 사용했다.
원시 파일은 삭제하지 않았지만 유효한 author-loader 결과로 사용하지
않는다. 현재 verifier로 이 첫 실행을 검증하면 실제 training metadata와
provenance의 policy 불일치로 실패한다. 수정 후 별도 v2 디렉터리에서
재실행한 결과만 이 보고서와 results.json에 담았다. Exporter도 같은
불일치를 거부한다.

정상·공격 모두 actual training metadata가 author-loader인 것을 확인한
공식 verifier가 모델·선택·입력 및 staged source/config hash를 검증했다.
원본 attacker가 round 간 유지하는 cached clean index 순서와 전체
Python/Torch RNG는 재현하지 않는다. 원본 함수 전체의 공격 업데이트
bitwise 동등성도 입증하지 않았다.

## 실행

실행 위치는 trustlessFL이며 새 출력 디렉터리를 사용한다.

```bash
PATH="$PWD/.cache/flower-deps/bin:$PATH" \
PYTHONPATH=.cache/flower-deps:.cache/torch-deps:. \
python3 -m experiments.run_fmnist_official --phase all \
  --output .cache/fmnist/official-author-shprg-loader-four-round-v2-seed0 \
  --modes mgf quantized --author-mgf --training-sampling author-loader \
  --population 100 --participants 20 --aggregators 4 --rounds 4 --workers 4 \
  --attack-clients 4 --attack-rounds 1 4 --cohort-sampling individuals --timeout 600
```

[해시 연결된 결과](results.json), [포팅 기준](../../aion-author-port-goal.md),
[기존 legacy sampling의 HPRF 결합 10라운드](../fmnist-flower-author-hprf-shprg-hotstuff-ten-round-2026-09-30/report.md)를 참고한다.
