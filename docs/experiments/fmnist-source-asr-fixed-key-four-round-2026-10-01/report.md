# 원본 ASR 고정 키 학습 어댑터: FMNIST 4라운드

2026-10-01. 원본 ASR 키 공유·HPRF·MMF·VSS와 정상 경로 BFT를 Flower
ClientApp/ServerApp에 연결한 경로에서 실제 학습을 실행했다. 양자화 집계는
재현되었지만, 공격 방어는 실패했다. 논문 실험 재현 완료를 의미하지 않는다.

## 구성

- 원본은 `/home/jisung/trustlessfl/Aion`; 실행별 source snapshot과 SHA-256을 보관한다.
- 저자 100-way 분할의 첫 10개 shard를 고정 client 0–9에 배정했다.
  100명 중 매 라운드 10명 동적 참여 실험과 다르다.
- committee client 4명은 원본 ChaCha20 함수로 선정한다. 별도 aggregator 1명.
- Flower Message 직렬화를 사용하는 독립 프로세스 ProcessGrid다.
  공식 SuperLink/Ray나 원격 네트워크 성능 측정은 아니다.
- FMNIST LeNet 61,706좌표, reference checkpoint부터 시작, 로컬 2 epoch,
  batch 64, learning rate 0.001, author-loader, CPU thread 1.
- 클라이언트가 업데이트를 정수 양자화(소수 6자리)한 뒤 원본 HPRF로 마스킹한다.
  MMF norm 입력만 float64이며 집계는 정수, 복원 합계를 디코딩한 뒤 평균한다.
- 원본 ASR `MMF`의 전체 벡터 norm·최소 30%·최대 80%·inclusive threshold를
  유지한다. 별도 학습 소스 `roles/aggregation_rules.py::aion`의 classifier
  MGF(최소 10%, bounded SHPRG 등)와 같은 필터가 아니다.
- 키 share는 첫 라운드 10×4=40개뿐이고, 좌표별 mask share는 0개다.
  개인 업데이트를 aggregator에 평문 전송하지 않는다. 보안성 증명은 아니다.

## 결과

| 라운드 | 정상 정확도 | 공격 정확도 | 공격 ASR |
| --- | ---: | ---: | ---: |
| 1 | 88.32% | 10.00% | 100.00% |
| 2 | 88.31% | 56.77% | 98.046875% |
| 3 | 88.31% | 68.98% | 97.65625% |
| 4 | 88.46% | 14.84% | 0.1953125% |

공격 client는 0·1, 공격 라운드는 1·4, 120 step, boost 20, poison batch 6이다.
공격 실행의 선택 집합은 1–3라운드 `[1,4,9,5]`, 4라운드 `[1,4,9]`였다.
공격자 1이 두 공격 라운드 모두 선택되었다. 최종 ASR만 낮아졌지만 정상 정확도가
14.84%로 붕괴했으므로 방어 성공으로 해석하면 안 된다.

정상 선택 집합은 `[2,8,4,9]`, `[2,8,9,7]`, `[2,8,7,9]`, `[2,7,8]`이었다.
두 실행의 committee seed와 개인 mask seed는 따로 생성되었으므로 완전히 같은
난수 조건의 방어 대조군도 아니다.

두 실행 모두 선택 client를 15회 다시 학습하여 모든 라운드의 전체 양자화 평균과
모델을 비교했다. 최대 절대 오차는 0(허용 오차 1e-12)이었다. 초기 참여자,
라운드별 온라인 참여자, 최종 모델의 정상 경로 BFT commit 서명도 검증했다.
이는 집계 수치와 정상 합의 경로의 검증이며 공격 필터의 성공이나 전체 HotStuff
장애 복구 보장은 아니다.

공격 실행의 ProcessGrid 시작부터 서버 완료까지 24.8195초였다. 평가·오프라인
재학습 검증 시간은 제외한다. 정상 실행은 시간 기록 추가 전이라 소요 시간을
보고하지 않는다. 정상 입력 hash는 재검증 시 기록되었고, 공격 입력 hash는 실행
전 manifest에 고정되었다. 평가 test/poison-test 데이터 hash는 이 manifest에
고정하지 않았으므로 완전한 실험 provenance 검증으로 주장하지 않는다.

## 원본 결과와 실행

저장소 기준 실행 디렉터리:

- `.cache/author-asr-fmnist-learning-four-round-20261001`
- `.cache/author-asr-fmnist-attack-four-round-20261001`

각 디렉터리의 `manifest.json`, `results.json`, `verification.json`을 보존한다.
공개 결과에는 모델과 commit 증명이 있지만 개별 client delta/개인 키는 내보내지 않는다.

```bash
PYTHONPATH=.cache/author-asr-deps:.cache/flower-deps:.cache/torch-deps:. \
  python3 -m experiments.run_author_asr_flower \
  --output .cache/NEW-source-asr-attack --workload fmnist \
  --fmnist-inputs .cache/fmnist/official-original-single-view-mgf-attack-four-round-20261001/inputs \
  --rounds 4 --attack-clients 2 --attack-rounds 1 4

PYTHONPATH=.cache/author-asr-deps:.cache/flower-deps:.cache/torch-deps:. \
  python3 -m experiments.verify_source_learning \
  --run .cache/NEW-source-asr-attack \
  --inputs .cache/fmnist/official-original-single-view-mgf-attack-four-round-20261001/inputs
```

관련 회귀 시험은 38개 통과(68.50초, deprecation warning 2개)다. 전체 저장소
시험을 전부 실행했다는 의미는 아니다. 다음 과제는 ASR MMF와 별도 학습 MGF의
차이를 해소하는 것이다. 중앙에서 평문 classifier를 읽는 기존 저자 학습 코드를
클라이언트 마스킹 포팅과 같은 것으로 취급하거나, 실패를 감추기 위해 새 필터를
원본 MGF라고 표시하지 않는다.
