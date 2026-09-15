# Crowdsensing 평문 학습 탐색 실험

실행일: 2026-09-13. AION/Flower 전송·보안집계를 실행하지 않은 학습 시뮬레이션이다.
현재 목적은 이 데이터에서 학습 품질과 poisoning 문제를 먼저 계측하는 것이다.

## 데이터 감사 결과

- 출처: [Science Data Bank 공식 V2 배포](https://www.scidb.cn/en/detail?dataSetId=0151eff3132541e2852a10ed65e0991f), DOI `10.57760/sciencedb.25380`, CC BY 4.0.
- `32d-feature data/device/0.csv`–`7.csv`만 사용. 총 87,742,914 bytes, 배포처 MD5 전부 검증; SHA-256은 `data-audit.json`에 기록.
- 실제 171,053행, 입력 31개 + label 1열. 논문의 342,106행/32개 입력 특징과 일치하지 않는다. 행 복제나 임의 특징 추가로 맞추지 않았다.
- 파일별 클라이언트 소유권을 유지했지만 파일 번호와 물리 장치 ID의 대응은 확인되지 않았다. `merged_df.csv`나 원시 로그는 합치지 않았다.
- 서로 다른 특징 벡터는 33,354개. 반복으로 추가된 행은 137,699개다. 같은 특징의 상충 label 480개 그룹/4,800행은 제거하지 않고 유지했다.
- 파일 간 동일 특징 그룹은 0개. 동일 특징 그룹 전체를 한 split에 넣어 train/validation/test 간 정확한 중복 누수를 막았다.
- 분할: {'train': 102509, 'validation': 34227, 'test': 34317}. 시간/세션 메타데이터가 없으므로 비시간적 그룹 분할이다. 근접 윈도 상관관계까지 제거했다는 뜻은 아니다.
- 공개 특징은 이미 선택·정규화되어 있다. 엄밀한 미래 데이터 일반화나 train-only 전처리 평가로 해석하지 않는다.
- 숫자 label은 [연결된 공식 encoder](https://github.com/Cyber-Tracer/iot-feature-engineering/blob/bf04ddfa010c3de5a003bd087497b9f9184e58e9/py_dataset/sys_func.py#L25)에 따라 0 Normal, 1 Ransomware, 2 TheTick, 3 Bashlite, 4 HttpBackdoor, 5 Beurk, 6 Backdoor, 7 Bdvl, 8 XMRig로 해석한다. 배포 CSV 자체에는 의미 mapping이 내장되어 있지 않다.

## 고정한 비교 조건

- 모델: 31→128 ReLU→9 MLP, 5,257 parameters, NumPy float64 CPU.
- 8 clients 전원 참여, 동일 가중 평균. 데이터 수 가중 FedAvg와는 다르다.
- 10 rounds × local 3 epochs, batch 128, SGD, momentum/weight decay 없음.
- seeds `[42, 43, 44]`. 동일 seed에서 초기 모델·batch 순서·공격자는 방법 간 동일.
- FedProx: 매 round 시작 모델에 대한 `μ/2 * ||w-w_global||²`, μ `[0.0, 0.01, 0.1]`. μ=0은 일반 평균의 로컬 학습이다.
- 각 seed의 공격자 2명은 난수로 사전 선정. train label만 `(y+1)%9`로 한 번 바꾼 뒤 모든 round에서 사용. validation/test는 변조하지 않는다.
- learning rate는 seed42/clean/μ=0의 마지막 round validation macro-F1로 선택했다. test 값으로 학습률이나 μ를 선택하지 않았다.
- μ 값들은 사전 지정 민감도 탐색이며, 최적 FedProx 또는 새로운 방어 알고리즘의 결과가 아니다.

| 후보 learning rate | validation macro-F1 |
| --- | --- |
| 0.01 | 0.536743 |
| 0.1 | 0.588408 |

선택 learning rate: `0.1`.

## 마지막 round 결과

모든 값은 %, 평균 ± seed 간 표본 표준편차다. macro-F1·최저 장치 F1은 높을수록, 오탐·미탐률은 낮을수록 좋다.
미탐률은 실제 악성의 Normal 예측 비율이며 악성 계열끼리의 오분류는 포함하지 않는다.

| 조건 | 방법 | macro-F1 ↑ | 정상 오탐률 ↓ | 악성 미탐률 ↓ | 최저 장치 F1 ↑ |
| --- | --- | --- | --- | --- | --- |
| 정상 | 일반 평균 | 58.36 ± 0.79 | 85.33 ± 0.50 | 1.73 ± 0.01 | 43.73 ± 0.44 |
| 정상 | FedProx μ=0.01 | 58.33 ± 0.74 | 85.41 ± 0.47 | 1.71 ± 0.02 | 43.78 ± 0.56 |
| 정상 | FedProx μ=0.1 | 57.13 ± 0.92 | 82.96 ± 1.45 | 1.86 ± 0.11 | 44.15 ± 1.82 |
| 25% label-flip | 일반 평균 | 53.93 ± 2.74 | 57.60 ± 5.10 | 4.09 ± 0.57 | 33.34 ± 9.49 |
| 25% label-flip | FedProx μ=0.01 | 54.02 ± 2.98 | 57.38 ± 5.34 | 4.17 ± 0.59 | 33.55 ± 10.24 |
| 25% label-flip | FedProx μ=0.1 | 53.15 ± 2.79 | 55.19 ± 6.15 | 5.27 ± 0.83 | 34.99 ± 10.22 |

- μ=0: clean 대비 공격 시 macro-F1 평균 4.43 pp 감소.
- μ=0.01: clean 대비 공격 시 macro-F1 평균 4.32 pp 감소.
- μ=0.1: clean 대비 공격 시 macro-F1 평균 3.98 pp 감소.

## 이번 실험에서 얻은 판단

1. **시험한 FedProx 설정에서 뚜렷한 개선 근거는 없다.** μ=0.01의 공격 조건 F1 증가는 일반 평균 대비 약 0.09 pp이고, seed별 방향도 일관되지 않으며 악성 미탐률은 더 높다. μ=0.1은 정상/공격 모두 pooled macro-F1이 낮다. 다만 일반 평균 기준으로 고른 learning rate를 공유했으므로 FedProx 전체의 가능성을 부정하는 실험은 아니다.
2. **현재 기본 모델의 정상 오탐이 먼저 해결해야 할 문제다.** 일반 평균의 정상 조건에서 정상 샘플 약 85%를 악성으로 분류한다. 악성 미탐률 1.73%만 보고 좋은 탐지기로 평가하면 안 된다. 현재 수치만으로는 학습 길이·모델/특징 문제인지, 장치별 이질성과 글로벌 평균의 문제인지 구분되지 않는다.
3. **학습 오염의 영향은 관측했다.** 일반 평균은 macro-F1 4.43 pp 감소, 악성 미탐률 1.73%→4.09%다. 공격 후 정상 오탐률이 낮아진 것은 poisoning 방어 성공이 아니며, 예측 변화의 다른 측면이다.
4. 다음 대조군은 동일 split의 local-only 및 centralized pooled 학습이다. 이것으로 공동학습의 손실과 데이터/모델 자체의 한계를 먼저 구분한다. 이번 턴에는 해당 대조군이나 새 보안 방어 기법을 실행하지 않았다.

## 해석 제한

- 위 값은 실제 파일에 대한 관측치이며 논문 실험 재현 판정이 아니다.
- 정상과 공격의 비교는 label 오염 효과를, μ 간 비교는 proximal local training 효과를 보여준다. FedProx를 Byzantine 방어로 간주하지 않는다.
- 일반 평균보다 특정 μ가 좋아도 사전 고정된 전체 조건과 seed별 결과를 함께 해석해야 한다. 세 seed만으로 유의성을 주장하지 않는다.
- 그룹 분할을 했지만 반복 행의 학습 가중치는 유지했다. 중복 제거/상충 label 처리와 원본 전처리 재구축에 대한 민감도는 후속 작업이다.
- 평문 환경은 서버가 개별 update를 볼 수 있다. 이 실험은 프라이버시, 악성 서버 내성, 보안집계 비용의 증거가 아니다.
- CPU 단일 프로세스의 순차 클라이언트 실행 시간은 AION 병렬 실행의 overhead 비교에 사용하지 않는다.

## Seed별 원시 지표

F1·미탐률은 0–1 단위. 공격자 `[]`는 clean이다.

| seed | μ | 공격 클라이언트 | macro-F1 | 악성 미탐률 |
| --- | --- | --- | --- | --- |
| 42 | 0 | [] | 0.580227 | 0.017206 |
| 42 | 0.01 | [] | 0.581043 | 0.017206 |
| 42 | 0.1 | [] | 0.566797 | 0.019828 |
| 42 | 0 | [1, 2] | 0.533324 | 0.034413 |
| 42 | 0.01 | [1, 2] | 0.532611 | 0.035396 |
| 42 | 0.1 | [1, 2] | 0.523853 | 0.043426 |
| 43 | 0 | [] | 0.577930 | 0.017370 |
| 43 | 0.01 | [] | 0.577299 | 0.017206 |
| 43 | 0.1 | [] | 0.565261 | 0.018353 |
| 43 | 0 | [2, 6] | 0.515307 | 0.043098 |
| 43 | 0.01 | [2, 6] | 0.514831 | 0.042606 |
| 43 | 0.1 | [2, 6] | 0.508167 | 0.055224 |
| 44 | 0 | [] | 0.592597 | 0.017206 |
| 44 | 0.01 | [] | 0.591655 | 0.016879 |
| 44 | 0.1 | [] | 0.581894 | 0.017698 |
| 44 | 0 | [2, 7] | 0.569203 | 0.045064 |
| 44 | 0.01 | [2, 7] | 0.573076 | 0.047031 |
| 44 | 0.1 | [2, 7] | 0.562472 | 0.059321 |

## 재실행

```bash
.venv/bin/python -m experiments.download_endpoint
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
  .venv/bin/python -m experiments.run_endpoint \
  --output .cache/endpoint/runs/plaintext-new --seeds 42 43 44 --rounds 10
.venv/bin/python -m experiments.export_endpoint \
  --run .cache/endpoint/runs/plaintext-new \
  --output docs/experiments/endpoint-plaintext-new
```

출력은 새 경로여야 한다. `config.json`에 구현 소스 hash·환경, `rounds.json`에 라운드별/장치별 지표·confusion matrix를 기록했다.
원본 CSV, split 인덱스, 모델 checkpoint는 `.cache/endpoint/`에 유지하며 이 공개 요약에는 복제하지 않았다.
