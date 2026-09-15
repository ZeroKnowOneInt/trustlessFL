# Fashion-MNIST 공식 AION artifact: checkpoint·공격/MGF pilot

실행일: 2026-09-13. **공식 checkpoint 평가와 2라운드 공격 실험을 완료했다.
논문의 60라운드 결과 또는 분산 secure aggregation을 재현했다는 판정은 아니다.**

## 실제 관측값

공식 `avg_300.pth` LeNet5(61,706 parameters)에서 시작했다. 정상 정확도는 Fashion-MNIST
테스트 10,000장 전체에서 측정한다. ASR은 **원 artifact의 공격 학습에도 사용된 512개 항목**에
trigger를 넣고 target label 2를 예측한 비율이다. 독립 held-out ASR이 아니다.

| 집계 | 라운드 | 정상 정확도 | 공격 성공률(ASR) | 선택한 정상/악성 client |
|---|---:|---:|---:|---:|
| 공통 checkpoint | 300 | 88.56% | 0.5859375% | 해당 없음 |
| 평균(`avg`) | 301 | 10.11% | 100% | 80 / 20 |
| 평균(`avg`) | 302 | 38.25% | 0% | 80 / 20 |
| AION artifact 필터 | 301 | 88.56% | 0.5859375% | 10 / 0 |
| AION artifact 필터 | 302 | 88.57% | 0.5859375% | 10 / 0 |

- 첫 라운드는 초기 모델, partition, 참여자, **실제 전체 local-update tensor hash까지 동일**하다.
  같은 공격 업데이트에 대한 집계 차이를 확인한 대조다.
- 두 번째 라운드는 원 코드의 AION mask 생성이 Python RNG를 추가 소비해 참여자가 달라졌다.
  두 라운드 전체가 같은 참여자·미니배치로 짝지어진 대조라는 뜻은 아니다.
- AION은 두 라운드 모두 공격 update를 제외하고 정확도를 유지했다. 그러나 정상 80명 중
  10명만 채택했다. 이는 bootstrap의 최소 10% 선택 동작이며, 모든 정상 client를 식별했다는 뜻이 아니다.
- 평균 집계의 두 번째 ASR 0%만으로 방어 성공이라 판단할 수 없다. 정상 정확도가 38.25%로
  낮고 앞선 라운드에서 ASR 100%였다. AION의 ASR도 엄밀히 **0%가 아니라 초기값과 같은 3/512**다.

원 코드의 상이한 두 요약을 모두 보존했다.

| 집계 | 평균 ASR (`trainer.py`) | 평균 TER | 최대 ASR (`check_results.py`) | 최대 ASR 라운드 중 최소 TER |
|---|---:|---:|---:|---:|
| 평균 | 50% | 75.82% | 100% | 89.89% |
| AION | 0.5859375% | 11.435% | 0.5859375% | 11.43% |

## 설정·데이터·실행 경로

- 출처: [공식 AION artifact](https://zenodo.org/records/15870338),
  [원본 감사](../../reproduction/source-audit.md), [동결 설정](../../../configs/reproduction/fmnist-artifact.json).
- [공식 Fashion-MNIST](https://github.com/zalandoresearch/fashion-mnist)에서 학습 60,000장·테스트
  10,000장을 확보했다. 공개 MD5 네 개와 IDX header/길이/라벨을 검증하고
  [압축·원본 SHA-256 manifest](../../reproduction/fashion-mnist-data.json)를 기록했다.
- N=500, q=100, 악성 client 20명, Dirichlet alpha=0.5, batch 64, benign local epochs=2,
  benign lr=0.001, attack steps=120, poison lr=0.0005, 실제 model-replacement boost=20,
  MGF weight=0.1, min_threshold=0.1. 원 seed torch=1 / Python·NumPy=0을 유지했다.
- 원 partition 알고리즘의 반올림 때문에 **59,941장이 client에 중복 없이 배정되고 59장은 미배정**됐다.
  이를 수정하지 않았다. 악성 client의 정상 이미지 sampling은 원 코드처럼 target label을 제외한
  전체 학습셋을 사용하며, 자신의 local shard에 제한되지 않는다.
- 공격 학습/평가 pool은 512개 항목, **고유 이미지는 502개**다. 양쪽이 같은 인덱스를 사용한다.
- `poison_prob=0.5`를 유지한 자연 난수 일정이 `[301, 302]`였다. 강제로 공격 라운드를 지정하지 않았다.
  따라서 이번 pilot에는 공격 없는 라운드가 없으며, bootstrap 이후 evolving bound도 아직 실행하지 않았다.
- Python 3.12.12 / torch 2.4.0+cpu / torchvision 0.19.0+cpu, torch 1 thread.
  [의존성 freeze](../../../configs/reproduction/artifact-pilot-cpu.lock.txt)는 최소 실행 환경이며
  원 Python 3.11/CUDA 환경 전체의 재현이 아니다. 기존 Flower 환경과 코드는 변경하지 않았다.

검토용 원본을 보존하고 별도 실행 사본을 생성했다. 변경은 device portability 2곳,
제한된 checkpoint loader, SHPRG 초기 tuple 안전 로딩, read-only filtering 관측이다.
모델을 새로 생성해 checkpoint를 읽을 때 추가 소모될 torch RNG는 복구했다.
학습·공격·집계 함수는 원 코드이며, driver는 원 `Trainer` 초기화와
`select → train/aggregate → clean evaluation → poison evaluation` 순서를 사용한다.
20라운드마다 pickle을 저장하는 대신 매 라운드 JSONL과 최종 NPZ를 저장한다.

원 artifact의 MGF는 중앙에서 평문 update를 보고 마지막 classifier weight 840개의
masked norm으로 client를 고른 뒤 **선택된 평문 전체 update를 평균**한다.
이 실행에는 Flower 서버, 독립 aggregator, 비밀분산·복구·합의 프로토콜이 없다.

## 증거와 재실행

- 최초 실행: [평균 집계 결과](./avg-result.json), [AION 결과](./aion-result.json),
  [첫 라운드 입력 일치 검증](./comparison.json).
- 라운드별 원시값: [avg JSONL](./avg-rounds.jsonl), [AION JSONL](./aion-rounds.jsonl).
- 독립 프로세스·새 작업 디렉터리에서 같은 seed로 1회씩 재실행했다.
  [반복 검증](./repeat/comparison.json)에서 **시간을 제외한 모든 라운드 관측값, 업데이트·모델 hash,
  선택 집합, MGF norm/bound, partition 및 SHPRG matrix가 동일**했다.
  이는 동일 seed의 반복 가능성 확인이지 여러 seed의 통계적 재현 검증은 아니다.
- 재실행의 [avg 결과](./repeat/avg-result.json), [AION 결과](./repeat/aion-result.json),
  [변경 patch](./repeat/aion-runtime.patch), [실행 adapter 사본](./repeat/aion-adapter-used.py)을 보존했다.
  최초 run의 diff에서 파일 끝 개행 표시가 누락되어 재실행 시 diff 출력만 보완했다.
  CPU 메모리 측정과 adapter 사본 저장도 추가했으며, 계산·선택 결과는 위 반복 검증으로 동일함을 확인했다.
- [실행 runner](../../../experiments/run_aion_artifact.py),
  [비교·반복 검증 exporter](../../../experiments/export_artifact_pilot.py),
  [명령·환경 설명](../../../experiments/README.md#공식-fashion-mnist-artifact-cpu-pilot).
- 상세 stdout, 전체 partition 인덱스, fresh SHPRG matrix, 최종 weights는
  `.cache/aion-artifact/runs/fmnist-pilot-{avg,aion}-001`에 보존했다.
  반복 실행은 같은 이름의 `-002` 디렉터리다.
  문서에는 raw 지표와 source/partition/model hash를 내보냈다.

첫 실행 wall time은 avg 약 142초, AION 약 139초였다. 두 작업을 병행했고 중간에 회귀 테스트도
실행했으므로 **성능 비교에 사용하지 않는다**. 논문의 GPU 시간·통신량과 비교할 수 없다.
재실행에서 프로세스별 peak RSS는 avg 611,576 KiB(약 597 MiB), AION 618,780 KiB(약 604 MiB)였다.
CUDA/GPU 메모리나 분산 노드별 메모리를 측정한 값은 아니다.

체크섬·IDX 검증, 제한된 loader, 패치 guard/EOF 처리, 평균·최대 지표 계산, 반복 검증과
기존 프로토콜 회귀 테스트를 합쳐 **54 passed**를 확인했다. 기존 Typer/Click의 deprecation
warning 2개가 있다. 실행 patch의 원본 대상 dry-run과 `git diff --check`도 통과했다.

## 다음 단계와 판정

P1의 데이터·checkpoint·공격/MGF bootstrap 실행 점검은 통과했다. 다음은 **새 output에서
각각 `--rounds 60`으로 checkpoint 300부터 다시 시작하는 공식 artifact 기준선**이다.
공격 없는 라운드와 round 304 이후 evolving bound, 평균/최대 ASR·TER를 함께 확인해야 한다.
2라운드 NPZ만으로 RNG와 필터 상태까지 이어 붙이지 않는다.

그 이후 paper/artifact 설정 차이, 복수 seed, 별도의 held-out 공격 평가, Flower 이식과
분산 MGF 검증을 분리해 수행한다. 현재 결과는 제한된 **공식 중앙 실험 코드의 pilot 성공**이며,
논문의 ASR 0%, Table 3 시간/통신량, 서버·클라이언트가 악의적일 때의 보안 보장을 확인한 결과는 아니다.
