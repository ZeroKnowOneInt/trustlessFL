# AION 재현: 공식 artifact 1차 감사 및 실행 준비 결과

검토일: 2026-09-12. **전체 archive 확보·무결성 검사와 FMNIST 설정 추적을 완료했고,
공식 LeNet5 checkpoint의 CPU 실행 준비 검사를 통과했다. 아직 논문 학습·공격 결과를 재현한 것은 아니다.**

2026-09-13 업데이트: 실제 Fashion-MNIST 데이터와 공식 checkpoint에서 avg/AION 각각
2라운드 공격 pilot을 완료했다. 최신 수치·한계는 [pilot 보고서](../experiments/fmnist-artifact-pilot-2026-09-13/report.md)를 따른다.
아래 §5까지의 준비 검사 서술은 2026-09-12 시점의 기록이다.

## 1. 확보한 원본

- 출처: [Zenodo record 15870338](https://zenodo.org/records/15870338), DOI `10.5281/zenodo.15870338`
- publication date: 2025-07-11, record revision 4
- 파일: `Aion.zip`, **403,162,679 bytes**, 게시 MD5 `dadf60eeb3713398ef0d189ea9cec920`와 일치
- 계산 SHA-256: `dff11dfbdf8c40121c01220b3292007cfea5b8401ecd413af0b7701ebbc742f3`
- ZIP CRC: 전체 통과. 파일 **226개**, 검토용 UTF-8 텍스트 **145개** 추출
- Zenodo 메타데이터 license: CC-BY-4.0. archive 안에서 별도 LICENSE 파일은 찾지 못했다.
  포함된 타 프로젝트 코드의 재배포 조건은 이 메타데이터만으로 일괄 확정하지 않는다.
- 원본 archive와 텍스트 추출본은 git 제외 `.cache/aion-artifact/`에 보존했다.

[검사 inventory](./artifact-inventory.json)에 전체 경로·크기·CRC 및 추출 텍스트의 SHA-256이 있다.
이 inventory의 `execution: none`은 **추출 시점**의 상태다. 이후 아래 §5에서 검토 완료된 `cnn.py`만
로드했다. 이후 2026-09-13에는 별도 사본의 trainer 초기화·공격/집계를 실행했으나 protocol은 실행하지 않았다.

검사 도구는 [audit_artifact.py](../../experiments/audit_artifact.py)다. 기존 range-download 조각 대신
전체 archive를 확인했으며, 경로 traversal·symlink·중복 경로·과대 파일은 거부한다.
원본 코드·checkpoint를 변경하지 않았고 기존 Flower 구현·MNIST 결과도 보존했다.

## 2. 실험 경로가 실제로 분리되어 있음

공식 README는 세 경로를 제공한다.

| 경로 | entrypoint / 대상 | 확인 결과 |
|---|---|---|
| Main Protocol | `abides.py -c aion -n ... -A ... -i ...` | discrete-event simulation. client는 학습 대신 ones vector에 mask를 더함 |
| Input Validation | `input_validation/FL_Backdoor_CV/roles/attack{1,2,3}_fmnist.py` | pretrained model 기반 중앙 model-replacement/필터 실험 |
| GIA | `GradAttack/examples/attack_cifar10_gradinversion.py` | 별도 코드·의존성·checkpoint. 이번에는 미실행 |

근거: `config/aion.py:42,173–186`, `agent/Aion/SA_ClientAgent.py:318–322`,
`input_validation/README.md`, 각 attack wrapper. 경로는 모두 archive의 `Aion/` 기준이다.
모든 파일의 hash는 inventory에서 확인할 수 있다.

따라서 Main Protocol 결과와 Input Validation 결과를 합쳐 **FMNIST end-to-end secure aggregation을
이미 실행했다**고 주장할 수 없다. Table 3의 q=256/n=8/44-round 학습·통신을 연결한 재현 entrypoint와
그 측정 로그는 이번 archive 검토에서 확인하지 못했다. archive에는 `/results/` 아래 raw result 파일도 없다.

추가 main-protocol 차이:

- `config/aion.py`의 CLI `--vector_len` 기본값은 **1,000**이다. 논문 §7.1의 10K와 맞추려면
  `-V 10000`이 필요하며, README의 예시 명령에는 해당 옵션이 없다.
- `-A`는 client ID 중 committee를 고르는 데 사용된다. `config/aion.py`는 client agents와 service agent
  하나를 생성한다. 이것은 우리의 별도 학습 client/독립 aggregator Flower 배포 구조와 같지 않다.
- Figure 14 설명의 논문 q=256과 README 명령의 `-n 512`가 다르다.
- `bandwidth`의 help는 Mbps, 인접 comment는 Gbps라고 되어 있어 실제 지연 계산의 단위 추적이 필요하다.
- main protocol에는 model/accuracy 평가가 없는 synthetic workload가 있으므로 그 명령으로 Table 3 학습 정확도를
  확인할 수 없다. 이후 성능 재실행에서는 wall time, 모사 시간, 단계별 연산 시간의 경계를 구분해야 한다.

## 3. FMNIST 공격 설정: 확인된 값

실행에 사용할 관찰 설정은 [fmnist-artifact.json](../../configs/reproduction/fmnist-artifact.json)에 기록했다.
이는 **artifact의 설정**이며 논문 전체 설정과 동일하다는 승인이 아니다.

| 항목 | 확인된 artifact 동작 | 근거 |
|---|---|---|
| 모델 | LeNet5, 61,706 parameters | `models/cnn.py`, CPU strict state-dict load로 확인 |
| 초기 상태 | `fmnist/avg_300.pth` 로드, round=300으로 해석 | `roles/server.py:40–42,68` |
| 공격 실행 | rounds 301–360, 60 rounds | `roles/trainer.py:175–179`, `--retrain_rounds=60` |
| 모집단 / 참여자 | N=500, q=100 | `attack1_fmnist.py:19–20` |
| 분할 | Dirichlet alpha=0.5 | `image_helper.py:211–220`, `fmnist_params.yaml` |
| 정규화 | ToTensor 후 mean=0.1307, std=0.3081 | `image_helper.py:101–114` |
| batch / local epoch | batch=64, 정직 local epoch=2 | `configs.py`, `client.py:264`, YAML |
| 정직 learning rate | 공격 평가 중 0.001 | `client.py`의 `args.is_poison` branch |
| 공격 유형 | model replacement + pixel-pattern backdoor, target class=2 | YAML, `get_poison_batch`, `add_pixel_pattern` |
| 악성 local 학습 | 120회 local step, batch의 poison sample=6, lr=0.0005 | YAML 및 `client.py` |
| 공격 라운드 | 확률 0.5. 공격 round에는 악성 client 전원 포함, 나머지 정직 client를 sample | `server.py:103–119,140–177` |
| 실제 증폭 | `mal_boost / adversaries / global_lr / s_norm` | `server.py:228,238` |
| seed | torch/CUDA=1, Python random/NumPy=0 | `trainer.py:33–38`, `helper.py`, `image_helper.py` |

이 공개 **입력 검증용 FMNIST 실험 코드**의 `server.py:183–249`는 각 client의
학습 모델을 서버 메모리의 `trained_models`에 쌓고 평문 `model_updates`를 만든 뒤
`aggregation_rules.aion()`에 전달한다. 그 함수의 `aggregation_rules.py:105–151`은
평문 마지막 분류기 층에서 서버가 SHPRG seed와 mask를 생성해 masked norm으로
client를 선택하고, 선택된 **평문 전체 update**를 평균한다. 즉 공개 artifact의
이 ML 실험은 비공개 분산 AION-ASR 네트워크 프로토콜을 실행한 증거가 아니다.
Flower의 `aion_mgf_oracle`은 이 중앙 선택 규칙을 재현한 뒤 선택된 전체 update를
별도의 AION 마스킹 집계 경로로 보낸다. 이 때문에 artifact의 선택 결과와 비교할
수 있지만, coordinator가 개별 classifier 840좌표를 보는 실험용 경계가 남는다.
이를 논문 수준의 보안 MGF 완료로 분류하지 않는다.

`class_imbalance=0`은 여기서 IID를 뜻하지 않는다. 이 branch는 Dirichlet 분할을 호출한다.
같이 전달되는 `classes_per_client=2`와 `balance=0.99`는 해당 분할 branch에서 사용되지 않는다.
FMNIST의 class 방문 순서는 번호순이 아니라 `get_img_classes()`의 첫 등장 순서
`[9,0,3,2,7,5,1,6,4,8]`이다. 또한 `Trainer.__init__`가 분할 전에
정상 참여자 150명을 `random.sample`로 뽑아 Python 난수 상태를 소비한다.
class별 반올림으로 N=500, seed 0 포트에서는 59,941장만 중복 없이 배정되고
59장은 남는다. 이전 Flower 보고서는 번호순·사전 sample 생략 transcript였으며,
현재 CLI의 `--partition-rng legacy`로 그 입력을 재현한다. 새 기본값 `artifact`는
원본의 class 순서와 난수 선행 소비를 따른다.
원본은 이어서 같은 Python 난수기로 공격 이미지 풀을 `random.sample`한다.
Flower 포트의 이전 결과는 이 단계에서 seed 0으로 다시 시작했으므로 이미지
풀이 다르다. 새 기본 `--poison-rng artifact`는 분할 뒤의 난수 상태를 이어
쓰며, `--poison-rng legacy`는 이전 결과의 풀을 재현한다. 두 정책의 결과는
서로 다른 실험 입력으로 구분한다.
공격 라운드를 명시하지 않으면 분할에 사용한 **같은 NumPy RNG의 다음 값**으로
확률 추첨한다. seed 0의 N=500, q=100, 10라운드에서는 공격 라운드가
`1,2,5,6,7,10`이다. 이전 공식 Flower 10라운드 보고서의 `5,7,10`은
명시적으로 지정한 일정이므로 유효하지만, 원본의 확률 추첨 결과로 해석하지 않는다.
참여자 선정은 원본 `server.py:140–177`처럼 비공격 라운드에 정상 client
q명을 개별 추첨하고, 공격 라운드에 악성 client 전원과 나머지 정상 client를
추첨한다. Flower의 `--cohort-sampling individuals`가 이 포함 규칙과 순서를
사용한다. 원본은 local training 중 Python 난수 호출을 라운드 선정과 섞으므로,
Flower에서 미리 저장한 일정의 정확한 난수 transcript 일치까지 주장하지 않는다.

checkpoint SHA-256은 `047d40adbfdf3c0a5c95db299bec49c48ff1cc16125f5455094e974251c143e2`다.
`avg_300`이라는 이름을 통해 코드가 300-round checkpoint로 취급함을 확인했지만,
이를 생성한 원 학습 로그·partition hash는 확보하지 못했으므로 그 이력을 별도로 검증해야 한다.

### Sweep wrapper의 차이

- Figure 5: `attack1_fmnist.py`는 악성 client 수 a를 전달하면서 `mal_boost=a*20`을 설정한다.
  따라서 default global_lr=s_norm=1일 때 실제 증폭은 20이다.
- Figure 7: `attack2_fmnist.py`는 자식 trainer의 악성 client 수를 **20으로 고정**한다.
  바깥 CLI의 adversary 수를 바꾸면 boost 계산만 달라지고 자식의 adversary 수는 바뀌지 않는다.
  논문의 10%와 20% 곡선을 이 wrapper의 adversary 옵션만 바꿔 재현할 수 없다.
- Figure 9: `attack3_fmnist.py`도 악성 client 수 20을 고정한다. 논문 본문은 boost sweep에 10%를 설명한다.
  `--mal_boost=50`은 이 wrapper에서 실질 boost 2.5이고, 50배 증폭이 아니다.
- 두 값을 혼합해 숫자를 맞추지 않는다. artifact branch와 paper-aligned 변경 branch를 별도로 실행할 예정이다.

### 공격 데이터의 해석

`image_helper.py:280–298`은 poison-training sample을 **test dataset에서** 뽑는다.
FMNIST 평가 trigger는 YAML의 네 pixel pattern을 합친 것으로, 정규화된 pixel을 `0.1307*30`으로 바꾸고
label을 2로 설정한다(`image_helper.py:405–494`).
따라서 원 artifact 재실행에서 “평가 데이터가 공격자 학습에 전혀 사용되지 않았다”고 쓰면 안 된다.
엄격한 held-out 분리를 추가한 실험은 재현과 별도의 개선 실험으로 분리한다.

## 4. MGF와 결과 요약: 논문과 구분할 사항

핵심 근거는 `input_validation/FL_Backdoor_CV/roles/aggregation_rules.py:107–159`다.

1. FMNIST에서는 **classifier.weight의 840개 값만** mask하고 norm으로 client를 고른다.
   전체 61,706개 파라미터의 masked norm을 계산하지 않는다.
2. 중앙 `aion()`이 client의 평문 update를 입력받고, fresh seed와 mask를 매 호출 생성한다.
3. mask의 범위는 nonnegative이며 `weight * linf_old`로 scale한다. wrapper의 기본 weight는 **0.1**이다.
   이는 §5의 beta=0.2 설명과 별도 설정이다.
4. 재시작 후 첫 세 round의 bound는 정렬한 norm의 10% 위치값이다.
   이후 evolving 식을 사용하지만 통과 인원은 매번 최소 10%·최대 80%로 clamp한다.
5. 선택된 client의 **평문 전체 update를 평균**한다. 분산 secret reconstruction/unmask를 통해
   선택 집합의 합을 얻는 코드가 아니다. 이 경로의 성공은 end-to-end secure aggregation 성공이 아니다.
6. `.cuda()`가 두 곳에 하드코딩되어 있다. `--device=cpu`만 전달해서 MGF를 CPU 실행할 수 없다.
7. 이 directory의 SHPRG 초기 parameter는 `(1, 8, 173569775688864, 5000999999999999)`다.
   pickle opcode만 검사해 확인했으며 `pickle.load`는 사용하지 않았다. `matrix_840`은 archive에 없고
   첫 실행에서 생성된다. 생성 상태가 이후 RNG와 공격 일정에 영향을 줄 수 있으므로 반드시 기록해야 한다.

현재 Flower의 fixed-cohort ASR에 이 함수만 붙이지 않는다. 평문 접근 권한, mask 표현,
subset privacy, 유효 집합 합의가 서로 다르기 때문이다.

### ASR/TER가 두 방식으로 요약됨

| 코드 | ASR | TER |
|---|---|---|
| `roles/trainer.py` 최종 결과 | 모든 round의 poison accuracy 평균 | 1 − clean accuracy 평균 |
| `check_results.py:24–29` | 모든 round 중 poison accuracy 최댓값 | 최대 ASR을 달성한 round들 중 최소 TER |

`check_results.py`는 Windows 경로 separator로 파일명을 파싱하기도 한다.
다음 실행에서는 raw per-round 값을 보존하고 두 요약을 모두 계산한다. 어떤 요약이 논문의 각 그림에
사용되었는지는 미확정이다. 평균만 선택해 논문의 0%를 재현했다고 선언하지 않는다.

## 5. 실제 수행한 실행 준비 검사

기존 Flower `.venv`는 변경하지 않고 `.cache/aion-artifact/iv-cpu-venv`에 별도 환경을 만들었다.

- Python 3.12.12, PyTorch 2.4.0+cpu, torchvision 0.19.0+cpu, NumPy 1.26.3
- [환경 freeze](../../configs/reproduction/checkpoint-cpu.lock.txt)는 **checkpoint 검사 전용**이다.
  공식 전체 requirements를 설치한 lock이나 원 GPU 환경의 재현 lock은 아니다.
- 공식 README는 input validation에 Python 3.11 및 torch 2.4.0+cu124를 안내한다.
  CPU build, Python minor version, 일부 전이 의존성은 원 환경과 다르다.
- 권한을 확보한 `nvidia-smi` 조회: RTX 5060, 8,151 MiB, driver 610.74.
  GPU PyTorch 연산은 아직 검증하지 않았다. 논문 RTX4090/i9-14900KF와의 절대 시간 비교는 보류한다.

[checkpoint 검사 코드](../../experiments/probe_aion_checkpoint.py)는 검토한 `cnn.py`의 SHA를 확인하고
그 LeNet5 클래스를 로드한다. checkpoint 자체는 **일반 torch.load를 사용하지 않고**,
고정 SHA 및 제한된 global/storage 해석기로 inert module record와 float32 tensor만 추출했다.
알 수 없는 pickle global, 범위를 벗어난 tensor view는 거부한다. 범용 unpickler가 아니다.

실행 명령:

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
  .cache/aion-artifact/iv-cpu-venv/bin/python -m experiments.probe_aion_checkpoint \
  --output docs/reproduction/checkpoint-preflight.json
```

[실행 결과](./checkpoint-preflight.json):

- 10개 parameter tensor가 strict load에 성공, 총 **61,706개 parameter**
- 임의 fixture 4개에서 logits shape `(4,10)`, forward/backward 모두 finite
- SGD 1 step 실행: fixture loss `4.6555624 → 3.9015050`
- 이 fixture는 Fashion-MNIST가 아니며 **학습 정확도·poisoning·secure aggregation은 측정하지 않았다**.

검사 결과 파일은 덮어쓰지 않는다. 재실행 시 새로운 output 파일을 지정한다.
당시 Fashion-MNIST 원본 데이터와 partition checksum은 없었다.
2026-09-13 [데이터 manifest](./fashion-mnist-data.json)와 pilot partition checksum을 확보했다.

## 6. 단계 판정 및 다음 실행

| 단계 | 상태 |
|---|---|
| P0 archive 전체 확보·검사 | 완료 |
| P0 FMNIST wrapper·모델·MGF·공격·지표 추적 | 1차 완료, paper/artifact 불일치 기록 |
| P0 E1·E2 엄밀한 paper 설정 동결 | **부분 완료**: E2 artifact 설정은 기록, Table 3 연결과 plot 요약 미확정 |
| P1 checkpoint 실행 준비 | 통과 |
| P1 실제 FMNIST 공격/MGF pilot | **2라운드 완료**; 정상-only·60라운드 기준선은 미실행 |
| P2 이후 Flower 이식·MGF·성능 재현 | 미착수 |

실행 순서와 현재 상태는 다음과 같다.

1. **완료:** Fashion-MNIST checksum과 원 checkpoint 정확도 88.56%를 확보했다. 평가 transform은 원 artifact와 동일하다.
2. **완료:** 검토용 원본을 보존하고 별도 실행 사본에 device portability와 제한된 checkpoint loader를 적용했다.
   실제로 필요한 input-validation 의존성과 전체 설치 목록·변경 patch를 기록했다.
3. **pilot 완료:** 데이터 배정·MGF bootstrap·per-round metric·실행 시간을 확인했다.
   pilot은 60-round 결과 재현으로 세지 않는다. 상세 측정·반복 검증은 최신 pilot 보고서를 따른다.
4. artifact 설정의 60-round 기준선을 먼저 실행한다. 평균/최대 ASR과 대응 TER 모두 저장한다.
5. 논문과 다른 adversary 비율/요약 방식은 별도 paper-aligned branch로 대조한다.
   Table 3 연결 entrypoint·raw plot 결과가 더 필요하면 공식 Docker image를 digest로 고정해 확인하거나,
   사용자 승인 후 저자에게 자료를 요청한다. 현재까지 외부 문의는 하지 않았다.

검증 도구·checkpoint reader와 기존 프로토콜 회귀 테스트를 함께 실행해 **45 passed**를 확인했다.
`git diff --check`도 통과했다.
진행 중 찾은 차이는 곧바로 논문 오류나 보안 취약성의 증명으로 취급하지 않으며,
명확히 다른 구현 의미와 아직 확인하지 못한 부분을 구분한다.
