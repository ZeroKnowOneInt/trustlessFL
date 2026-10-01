# 원본 HPRF·저자 SHPRG/MGF·HotStuff의 공식 Flower 10라운드

저자 ASR HPRF의 저장된 공개 행렬·p/q·입력식·반올림과 저자 학습
SHPRG·MGF의 CPU torch.float32 계산을 Flower SuperLink/Ray에 연결했다.
전체 업데이트는 HPRF로 마스킹하지만 classifier 840개 좌표는 coordinator에
평문 공개한다. 따라서 **classifier-plaintext 선택 + 마스킹 ASR** 실행이며
비공개 MGF나 논문 전체 프로토콜의 완전한 재현을 주장하지 않는다.

## 조건과 검증 결과

Fashion-MNIST/LeNet5, avg_300 checkpoint, N=100/q=20, 집계자 4개/f=1,
CPU worker 4개, seed=0, 10라운드다. 공격 client 4명과 공격 라운드
1·4·7·10을 명시했다. 세 경로는 동일한 데이터 분할·학습 설정·공격 및
개별 client 참여 일정을 사용한다. 논문 규모 N=500/q=100이나 60라운드
결과와 구분한다.

| 실행 | 최종 정확도 | 최종 공격 성공률 | 평균 공격 성공률 | 평균 테스트 오류 |
|---|---:|---:|---:|---:|
| 원본 HPRF + 저자 MGF + HotStuff | 88.88% | 0.78125% | 0.859375% | 11.198% |
| 평문 저자 MGF | 88.88% | 0.78125% | 0.859375% | 11.198% |
| 양자화 무방어 | 79.31% | 97.851563% | 87.890625% | 29.898% |

평균은 원본 trainer.py처럼 checkpoint round 0을 제외한 학습 라운드
1~10 전체에서 계산한다. 공격하지 않은 라운드도 포함한다. 최대 공격
성공률은 두 MGF 경로 0.976563%, 무방어 100%다. 이 요약이 특정 논문
그림의 계산 방법이라는 뜻은 아니다. 전체 라운드 curve는 results.json에
보존한다.

HPRF 연결 경로와 평문 저자 MGF는 **10라운드 모두 같은 client**를
선택했다. 선택 수는 2·2·2·6·9·5·4·7·8·4명이며 선택된 공격자는 없었다.
소규모 cohort의 최소 선택 수를 임의로 늘리지 않았다.
두 모델의 전 라운드·전 좌표 최대 차이는 `6.194870467055784e-5`다.
지표가 같아도 모델이 비트 단위로 같지는 않으며, 선택 일치가 다른
seed와 긴 실행에서도 유지된다는 보장은 없다.

공식 verifier를 완료 후 다시 실행했다. 입력·source/catalog/config hash,
원본 HPRF public setup digest, 실제 참여·공격 일정, 집계자 모델 및
roster/model HotStuff 인증서, MGF float32 선택과 모델 변화 norm 이력,
매 라운드 두 필터 경로의 선택 일치를 검증했다. 정상 실행에서의 합의
완료 증거이며 모든 부분 동기 장애 상황의 진행성 증명은 아니다.

| 실행 | Flower run ID | 서버 케이스 측정 시간 |
|---|---|---:|
| 원본 HPRF + 저자 MGF + HotStuff | 12703276003729550713 | 1488.517초 |
| 평문 저자 MGF | 3314778985064037216 | 30.021초 |
| 양자화 무방어 | 15176940860872406358 | 48.844초 |

HPRF 연결 경로는 약 24분 49초였다. 위 시간은 CLI 시작·스테이징·후속
평가까지 포함한 전체 벽시계 시간이 아니다. 회귀 시험 부하가 일부
병행됐으며 각 경로의 작업량도 달라 순수 암호 연산 benchmark로
해석하지 않는다.

원본 HPRF·SHPRG 직접 비교, 원본 MGF·MMF 계산 대조, 결과 요약,
기존 ASR 및 HotStuff를 포함한 선택 회귀 시험 143개도 통과했다.
이는 해당 테스트 범위의 결과이며 모든 보안 성질의 증명이 아니다.
이후 전체 `pytest -q`도 331개 통과·2개 skip으로 완료했다
(353.61초, 의존성 deprecation warning 2개). 전체 테스트 역시 논문 전체
실험이나 모든 보안 성질의 증명은 아니다.

## 실행 및 원본 대비 차이

실행 위치는 `trustlessFL`이며 새 출력 디렉터리를 사용한다.

```bash
PATH="$PWD/.cache/flower-deps/bin:$PATH" \
PYTHONPATH=.cache/flower-deps:.cache/torch-deps:. \
python3 -m experiments.run_fmnist_official --phase all \
  --output .cache/fmnist/official-author-hprf-shprg-hotstuff-ten-round-seed0 \
  --modes aion_mgf_oracle mgf quantized --author-mgf \
  --original-hprf-dir ../Aion/agent/Aion/HPRF --hotstuff \
  --population 100 --participants 20 --aggregators 4 --rounds 10 --workers 4 \
  --attack-clients 4 --attack-rounds 1 4 7 10 \
  --cohort-sampling individuals --timeout 600
```

기존 완료 실행은 재학습하지 않고 다음 명령으로 검증한다.

```bash
PYTHONPATH=.cache/flower-deps:.cache/torch-deps:. \
python3 -m experiments.run_fmnist_official --phase verify \
  --output .cache/fmnist/official-author-hprf-shprg-hotstuff-ten-round-seed0
```

공개 요약은 `python3 -m experiments.export_fmnist_official --source
.cache/fmnist/official-author-hprf-shprg-hotstuff-ten-round-seed0 --output
docs/experiments/<새-출력-디렉터리>`로 내보낸다. 이때도 위 PYTHONPATH를
설정하며 exporter는 기존 출력 디렉터리를 덮어쓰지 않는다.

- 원본 HPRF 저장 파일의 실제 p/q를 사용하며 init.py로 재생성하지 않는다.
  원본 소스·입력 hash와 public setup digest는 결과에 기록했다.
- 원본 ASR의 float64 1 벡터 성능 측정 대신 실제 delta를 고정소수점으로
  인코딩한다. VSS·서명·암호화·합의는 기존 Flower 연구 포트다.
- 선택 부분집합의 장기 키 합 차분을 피하도록 매 라운드 새 ASR 키와
  VSS 공유를 사용한다. 원본 one-time sharing 비용은 재현하지 않는다.
- MGF는 classifier 평문 공개 방식이다. 개별 mask/input 일치의 영지식
  증명이 없고 작은 원본 seed 범위도 사용하므로 운영 보안을 주장하지 않는다.
- MGF norm 이력은 인증된 양자화 모델 변화에서 얻는다. 평문 float32
  평균과 수치 차이가 있으며 원본 전체 프로그램의 공유 RNG 순서 및
  GPU 비트 단위 결과를 재현한 것은 아니다.
- 이 실행의 resume는 checkpoint 뒤 상대 라운드 1부터 시작한다.
  resume=300 계산 분기의 원본 대조 시험과 Flower 전체 프로세스 복구는
  별개다. 후자는 완료됐다고 주장하지 않는다.

[해시 연결된 결과](results.json), [4라운드 결과](../fmnist-flower-author-hprf-shprg-hotstuff-four-round-2026-09-30/report.md),
[포팅 기준](../../aion-author-port-goal.md)을 참고한다.
원시 실행은 `.cache/fmnist/official-author-hprf-shprg-hotstuff-ten-round-seed0`에 보존했다.
