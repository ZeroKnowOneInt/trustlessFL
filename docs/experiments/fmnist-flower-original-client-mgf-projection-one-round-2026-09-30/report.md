# 원본 HPRF·클라이언트 마스킹 MGF의 공식 Flower 공격 실험

2026-09-30. 이전 평문 classifier oracle 결과가 아니라 새 masked wire의 실제 학습 결과다.

## 결과

| 경로 | 정확도 | 공격 성공률 | ServerApp 시간 |
| --- | ---: | ---: | ---: |
| 원본 HPRF·masked MGF·HotStuff | 88.73% | 0.585938% | 247.77초 |
| 동일 학습 조건의 무방어 양자화 평균 | 10.10% | 100% | 11.94초 |

N=100, q=10, aggregator 4개/f=1, seed=0, 1라운드.
참여 공격자 `client-0`, `client-1`을 모두 제외하고 정상 `client-51`,
`client-67` 두 명을 선택했다. 소규모 cohort에서는 안전한 집계를 위해
최소 2명을 선택하므로 10% 하한보다 높게 선택했다.
기존 checkpoint의 정확도는 88.56%, 공격 성공률은 0.390625%였다.
전체 분할에 실제 배정된 데이터는 59,972장이며, 저자 분할 방식의 버림 처리를 따른다.

원본 `agent/Aion/HPRF`의 matrix·initialization_values·hprf.py를 읽고
public setup과 파일 hash를 고정했다. 실제 original HPRF를 사용하며,
학습 실험의 SHPRG를 동일한 것으로 부르지 않는다.
Flower 1.36.0의 공식 SuperLink/Ray 2.55.1 런타임, CPU worker 4개,
PyTorch 2.4.0+cpu·GMP 가속으로 실행했다.

## 확인한 범위

클라이언트가 전체 LeNet5 업데이트 61,706좌표를 ASR 마스킹하고,
classifier weight 840좌표를 작은 bounded mask로 별도 마스킹한다.
MGF는 이 masked classifier로 percentile 선택한다. 전체 모델의 집계와
projection의 bounded-mask 복원이 일치하는지 aggregator에서 검사한다.
선택 집합과 모델의 HotStuff commit QC를 검증했다.

새 offline wire 감사는 **선택되지 않은 후보도 포함한 10개 signed update**를
읽어 평문 classifier 필드가 없는지, task/round/parent, 전체 정수 벡터,
인증된 mask scale, signed probe와 실제 update digest의 일치,
인증 roster의 선택 update hash를 확인한다. 공개 export에는 값·키·share를
넣지 않고 확인 건수만 저장한다. 로컬 simulation cache 검사이지
악성 클라이언트의 정직한 학습이나 mask-key 관계를 증명하지 않는다.
저자 DataLoader sampling metadata의 실제 학습 호출 10회도 별도 검증했다.

추가로 선택된 두 클라이언트를 같은 staged 데이터·seed·학습 조건으로
다시 학습하고 양자화 평균을 계산했다. 인증된 전체 61,706좌표 모델과
**최대 절대 오차 0**으로 일치했다. 이 offline replay는 검증용 실험 데이터에
접근하며, coordinator의 정상 집계 경로에 평문 gradient를 전달하는 기능이 아니다.
[replay 결과](selected-replay.json)에는 개별 gradient를 저장하지 않았다.

raw run ID는 masked MGF `14901081351899754452`, 무방어 대조
`4978142155370824239`이다. 수치·hash·단계별 시간은 [results.json](results.json)에 있다.
클라이언트와 aggregator의 private state는 `.cache`에만 보존하고 공개 문서로 복사하지 않았다.

## 재현 명령

```bash
python experiments/run_fmnist_official.py \
  --output .cache/fmnist/official-original-client-mgf-projection-attack-one-round-20260930 \
  --phase all --modes aion_mgf_beta quantized \
  --population 100 --participants 10 --aggregators 4 --rounds 1 \
  --attack-clients 2 --attack-rounds 1 \
  --original-hprf-dir ../Aion/agent/Aion/HPRF \
  --training-sampling author-loader --mgf-beta 0.2 \
  --mgf-projection --mgf-percentile --mgf-artifact-bound --hotstuff \
  --workers 4 --device cpu --cli-timeout 1800
```

실제 실행 시 캐시된 의존성의 `PYTHONPATH`와 Flower CLI의 `PATH`를 지정했다.
재실행은 새로운 output 디렉터리로 한다. 실행 후 최신 verifier로 다시
인증서·입력/source hash와 signed-wire 감사를 확인한 뒤 sanitized export를 생성했다.

## 남은 차이

wire 감사·학습 replay·export·원본 MGF 관련 회귀 시험 66개와,
FMNIST·비교·percentile 관련 시험 28개가 별도 실행에서 통과했다.

**논문 길이·규모의 완전 재현이 아니다.** 한 seed·한 공격 라운드이며,
4라운드 이후의 threshold 진화나 장기 방어 성능을 이 결과로 입증하지 않는다.
전체 gradient norm 대신 classifier projection을 검사한다. 저자 학습 artifact의
선택형 percentile/bootstrap과 명시적 초기 mask 진폭 0.001을 사용했으며,
paper Algorithm 6만으로 지정되지 않은 초기 조건을 임의로 숨기지 않는다.

매 라운드 fresh key와 실제 bounded mask의 좌표별 Pedersen share가 남아 있어,
논문의 일회성 키 공유·경량 통신량과 다르다. 원본 기본 ASR의 모듈러
오류 보정만으로 이를 제거하면 실수 스케일링의 carry를 놓칠 수 있다.
예를 들어 HPRF 출력의 합이 `2.4p`이고 합계 키 출력이 `0.4p`라면,
실수로 정규화한 마스크의 차이는 반올림 1~2단위가 아니라 진폭의 두 배다.
따라서 추가 복원 정보를 제거하는 수정은 별도로 정확성을 검증해야 한다.

작은 bounded mask의 입력 정보 노출, 개별 mask-key 일치 증명, 모든 부분 동기
상황의 HotStuff 진행 보장, CCS/VRF 및 EMA 통합은 아직 해결됐다고 주장하지 않는다.
전체 벡터 MGF의 실제 FMNIST 실행도 별도 과제다.
