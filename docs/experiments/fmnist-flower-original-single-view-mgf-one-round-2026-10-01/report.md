# Single-view MGF: 공식 Flower FMNIST 공격 1라운드

2026-10-01. 검사 좌표를 두 가지 스케일의 masked 표현으로 중복 전송하지 않는
새 `--mgf-single-view` 경로의 실제 학습 실험이다. 기존 dual-view 4라운드와 구분한다.

## 결과

| 경로 | 정확도 | 공격 성공률 | ServerApp 시간 |
| --- | ---: | ---: | ---: |
| 원본 HPRF·single-view MGF·HotStuff | 88.73% | 0.585938% | 235.45초 |
| 동일 조건 무방어 양자화 평균 | 10.10% | 100% | 11.96초 |

N=100/q=10, aggregator 4개/f=1, seed=0, CPU worker 4개, 1라운드.
참여한 공격자 client-0·client-1을 모두 제외하고 정상 client-51·client-67을
선택했다. 소규모 cohort에서는 집계 하한 2명을 적용한다.
저자 artifact 분할로 59,972장을 배정했고, author-loader batch semantics로 학습했다.

## 새 경로에서 확인한 것

검사 좌표 840개는 bounded probe로만 전송한다. 전체 modular 벡터의 해당
위치는 0 placeholder이고, 다른 60,866좌표만 기존 ASR로 복원한다.
Aggregator는 복원한 bounded probe를 모델의 검사 좌표에 채워 전체 61,706좌표를
집계한다. 정책은 config digest에 포함되며, 중복 표현을 보내면 거부한다.

실제 Flower 1.36.0 SuperLink/Ray 런타임의 후보 signed update 10개를 검사했다.
모든 후보가 single-view 정책을 지켰고 평문 classifier 필드는 없었다.
검사 값·서명·task/round/parent·mask scale·update/probe·인증 roster의 연결을
확인했으며, roster와 모델의 HotStuff commit QC도 재검증했다.
실제 author-loader 학습 metadata 10회도 확인했다.

선택된 두 클라이언트를 동일 staged 데이터·seed·이전 인증 모델로 다시 학습했다.
**전체 모델의 양자화 평균 최대 절대 오차는 0**이었다.
CPU replay는 worker와 동일한 intraop thread 1개를 사용하고 host 설정을 복원한다.
검사 결과에 개별 gradient·키·share는 저장하지 않았다.

수치·원본 HPRF hash·모델 hash·검증 hash·phase 시간·replay는
[results.json](results.json)에 있다. raw run ID는 single-view
`4169320513419823867`, 무방어 `4696908865637631605`이다.
81개 wire 감사/export 회귀 시험 통과, single-view가 아닌 정책의 전용 검사 2개 skip.

## 실행법

```bash
python -m experiments.run_fmnist_official \
  --output .cache/fmnist/official-original-single-view-mgf-attack-one-round-20261001 \
  --phase all --modes aion_mgf_beta quantized \
  --population 100 --participants 10 --aggregators 4 --rounds 1 \
  --attack-clients 2 --attack-rounds 1 \
  --original-hprf-dir ../Aion/agent/Aion/HPRF \
  --training-sampling author-loader --mgf-beta 0.2 \
  --mgf-projection --mgf-single-view --mgf-percentile --mgf-artifact-bound \
  --hotstuff --workers 4 --device cpu --cli-timeout 1800 --replay-selected
```

실행에는 cached dependency PYTHONPATH와 Flower CLI PATH를 지정했다.
첫 시작은 sandbox의 socket 제한으로 실패했으며, 허용받은 로컬 runtime으로
이미 생성된 입력을 `--phase run --replay-selected`로 실행했다.
재현할 때는 새 output 경로를 사용한다.

## 한계와 다음 단계

새 wire를 실제 학습·공격·집계에 연결한 한 seed·1라운드 검증이다.
이전 dual-view 4라운드를 single-view 장기 실험으로 취급하지 않는다.
mask key와 실제 bounded mask 좌표의 share는 여전히 매 라운드 공유한다.
일회성 키 공유·경량 통신량, 입력 프라이버시의 증명, 개별 mask-key 관계 증명,
CCS/VRF·EMA 및 모든 부분 동기 상황의 HotStuff 진행 보장은 완료하지 않았다.

중복된 두 masked 표현을 제거한 것은 입력 정보 노출을 모두 해결한 것과 다르다.
다른 좌표와의 상관관계, bounded mask 자체의 범위 정보 노출, 원본 HPRF의
보안 가정은 별도로 검토해야 한다. 실행 시간은 단일 측정이며 speedup을 주장하지 않는다.
다음 실험은 single-view로 4라운드 이후 evolving threshold를 검증하는 것이다.
