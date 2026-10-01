# 원본 HPRF·SHPRG·MGF와 HotStuff의 Flower 연결: 4라운드

저자 ASR HPRF의 실제 공개 행렬·p/q·입력식·반올림을 보존하는
`aion-original` 백엔드와, 저자 학습 SHPRG·torch.float32 MGF를 공식
Flower SuperLink/Ray에서 연결했다. 전체 업데이트는 HPRF로 마스킹하고
classifier 840개 좌표는 필터 입력으로 coordinator에 평문 공개한다.
따라서 이 결과는 **classifier-plaintext 선택 + 마스킹 ASR** 연구 실행이며
비공개 MGF나 저자 전체 프로토콜의 완전한 재현 완료가 아니다.

## 조건과 결과

N=100, 매 라운드 q=20, 집계자 4개/f=1, CPU worker 4개, seed=0,
4라운드다. 공격 client 4명, 공격 라운드 1·4를 명시했다. 저자
Fashion-MNIST 데이터·감사된 avg_300 checkpoint·분할/poison RNG 정책과
개별 참여 일정을 세 Flower run에 동일하게 적용했다.

| 라운드 | HPRF ASR + MGF 정확도 | 평문 저자 MGF 정확도 | 무방어 정확도 | 필터 적용 공격 성공률 | 무방어 공격 성공률 |
|---|---:|---:|---:|---:|---:|
| 0 | 88.56% | 88.56% | 88.56% | 0.390625% | 0.390625% |
| 1 | 88.62% | 88.62% | 10.03% | 0.976563% | 100% |
| 2 | 88.58% | 88.58% | 68.64% | 0.976563% | 94.726563% |
| 3 | 88.69% | 88.69% | 78.10% | 0.976563% | 94.921875% |
| 4 | 88.77% | 88.77% | 64.92% | 0.781250% | 46.484375% |

HPRF ASR 연결 경로와 평문 저자 MGF는 **모든 4라운드에서 같은 client**를
선택했다. 선택 수는 2·2·2·6명이며 모두 정상 client다. 두 모델의 전
라운드·전 좌표 최대 차이는 `2.832545083171446e-6`이다. 지표는 같지만
모델이 비트 단위로 같은 것은 아니다. 연결 경로는 소수점 6자리 양자화
ASR, 평문 MGF는 레이어별 float32 평균이다.

집계자 4개 모두 4라운드 모델까지 확정했다. 각 roster/model의
HotStuff commit-QC와 결정 인증서를 검증했다. 이는 이 실행의 정상
합의 완료 증거이지 모든 부분 동기 장애 스케줄의 진행성 증명이 아니다.

| 실행 | Flower run ID | 서버 케이스 측정 시간 |
|---|---|---:|
| 원본 HPRF + 저자 MGF + HotStuff | 4435943466199690611 | 378.518495856초 |
| 평문 저자 MGF | 13789646187370097775 | 18.173428042초 |
| 양자화 무방어 | 8866632378070682770 | 26.002896072초 |

위 시간은 CLI 시작·스테이징·후속 평가까지 포함한 전체 벽시계 시간이
아니다. 세 경로의 암호·합의 작업량은 다르므로 순수 HPRF 성능 비교로
사용하지 않는다. 실행 중 일부 회귀 시험도 병행해 부하가 있었다.

## 검증과 남은 차이

원본 trainer와 같은 전체 학습 라운드(1~4, checkpoint round 0 제외)
요약을 추가로 계산하면 다음과 같다. 원시 curve는 기존 results.json에
그대로 보존하며, 최종 라운드 지표와 평균·최대값을 혼동하지 않는다.

| 실행 | 평균 공격 성공률 | 평균 테스트 오류 | 최대 공격 성공률 |
|---|---:|---:|---:|
| 원본 HPRF + 저자 MGF + HotStuff | 0.927734% | 11.335% | 0.976563% |
| 평문 저자 MGF | 0.927734% | 11.335% | 0.976563% |
| 양자화 무방어 | 84.033203% | 44.5775% | 100% |

원본 trainer.py의 ASR·TER·MAX-ASR 계산에 맞춘 요약이며, 논문의 특정
그림에서 사용한 요약 방법을 확정했다는 뜻은 아니다.

- 원본 HPRF와 10,000·61,706차원 출력 전체를 직접 비교했다.
- 원본 SHPRG 및 `aggregation_rules.py::aion`과 동일한 입력·행렬·seed
  transcript로 4라운드 선택·평균·bound·norm 이력을 직접 비교했다.
  원본 함수의 CUDA 호출만 CPU로 대체했으며 GPU bitwise 동등성은 아니다.
- 원본 HPRF matrix/initialization/hprf.py의 hash 및 공개 열 합 setup
  digest를 provenance에 기록했다. worker는 manifest의 공개 setup으로
  계산하며 새 행렬을 생성하지 않는다.
- 공식 verifier를 실행 후 다시 실행하여 입력/source/catalog/config hash,
  실제 참여·공격 일정, 원본 HPRF setup, 모델/roster 인증서, MGF float32
  선택 계산과 saved model의 norm 이력, 매 라운드 선택 일치를 확인했다.
- 원본의 float64 1 벡터 시간 측정 대신 실제 학습 delta를 고정소수점으로
  인코딩한다. VSS·서명·암호화·HotStuff는 기존 Flower 연구 포트다.
- 선택된 부분집합의 장기 키 합 차분을 피하기 위해 매 라운드 새 ASR
  키와 VSS 공유를 사용한다. 원본 one-time sharing 효율은 재현하지 않는다.
- classifier는 평문이며 개별 mask/input 관계의 영지식 증명도 없다.
  작은 원본 seed 범위를 사용한 이 백엔드는 운영 보안용이 아니다.
- MGF의 후속 norm 이력은 인증된 양자화 모델 변화에서 얻는다. 원본의
  레이어별 float32 경로와 수치 차이가 있으며, source 전체의 공유 RNG
  호출 순서 및 resume 분기 재현도 남아 있다.
- 단일 seed·축소 4라운드 실행으로 논문의 60라운드 방어 곡선이나
  일반적 프라이버시·방어 성능을 입증하지 않는다.

[해시 연결된 결과](results.json)와
[포팅 기준·실행 명령](../../aion-author-port-goal.md)을 참고한다.
원시 결과는 `.cache/fmnist/official-author-hprf-shprg-hotstuff-four-round-seed0`다.
