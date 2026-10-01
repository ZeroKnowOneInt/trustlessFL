# 최신 저자 구현 기반 Flower 포팅: 결합 10라운드

저자 ASR HPRF의 저장된 행렬·실제 p/q·입력식·반올림, 학습 SHPRG/MGF의
CPU float32 계산, author-loader 학습 batch 구성을 Flower SuperLink/Ray의
HotStuff 집계 경로에 연결했다. 원본 학습 소스 5개와 SHPRG 초기화 파일의
스냅샷·SHA-256도 이번 실행 시작 시점의 provenance에 기록했다.

classifier 840개 좌표는 coordinator에 평문 공개한다. 이는 저자 학습
실험을 연결한 연구용 포팅이며 비공개 MGF, 운영 보안 또는 논문 전체
실험의 완전한 재현이 아니다.

## 조건과 결과

Fashion-MNIST/LeNet5 avg_300 checkpoint, N=100/q=20, 집계자 4개/f=1,
CPU worker 4개, seed 0, 10라운드다. 공격 client 4명과 공격 라운드
1·4·7·10을 명시했다. 세 경로는 데이터 분할·학습 설정·개별 참여 및
공격 일정이 같으며 독립 Flower run·identity·모델 이력을 사용한다.

| 실행 | 최종 정확도 | 최종 공격 성공률 | 평균 공격 성공률 | 평균 테스트 오류 |
|---|---:|---:|---:|---:|
| 원본 HPRF + 저자 MGF + HotStuff | 88.67% | 0.585938% | 0.742188% | 11.234% |
| 평문 저자 MGF | 88.67% | 0.585938% | 0.742188% | 11.234% |
| 양자화 무방어 | 79.32% | 95.898438% | 88.105469% | 30.252% |

평균은 원본 trainer처럼 checkpoint round 0을 제외한 학습 라운드
1~10 전체에서 계산하며 비공격 라운드도 포함한다. 최대 공격 성공률은
MGF 경로 0.78125%, 무방어 100%다. 원시 curve는 results.json에 보존한다.

HPRF 연결 경로와 평문 저자 MGF는 **10라운드 모두 같은 client**를
선택했다. 선택 수는 2·2·2·7·9·7·5·8·9·2명이며 선택된 공격자는 없었다.
작은 cohort에서 최소 선택 수를 임의로 늘리지 않았다.
모델의 전 라운드·전 좌표 최대 차이는 `3.54471641517674e-5`다.
선택과 지표가 같더라도 모델이 비트 단위로 같은 것은 아니다.

| 실행 | Flower run ID | 서버 케이스 측정 시간 |
|---|---|---:|
| 원본 HPRF + 저자 MGF + HotStuff | 7439020064493362604 | 1580.227초 |
| 평문 저자 MGF | 7014397655962859833 | 29.462초 |
| 양자화 무방어 | 2237322712036382341 | 49.051초 |

결합 경로는 약 26분 20초였다. 위 시간은 CLI 시작·staging·후속 평가까지
포함한 전체 벽시계 시간이 아니다. 전체 회귀 시험도 병행했으며 순수
암호 연산 benchmark로 해석하지 않는다.

## 완료 후 재검증

공식 verifier를 다시 실행하여 다음을 확인했다.

- 원본 HPRF public setup과 파일 hash, 저자 학습 reference snapshot의
  전체 inventory·초기화 값·hash, staged worker source/config/catalog 및 입력 hash.
- 실제 참여·공격 일정, roster/model HotStuff 인증서와 전체 모델 이력.
- MGF float32 threshold·norm 이력·선택과 두 필터 경로의 매 라운드 일치.
- 후보 20명 × 10라운드의 **200회 학습 metadata**가 모두 author-loader,
  실제 round·partition·참여 일정과 일치함. MGF 탈락 후보도 포함한다.

Metadata 감사는 로컬 시뮬레이션 검증이며 악성 client의 학습 증명이
아니다. 공개 요약은 policy·call 수만 내보내고 키/share/업데이트는
내보내지 않는다. 전체 회귀 시험은 358개 통과·2개 GPU opt-in 시험
skip이었다(407.62초). 추가로 torch가 없는 상황을 import hook으로
모사한 collection 검사를 통과했다. 이는 별도의 clean-install 시험이
아니며, optional torch 시험의 collection failure를 방지하는 확인이다.

## 원본 대비 경계

- 실제 학습 delta를 고정소수점으로 인코딩한다. 원본의 float64 1 벡터
  성능 측정이나 전체 프로토콜의 비트 단위 포팅은 아니다.
- 매 라운드 새 ASR 키와 VSS 공유를 사용하므로 원본 one-time sharing
  효율은 재현하지 않는다. VSS·서명·암호화·합의는 기존 Flower 연구 포트다.
- classifier 평문 공개, 개별 mask/input 일치 증명의 부재, 작은 원본
  seed 범위 때문에 운영 보안이나 완전한 프라이버시를 주장하지 않는다.
- client/round별 분리 RNG를 사용한다. 원본 전체 공유 RNG, attacker의
  cached clean index 순서, CUDA bitwise 결과는 동일하지 않다.
- MGF norm 이력은 인증된 양자화 모델 변화에서 얻는다. 평문 float32
  대조군과 미세한 수치 차이가 있으며 다른 seed의 선택 일치를 보장하지 않는다.
- 이번은 축소 10라운드 검증이다. N=500/q=100·60라운드 논문 곡선,
  CCS/VRF 또는 모든 부분 동기 장애 스케줄의 진행성을 입증하지 않는다.

## 실행

실행 위치는 trustlessFL이며 새 출력 디렉터리를 사용한다.

```bash
PATH="$PWD/.cache/flower-deps/bin:$PATH" \
PYTHONPATH=.cache/flower-deps:.cache/torch-deps:. \
python3 -m experiments.run_fmnist_official --phase all \
  --output .cache/fmnist/official-author-reference-hprf-loader-hotstuff-ten-round-seed0 \
  --modes aion_mgf_oracle mgf quantized --author-mgf \
  --training-sampling author-loader \
  --author-reference-dir ../Aion/input_validation/FL_Backdoor_CV \
  --original-hprf-dir ../Aion/agent/Aion/HPRF --hotstuff \
  --population 100 --participants 20 --aggregators 4 --rounds 10 --workers 4 \
  --attack-clients 4 --attack-rounds 1 4 7 10 --cohort-sampling individuals --timeout 600
```

같은 명령의 `--phase verify --output <기존 디렉터리>`만으로 완료 결과를
재검증할 수 있다. 기존 결과를 다시 stage하거나 덮어쓰지 않는다.
[해시 연결된 결과](results.json), [포팅 기준](../../aion-author-port-goal.md)을 참고한다.
