# 저자 Aion-ASR Flower 포팅 완료 감사

이 문서는 이전 연구용 포팅 목표의 이력이다. 현재 활성 목표인 클라이언트
마스킹 기반 scaled-MGF 전체 경로의 완료 판정은 아니다.

이 문서는 운영 보안 구현이 아니라 사용자가 지정한 **저자 구현 우선 연구용
Flower 포팅과 논문에 가까운 실험 재현** 목표를 감사한다. 새로운 암호
프로토콜 설계, 모든 장애 스케줄의 HotStuff 진행 증명, 외부 보안 검토는
이 완료 판정의 요구사항이 아니다. 그런 항목은 미완료 경계로 남긴다.

## 요구사항별 증거

| 요구사항 | 현재 증거 | 판정 |
| --- | --- | --- |
| 저자 ASR 구조 보존 | 공식/로컬 저자 snapshot inventory, 핵심 8개 메서드 AST 대조, 원본 HPRF 행렬·initialization hash | 충족 |
| Flower ClientApp/ServerApp | ProcessGrid와 실제 SuperLink/Ray fresh task, node별 Context 및 catalog/config hash 검증 | 충족 |
| client-side masking | FMNIST client가 로컬 update를 원본 HPRF로 마스킹하고 aggregator에는 masked VECTOR만 전달; inbox exact schema | 충족 |
| 원본 HPRF | 저장된 p/q/matrix와 원본 함수의 다중 round/block/전체 좌표 출력 대조 | 기능 재현 충족; 보안성은 별도 |
| 초기 일회성 키 공유 | population 500에서 VSS share 2,000건(500×committee 4), 이후 추가 mask share 0; 4라운드 및 기존 20라운드 검증 | 충족 |
| 대규모 Flower 전송 | 100×61,706 masked vector를 최대 약 8 MiB Flower batch/inbox로 전달, 68 batch·최대 body 7,498,453 bytes | 충족 |
| 실제 학습·공격 | source-ASR 500/100 FMNIST 공격 4라운드 공식 실행, 선택 update 123회 재학습의 모델 오차 0 | 충족 |
| 정상 BFT commit | 초기/온라인/최종 정상 prepare→precommit→commit 인증서와 고유 sender 정족수 검증 | 목표 범위 충족 |
| ASR-MMF와 학습 MGF 구분 | 네 원본 파일 hash와 핵심 함수 AST를 이용한 15개 data-flow 조건; threshold·mask·aggregation 차이 표 | 충족 |
| 저자 학습 artifact 방어 재현 | 500/100·author-loader·원본 SHPRG/torch.float32 MGF 공식 Flower 10라운드와 동일 cohort 무방어 대조 완료 | 충족 |
| 논문 길이 수치 검증 | 원본 HPRF 공개 fixture q=100·60라운드·840좌표 DMC/DMR 감사, 추가 share 0 | 충족 |
| 장기 학습 검증 | 500/100·60라운드 저자 artifact MGF와 동일 cohort 무방어 run, 12,000 training metadata, 60-round trace verifier 및 hash-linked export | 충족 |
| 차이·한계 공개 | 각 result/report에 plaintext artifact, RNG/CUDA 차이, key-search, carry, VRF/EMA/HotStuff 경계 기록 | 충족 |

## 완료된 핵심 실행

- source-ASR local 500/100/4: 168.1151 s, keys 2,000, extra mask
  shares 0, selected replays 127, model error 0.
- source-ASR official Flower 500/100/4: 575.9410 s, keys 2,000,
  extra mask shares 0, selected replays 123, model error 0.
- author artifact official Flower 500/100/10: MGF 65.2944 s, final
  accuracy 88.59%, mean/max ASR 0.5859375%; quantized control 160.6271 s,
  mean ASR 60.078125%, max ASR 100%.
- author artifact official Flower 500/100/60, attack probability 50%:
  MGF 350.2039 s, final accuracy 88.80%, mean/max ASR
  0.631510%/0.78125%, selected attackers 0; quantized control 886.5262 s,
  final accuracy 56.81%, mean/max ASR 83.141276%/100%.
- literal DMC/DMR public numeric 100/60/840: 100,800/100,800 measured
  aggregate coordinates had nonzero carry; raw-hmax candidate exposed
  5,040,000/5,040,000 wire coordinates by public rounding.

## 명시적으로 재현되지 않은 부분

- 공개 학습 `aion()`에는 client-side scaled-HPRF/DMC/DMR network path가
  없다. 중앙 평문 artifact 결과를 secure MGF 결과로 표시하지 않는다.
- 공개 scalar key 1..100000은 현재 wire에서 public key-search가 가능하다.
  원본 재현용이며 `production_privacy=false`다.
- 후속 원본 VSS 감사에서 고정 다항식 계수로 단일 share만으로 개인 키를
  복원할 수 있고 Flower relay에도 그 share가 평문으로 전달됨을 확인했다.
  [초기 공유 감사](source-vss-privacy-2026-10-01.md)에 범위와 증거를 기록한다.
  새 learning 작업은 무작위 Pedersen 계수와 수신자별 암호화·서명으로
  수정됐으며 별도 fresh 공식 Flower 4라운드를 검증했다. 과거 실행의
  키 공유 비공개성 판정을 이 수정 결과로 소급하지 않는다.
- 논문의 CCS/VRF sortition은 공개 Python 학습/ASR 경로에서 찾지 못했다.
  현재 참여 schedule은 고정 RNG로 재현하며 CCS 보안을 주장하지 않는다.
- EMA late update aggregation은 source 동적 skip/rejoin과 다르며 포팅하지
  않았다.
- BFT는 정상 경로 commit 증거다. 임의 부분 동기 스케줄의 전체 HotStuff
  liveness 증명이나 모든 peer 재시작 조합의 보장은 아니다.
- original HPRF parameter/key distribution의 LWE 보안성, 작은-mask MGF의
  입력 privacy, 외부 암호 검토는 완료되지 않았다.

위 항목은 숨겨진 TODO가 아니라 현재 연구 재현물의 사용 경계다. 공개 자료에
없는 wire 규칙을 임의로 발명하지 않는다는 목표 결정에 따라, private MGF의
부재를 중앙 artifact나 추가 share 프로토콜로 대체하지 않는다.

현재 구현 변경 후 전체 저장소 회귀는 네트워크 허용 환경에서
**554 passed, 4 skipped, 0 failed**로 완료됐다(494.22 s). 관리형 sandbox의
소켓 차단으로 P2P 시험이 실패한 실행은 증거에서 제외했고, 동일 전체 suite를
로컬 소켓 허용 상태로 새로 실행했다. 두 legacy config-digest fixture는 새
기본-false opt-in 필드를 old claim에서 누락한 테스트 문제를 수정한 뒤
개별 및 전체 suite에서 재통과했다.
