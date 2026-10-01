# FMNIST 공식 Flower 2라운드 MGF→AION HotStuff 연결 확인

2026-09-29에 Flower 1.36.0 SuperLink/Ray CPU runtime에서 실행한 짧은 기능 확인이다. 논문 길이의 성능 재현이나 보안 검증은 아니다.

## 설정과 결과

- FMNIST/LeNet5, 공개 checkpoint, artifact 분할 순서 및 RNG 이어쓰기
- 모집단 500명 중 라운드마다 100명 참여, 집계자 8개
- 악성 client 20명, seed 0에서 공격 라운드 1·2
- `aion_mgf_oracle`은 선택형 HotStuff 활성화, `mgf`는 평문 비교 경로
- 두 라운드 모두 두 경로가 같은 client 10명을 선택했고 선택 집합의 악성 client는 0명이었다.
- 두 모델 이력 간 최대 절대 오차는 `5.13e-7`; 최종 accuracy는 88.59%, ASR은 0.586%였다.
- AION 경로에서 라운드별 HotStuff commit 인증서를 확인했다.

## 해석과 제한

이는 Flower 실행에서 MGF 선택 결과를 AION 집계에 넘기고 선택형 HotStuff 인증까지 연결한 기능 증거다. `aion_mgf_oracle`은 classifier 층 840개 좌표의 개별 평문 delta를 coordinator에 공개한다. 따라서 이 결과는 비공개 MGF의 프라이버시 증거가 아니며, 공식 FMNIST 실행에서 `mgf_beta`의 차원별 Pedersen share 경로를 검증한 것도 아니다. 공격자가 선택되지 않은 두 라운드 결과만으로 방어 성능을 주장할 수도 없다.

## 재현 정보

원시 실행은 `.cache/fmnist/official-hotstuff-mgf-shared-rng-two-round-seed0`에 있다. 이 디렉터리의 `verification.json`은 선택 결과와 인증서를 확인하며, 이 보고서의 `results.json`은 실행 provenance 및 결과 해시를 보존한다.
