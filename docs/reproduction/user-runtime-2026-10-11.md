# 사용자용 Seed-MPC 실행 경로 검증

작성일: 2026-10-11. WSL `work/aion-private-bound-no-wrap`.
[사용자 명령과 역할 설정](../seed-mpc-user-runtime.md), [공개 검증 JSON](user-runtime-2026-10-11/independent-checks.json).

## 변경한 부분

기본 Flower component를 이전 AION 앱에서 Seed-MPC ServerApp/ClientApp으로 연결했다. `trustlessfl-seed-mpc`와 `python -m trustlessfl.seed_mpc_user`의 prepare/run/status 명령은 experiments 모듈을 import하지 않는다. 기존 실험 harness를 지우거나 raw oracle를 사용자 경로로 옮기지 않았다.

Client, aggregator, coordinator의 role.json을 별도로 만들며 ClientApp은 자기 client-config를 받을 수 있다. Coordinator 설정은 실제 app component/run config와 일치해야 한다. 일반 실행은 raw audit을 만들지 않으며 test fixture·poisoning·fault hook과 audit 활성화를 거부한다. 시작 전 O_EXCL marker를 만들어 동일 세션 재시작을 막는다.

공개 회로 source를 패키지 resource로 포함하여 repo 외부의 wheel 설치에서도 회로를 준비할 수 있다. 기존 backend/source/library pin과 artifact hash, wrap 복원·정수 폭·global norm 검사 로직을 유지한다. `uv.lock`을 갱신했고 `uv lock --check`도 통과했다. Publisher 값은 기존 placeholder를 유지하며 로그인·계정 설정·게시를 수행하지 않았다.

## 실제 실행

Wheel을 `uv build --wheel`로 만든 뒤 dependencies가 설치된 기존 Python 환경의 별도 target directory에 `uv pip install --no-deps --target`으로 설치했다. CLI는 `/tmp`를 cwd로 하고 PYTHONPATH를 그 설치 directory로 지정해 실행했다. 새 OS/컨테이너에 dependency까지 처음 설치한 시험은 아니다.

| 실행 | 모델 | 라운드 | 통과 | 컴파일 | raw audit |
|---|---|---:|---|---:|---:|
| user-mlp53-v1 | 합성 분류 MLP, D=53 | 2 | 매 라운드 4명 | 1회 | 0개 |
| user-cnn666-v1 | FMNIST CNN, D=666 | 2 | 매 라운드 4명 | cache hit, 0회 | 0개 |
| final-user-mlp53-v2 | 최종 coordinator binding / 별도 runtime alias 포함 D=53 | 2 | 매 라운드 4명 | cache hit, 0회 | 0개 |

CNN은 client당 1,024장, 평가 2,048장이다. 53개 모델은 client당 64개 합성 샘플, 평가 96개다. 정적 B=20000, T=2500000000, S=10000, min accepted=2. Backend는 승인된 MP-SPDZ 0.4.3 direct Rep4 build이며 component-input=holder-checked-direct-v1, snapshot v2, collection window 20초, communication meter를 사용했다.

사용자 summary는 **공개 인증서·모델 전이만 검증**하므로 `independent_retraining_verified=false`를 정확히 유지한다. 별도 신뢰된 개발 검증에서 각 client의 원본 데이터로 동일 학습을 재실행해 정수 update를 계산한 결과, 세 실행의 모든 라운드에서 정수 합·갱신 모델·평가가 정확히 일치했다. 이 검증은 사용자 CLI가 실행한 작업이 아니며 기록된 raw update 파일이나 seed를 필요로 하지 않았다. 개인별 update 벡터는 공개 artifact에 넣지 않았다.

최종 패키지에서 check-client/check-coordinator가 통과했고, 완료된 output에 다시 run을 요청하면 FileExistsError로 process launch 전에 거부됐다. Flower attempt 수가 1개로 유지되는 것도 확인했다.

## 회귀와 패키징

- Seed-MPC 전체 관련 test와 Rep4 candidate 회귀: **382 passed**, 기존 Click 경고 2개.
- 최종 coordinator app/config binding의 4개 추가 사례 후 사용자 경로 test 재실행: **22 passed**. 앞의 382개와 겹치는 18개 및 추가 4개다.
- CLI import 과정에서 experiments namespace를 강제로 차단해도 help 실행이 통과했다.
- Package MPC source bytes는 원래 source와 동일함을 검증했다.
- Wheel에 experiments, NPZ, SQLite, TLS private key, Player-Data 파일이 없는 것을 확인했다. Public source resources와 entry point는 포함됐다.
- 공개 검증 파일의 hash manifest를 만들고, 실제 세 세션의 identity private 문자열과 client seed 문자열이 섞이지 않았는지 검사했다.

[Package hash와 파일 검사](user-runtime-2026-10-11/package-checks.json), [공개 파일 manifest](user-runtime-2026-10-11/manifest.json). 전 프로젝트 테스트나 독립 host 배포를 완료했다는 기록은 아니다.

## 범위와 남은 부분

새 경로도 client 4명 / aggregator 4명, 단일 WSL UID의 로컬 bootstrap이다. Role config 분리는 OS 권한 격리와 다르다. 공개 SUM/count/abort에서 가능한 역추론 한계, 정적 malicious aggregator f<=1, protocol abort 가용성 한계는 그대로다. 사용자 모델을 두 개 연결해 집계 정확성을 확인한 것이 전체 프라이버시 증명을 대신하지 않는다.

독립 host provisioning·RPC/TLS 배포·backend 설치 자동화·client N 범용화는 후속 단계다. 모델별 threshold 자동 선정, 동적 threshold 회로, DP, arbitrary loss, 변동 buffer 지원을 추가하지 않았다. Hub 게시용 최종 metadata/업로드는 수행하지 않았다.
