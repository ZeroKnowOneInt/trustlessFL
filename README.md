# TrustlessFL — Private MPC Update Validation on Flower

## 현재 구현과 검증 (2026-10-19)

현재 기본 구현은 **고정 4개 aggregator의 MP-SPDZ Rep4로 개별 업데이트를 직접 공개하지 않고 정적 좌표·L2 바운더리를 검사하는 Flower 프레임워크**입니다. 아래의 Aion 재현·초기 MPC 기록은 개발 시점별 자료입니다.

- [발표 구성·선행연구·DP와의 관계·결과 비교](docs/graduation-presentation-outline-2026-10-17.md)
- [전체 구현 및 실험 완료 범위](docs/reproduction/graduation-status-2026-10-14.md)
- [FMNIST·LeNet5: 무필터·평문 검사·실제 MPC 비교](docs/reproduction/graduation-three-way-2026-10-12.md)
- [동일 Flower 환경의 평문 대비 실행 시간·통신 비용](docs/reproduction/flower-cost-improved-2026-10-12.md)

공모 한도는 세션 전체에서 static 악성 aggregator 최대 1개입니다. 두 aggregator 공모와 공개 집계·모델에서의 역추론은 보호 범위에 포함되지 않으며, DP 보장은 제공하지 않습니다. Norm bound의 적절성은 운영 정책이며 norm 이내의 poisoning을 일반적으로 방어한다고 주장하지 않습니다. 100명 실제 학습과 네 독립 기관의 실운영은 미완료입니다. 비용·정확도 수치는 각 보고서의 기록된 구현에 대한 결과입니다.

업로드 전 관련 회귀 검사: **28개 테스트 파일, 663 passed** (2026-10-19). 전체 저장소 테스트나 전체 학습을 재실행한 결과는 아닙니다. 개인 키·seed·로컬 데이터·SQLite 상태·빌드 캐시는 저장소에 포함하지 않습니다. Flower Hub에는 게시하지 않았습니다. 재현 자료에 포함된 MP-SPDZ 소스의 라이선스는 [원문 고지](licenses/MP-SPDZ.txt)를 따릅니다.

## 사용자용 Seed-MPC 로컬 실행

[역할별 설치·패키지 실행 안내](docs/seed-mpc-package-guide.md): 독립 실행의 client에는 MP-SPDZ·컴파일러·Ray가 필요 없습니다. 새 client 환경에서 MLP의 4→3→4 복귀와 CNN 2라운드를 검증했습니다. [패키지 검증 결과](docs/reproduction/package-validation-2026-10-12.md).

MPC backend는 `trustlessfl-mpc doctor/setup/verify/smoke`로 준비·검증할 수 있습니다. [Linux/WSL 설치·실행 자동화](docs/seed-mpc-backend-setup.md).

현재 기본 Flower 진입점은 Seed-MPC `ServerApp` / `ClientApp`입니다. 사용자 모델·정적 정책으로 `python -m trustlessfl.seed_mpc_user prepare/run/status`를 사용하며 일반 실행은 raw 업데이트 audit을 생성하지 않습니다. Client·aggregator·coordinator 설정을 분리했습니다. Client 수는 데이터 목록에서 N명으로 설정하며 aggregator는 4명입니다. 4·8·16명 기능 검증을 수행한 같은 Linux/WSL UID의 로컬 실행입니다. 독립 host용 별도 네트워크 실행 경로와 역할별 키·데이터 provisioning도 구현했습니다. [실행 절차](docs/seed-mpc-independent-hosts.md), [분리 환경의 이탈·복귀·최종 패키지 검증](docs/reproduction/independent-hosts-2026-10-12.md). 실제 네 독립 운영자 배포와 Hub 게시는 아직 수행하지 않았습니다. [실행 방법과 프라이버시 경계](docs/seed-mpc-user-runtime.md).

## 비공개 bound·no-wrap 확장 분기 (2026-10-10)

**마스크 생성 비용 개선 (2026-10-11):** 현재 Flower 실행의 기본 경로는 클라이언트별 네 seed를 수신자별 세 개씩 암호화 전달하고, aggregator가 로컬 PRG로 마스크 component를 생성하는 방식입니다. 기존 악성 보안 binary input과 component 사본 일치 검사를 유지하면서 MPC 내부 AES를 제거했습니다. Single mask·정적 바운더리·carry/wrap 복원 계약을 유지합니다. [프로토콜](docs/aion-seeded-components-protocol.md), [검증·측정](docs/reproduction/seeded-components-2026-10-11.md). 이전 경로는 `--mask-mode secret-aes-v1`로 실행합니다.
- [공개 입력 비교·SIMD packing 최적화 및 통신량](docs/reproduction/public-packed-2026-10-11.md)
- [직접 share 연결 검증·통신량: 345.57 → 274.11 MB](<docs/reproduction/direct-rep4-import-2026-10-11.md>)
- [Seed component의 native Rep4 share 직접 연결](<docs/aion-direct-rep4-import-protocol.md>)
- [최신 packing 이후 구현 계획](docs/seed-mpc-roadmap-after-packing.md)
- [사용자 PyTorch 모델·정적 정책·회로 캐시](docs/seed-mpc-user-models.md)
- [사용자 모델 native 검증·cache 재사용 결과](docs/reproduction/user-models-2026-10-11.md)

**일반 PRG + seed MPC:** [현재 통합 프로토콜](docs/aion-seed-mpc-current-protocol.md), [설계 변천](docs/aion-seed-mpc-protocol.md). 고정 committee에서 single mask, 작은 seed 등록·재사용, 입력 snapshot 확정, 비공개 바운더리 검사와 정확한 no-wrap 집계를 구성합니다. 등록 후 client dropout/복귀와 통신 계측도 구현했으며 각 검증 범위는 통합 문서에서 구분합니다. Q=65536에서 SUM=80000과 -40000 복원, 정적 norm/좌표 검사, 통과 인원 부족 및 invalid seed 중단을 확인했습니다. [첫 native 구현](docs/reproduction/seed-mpc-native-2026-10-11.md). 공식 Flower 학습까지 완료했으며, 안전한 disk share persistence와 전체 BFT liveness는 미완료입니다.

**입력·결과 인증과 영속 ledger:** 서명된 masked chunk와 등록 handle을 native 입력에 연결하고, 실행 전 예약·사후 CHECK·3서명 결과 인증·모델 한 번 적용을 구현했습니다. 65좌표/3라운드, 등록 1회, 내부 **4.18145 MB**를 확인했습니다. 입력/등록 변조는 인증서와 모델 갱신 없이 중단됐고 재시작 후 재실행도 거부했습니다. 관련 Python 검사 **169개**와 native 회귀 9개가 통과했습니다. [구현·측정·남은 범위](docs/reproduction/seed-mpc-certified-review-2026-10-11.md). 고정 committee의 안전성 경로이며 전체 BFT/Flower 완료 결과는 아닙니다.

[Seed-MPC 구현 계획: 실제 MPC부터 Flower FMNIST까지](docs/seed-mpc-implementation-plan.md).

**등록·라운드별 통신 계측:** 공식 MP-SPDZ 설치를 보존한 별도 승인 observer build에서 정확한 native 송신 counter를 추가했습니다. D65 정상 3라운드의 등록 **188,960 bytes**, 라운드 **1,718,868 / 1,118,580 / 1,118,580 bytes**, 추적된 종료 **0 bytes**의 합이 전체 **4,144,988 bytes**와 일치합니다. Flower 객체 그래프·RPC JSON 양 endpoint·최초 external seed 입력을 따로 기록했고 회귀 **351개**, dropout 10라운드·D170 FMNIST·기존 v1 실행을 통과했습니다. [측정 정의·결과·재현](docs/reproduction/seed-mpc-meter-2026-10-11.md). Transport overhead와 전체 LeNet5 새 계측은 별도 검증 범위입니다.

**Flower masked 연결:** 공식 `flwr run`에서 네 client와 네 별도 aggregator service를 연결했습니다. Client는 signed masked 입력만 반환하고, 결과 인증서를 확인한 뒤 모델을 채택합니다. **170파라미터 FMNIST/3라운드**에서 별도 재학습의 정수 SUM과 모델이 정확히 일치했고 내부 통신은 **8.34355 MB**였습니다. 65좌표 wrap/음수/abort와 인증되지 않은 모델의 학습 전 거부도 확인했습니다. [실행·비용·검증과 한계](docs/reproduction/seed-mpc-flower-review-2026-10-11.md). 같은 WSL UID의 기능 시험이며 전체 61706파라미터 LeNet5, 독립 운영자 격리 및 전체 BFT 완료 결과는 아닙니다.

**전체 차원 검증:** 같은 Flower 경로에서 **61706좌표의 dense 합성 입력/3라운드**를 실제 Rep4로 검증했습니다. ±80000/±40000 정수 합, 마지막 좌표 위반·전체 norm 위반 제외, abort 시 모델 유지가 모두 참조와 일치했습니다. 실행 **733.502초**, native 통신 **2476.15MB**, native 프로세스별 최대 RSS **145.82MiB**, compile **6.870초/1회**, seed 입력도 client당 1회였습니다. 묶음 출력 개선 후 1024좌표 실행 시간이 14.8% 줄었고 관련 Python 검사 202개와 native 회귀 9개가 통과했습니다. [전체 자원·통신·재현과 한계](docs/reproduction/seed-mpc-scale-review-2026-10-11.md). LeNet5 크기의 합성 입력 검증입니다.

**실제 전체 LeNet5 학습:** 공식 Flower·Rep4에서 FMNIST 학습 **60000장**, 테스트 **10000장**, IID client 4명/1라운드를 완료했습니다. 정확도 **10.00% → 74.84%**, 통과 **4/4명**이며, 기존 학습 코드의 독립 재학습과 양자화 업데이트·정수 SUM·최종 모델이 정확히 일치했습니다. ServerApp **256.587초**, native 통신 **825.968MB**, native 최대 RSS **71.52MiB**, compile **6.300초/1회**였습니다. 관련 Python 검사 **204개**가 통과했습니다. [1라운드 학습·비용·재현](docs/reproduction/seed-mpc-lenet5-learning-2026-10-11.md).

**실제 IID 5라운드 완료:** 같은 초기 모델/전체 데이터로 **74.84% → 80.54% → 83.72% → 84.99% → 86.24%**를 확인했습니다. 정상 업데이트 제외 **0/20회**, 모든 양자화 업데이트·정수 SUM·모델이 독립 재학습과 정확히 일치했습니다. Compile과 client별 seed 입력은 **각 1회**, ServerApp **1253.902초**, native 통신 **4126.98MB**, native 최대 RSS **204.61MiB**였습니다. [5라운드 결과·비용·학습된 모델](docs/reproduction/seed-mpc-lenet5-iid-5r-2026-10-11.md). Non-IID 실제 MPC 학습은 미실행이며, 같은 WSL UID의 기능 시험과 static f<=1 등의 보안 범위는 유지됩니다.

[Seed-MPC 초기 MASCOT 통신 분석: 전처리·AES·바운더리 검사·키 등록의 크기](docs/reproduction/seed-mpc-communication-2026-10-11.md). 해당 2좌표 native fixture의 내부 통신 11.74 GB 중 99.96%가 전처리였습니다. 이후 Rep4 전체 차원 측정과 구분합니다.

**Rep4 + 비트 회로 후보:** 같은 4클라이언트·2좌표·3라운드에서 내부 통신 **0.350628 MB**, Rep4 산술 회로 대비 **19.32% 감소**를 확인했습니다. 4 aggregator 중 최대 1개 악성이라는 계약에 맞춰 구현했으며, signed 경계·Q를 넘는 정수 합·악성 키 등록 중단을 검증했습니다. 이전 11.74 GB는 MASCOT 구현의 측정값입니다. [비용 비교·wrap 방지·등록 수정·남은 검증](docs/reproduction/rep4-candidate-review-2026-10-11.md). 전체 모델과 Flower 연결의 완료 결과는 아닙니다.

**실행 시 입력·chunk 회로:** 64좌표 compile을 84.487초에서 **6.727초**로 줄였고, **1024좌표/3라운드**도 실제 MPC로 검증했습니다. 같은 bytecode에 새 masked 입력을 넣으면 compile 호출 없이 실행됩니다. 여러 chunk의 전체 norm과 단일 선택을 유지하며 입력 불일치·padding·counter 재사용을 거부합니다. [측정·등록 보안 검토·재현](docs/reproduction/rep4-chunked-review-2026-10-11.md). 이후 FIFO 입력과 위의 공식 Flower masked 업로드 경로로 연결했습니다.

[유사 FL 선행연구 비교: AlphaFL·ELSA·Falkor·ScionFL](docs/seed-mpc-related-work.md).

**MPC 후보 재검토:** 직접 비밀 입력형으로 같은 검사 함수를 단순화할 수 있다. toy compile 자원 비교와 선택 합계 누출·정상 입력 정책은 [재검토 기록](docs/reproduction/mpc-candidate-review-2026-10-10.md)을 참고한다. 전체 모델 native MPC 연결은 미완료다.

[현재 프로토콜: carry·wrap 방지 조건과 MPC 바운더리 체크](docs/aion-no-wrap-mpc-protocol.md).

**현재 기본 검사 정책은 정적 threshold입니다.** 새 no-wrap 학습 경로는 업데이트
L2 반경 5, `T=25*S²`를 학습 시작 전에 고정하고 공개 평균으로 갱신하지 않습니다.
좌표 상한 `B=20000`, scale `S=10000`은 별도의 산술 안전 조건입니다.
공식 Flower IID 5라운드 86.37%, 로컬 non-IID 10라운드 62.68%였으며,
정상 업데이트 제외는 각각 0/20, 0/40건이고 양자화 집계 모델과 모두 일치했습니다.
[변경 내용·설정·재현 기록](docs/reproduction/static-threshold-2026-10-10.md)을 참고하세요.

이 학습 검증은 평문 reference입니다. 별도의 소규모 로컬 MASCOT MPC 경로는
구현했으나 전체 모델의 Flower MPC 연결은 아직 완료하지 않았습니다.
[산술·MPC 구현 범위](docs/reproduction/private-bound-no-wrap-2026-10-10.md)와
[출력 정책·재질의 등 남은 보안 문제](docs/reproduction/private-bound-security-2026-10-10.md)를
확인하세요. 정적 norm threshold의 poisoning 방어는 아직 검증하지 않았습니다.

이전 동적 필터는 non-IID 학습에서 정상 업데이트 7/40건을 제외하고 57.10%를
기록했습니다. [동적 정책의 학습 문제](docs/reproduction/mpc-aion-learning-2026-10-10.md)와
[이전 IID pilot](docs/reproduction/fmnist-no-wrap-2026-10-10.md)은 비교용 과거 기록으로
보존합니다. 기존 원본 Aion 재현 경로의 실행 의미는 유지합니다.

## 첫 번째 집계 BFT의 논문 순서 보정 (2026-10-02)

새 실행은 **필터 → 위원회 검증(paper-MGF 경로) → 통과 명단 BFT →
합계 key share 제공 → 복원 → 모델 BFT** 순서로 동작합니다.
첫 번째 BFT 인증서는 수신 명단이 아니라 필터 통과 명단에 바인딩하며,
인증서 없는 key release를 거부합니다. 과거 manifest는 이전 의미를 보존합니다.
[변경 범위·회귀·공식 Flower 검증](docs/reproduction/post-filter-bft-2026-10-02.md)을
참고하세요. HPRF/scaling은 바꾸지 않았으며 아래 복원·비공개성 한계도 남아 있습니다.

새 paper-MGF 실행은 **모델 BFT② 앞에도 위원회의 집계/norm 재검증**을
수행합니다. 선택 합계 키를 초기 VSS commitment와 대조하고, 위원회가
masked SUM·모델·MGF history를 다시 계산합니다. 공식 Flower synthetic
10라운드에서 초기 key shares 80건·추가 mask shares 0건·모델 재계산 오차 0을
확인했습니다. [검증 범위와 남은 carry 모호성](docs/reproduction/source-aggregate-validation-2026-10-02.md)을
참고하세요. 이 성공을 일반적인 private MGF 완성으로 표시하지 않습니다.

## 최신 상태 (2026-10-01)

현재는 **저자 Aion 구현을 활용한 Flower 연구용 포팅**이며, 논문 전체의
비공개 MGF나 production-secure 구현의 완성본은 아닙니다.
[진행 상황·검증 결과·남은 작업 요약](docs/reproduction/aion-flower-status-2026-10-01.md)을
먼저 참고하세요. 아래 내용은 서로 다른 시점과 실험 경로의 기록입니다.

최신 목표는 클라이언트 마스킹·일회성 키 공유·추가 mask share 없는
scaled-MGF입니다. 서명된 masked-vector 전달과 위원회별 선택 검증을 연결했고
공식 Flower synthetic 1라운드는 통과했지만, 10라운드 시도는 3라운드 commit 후
4라운드 복원 모호성으로 실패했습니다. 원본 ASR 집계 성공이나 중앙 평문
MGF의 60라운드 결과를 이 목표의 완료로 취급하지 않습니다.

## 이전 구현·실험 기록

사용자 확인에 따라 [원본 Aion-ASR의 Flower 통신 포팅](docs/source-asr-flower-port.md)을
별도 경로로 추가했습니다. 원본 키 공유·MMF·복원 함수를 실행하며,
첫 라운드 키 share를 재사용하고 추가 mask share는 없습니다.
아래 bounded-MGF 학습 실험과 구분되는 경로입니다. 원본 합성 workload 외에
실제 FMNIST 학습도 연결했습니다. [4라운드 검증](docs/experiments/fmnist-source-asr-fixed-key-four-round-2026-10-01/report.md)에서
집계 오차는 0이었으나 원본 ASR MMF의 공격 방어는 실패했습니다.
이를 논문 MGF의 공격 방어 재현으로 취급하지 않습니다.
새 소스 경로의 [공식 Flower SuperLink/Ray 실행과 20라운드 재검증](docs/experiments/fmnist-source-asr-official-2026-10-01/report.md)도
완료했습니다. 전체 모델 오차는 0이지만 공격 방어는 미완료이며, 활성 목표로 계속 진행합니다.
후속 [100명/10명 동적 참여 검증](docs/experiments/fmnist-source-asr-dynamic-2026-10-01/report.md)도
로컬·공식 Flower에서 완료했습니다. 재참여자는 기존 키/share를 유지합니다.

새 [single-view MGF의 공식 Flower 공격 4라운드](docs/experiments/fmnist-flower-original-single-view-mgf-four-round-2026-10-01/report.md)를
완료했습니다. 검사 좌표의 중복 masked 표현 없이 정확도 88.60%·공격 성공률
0.390625%였고, 네 라운드 전체 모델의 재학습 양자화 평균 오차는 0이었습니다.
1·4라운드 공격자를 제외했고 후보 40개·선택 8개와 threshold 갱신을 검증했습니다.
일회성 키 공유·추가 share 제거는 [별도 완료 조건](docs/mgf-key-sharing-reduction.md)이 남아 있습니다.

추가 `--mgf-projection --mgf-single-view`는 검사 좌표의 중복 masked 표현을
제거합니다. 해당 좌표는 bounded probe에서만 복원하며,
[구현 범위](docs/paper-client-mgf-port.md)에 설명했습니다.
아래 FMNIST 결과는 이 옵션을 적용하기 전 결과입니다.

이전 dual-view [원본 HPRF·클라이언트 마스킹 MGF·HotStuff의 공식 Flower 4라운드](docs/experiments/fmnist-flower-original-client-mgf-projection-four-round-2026-10-01/report.md)는
정확도 88.60%·공격 성공률 0.390625%였으며, 전체 61,706좌표 모델이
선택된 업데이트의 양자화 평균과 네 라운드 모두 오차 0으로 일치했습니다.
40개 후보의 signed-wire와 4라운드의 threshold 갱신도 확인했습니다.
classifier projection을 쓰는 축소 실험이며 일회성 키 공유는 아직 다릅니다.

논문의 **클라이언트 마스킹 → masked-vector MGF → 선택 집합 합의 → 집계** 흐름에
맞추기 위해 `aion_mgf_beta`에 원본 `aion-original` HPRF를 연결했습니다.
이 경로는 평문 `oracle_classifier`를 전송하지 않습니다.
[구현 범위·실행법·검증](docs/paper-client-mgf-port.md)을 참고하세요.
[새 원본 HPRF·masked MGF·HotStuff의 공식 Flower FMNIST 공격 1라운드](docs/experiments/fmnist-flower-original-client-mgf-projection-one-round-2026-09-30/report.md)는
정확도 88.73%·공격 성공률 0.585938%였고, 선택된 두 업데이트의 양자화 평균과
전체 모델이 오차 0으로 일치했습니다. classifier projection을 쓰는 축소 시험입니다.
기존 아래의 10라운드 결과는 평문 classifier를 공개한 oracle 경로이며,
새 클라이언트 마스킹 경로의 실험 결과로 취급하지 않습니다.

현재 우선 작업은 [저자 Aion 구현의 Flower 포팅](docs/aion-author-port-goal.md)입니다.
최신 [공식 Flower 결합 10라운드](docs/experiments/fmnist-flower-author-reference-hprf-loader-hotstuff-ten-round-2026-09-30/report.md)는
author-loader·원본 HPRF·저자 SHPRG/MGF·HotStuff·저자 소스 기록을 포함합니다.
최종 정확도 88.67%·공격 성공률 0.585938%, 평문 MGF와 모든 라운드 선택
일치를 확인했습니다. classifier 평문 공개 등 연구용 경계는 유지합니다.
원본 ASR HPRF의 파일·계산을 보존하는 `aion-original`과 원본 학습
SHPRG·MGF의 CPU 계산을 보존하는 `--author-mgf`를 구분해 제공합니다.
[저자 SHPRG·MGF 4라운드 실험](docs/experiments/fmnist-flower-author-shprg-mgf-four-round-2026-09-30/report.md)은
평문 학습 경로입니다. 아래의 기존 경량 연구 백엔드 결과를 원본 HPRF
재현 결과로 취급하지 않습니다.

[원본 HPRF·저자 SHPRG/MGF·HotStuff 연결의 공식 Flower 4라운드](docs/experiments/fmnist-flower-author-hprf-shprg-hotstuff-four-round-2026-09-30/report.md)에서는
평문 저자 MGF와 모든 라운드 선택 및 최종 지표가 일치했습니다.
classifier 평문 공개와 매 라운드 키 공유, 고정소수점 인코딩이라는
원본 대비 차이를 보고서에 명시했습니다.

[동일 경로의 공식 Flower 10라운드](docs/experiments/fmnist-flower-author-hprf-shprg-hotstuff-ten-round-2026-09-30/report.md)도
완료·재검증했습니다. 평문 저자 MGF와 모든 라운드 선택이 같았고 최종
정확도 88.88%·공격 성공률 0.78125%였습니다. N=100/q=20의 축소 검증이며
논문 규모·길이 전체 재현이나 비공개 MGF 구현 완료는 아닙니다.

추가 `--training-sampling author-loader`는 원본 DataLoader batch 구성과
중복 없는 poison sampling을 선택합니다.
[공식 Flower 4라운드 대조](docs/experiments/fmnist-flower-author-shprg-loader-four-round-2026-09-30/report.md)로
확인했으며, 기존 10라운드의 legacy sampling 결과와 구분합니다.
[같은 학습 방식의 원본 HPRF·HotStuff 결합 4라운드](docs/experiments/fmnist-flower-author-hprf-shprg-loader-hotstuff-four-round-2026-09-30/report.md)도
완료했고 평문 MGF와 모든 라운드 선택이 일치했습니다. 후보 80회 학습의
실제 sampling metadata와 HotStuff 인증서를 재검증했습니다.

Flower 1.36의 `ServerApp`, `ClientApp`, `Message`, `Grid`를 사용하는 **AION-ASR 연구용 구현**입니다. 서버 1개가 여러 독립 aggregator와 학습 client를 조정합니다. 합성 NumPy 회귀 데이터로 여러 라운드의 집계·학습을 실행할 수 있습니다.

[MNIST 실험](experiments/README.md#mnist-전체-데이터-실험)에서는 전체 학습 60,000장·테스트 10,000장으로 softmax 분류기를 학습하고 일반 집계와 비교합니다.
[공식 Flower FMNIST/LeNet5 10라운드 실험](docs/experiments/fmnist-flower-official-ten-round-2026-09-29/report.md)은 원본 checkpoint·데이터, N=500/q=100, **명시적으로 지정한** model-replacement 공격 라운드 5·7·10으로 AION과 평문 양자화 모델의 매 라운드 오차 0을 확인했습니다. 기본 50% 확률 추첨은 분할 직후의 NumPy 난수 상태를 이어 쓰며, 같은 설정의 10라운드에서는 1·2·5·6·7·10라운드가 선택됩니다. 평문 MGF 대조군은 공격을 걸러냈지만 AION 보안 집계 내부 MGF 방어를 입증하지는 않습니다. 논문 길이의 60라운드 곡선도 아직 실행하지 않았습니다.
[원본식 개별 client 추첨의 MGF→AION-ASR 집계 10라운드 실험](docs/experiments/fmnist-flower-official-oracle-individual-ten-round-2026-09-29/report.md)은 N=500/q=100에서 평문 MGF와 매 라운드 선택·지표가 일치했습니다. 별도의 `aion_mgf_oracle` 모드가 평문 classifier 층을 coordinator에 공개하므로 안전한 MGF 구현으로 해석하면 안 됩니다. [2인 그룹 추첨 결과](docs/experiments/fmnist-flower-official-oracle-mgf-artifact-ten-round-2026-09-29/report.md)도 별도 보존했습니다.
[원본식 기본 확률 추첨 10라운드](docs/experiments/fmnist-flower-official-default-rng-ten-round-2026-09-29/report.md)에서는 공격 라운드 1·2·5·6·7·10으로 두 Flower 경로의 선택·지표가 일치했습니다. 이는 위의 명시적 5·7·10 실험과 다른 참여 일정입니다.
[분할 뒤 Python 난수를 이어 쓴 공격 풀의 10라운드](docs/experiments/fmnist-flower-official-shared-python-rng-ten-round-2026-09-29/report.md)에서도 두 경로의 선택·모델이 일치했습니다. 이전 기본 일정 실행과 모델은 같지만 평가 이미지 풀이 달라 ASR은 0.390625%에서 0.5859375%로 바뀌었습니다.
[공격·동적 참여 실험](docs/experiments/fmnist-flower-dynamic-2026-09-28/report.md)은 node-local model-replacement 학습과 사전 확정된 2인 group 단위의 라운드별 참여를 확인했습니다. 이는 논문의 CCS/VRF 추첨이 아닙니다.

[마스킹된 classifier MGF의 공식 Flower 기능 시험](docs/experiments/fmnist-flower-masked-classifier-mgf-one-round-2026-09-30/report.md)은 `aion_mgf_beta --mgf-projection`으로 평문 classifier 없이 전체 모델을 ASR 집계했습니다. 추가 `--mgf-percentile` 옵션은 첫 3라운드의 percentile 초기화와 최소 10%·최대 80% 선택을 마스킹된 값으로 수행하며, 각 aggregator가 client 서명과 선택 결과를 독립 검증합니다. `--mgf-artifact-bound`까지 켜면 전체 후보 mask norm 인증서와 최근 두 집계 norm을 사용해 4라운드 이후 원본식 threshold를 계산합니다. 기존 percentile 경로의 bound 전이는 그대로 유지합니다. 작은 마스크의 정보 노출 및 악성 client의 개별 mask 일치 증명 한계는 [검증 기준](docs/security-completion-criteria.md#마스킹된-classifier의-percentile-선택-경로)에 명시했습니다.
[N=500/q=100 마스킹 MGF 공격 실험](docs/experiments/fmnist-flower-masked-percentile-paper-scale-one-round-2026-09-30/report.md)은 20명 공격자가 참여한 1라운드에서 정상 client 10명을 선택하고 ASR 집계를 완료했습니다. 정확도 88.55%, 공격 성공률 0.5859375%, 공식 실행 시간 737.34초입니다. 단일 라운드 기능·선택 검증이며 장기 방어 성능이나 논문의 집계 성능 재현을 입증하지 않습니다.
[원본식 threshold의 공식 Flower 4라운드](docs/experiments/fmnist-flower-masked-artifact-bound-four-round-2026-09-30/report.md)와 [동일 조건 무방어 비교](docs/experiments/fmnist-flower-masked-artifact-bound-comparison-2026-09-30/report.md)도 완료했습니다. N=100/q=20, seed 0에서 마지막 정확도·공격 성공률은 MGF 88.82%·1.37%, 무방어 64.92%·46.48%였습니다. 축소된 짧은 실험이며 일반적인 방어 성능으로 확대하지 않습니다.

마스킹 backend와 LWE-HPRF reference는 연구용이며 검증된 보안 구현이 아닙니다. 선택형 MGF·EMA·HotStuff/P2P 복구 경로도 논문의 전체 보안 보장이나 모든 장애 상황을 재현한 것으로 해석하면 안 됩니다. 우선순위와 남은 실험 차이는 [재현 계획](docs/aion-reproduction-plan.md)을 참고하세요.

[마스킹 MGF·원본식 threshold·HotStuff 공식 Flower 4라운드](docs/experiments/fmnist-flower-masked-artifact-bound-hotstuff-four-round-2026-09-30/report.md)도 완료했습니다. N=100/q=20에서 최종 정확도 88.71%, 공격 성공률 1.37%였고 모든 라운드의 commit QC를 검증했습니다. ServerApp 내부 시간은 약 20분 55초입니다. 실행 후 개발한 HotStuff 검증 재사용 최적화는 이 측정에 포함되지 않았습니다.

[검증 재사용 적용 4라운드](docs/experiments/fmnist-flower-hotstuff-validation-reuse-four-round-2026-09-30/report.md)는 최신 코드로 완료·검증했습니다. 최종 정확도 88.52%, 공격 성공률 0.390625%, ServerApp 내부 시간 약 16분 48초였습니다. [같은 학습 조건의 무방어 대조](docs/experiments/fmnist-flower-hotstuff-validation-reuse-comparison-2026-09-30/report.md)는 64.92%·46.48%였습니다. 이는 축소된 단일-seed 학습 결과이며, 서로 다른 암호 마스크의 실행 시간을 엄밀한 speedup으로 표시하지 않습니다.

## 실행

Python 3.12 이상, Linux/WSL 환경에서:

```bash
uv sync
uv run aion-demo --clients 4 --aggregators 4 --faults 1 --rounds 3
uv run pytest -q
uv run flwr build
```

데모는 실제 Flower 앱과 protobuf 직렬화를 사용하며, client 4개와 aggregator 4개를 각각 별도 프로세스에서 실행합니다. 네트워크 대신 로컬 `ProcessGrid`를 쓰므로 Ray, GPU, 외부 데이터셋, 실행 중 인터넷 연결이 필요하지 않습니다. 종료하면 임시 identity와 share 상태도 정리합니다.

구현한 흐름은 client별 일회성 Feldman VSS, X25519/HKDF/AES-GCM share 전달, 라운드별 masking, 서명된 참여 집합 정족수, 검증 가능한 집계 share 복원, DMC/DMR 정수 연산, aggregator별 결과 재계산 및 Ed25519 결과 인증입니다. 기본 모드는 고정 cohort이고, 선택적으로 사전 확정된 privacy group 전체를 라운드별로 선택할 수 있습니다.

[실행 및 배포 가이드](docs/aion-flower-implementation.md), [논문 구현 포인트](docs/aion-implementation-notes.md), [요구사항](docs/secure-aggregation-requirements.md)을 참고하세요.
