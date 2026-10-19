# MPC backend 설치·실행 자동화

작성일: 2026-10-12. Linux/WSL x86_64, Python 3.12+.
단계 3은 검증된 MP-SPDZ 0.4.3과 기존 checked Rep4 패치를 설치하고 실행 가능 여부를 확인한다. Flower Hub 게시·계정 설정과 독립 운영 도메인 배포는 포함하지 않는다.

## 명령

프로젝트 의존성을 `uv sync --extra seed-mpc` 또는 `pip install '.[seed-mpc]'`로 설치한다. Wheel 설치에서도 같은 명령을 제공하며 experiments 모듈은 필요하지 않다.

```bash
trustlessfl-mpc doctor
trustlessfl-mpc setup --install-system-deps
trustlessfl-mpc verify --installation "$HOME/.cache/trustlessfl/mp-spdz/mp-spdz-0.4.3-checked-source-v1"
trustlessfl-mpc smoke \
  --installation "$HOME/.cache/trustlessfl/mp-spdz/mp-spdz-0.4.3-checked-source-v1" \
  --output .cache/native-self-test-new
```

개발 checkout에서는 각 명령을 `python -m trustlessfl.seed_mpc_setup`으로 호출할 수 있다. `--directory PATH`로 backend 저장 위치를 변경한다. `--install-system-deps`는 apt-get을 사용하는 Linux에서 root 또는 passwordless sudo 권한으로 시스템 패키지를 설치한다. sudo 암호가 필요한 환경은 출력된 apt 명령을 운영자가 먼저 실행하고 `setup`을 호출한다. 시스템 설치 flag 없이 missing dependency를 발견하면 변경 없이 실패한다.

Doctor는 운영체제·Python·CPU 기능·실행 도구·개발 header를 확인한다. Direct profile은 SSE4.2/AES/PCLMUL/AVX2/BMI2/ADX를 지원하는 x86_64를 요구한다. ARM·Windows native용 source build는 제공하지 않는다. 경로에는 whitespace와 shell/Makefile 특수문자를 허용하지 않는다.

오프라인 설치는 `setup --archive /path/mp-spdz-0.4.3.tar.xz`를 사용한다. 파일은 동일한 고정 SHA-256 검사를 통과해야 한다. 일반 설치는 고정된 공식 GitHub release URL에서 다운로드한다.

## 설치 과정과 신뢰 기준

1. 고정 release archive SHA-256을 검사한 뒤 fresh directory에 안전한 extraction을 수행한다.
2. 기존 observer 및 holder-checked native import 패치를 공식 원본으로부터 다시 도출한다.
3. 고정 CONFIG.mine과 `/usr/bin/make -j1 rep4-ring-party.x`로 active Rep4를 빌드한다. Make/compiler flag와 loader override 환경을 상속하지 않는다.
4. 전체 공식 source inventory와 패치, CONFIG.mine, binary, libSPDZ, 실제 loader의 라이브러리, compiler hash를 확인한다.
5. 해당 운영자의 `~/.local/state/trustlessfl/native-approvals/`에 설치 경로별 승인 기록을 0700 directory / 0600 file로 저장한다.
6. 기존 runtime `pin_backend`가 설치물과 로컬 승인 기록을 다시 검증한 뒤에만 ready를 반환한다.

기존 backend의 repository 고정 승인 hash는 변경하지 않았다. 새 source build는 다른 컴파일러·라이브러리·경로에서 binary가 달라질 수 있어, **신뢰하는 로컬 설치기와 OS/toolchain이 직접 생성한 artifact를 승인**한다. 배포 JSON이나 설치 디렉터리의 자체 hash manifest만으로 승인되지 않는다. 승인 registry는 OS 계정의 home을 사용하며 서버/deployment나 HOME/XDG 환경변수가 위치를 지정할 수 없다. 승인 기록·source·binary·library가 변조되면 실행을 거부한다.

이는 신뢰하는 운영자/host/toolchain을 전제로 하는 source build provenance이며 동일 binary bytes의 전 세계 재현성, 독립 운영자 인증 또는 FL 전체 보안 증명을 뜻하지 않는다. 시스템 library/compiler가 바뀌어 pin 검사가 실패하면 새 directory에서 다시 설치한다. 승인을 자동 갱신하여 실패를 통과시키지 않는다. 승인 파일을 다른 aggregator 운영자에게 전달해 신뢰 기준으로 사용하지 않는다.

## 재사용과 실패

완료된 설치에서 setup을 다시 실행하면 전체 무결성 검증 후 reused=true를 반환하며 재다운로드·재컴파일하지 않는다. 설치 flag를 줘도 완료된 설치에서는 apt를 다시 실행하지 않는다. 설치 lock으로 같은 directory의 동시 작업을 직렬화한다.

기존 설치·실패 디렉터리는 덮어쓰지 않는다. 다운로드 실패의 partial file은 제거하며, extraction/build가 중단된 directory는 진단을 위해 남긴다. 승인 없는 설치는 실행되지 않는다. 새 directory를 지정해 다시 설치한다. 빌드 로그는 backend directory에 남는다. 기존 공식/observer/direct 설치와 학습 세션을 변경하지 않는다.

`--mode stock`은 공식 release의 CPU profile binary를 설치한다. 패치 없이 기존 악성 보안 component private input 경로를 사용하며 direct import와 별도 communication meter를 지원하지 않는다. Direct를 요청했는데 자동으로 stock으로 바꾸지 않는다.

## Native self-test와 학습 연결

Smoke는 4개 native party로 synthetic 입력을 실행한다. 평문 학습 데이터나 실제 client seed를 사용하지 않는다. 성공 조건은 SUM 80,000, invalid coordinate/global norm 제외 후 SUM −40,000, 인원 부족 시 SUM/count를 0으로 차단하는 abort다. `smoke --fault`는 holder component 한 사본의 변조를 넣어 첫 결과 공개 전에 거부되는지 검사한다. 실제 FL session의 raw audit을 켜는 옵션이 아니다.

설치 이후 [사용자용 실행](seed-mpc-user-runtime.md)의 prepare에 출력된 installation을 지정한다.

```bash
trustlessfl-seed-mpc prepare \
  --output .cache/my-session-new --model-config /path/model.json \
  --mp-spdz-dir "$HOME/.cache/trustlessfl/mp-spdz/mp-spdz-0.4.3-checked-source-v1" \
  --component-input holder-checked-direct-v1 --communication-meter --rounds 2
trustlessfl-seed-mpc run --output .cache/my-session-new
```

MPC backend는 운영 환경마다 한 번 설치한다. 모델·정책·N이 달라질 때 필요한 **MPC 회로 컴파일/cache**는 별도로 처리하며 라운드마다 backend를 빌드하지 않는다.

## 깨끗한 환경 검증

`deployment/seed-mpc/Dockerfile.validation`은 digest가 고정된 Ubuntu 24.04 base, wheel, CPU Torch/Flower/Ray, 시스템 개발 패키지로 새 검증 환경을 만든다. Docker build context에는 Dockerfile과 wheel만 넣는다. 전체 checkout을 context로 보내 private runtime/학습 데이터가 포함되게 하지 않는다. Local image만 만들며 registry에 push하지 않는다.

결과는 [설치·패치·native·Flower 재현 기록](reproduction/backend-setup-2026-10-12.md)에 정리한다. 독립 host role provisioning은 다음 단계다.

[공식 0.4.3 설치 안내](https://mp-spdz.readthedocs.io/en/v0.4.3/readme.html), [공식 release](https://github.com/data61/MP-SPDZ/releases/tag/v0.4.3).
