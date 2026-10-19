# MPC 설치·실행 자동화 검증

작성일: 2026-10-12. 브랜치 `work/aion-private-bound-no-wrap`.
[실행 방법](../seed-mpc-backend-setup.md). 단계 3의 Linux/WSL용 backend 설치·패치·검증·native self-test를 패키지 안에 구현했다. Flower Hub 설정·게시와 독립 host 배포는 수행하지 않았다.

## 구현

`trustlessfl-mpc doctor/setup/verify/smoke` 및 동일한 `python -m trustlessfl.seed_mpc_setup` 명령을 제공한다. 일반 사용자 경로에서 experiments import는 없다.

- 고정 MP-SPDZ 0.4.3 archive 다운로드·SHA-256 확인, 오프라인 archive 옵션, 안전한 extraction.
- 기존 observer 및 holder-checked import 패치를 원본에서 다시 도출하고 고정 CONFIG로 active Rep4를 -j1 빌드.
- 기존 repository 승인 build를 유지하면서, 새 운영 환경에서 installer가 빌드한 artifact를 OS 계정의 owner-only 로컬 registry에 승인.
- 설치/deployment의 manifest만으로 승인하지 않고 source inventory·패치·config·binary·compiler·실제 runtime library를 확인.
- 완료된 설치 재사용, 동일 directory 설치 lock, partial download cleanup, 실패/기존 설치 보존.
- apt 기반 시스템 의존성 설치 옵션과 환경 점검, loader/Make/compiler 환경 override 차단.
- Synthetic 4-party native self-test 및 holder 사본 변조의 결과 공개 전 거부.

기존 native 명령과 malicious Rep4, 최종 CHECK, 4 aggregator/f<=1 계약은 유지했다. Source build의 추가 신뢰 기준은 로컬 installer·OS/toolchain과 비공개 승인 registry다. 원격 서버의 자기 hash map을 승인 기준으로 사용하지 않는다.

## 검증 환경과 결과

Digest가 고정된 Ubuntu 24.04 image를 새로 만들고 Python 3.12.3, CPU Torch 2.8.0, Flower 1.36.0, Ray 2.55.1 및 native 개발 패키지를 설치했다. 기존 host native binary/object 파일과 학습 dataset/개인키를 가져오지 않았다. 검증된 공식 archive만 read-only로 제공하여 source build를 새로 수행했다. 실행한 프로젝트 코드는 wheel을 별도 target에 설치한 것이며 checkout 밖에서 실행했다.

| 검증 | 결과 |
|---|---|
| 새 Ubuntu source build | 의존성 준비 후 신규 설치·빌드 180.991초, 원본·패치·artifact 검증 통과 |
| setup 재호출 | reused=true, rebuild/download 없음 |
| native 정상 self-test | SUM 80,000, invalid 좌표/global norm 제외 후 −40,000, 인원 부족 abort 확인 |
| native holder 변조 | 첫 public result 이전 중단, public result 0개 |
| 새 Ubuntu Flower | 53-parameter MLP, client 8명/aggregator 4명/2라운드 |
| 독립 synthetic 재학습 비교 | 매 round 정수 SUM·모델·평가 모두 정확히 일치, 매 round 8명 통과 |
| 일반 사용자 audit | raw update audit 파일 0개 |
| Python 관련 회귀 | 445 passed, 기존 Click deprecation warning 2개 |
| dependency lock | uv lock --check 통과 |

Native self-test는 D=2, B=20,000, T=400,000,000, minimum=2인 전용 synthetic 정책이다. 실제 사용자 MLP는 B=20,000, T=2,500,000,000, S=10,000을 사용했다. 둘 모두 Q=65,536과 넓은 64-bit SUM을 사용한다. Native self-test를 실제 학습 성능 또는 프라이버시 증명으로 해석하지 않는다.

새 Ubuntu의 첫 준비에서 회로 compile은 1회/7.009초였다. 이후 동일 설정의 새 세션은 cache hit/compile 0회였고 라운드마다 다시 컴파일하지 않았다. Backend source build도 매 라운드 재실행하지 않는다.

네 aggregator의 tracked Player payload 송신 합계는 setup **61,580 B**, round 1 **1,062,798 B**, round 2 **528,878 B**였고 합계 reconciliation이 통과했다. Live preprocessing을 포함하며 native framing·TLS/TCP/IP·untracked exchange·Flower/RPC는 이 수치에서 제외한다.

[설치 결과](backend-setup-2026-10-12/setup.json), [source build provenance](backend-setup-2026-10-12/source-build.json), [학습 검증](backend-setup-2026-10-12/flower-8-2r.json), [native 정상](backend-setup-2026-10-12/native-normal.json), [native 변조](backend-setup-2026-10-12/native-fault.json).

## 실제 다운로드·공식 prebuilt 경로

WSL의 새 directory에서 offline archive 없이 고정 GitHub URL로 release를 실제 다운로드했고 SHA-256/원본 source/공식 binary 검증을 통과했다. 별도의 offline stock 설치도 native self-test를 통과했다. Stock은 direct import/observer가 없는 기존 악성 보안 private input 경로다. [실제 다운로드 설치](backend-setup-2026-10-12/network-stock-setup.json), [공식 stock self-test](backend-setup-2026-10-12/official-stock-normal.json).

## 연결 시험에서 확인한 수정

첫 clean Flower 시도의 A2 service가 `Address already in use`로 시작하지 못했다. 선택된 RPC port 33760은 OS 기본 outgoing ephemeral 범위와 겹쳤다. 이 실행은 실패로 보존했고 완료된 학습으로 집계하지 않았다.

이후 RPC listener를 native 시작 전에 bind하여 bind 실패 시 native를 실행하지 않도록 수정했다. Local port selection도 `/proc/sys/net/ipv4/ip_local_port_range`를 읽어 해당 범위를 피한다. Busy RPC port의 native launch 방지와 ephemeral 범위 제외 회귀를 추가했다. 새 세션에서 수정 패키지의 8명/2라운드가 완료됐다.

## 최종 wheel와 공개 산출물

최종 wheel도 새 Ubuntu에서 설치·재검증 및 정상/변조 native self-test를 통과했다. Flower 검증 wheel과 최종 wheel의 모든 실행 Python 모듈 AST가 동일함을 확인했다(모듈 설명문만 갱신). Wheel에는 설치기·로컬 승인 검증·native self-test·공개 회로 resource·CLI entry point가 포함되고 experiments/tests, NPZ, SQLite, TLS private key, native runtime 개인 입력은 없다.

공개 JSON 8개와 hash manifest를 보존하고 실제 세션의 client seed·client/aggregator private identity 문자열 포함 여부를 확인해 clean이었다. 승인 registry 파일, client NPZ와 개인 입력은 공개하지 않았다. [Package 검사](backend-setup-2026-10-12/package.json), [공개 manifest](backend-setup-2026-10-12/manifest.json).

## 재현 및 범위

[설치 문서](../seed-mpc-backend-setup.md)의 명령을 사용한다. Clean image에는 `deployment/seed-mpc/Dockerfile.validation`과 wheel만 build context로 제공한다. 설치한 wheel의 client-N 사용자 학습은 `experiments/validate_seed_mpc_setup_user.py`를 별도의 trusted 검증 도구로 실행했다. 이 도구는 일반 사용자 runtime의 dependency가 아니다.

검증은 Linux/WSL의 동일 kernel·CPU 위에 새 Ubuntu userland를 사용한 기능 시험이며, 새 WSL distro와 모든 OS/CPU 조합을 검증한 것은 아니다. Source build profile은 Linux x86_64/SSE4.2/AES/PCLMUL/AVX2/BMI2/ADX를 요구한다. Source 고정과 기능 재현성을 검증했으며 환경 간 동일 binary bytes를 요구하지 않는다.

네 독립 운영 도메인 간 RPC/native 주소·TLS·key provisioning과 per-host backend pin의 공통 실행 계약 연결은 단계 4의 과제다. 전체 FL 합성 프라이버시 증명, DP 또는 공개 aggregate의 역추론 방어를 추가하지 않았다. 검증 container는 모두 종료했고 기존 native 설치·학습 세션은 보존했다.

[공식 MP-SPDZ 설치 안내](https://mp-spdz.readthedocs.io/en/v0.4.3/readme.html), [0.4.3 release](https://github.com/data61/MP-SPDZ/releases/tag/v0.4.3).
