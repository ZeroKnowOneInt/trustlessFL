# Seed-MPC 첫 native 구현과 검증

검증일: 2026-10-11. WSL Ubuntu-24.04, `work/aion-private-bound-no-wrap`.

**첫 구현 단위인 실제 비밀 키 AES + 4party MPC + 최초 seed 입력 1회 + 3round 비공개 검사/집계가 동작한다.** 전체 Flower FMNIST 앱이나 독립 운영자 환경의 보안 검증까지 완료한 것은 아니다.

## 구현 범위

- [정적 정책](../../trustlessfl/seed_mpc_policy.py): wire Q와 backend field 분리, 최대 norm/SUM 및 comparison 폭 계산. 부족한 field/폭 거부. Threshold 자체가 DB²보다 클 때도 비교폭에 반영한다.
- [Client wire encoder](../../trustlessfl/seed_mpc_wire.py): AES-128의 distinct counter block, big-endian 16/32-bit words, canonical fixed-width byte packing, 전체 벡터 기준 chunk offset, policy/model/session/epoch/handle을 묶는 서명 대상 payload.
- [Compiler primitives](../../mpc/Programs/Source/seed_mpc_primitives.py): 4개의 외부 client에서 seed의 128bit를 한 번만 받아 Boolean 관계 검사. 동일 MPC 세션의 인증 shares를 유지한다. daBit으로 arithmetic/binary 변환하고 secret key의 Bristol AES를 실행한다.
- [Native session](../../mpc/Programs/Source/seed_mpc_session.mpc): public masked input을 비밀 복원하고 좌표 range/sanitation/global norm/선택 SUM을 계산. 개별 norm, 업데이트, mask, seed, 통과 비트는 출력하지 않는다.
- [Runner](../../experiments/run_seed_mpc_probe.py): pinned MP-SPDZ 0.4.3, 4 MASCOT party와 4 ExternalIO client를 별도 actor directory로 실행한다. 합계는 모든 native party가 정상 종료하여 인증 검사를 완료한 뒤에만 성공으로 기록한다.

Binary AES circuit는 MP-SPDZ가 참조하는 Bristol Fashion 저장소 commit `1603ed6aa12348c2ef15ed8395b9b96e4c558b7f`의 `aes_128.txt`를 사용한다. SHA-256은 `40423a0cdaf5d4d34aba872c12660f115dc25c12eea6e24a9304578e79df6d04`이고 runner가 확인한다. [회로 원본](https://github.com/mkskeller/bristol-fashion/blob/1603ed6aa12348c2ef15ed8395b9b96e4c558b7f/aes_128.txt)

Arithmetic/binary 변환은 `-X`의 daBits를 사용한다. 검증된 Boolean seed bit를 fresh arithmetic/binary pad로 변환한다. 암호화된 mask words는 unsigned bit composition으로 큰 prime field에 옮긴다. 키 전체를 127-bit field로 줄여서 입력하지 않는다. Ciphertext를 공개하는 known-answer probe는 별도의 **test-only** 파일이며 공개 합성 키만 사용한다.

## 결과

| 실행 | 확인한 결과 | Native wall time | 모든 party의 내부 통신 |
|---|---|---:|---:|
| [Secret-key AES known-answer](seed-mpc-aes-2026-10-11.json) | 4client의 실제 외부 입력 키로 평문 AES와 모두 일치 | 9.308초 | 2311.6 MB |
| [3round session, 최종 fixture](seed-mpc-session-2026-10-11-v2.json) | 동일 key shares 재사용, 아래 SUM/count/abort 일치 | 22.872초 | 11743.5 MB |
| [Invalid seed bit](seed-mpc-invalid-seed-2026-10-11.json) | Boolean seed 관계 위반 시 input-abort, pending output 없음 | 7.322초 | abort 시 집계값 없음 |

모두 live active preprocessing을 포함한다. 로컬 루프백 통신이며 네트워크 배포의 성능은 아니다. AES-only의 작은 프로그램에서는 unused triples와 최소 batch 경고가 발생했다. Final session도 batch 잔여 재료가 있지만 전체 비용을 잔여분만으로 설명할 수는 없다. [후속 통신 분석](seed-mpc-communication-2026-10-11.md)에서 내부 통신의 99.96%가 전처리이고 모듈러 복원·좌표 검사 구간의 비용이 가장 컸음을 확인했다. 위 시간/통신을 전체 모델에 선형 외삽하지 않는다. Final session의 compile 시간은 6.262초였다.

Session fixture는 D=2, clients=4, Q=65536, B=20000, tau=400000000, a_min=2, backend P=2^127-1이다. 실제 학습 기본값 S=10000/tau=2500000000과 구분한다. Fixture는 scale=1을 사용하며 양자화된 정수 자체를 검사한다.

1. Round 1: 네 입력 `(20000,0)`이 정확한 norm 경계에서 통과. **SUM `(80000,0)`**, count=4. Wire modulus를 넘었지만 14464로 줄지 않는다.
2. Round 2: 두 입력 `(-20000,0)` 통과, `(20001,1)`은 좌표 상한 위반, `(20000,1)`은 norm 위반으로 제외. **SUM `(-40000,0)`**, count=2. Invalid 첫 좌표를 0으로 sanitize해도 전체 client가 제외된다.
3. Round 3: 통과자가 한 명만 남아 **abort**. Wire에 담긴 SUM/count 자리도 모두 0이며 공개 결과에는 해당 값이 없다.

Final fixture에서 실제 AES mask에 대해 positive wrap 5회, negative wrap 1회가 발생했다. 이 event count는 입력을 아는 synthetic harness의 진단이며 제품의 per-client 로그가 아니다.

처음 실행한 [v1 session 결과](seed-mpc-session-2026-10-11.json)는 두 번째 라운드의 합을 0으로 만든 fixture다. 음수 최종 출력까지 검증하기 위해 runner fixture를 수정한 v2를 최종 결과로 사용한다. Circuit 본문과 primitive 해시는 두 실행에서 동일하다. 결과 JSON의 source/harness 해시와 cache workspace의 policy/config를 통해 실행 조건을 구분한다.

## 재현

WSL의 프로젝트 root에서 실행한다. 기존 설치가 없으면 기존 `prepare_private_bound_mpc` runner로 pinned backend를 준비한다. 새 결과 파일명은 아직 존재하지 않는 경로를 사용한다.

```bash
.venv/bin/python -m pytest -q tests/test_seed_mpc_math.py tests/test_static_bound.py tests/test_private_bound.py tests/test_mpc_private_input.py tests/test_fmnist_no_wrap_math.py tests/test_private_bound_security.py
.venv/bin/python -m experiments.run_seed_mpc_probe --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 --case aes
.venv/bin/python -m experiments.run_seed_mpc_probe --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 --case multi-round
.venv/bin/python -m experiments.run_seed_mpc_probe --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 --case nonboolean
.venv/bin/python -m experiments.audit_seed_mpc_protocol
```

Python 검증: 새 산술/byte framing 검사 18개와 관련 기존 회귀 검사 89개, 합계 **107개 통과**. 기존 Typer/Click deprecation warning 2개가 남는다. 기존 oracle의 21712개 exhaustive 검사와 300개 randomized AES round도 통과했다.

## 아직 연결하지 않은 부분

- Native session의 Y/context는 synthetic fixture의 **확정된 public config**다. 실제 입력 수신, roster 합의, signature 검증과 anti-replay ledger는 아직 없다. `RoundContext.payload`는 서명할 canonical 본문을 만들며 제품 서비스에서 검증하는 것까지 구현한 것은 아니다.
- Key bit 입력의 인증 계산은 ExternalIO DDNNT 경로를 사용한다. Client identity/등록 handle의 활성화, public 등록 인증서, 악성 client–aggregator 공동 공모 모델의 전체 검토는 남아 있다. Aion과 동일한 보안 보장을 달성했다고 표시하지 않는다.
- Key 재사용은 **한 프로세스 세션 안의 메모리 재사용**이다. 안전한 disk persistence, rollback 복구, proactive refresh와 committee 교체는 구현하지 않았다.
- Output은 fixture client들이 받는다. Coordinator에 전달되는 post-MAC-check 3/4 output certificate, 실제 BFT 연결과 모델 적용은 후속 단계다.
- Malicious aggregator fault injection, public-input equivocation, 독립 host 배포, 구현 side-channel 및 합성 보안 증명은 미완료다.
- 전체 61706좌표, 공식 Flower native MPC FMNIST 실행과 성능 최적화는 미완료다. 기존 평문 FMNIST 정확도를 새 seed-MPC의 결과로 사용하지 않는다.

Private fixture key 파일과 인증 share를 artifact에 복사하지 않는다. Trusted synthetic harness가 실제 사용자 입력을 수집하는 서비스로 사용되어서는 안 된다. Flower Hub 설정 및 기존 원본 Aion 실행 경로는 변경하지 않았다.
