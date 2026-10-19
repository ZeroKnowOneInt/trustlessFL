# Native Rep4 share 직접 연결: 구현·검증·통신량

작성일: 2026-10-11. WSL `/home/hacho/@WSL-Projects/trustlessFL`,
브랜치 `work/aion-private-bound-no-wrap`.

사용자 지시에 따라 긴 최신 FMNIST 5라운드 검증보다 **seed component의 Rep4 share 직접 연결**을
먼저 구현했다. 기존 입력 경로는 보존하고 별도 승인 native build를 사용하는 선택형 경로를 추가했다.
프로토콜은 [직접 연결 문서](../aion-direct-rep4-import-protocol.md)에 정리했다.

## 1. 최종 변경

- Component를 일반 private input으로 12회 재입력하는 대신, 각 aggregator의 세 local
  component를 binary replicated share로 직접 가져온다.
- Holder 간 chunk digest를 검사한다. Digest는 해당 component를 이미 보유한 다른 두 holder에게만 보낸다.
- canonical word·프레임·import sequence를 검사하고 상태 broadcast의 CHECK가 완료된 뒤 register에 반영한다.
- 기존 seed 등록 검사, single mask, 정적 좌표/global norm 검사, signed 복원과 넓은 SUM,
  입력/결과 인증과 dropout 체인을 유지한다.
- 공식/observer 설치와 기본 `stock-private-v1` 경로를 보존한다.
  새 경로는 `--component-input holder-checked-direct-v1`과 별도 승인 설치를 함께 선택한다.

새 backend는 `mp-spdz-0.4.3-direct-rep4-v1`이다. 승인 manifest SHA-256은
`681d4b9da4039b98c59db368b30b4227f16ae49476149b815649fba0185b8842`이다.
Source patch는 공식 archive에서 다시 유도하고 binary/libSPDZ/실제 loader 의존성까지 검증한다.
Test-only adversary build는 실제 제품 backend pin에서 거부된다.

## 2. 전체 FMNIST/LeNet5 비교

D=61,706, client 4명, aggregator 4명, seed42, client당 학습 15,000장,
테스트 10,000장, local epoch1, 동일 초기 모델·양자화·정적 정책·packing이다.
새 session에서 실제 학습 **1라운드**를 실행했다.

| 항목 | 기존 stock + lane64 | Holder-checked direct + lane64 |
|---|---:|---:|
| Native 초기 setup | 33,308 B | 33,308 B |
| Native round1 | 345,574,822 B | 274,113,190 B |
| 최종 정확도 | 74.84% | 74.84% |
| 최종 loss | 0.6796211730957031 | 0.6796211730957031 |
| ServerApp wall | 41.246 s | 41.011 s |

Round 통신량은 **71,461,632 B, 약 20.679% 감소**했다.
독립 재학습의 양자화 update, 정수 SUM, 모델과 평가가 정확히 일치했고 전원 제출/통과했다.
현재 localhost 관측에서 실행 시간의 큰 개선은 확인하지 않았다.

Native 통신량은 네 aggregator의 추적된 Player payload **송신 합계**이며 live preprocessing을 포함한다.
Application/RPC, native framing, TLS/TCP/IP, 추적되지 않는 setup/final exchange는 포함하지 않는다.
전체 시스템의 모든 network bytes나 수신 합계로 표현하지 않는다.
Setup과 round를 분리하고 native global counter와 합계를 대조했다.

기존 전체 학습 결과와 새 결과는 native build가 다르다. 작은 D1024에서 같은 새 바이너리를 사용한
stock/direct 대조도 실행하여 추가 native patch의 영향과 입력 경로의 차이를 구분했다.

## 3. 같은 바이너리의 대조와 작은 산술 검증

| D1024, 실제 Flower | stock-private-v1 | holder-checked-direct-v1 |
|---|---:|---:|
| setup | 33,308 B | 33,308 B |
| round1 | 6,140,182 B | 4,958,998 B |
| round2 | 5,510,006 B | 4,328,822 B |
| round3 | 5,510,006 B | 4,328,822 B |

같은 바이너리의 stock 수치는 이전 observer baseline과도 같았다.
D65/D1024의 3라운드 fixture는 각각 정수 SUM·모델·인증 체인을 통과했다.
전원 통과 → 둘 통과 → 최소 인원 미달 abort를 대조했다.
좌표 ±20000, Q보다 큰 ±80000 SUM, 마지막 좌표 범위 초과,
chunk별 norm만으로는 발견하지 못하는 전체 norm 초과를 포함한다.

## 4. 실제 native 변조 검사

9건 모두 집계 공개값, 결과 vote/certificate, 모델 갱신 없이 중단됐다.

| 시험 | 차단 경계 |
|---|---|
| P0/P1/P2/P3 각각의 local component 변조: 4건 | Native holder digest 비교 |
| 16-bit 범위 밖 local component: 1건 | Native canonical 검사와 checked 상태 합의 |
| 최초 seed replica 변조: 1건 | 기존 비밀 seed 등록 비교 |
| 한 peer에게만 다른 digest 전송: 1건 | Native holder digest 비교 |
| 한 peer에게만 다른 bad 상태 전송: 1건 | 즉시 Check_Broadcast |
| 검사 후 한 local share 변경: 1건 | 이후 native ANDS의 sender/backup hash 검사 |

마지막 세 시험은 P0의 test-only C++ binary/library를 실제로 변조하고,
나머지 세 party는 승인된 정상 backend를 사용했다.
단순 Python 파일 hash 비교나 입력 fault만으로 native 메시지 검사까지 검증했다고 주장하지 않는다.

첫 상태 변조용 시험 코드는 실제 CryptoPlayer 전송 경로를 건드리지 않아 정상 실행되어 실패했다.
시험 코드를 해당 실제 경로로 수정한 뒤 fresh session으로 다시 실행해 차단을 확인했다.
검사 후 share 변조는 실제 ANDS hash mismatch로 차단되었으며, 처음 verifier의 예상 오류 문구를
이 실제 검사 경계에 맞춰 수정하고 fresh session에서 재확인했다.
이 중간 실패 실행은 성공한 보안 시험으로 계산하지 않는다.

## 5. Dropout과 역할 격리

Direct 입력 경로의 작은 D65 dropout fixture **10라운드**를 실행했다.
부재, 최소 인원 미달, 복귀, client ACK 부재와 인증 suffix catch-up을 검증했다.
등록 1회/compile 1회, 각 정수 SUM·모델·체인이 일치했다.
수집 window는 합성 fixture용 5,000 ms이다. 전체 FMNIST의 수집 window와 구분한다.

처음 학습용 600,000 ms window를 그대로 넣은 dropout 시험은 긴 deadline 대기를 발견해 중단했다.
해당 미완료 실행의 native 상태를 재사용하지 않고 새 세션/등록으로 작은 window 시험을 시작했다.
미완료 실행을 10라운드 완료 근거로 사용하지 않는다.

별도 Flower Deployment에서 client4/aggregator4/server의 **9개 격리 역할**로
D65 3라운드를 실행했다. Raw audit를 생성하지 않고 공개 fixture 기준으로 SUM/모델을 대조했다.
역할 간 파일 접근 72건 차단, 자기 파일 접근, host PID 비노출,
12개 수신 인증서와 native/RPC counter 일치를 확인했다.
신뢰하는 host bootstrap/관리자와 공유 loopback의 한계는 유지한다.

## 6. Python 검사와 공개 artifact

```bash
.venv/bin/python -m pytest -q tests/test_seed_mpc_*.py tests/test_rep4_candidate.py
```

최종 **332 passed**, 기존 Click deprecation warning 2개다.
별도로 전체 project pytest를 시도했으나 외부 Aion 원본
`/home/hacho/@WSL-Projects/Aion/agent/Aion/SA_ClientAgent.py`가 없는 과거 fixture 시험에서 실패했다.
해당 전체 실행은 중단하고 관련 회귀에 집중했다. 전체 project suite 통과로 표시하지 않는다.

공개 [74개 artifact와 manifest](direct-rep4-import-2026-10-11/manifest.json)에
counter, summary, source snapshot, 승인 native build/source와 대조 결과를 보존했다.
Client seed/private identity, encrypted seed packet, raw update audit는 내보내지 않았다.
[비교 JSON](direct-rep4-import-2026-10-11/comparison.json)과
[변조 시험 결과](direct-rep4-import-2026-10-11/faults/summary.json)를 함께 제공한다.

## 7. 재현과 남은 범위

```bash
# 직접 입력 정상 fixture 예제는 프로토콜 문서 참고.
.venv/bin/python -m experiments.build_seed_mpc_direct --jobs 1
.venv/bin/python -m experiments.build_seed_mpc_direct_adversary
PATH="$PWD/.venv/bin:/usr/local/bin:/usr/bin:/bin" .venv/bin/python -m experiments.run_seed_mpc_direct_security \
  --output .cache/direct-security-matrix-v1
.venv/bin/python -m experiments.validate_seed_mpc_direct
.venv/bin/python -m experiments.export_seed_mpc_direct
```

위 검증 runner의 cache 이름은 고정이며 이미 존재하는 실행에 덮어쓰지 않는다.
새 환경에서 재현하거나 실제로 완료한 검증만 `--resume`으로 이어간다.
Native 중단 상태를 같은 세션에서 다시 실행하는 의미로 사용하지 않는다.
다른 compiler/build/runtime에서는 manifest hash를 자동 승인하지 않고 검토 후 명시적으로 고정한다.

고정 committee의 세션 전체 악성 aggregator 최대 1명과 기존 output 누출 범위를 유지한다.
Norm 이내 악성 update, 두 aggregator 공모, host 침해, 무조건적인 가용성은 보장 범위에 추가하지 않았다.
Full composition 보안 증명, 실제 다중 host, 최신 FMNIST 5라운드 정상/학습 dropout 검증은 남아 있다.
Native mask 입력을 없앤 뒤에도 약 274 MB가 남으므로, 다음 최적화는 비용 계측을 근거로 진행해야 한다.
Flower Hub 설정·게시와 Git commit/push는 수행하지 않았다.
