# Seed-MPC 입력 확정·결과 인증·재실행 방지 검증

작성일: 2026-10-11  
환경: WSL Ubuntu-24.04, MP-SPDZ 0.4.3, Rep4 64bit ring  
브랜치: `work/aion-private-bound-no-wrap`

계획의 단계 E를 작은 실제 MPC 세션에 연결했다. 클라이언트의 서명된 masked 입력을 고정하고, 실행 전에 라운드를 영속 기록하며, native 내부 검사 완료 후에만 aggregator가 결과에 서명한다. Coordinator는 서로 다른 aggregator 3개의 결과 서명을 검증한 뒤 공개 모델을 한 번만 갱신한다. 2좌표와 65좌표의 3라운드 세션, 등록 바인딩 변조와 입력 해시 변조를 실제 Rep4로 검증했다.

이는 고정 committee의 안전성 경로다. 일반 BFT의 view change·pacemaker, 독립 운영자 배치, 전체 FMNIST 및 Flower masked 업로드는 아직 완료하지 않았다.

## 1. 구현한 처리 순서

1. **실행 계약 고정.** 클라이언트 4명, aggregator 4명, identity 공개키, 정책, 초기 공개 모델 hash, session/epoch 및 execution hash를 고정한다. Execution hash는 실제 native binary, AES 회로, MPC 소스, compiled bytecode/schedule과 설정을 묶는다. 정직 aggregator의 로컬 실행 adapter와 운영체제는 신뢰하는 코드다.
2. **등록 descriptor 서명과 비밀 입력 바인딩.** 각 클라이언트는 자신의 slot·key handle·session·epoch·policy·execution hash에 서명한다. 비밀 AES 키 입력은 최초 한 번만 수행한다. 같은 private-seed socket에서 descriptor의 SHA-256 네 word도 전송한다. MPC는 각 aggregator가 받은 descriptor hash와 공개 등록 계약의 일치를 전체 64bit로 검사한 뒤 `SEED_MPC_REG_CHECKED`를 출력한다. 이 공개 hash는 키의 hash가 아니며 키를 드러내지 않는다. 임의로 선택한 키의 품질이나 실제 SGD 수행을 증명하는 과정은 아니다.
3. **서명된 masked chunk 검증.** 각 입력은 client identity, key handle, session/epoch, round, 모델·정책 hash, 차원, word 폭, offset과 wire 값을 포함한다. 서명을 검증하고 각 클라이언트의 전체 좌표가 정확히 한 번씩 포함되는지 확인한다. 누락·겹침·중복·서명 변경·다른 handle을 거부한다. 수신 순서는 canonical 순서로 정렬한다. 검사 대상 명단은 등록된 입력 명단이며, 비밀 norm 통과 명단이 아니다.
4. **입력 투표 전에 영속 lock.** 이전 결정 body hash와 현재 공개 모델 hash를 확인한다. 입력 snapshot digest와 입력 투표를 SQLite의 `prepared` 상태로 원자적으로 기록한 후 서명된 투표를 반환한다. 같은 라운드의 다른 snapshot에는 다시 투표하지 않는다. 서로 다른 3개의 서명으로 입력 인증서를 만든다.
5. **MPC 입력 전달 전에 실행 예약.** 입력 인증서를 검증하고 `prepared → running`을 디스크에 commit한 뒤 FIFO에 입력한다. 실행 스트림은 round counter, snapshot SHA-256 네 word, canonical wire와 마지막 chunk의 0 padding이다. 각 aggregator 사본의 전체 폭 일치를 MPC 안에서 검사한다.
6. **비공개 검사와 사후 CHECK.** 비밀 seed로 AES 마스크를 만들고, signed 복원·좌표 범위·전체 norm·비밀 선택·넓은 정수 SUM을 계산한다. Native 공개 결과는 adapter에서 일단 pending으로 취급한다. `check_point()` 이후 출력하는 `SEED_MPC_CHECKED round digest`를 정직 aggregator 자신의 native process 로그에서 확인한다. Round와 snapshot digest 네 word가 모두 일치해야 한다. 그 뒤 결과 투표를 `checked` 상태로 commit한 후 서명을 반환한다.
7. **결과 인증서와 모델 적용.** 결과 body는 계약·라운드·snapshot·이전 결정·현재 모델·다음 모델 hash와 SUM/count/abort를 포함한다. 서로 다른 aggregator 3개 이상의 동일 body 서명이 필요하다. Coordinator와 aggregator는 인증서를 검증한 뒤 `decided`와 공개 모델을 같은 SQLite transaction에서 갱신한다.
8. **다음 라운드.** 완료한 결과의 body hash를 다음 parent로 사용한다. 3개 서명 인증서와 4개 서명 인증서는 body가 같으면 같은 parent다. 공개 모델이 확정된 뒤 다음 입력을 FIFO에 넣는다. Native process와 비밀 키 shares는 세 라운드 동안 계속 유지한다.

`check_point()`는 pinned 소스에서 pre-check 경계를 만들고 `check()`와 post-check 경계를 실행한다. Native CHECK는 산술·비트 및 공유 스레드의 검사를 수행한다. [MP-SPDZ 공식 API 설명](https://mp-spdz.readthedocs.io/en/stable/Compiler.html#Compiler.library.check_point)을 함께 참고한다. 로그 marker 자체가 원격 증명이나 ZKP인 것은 아니다. `NativeCheckpointReader`는 정직 aggregator가 직접 실행한 로컬 process만 관찰한다. Peer가 제공한 로그·파일 경로·`checked=True`를 증거로 받는 네트워크 API는 없다. 악성 aggregator는 자신의 서명을 위조된 결과에 붙일 수 있지만, 단독 서명으로 인증서를 완성할 수 없다.

## 2. 재실행과 재시작의 의미

SQLite는 WAL, `synchronous=FULL`, `BEGIN IMMEDIATE`를 사용한다. 등록 비밀 키나 MPC share는 저장하지 않고 공개 계약·snapshot·서명·결과·모델만 저장한다.

| 영속 상태 | 재시작 후 허용하는 동작 |
|---|---|
| prepared | 동일 snapshot의 저장된 입력 투표 반환. 다른 입력에는 투표하지 않음 |
| running | 실행을 소비한 것으로 취급. 동일 실행 예약도 다시 허용하지 않음 |
| checked | 저장된 동일 결과 투표 유지. 유효한 결과 인증서를 받아 결정할 수 있음 |
| decided | 동일 인증서 재전송은 모델 갱신 없이 종료. 다른 결과 거부 |

모델 적용과 결정 저장을 하나의 transaction으로 묶어 재시작 후 같은 합을 두 번 더하지 않는다. Abort 인증서는 라운드 결정만 전진시키며 모델은 유지한다. 초기 모델이 계약과 다르거나 ledger가 없거나 다른 session/owner의 ledger이면 거부한다. 실행 중단 후 비밀 share 상태를 복구하는 기능은 구현하지 않았다. 정상 디스크가 과거로 롤백되지 않는다는 가정이 필요하며, 상태가 유실되면 새 session과 새 키로 시작해야 한다. `create=True`는 최초 설치용이지 동일 session의 유실 상태를 복원하는 옵션이 아니다.

계약·서명·모델을 Python 값 비교만으로 검사하면 `True == 1`, `1.0 == 1` 문제가 생길 수 있어 canonical JSON 바이트로 비교한다. 호출자가 전달했던 registry·등록·snapshot·인증서 객체를 나중에 변경해 검사 상태가 변하지 않도록 복사한다.

## 3. 안전성과 남아 있는 범위

N=4, static 악성 aggregator f<=1을 유지한다. 3개 서명 quorum 두 개는 최소 두 aggregator에서 교차하며 그중 최소 하나는 정직하다. 정직 aggregator가 영속 lock을 유지하면 같은 라운드에서 서로 다른 입력을 인증할 수 없다. 결과는 정직 aggregator의 고정 회로·입력 실행과 사후 검사 서명에 의존한다. 외부 악성 클라이언트와 악성 aggregator의 전체 프로토콜 합성 증명은 이 시험으로 대체하지 않는다.

첫 proposal을 잠그는 구현에는 view change가 없다. 입력 투표가 2:2로 갈리면 멈출 수 있으며, native Rep4도 악성 party의 중단으로 계산을 완료하지 못할 수 있다. 이 상태에서 평문 집계로 대체하지 않는다. 결과 서명이 3개 필요하다는 사실이 native 계산을 3개 party만으로 지속할 수 있다는 뜻은 아니다.

공개 함수는 선택 SUM/count/abort다. 개인 업데이트·마스크·키·norm·선택 비트·추가 signed SUM을 공개하지 않는다. 그러나 공모자의 기여를 빼고 honest 기여 하나만 남으면 허용된 SUM 자체로 그 업데이트를 추론할 수 있다. 최소 통과 인원 2는 honest 기여 2명을 보장하지 않는다. Aggregator 2개 공모의 키 복원 위험도 그대로이며 f<=1 밖이다.

악성 coordinator가 자기 메모리의 모델을 임의로 바꾸는 행위 자체를 막을 수는 없다. 이 구현은 정직 endpoint가 **인증된 모델만 채택하는 규칙**을 제공한다. 이후 Flower 클라이언트도 결과 인증서·parent·모델 hash를 검증해야 한다. 현재 synthetic harness의 공개 모델은 float64이며 실제 PyTorch 모델 직렬화·float32 갱신 계약은 Flower 단계에서 별도로 고정해야 한다. 등록한 모든 클라이언트의 완전한 wire를 요구하는 초기 경로이므로 입력 dropout 처리도 후속 범위다.

## 4. carry·wrap 정확성은 유지되는가

기존 chunk 회로의 산술은 유지했다. `y=(x+m) mod Q`의 carry를 없애려고 마스크를 줄이지 않는다. MPC의 w-bit 뺄셈으로 `r=(y-m) mod Q`를 정확히 얻고, signed 복원 및 `|x|<=B`를 검사한다. `2B<Q`이면 허용 정수의 잔여값이 서로 겹치지 않는다. 정상 양자화 입력을 정확히 복원하며 악성 제출은 canonical effective input으로 해석한다.

Invalid 좌표를 0으로 sanitize해 안전하게 제곱하되, 해당 클라이언트 전체를 제외하는 비트를 유지한다. 모든 chunk의 전체 norm을 계산한 뒤 비밀 선택 비트를 한 번 정한다. SUM은 Q로 줄이지 않는다. 내부 64bit 링과 비교 폭이 DB², threshold, nB를 수용하는지는 시작 전에 validator로 확인한다. 잘못 설정한 내부 정수 폭을 자동으로 해결하는 구조는 아니다.

2좌표 실제 실행은 `80000 → -40000 → abort`를 인증했다. Q=65536보다 큰 80000이 14464로 변하지 않았고 음수도 정확했다. 첫 모델 `[20000,0]`, 두 번째 `[0,0]`, abort 후 `[0,0]`이었다. 이 작은 fixture의 scale은 1이며 전체 FMNIST 기본 scale=10000과 혼동하면 안 된다.

## 5. 실행 결과

모든 성공 사례는 4클라이언트·4 aggregator·3라운드, 클라이언트별 비밀 seed 입력 1회, native session 1개, compile 1회다. 마지막 라운드는 통과 인원 부족에 따른 정상 프로토콜 abort이며 인증된 결정으로 기록된다.

| 사례 | compile | native 경과 시간 | aggregator 내부 통신 | 결과 |
|---|---:|---:|---:|---|
| 2좌표 인증 경로, 최종 재실행 | 7.165초 | 1.918초 | 1.42587 MB | 정수 oracle·모델·재시작 후 중복 적용 차단 일치 |
| 65좌표 인증 경로 | 7.345초 | 3.095초 | 4.18145 MB | 마지막 partial chunk 포함, 3라운드 일치 |
| 등록 handle digest 변조 | — | — | — | 등록 중단, 결과 인증서·모델 갱신 0 |
| 한 party의 입력 digest 상위 bit 변조, 65좌표 | — | — | — | 입력 중단, 결과 인증서·모델 갱신 0, 재시작 후 예약 재사용 거부 |

MB는 MP-SPDZ가 보고한 all-party decimal MB이며 signed JSON·SQLite·coordinator 전달량을 포함한 전체 네트워크 총량이 아니다. Native 경과 시간에는 로컬 서명·ledger·라운드 전달을 기다리는 시간이 포함된다. 이전 0.350628 MB는 인증 없는 작은 비트 회로 측정이다. 이번 경로는 등록 descriptor/입력 digest의 전체 폭 검사와 매 라운드 CHECK를 추가했으므로 같은 기능의 직접 비교가 아니다. 전체 61706좌표의 실용성을 이 숫자만으로 단정하지 않는다.

결과 JSON: [2좌표](seed-mpc-certified-d2-2026-10-11-v2.json), [65좌표](seed-mpc-certified-d65-2026-10-11.json), [등록 변조](seed-mpc-certified-registration-reject-2026-10-11.json), [입력 digest 변조](seed-mpc-certified-input-reject-2026-10-11.json).

기본 runtime-file 경로도 변경된 회로로 9개 native 회귀 사례를 다시 실행했다. Partial chunk, 전체 norm 반례, 다른 Y의 bytecode 재사용, 공개 입력 불일치·상위 bit·비정규 wire·padding·round replay, 1024좌표, 32bit 경계가 모두 통과했다. 1024좌표는 compile 6.357초, native 16.915초, 내부 43.2678 MB였다. 이는 인증 경로의 1024좌표 시험이 아니라 기본 chunk 회로의 회귀다. [회귀 요약·로그 해시](rep4-certified-regression-2026-10-11/summary.json).

Python 검사는 새 transcript/ledger/checkpoint 47개와 기존 관련 검사 122개, 합계 **169개 통과**다. 서명 변경, canonical 타입 혼동, quorum 부족·중복·잘못된 결과, 입력 lock 교차, 실행 중단 복구, checked 상태 복구, 사후 marker 없는 pending 출력, 잘못된 round/digest, abort 값 노출, 결과 재적용 및 3/4서명 parent 동일성을 검사했다. 단위 시험의 가짜 process는 parser 시험용이며 MPC의 암호학적 검증 결과로 표시하지 않는다. 기존 Typer/Click 폐기 예정 API 경고 2개가 남는다.

로그 archive는 공개 출력과 compile/native/client 로그만 포함한다. 비밀 fixture JSON, TLS 개인키, AES seed 및 MPC shares는 복사하지 않는다. [인증 경로 로그·코드 해시 목록](seed-mpc-certified-2026-10-11/summary.json). 구현 중 vector public-input 전달에서 전체 digest word가 보존되지 않는 현상을 검사기가 잡아 scalar 입력으로 바꾸었다. 수정 전 실행은 입력 digest 불일치로 서명·모델 적용 전에 거부됐으며 성공 결과에 포함하지 않았다.

## 6. 재현과 다음 단계

```bash
cd /home/hacho/@WSL-Projects/trustlessFL
.venv/bin/python -m experiments.run_seed_mpc_certified \
  --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 \
  --dimension 65 --output /tmp/certified-new-result.json
# 변조 시험: --fault registration-bind 또는 --fault input-tag
.venv/bin/python -m pytest -q tests/test_seed_mpc_committee.py
```

결과 파일은 기존 기록을 덮어쓰지 않으므로 새 output 이름을 사용한다. 다음 단계는 이 인증 경로를 실제 Flower의 masked 업로드와 연결하는 것이다. 클라이언트의 키·raw delta를 coordinator가 받지 않는 구조, 모델 직렬화·인증서 검증, 서비스 수명과 native 세션 수명을 먼저 고정한 뒤 전체 FMNIST 크기를 올린다. Hub 게시 설정은 변경하지 않았다.
