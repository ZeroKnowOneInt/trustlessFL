# Rep4 회로의 chunk 처리·컴파일 재사용과 입력 보안 검토

작성일: 2026-10-11. WSL `/home/hacho/@WSL-Projects/trustlessFL`, 브랜치 `work/aion-private-bound-no-wrap`.

**다음 구현 단계인 병렬 AES·chunk 반복 회로와 실행 시 공개 입력을 추가했다.** 64좌표의 compile 시간이 기존 84.487초에서 6.727초로 줄었다. 1024좌표에서도 compile 6.409초로 native 실행을 완료했다. 같은 bytecode에 다른 입력을 넣은 재실행은 compile 호출 0회였고, 정수 SUM/count/실패 결과가 모두 기준과 일치했다. 전체 Flower FMNIST 완료 결과는 아니다.

## 1. 구현 변경

[새 회로](../../mpc/Programs/Source/seed_mpc_chunked_session.mpc)는 AES 네 block을 병렬 실행한다. 16bit wire에서는 chunk당 32좌표다. MP-SPDZ의 `for_range`를 사용해 chunk 반복을 실행 중에 수행하므로 좌표마다 전체 코드를 Python으로 펼치지 않는다. 하나의 회로가 여러 라운드를 반복하며 등록된 비밀 키를 메모리에서 재사용한다. [공식 고수준 인터페이스](https://mp-spdz.readthedocs.io/en/stable/Compiler.html).

공개 masked Y와 round counter를 각 aggregator의 runtime 입력 파일에서 읽는다. 이전 회로처럼 실제 Y를 compile 상수로 넣지 않는다. **공개 입력 파일은 실제 학습 업로드 서비스와 구분한다.** 파일은 synthetic 검증 도구가 작성하며 사용자 키나 평문 업데이트를 서비스로 수집하는 경로로 사용하지 않는다. [공식 입력·출력 문서](https://mp-spdz.readthedocs.io/en/stable/io.html).

네 aggregator가 읽은 값을 각각 MPC 입력으로 넣고, 차이의 전체 64bit를 분해해 불일치 여부를 검사한다. 일치 확인 후 기준 사본을 공개값으로 사용한다. mask된 Y는 원래 공개 허용 입력이므로 이 공개는 개인 업데이트를 열지 않는다. 한 서버의 파일만 바꿔도 실행이 중단된다. 하위 16/32bit만 대조하지 않는다.

마지막 chunk는 framing용 0으로 채운다. 실제 D를 벗어나는 좌표는 norm과 선택에 참여하지 않으며, 비정규 padding은 거부한다. 따라서 pad된 길이가 D보다 커져도 산술 상한은 DB²로 유지된다.

### 같은 회로를 재사용하는 조건

[runner](../../experiments/run_seed_mpc_probe.py)의 `--compiled-workspace`가 이전 bytecode/schedule을 사용한다. 정책·차원·클라이언트 수·word 폭·chunk 크기·라운드 슬롯 수와 입력 형식이 일치해야 한다. 원래 compile 설정의 digest, MPC source와 AES circuit hash, 실제 bytecode/schedule hash도 검사한다. 새로운 TLS fixture와 native 세션을 만든 뒤 다른 공개 입력 파일을 읽는다.

Y와 round counter의 값 변경은 재컴파일하지 않는다. 현재 회로는 라운드 슬롯 수를 사전에 정하며, 이를 바꾸거나 정책·차원·word 폭을 변경하면 다시 컴파일한다. 매 라운드 AES·검사·MPC 통신은 여전히 실행한다. 이 재실행 시험은 새 native 세션에서 synthetic 키를 다시 등록한 시험이다. 키 재등록 없이 계속하는 세 라운드와, 프로세스 재시작을 넘는 키 재사용은 구분한다. 후자는 아직 구현하지 않았다.

## 2. chunk마다 검사해도 전체 norm 정책을 유지하는 이유

각 chunk에서 복원한 signed 좌표 x에 대해 `b=[-B<=x<=B]`를 계산한다. invalid 좌표는 제곱 전에 0으로 만든다. actual 좌표만 `tilde x=b*x`로 메모리에 저장한다.

\[
v_i\leftarrow v_i\land\bigwedge_{j\in chunk}b_{ij},\qquad
t_i\leftarrow t_i+\sum_{j\in chunk}\tilde x_{ij}^{\,2}.
\]

모든 chunk가 끝난 후 한 번만 `e_i=v_i AND [t_i<=tau]`를 계산한다. 전체 업데이트에 같은 e_i를 곱해 최종 SUM을 만든다. chunk별 norm threshold, chunk별 통과 명단, 판정 전 chunk SUM 공개는 사용하지 않는다. 안전한 업데이트 메모리는 O(nD)다. 전체 메모리/RSS는 아직 계측하지 않았다.

검증용 반례는 첫 좌표와 마지막 좌표에 각각 15000을 넣는 입력이다. 각 좌표가 다른 chunk에 있고 제곱 225000000은 threshold 400000000보다 작다. 그러나 전체 제곱합 450000000은 초과하므로 클라이언트 전체를 제외해야 한다. 실제 native 회로가 이 결과를 냈다. 마지막 좌표에 B+1을 넣는 입력과, 첫 좌표 B/마지막 좌표 1의 norm 1 초과도 전체 제외했다.

마스크 제거는 이전 [Rep4 검토서](rep4-candidate-review-2026-10-11.md)의 exact w-bit subtraction 및 signed 변환과 같다. 최종 집계는 64bit 링에서 이루어져 SUM=±80000을 Q=65536으로 다시 줄이지 않는다. 입력 canonical 범위·norm/SUM 상한·비교 폭 검증을 유지했다.

## 3. native 측정 결과

모두 네 클라이언트와 네 aggregator의 로컬 실행이다. 시간은 단일 관측이며 WAN 성능 수치가 아니다.

| 회로/입력 | 좌표 | 라운드 | compile | native | 내부 통신 |
|---|---:|---:|---:|---:|---:|
| 이전 전개형 비트 회로 | 64 | 3 | 84.487초 | 3.829초 | 3.450640 MB |
| 새 chunk 회로 | 64 | 3 | **6.727초** | 2.267초 | 2.821500 MB |
| 같은 bytecode, 다른 입력 | 64 | 3 | **호출 0회** | 2.342초 | 2.821500 MB |
| partial chunk·전체 norm 반례 | 65 | 3 | 6.701초 | 2.766초 | 4.104300 MB |
| 같은 bytecode, 다른 입력 | 65 | 3 | **호출 0회** | 2.751초 | 4.104300 MB |
| 여러 chunk·전체 norm 반례 | 1024 | 3 | **6.409초** | 17.614초 | 43.267800 MB |
| 32bit signed 경계 | 65 | 6 | 6.267초 | 5.670초 | 10.304800 MB |

전송 카운터는 내부 native application bytes이며 TLS/TCP/IP와 클라이언트 등록 통신 및 실제 업로드 서비스 통신은 제외했다. 새 경로에는 공개 입력 일치 검사 비용이 포함된다. 기존 경로는 compile 상수였으므로 계산하는 입력 처리 방식이 다르다. 통신 절감만을 한 개 최적화의 효과로 주장하지 않는다.

이전 64좌표 실행은 v2 등록 helper, 새 실행은 v3 SIMD 등록 helper를 사용했다. 따라서 표의 이전/이후 차이는 새 구현 전체의 비교이며 chunk 변경만을 고립한 측정은 아니다.

65좌표는 32좌표 chunk 3개가 필요해 64좌표보다 비용이 크다. 특히 2좌표도 기본 chunk 크기로 32좌표를 처리해 내부 통신이 1.348720 MB였다. 이전 고정 입력 2좌표 회로의 0.350628 MB보다 많다. 작은 D에서는 chunk 크기를 줄일 수 있으며, 공통 입력 검증 비용도 남는다. compile 병목 개선과 모든 D에서의 통신 개선을 같은 주장으로 묶지 않는다.

1024좌표까지 코드 전개 문제의 개선을 확인했지만 런타임 통신·AES 계산량은 D와 함께 증가한다. 전체 61706좌표를 실행하거나 실용성을 확정하지 않았다. 전체 모델에 작은 수치를 단순 외삽하지 않는다.

## 4. 외부 키 입력의 합성 보안 검토

기존의 두-word 등록 adapter는 유지했다. 다음은 **Rep4 내부 입력/변환/전처리의 malicious security와 인증된 채널을 가정한 조건부 검토**이며, 새로운 전체 프로토콜의 simulation 증명을 제시한 것은 아니다.

### 한 악성 aggregator가 등록 키를 바꾸거나 알아내는 경우

각 random triple의 global component는 세 서버에 복제되어 있다. 최대 한 서버 악성이라면 component별로 두 honest 사본이 있다. honest 클라이언트는 사본 하나라도 다르면 중단한다. 따라서 악성 서버 하나의 frame 변경으로 서로 다른 유효 triple을 전달할 수 없다. 이 확인은 링의 zero divisor에 의존하는 `c=a*b` 확률 검사만으로 대체하지 않는다.

클라이언트는 `t=k+a mod 2^64`를 각 서버에 보낸다. 서버들이 받은 t를 MPC 안에서 full-width 비교한 다음, 공통 t에서 secret a를 빼 effective key word를 만든다. malicious 클라이언트가 서로 다른 t를 보내도 일치 검사에서 중단한다. 클라이언트가 임의 t를 보내는 것은 임의 자기 키를 선택하는 입력으로 해석한다. 양질의 SGD나 자기 데이터 소유 증명은 요구하지 않는다.

한 aggregator는 a의 additive component 하나를 갖지 않는다. backend가 fresh confidential random mask a를 제공한다는 조건에서 t는 다른 honest 클라이언트의 k를 드러내지 않는다. 악성 클라이언트가 자기 등록 triple과 키를 알고 있다는 사실은 다른 등록의 random mask를 공개하는 권한이 아니다. 등록마다 독립적인 fresh mask, 올바른 preprocessing check와 입력 identity를 유지해야 한다. triple 공유의 분포와 transcript 합성은 backend 보장에 기대며 새 adapter의 완전한 증명 과제로 남는다.

두 aggregator의 shares를 합치면 모든 additive component를 갖는다. 실제 독립 사본으로 이 복원 반례를 unit test에 추가했다. **f=1은 필수 조건이며 f=2까지 확대할 수 없다.** f=1을 세션 전체에 적용한다. 시간에 따라 서로 다른 aggregator의 shares를 수집하는 공격에는 refresh/erasure 설계가 필요하다.

### 입력 확정과 반복 질의

실행 중 공개 입력 사본의 exact 일치는 추가했지만, client signature와 key handle, model/policy/context, 순서와 cohort의 인증은 아직 없다. 서버 모두가 같은 위조 값을 읽으면 일치 검사는 통과한다. 이는 클라이언트가 그 값을 실제로 제출했다는 증명을 대신하지 않는다. 구현 계획의 입력 확정·ledger 단계가 필요하다.

현재 round counter는 같은 세션에서 양수이며 strictly increasing이어야 한다. 새 회로는 signed runtime counter를 쓰므로 현재 허용 범위는 1..2^63-1이다. 두 번째 라운드에서 첫 counter를 재사용하는 시험은 중단됐다. 그러나 프로세스 재시작을 넘는 ledger는 없다. 실제 서비스를 재시작할 때 상태를 복구할 수 없으면 새 키를 등록해야 하며, 같은 키/counter의 재사용은 금지해야 한다.

같은 업데이트에 정책·cohort를 바꿔 반복 질의하면 출력 count와 합에서 추가 추론이 가능하다. 현재 synthetic runner는 이런 제품 접근 정책을 구현하지 않는다. MPC가 이러한 질의 자체를 막는 것은 아니다. durable single-evaluation ledger와 확정된 입력 digest가 필요하다.

### 출력과 중단

전체 norm 판정 전에 개인/부분 SUM을 열지 않는다. 공개하는 실패 bit와 선택 SUM/count는 기존 허용 출력이다. honest 기여 하나만 남는 경우의 역추론은 그대로다. native 출력은 검사 완료 전에는 pending이며 제품은 사후 committee 인증서 없이 모델을 갱신하면 안 된다.

프로그램이 암호학적 프로토콜 메시지 자체를 조작하는 악성 native party를 주입한 시험은 아직 하지 않았다. 이번 fault injection은 한 aggregator의 runtime 공개 입력 파일을 변조하는 시험이다. malicious backend의 일반 보장을 이 시험만으로 새롭게 증명했다고 주장하지 않는다. 공격자는 중단시킬 수 있으며 가용성 보장은 별도다.

## 5. 확인한 공격·정확성 시험

- 같은 bytecode에 다른 signed 입력: compile 0회, artifact hash 동일, 세 라운드 기준 결과 일치.
- 서로 다른 chunk의 norm을 합치면 초과하는 입력: 전체 제외.
- 마지막 partial chunk의 좌표 범위 위반과 norm 1 초과: 전체 제외.
- 한 aggregator의 공개 입력 변경 및 2^63 상위 비트 변경: 첫 라운드 출력 없이 중단.
- Q 이상 wire 및 nonzero padding: 첫 라운드 출력 없이 중단.
- round counter 재사용: 첫 정상 라운드 출력만 존재하고 재사용 라운드 출력은 없음.
- 32bit signed 최솟값·최댓값, ±B, ±(B+1), ±80000 및 zero: 6라운드 기준 결과 일치.
- 변조된 compile 설정 3종과 다른 threshold 정책의 재사용: compile/native 실행 전에 거부.
- 관련 Python 회귀 **122개 통과**, 기존 Typer/Click deprecation 경고 2개.

[9개 native 시험 요약](rep4-chunked-2026-10-11/summary.json)은 원시 compile/native/client 로그 81개의 SHA-256과 개별 결과를 보존한다. [64좌표 결과](seed-mpc-rep4-chunked-d64-2026-10-11.json)와 [컴파일 재사용 결과](seed-mpc-rep4-chunked-d64-reused-2026-10-11.json)는 별도다. replay 결과의 초기 기록은 `rounds_executed=0`으로 세션 실패를 집계했지만 로그에는 첫 정상 라운드가 있다. runner는 이후 이 경우의 완료 라운드를 1로 기록하도록 고쳤다. 과거 결과는 변경하지 않았다.

[64좌표 원시 로그 보존·해시](rep4-chunked-comparison-2026-10-11.json)에는 두 추가 실행의 compile/native/client 로그 18개를 기록했다.

## 6. 다음 연결 작업

이 단계에서 compile 전개 병목을 줄이고 runtime 입력·bytecode 재사용을 검증했다. 다음은 client 서명된 Y/context와 key handle을 확정하고, durable 라운드 ledger 및 사후 결과 인증서를 연결하는 단계다. 이후 실제 masked upload 경로를 Flower에 붙이고 고정 전체 모델 fixture부터 검증한다. 외부 등록 adapter의 종합 증명과 실제 악성 native party 검증은 이 연결의 보안 완료 조건에 남긴다.

전체 FMNIST 정확도, 독립 장비/WAN, 안전한 share 영속화는 미완료다. Flower Hub 설정이나 게시 작업은 하지 않았다.

## 7. 재현

저장소 루트에서 실행한다. 새 결과 경로를 지정해야 한다.

```sh
.venv/bin/python -m experiments.run_seed_mpc_probe --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 --backend rep4 --coordinate-circuit chunked --dimension 64 --communication-stats --output /tmp/rep4-chunk-first.json
# 위 JSON의 workspace를 다음 인자의 경로로 사용한다.
.venv/bin/python -m experiments.run_seed_mpc_probe --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 --backend rep4 --coordinate-circuit chunked --dimension 64 --case alternate --compiled-workspace <workspace> --communication-stats
.venv/bin/python -m experiments.review_seed_mpc_chunked --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3 --output-directory docs/reproduction/rep4-chunk-new-review
```

[검증 runner](../../experiments/review_seed_mpc_chunked.py), [정책·등록·반례 시험](../../tests/test_rep4_candidate.py). 시험은 공개 synthetic 키를 사용한다. 사용자 키를 보고서/로그에 포함하지 않는다.
