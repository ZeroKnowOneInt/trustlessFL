# Seed-MPC 통신 계측: 등록·라운드·종료 분리 (2026-10-11)

계획의 단계 4를 구현했다. **같은 실행에서 네 native party의 정확한 byte counter를 읽고, 등록 + 각 라운드 + 종료가 전체 counter와 일치함을 확인했다.** Flower 직렬화 객체 그래프, aggregator RPC JSON, 최초 client private-input socket은 서로 다른 계층으로 기록했다. 이 자료는 로컬 기능·계측 검증이며 전체 프라이버시 증명이나 WAN 성능 평가가 아니다.

WSL Ubuntu-24.04 `/home/hacho/@WSL-Projects/trustlessFL`, branch `work/aion-private-bound-no-wrap`에서 실행했다. Committee 4개, static 악성 aggregator 최대 1개라는 기존 계약, AES single mask, 최초 seed 등록·세션 내 재사용, 정적 norm/좌표 검사, CHECK 이후 결과 서명 규칙을 유지했다. Flower Hub 설정·게시를 수행하지 않았다.

## 구현과 측정 정의

기존 MP-SPDZ 0.4.3 공식 설치·바이너리를 보존했다. 별도 `mp-spdz-0.4.3-telemetry` 빌드에는 `Processor/BaseMachine.cpp`의 출력만 추가했다. START/STOP에서 `total_stats().comm_stats.sent`, 최종 집계에서 upstream이 기존 Global MB 출력에 쓰던 `stats.sent`와 `global`을 정수로 출력한다. 네트워크 연산·검사·프로토콜 계산은 패치하지 않았다. [패치](../../trustlessfl/seed_mpc_telemetry_patch.py), [격리 빌드](../../experiments/build_seed_mpc_telemetry.py).

공식 archive SHA256은 `4b5f4f7a79f31365288fe4498ba2b70afc314c028696929c8d259ef50ab2e759`다. Observer binary SHA256은 `1ad2ddb90f6bcd715bcfac7e85b168688b46275c7e86b21b36334bfc6bb50e95`, 승인 build manifest SHA256은 `7af95c645bdfec6f24f2df71c51ebf9e399477737355e809dba7b09549886909`다. G++ 13.3.0, `-O2`와 고정 x86 명령 옵션을 사용했다. 정확한 CONFIG.mine, shared library, 17개 실제 loader dependency 및 다운로드한 dependency package hashes는 [빌드 기록](seed-mpc-meter-2026-10-11/normal/telemetry-build.json)에 있다.

Backend pin은 archive에서 알려진 패치를 다시 유도하고, 승인된 build manifest hash를 코드 상수와 비교한다. Caller가 임의 binary·patch·manifest·shared library를 만들어 자기끼리 hash를 맞춰도 받아들이지 않는다. 실제 `ldd` 경로와 library hashes를 확인하고 `LD_PRELOAD/LD_LIBRARY_PATH/LD_AUDIT` override를 거부한다. 이는 신뢰된 로컬 빌드의 artifact 고정이다. 다른 호스트·설치 경로·compiler·OS library 버전에서는 검토 후 명시적으로 다시 pin해야 하며, reproducible binary build나 전체 보안 증명을 주장하지 않는다.

계측 config도 compile/execution hash에 결합한다. 회로의 최초 시작과 등록 CHECK 직후는 timer 7, 각 라운드 시작과 결과 CHECK 직후는 timer 8을 사용한다. 결과 인증은 기존 locally owned native CHECK 경로를 그대로 사용한다. Counter의 순서·개수·단조성·CHECK 결합·네 party의 Global 합을 별도 검증한다.

Party p의 등록 종료 counter를 R_p, 각 라운드 START/STOP을 A_pr/Z_pr, 최종 counter를 F_p라 두면,

\[
\mathrm{setup}=\sum_pR_p,\quad
\mathrm{round}_1=\sum_p(Z_{p1}-R_p),\quad
\mathrm{round}_r=\sum_p(Z_{pr}-Z_{p,r-1}),\quad
\mathrm{shutdown}=\sum_p(F_p-Z_{pR}).
\]

따라서 setup + 모든 round + shutdown = sum_p F_p다. START→STOP의 active 비용과 이전 STOP→START의 사이 비용도 별도 저장한다. 이번 실행에서 사이 비용은 모두 0이었다. 시작 시점의 **추적된** counter도 0이었다. 이는 TCP/TLS 연결 비용이 0이라는 뜻이 아니다.

| 경로 | byte의 의미 | 합산 규칙·제외 범위 |
|---|---|---|
| Native 내부 | upstream Player/ThreadQueues가 추적한 payload 송신 | 네 송신자의 합. 송수신 양쪽을 더해 링크를 두 번 세지 않는다. Live preprocessing 포함. `no_stats` 초기/최종 교환, native framing, TLS/TCP/IP·재전송 제외. 수신 counter는 측정하지 않았다. |
| Flower | 실제 `deflate()`의 Message/Record/Array 자식 객체 길이 | 한 메시지 안의 같은 객체는 한 번, 다른 메시지 사이의 dedup/cache 할인은 적용하지 않는다. Coordinator Grid에서 수락된 요청·관측한 응답의 표현 크기다. Ray 내부 복사·저장·중계·HTTP/protobuf framing/실제 wire traffic은 측정하지 않았다. |
| Aggregator RPC | urllib에 제출한 실제 canonical JSON 요청 body와 읽은 응답 body | 네 service 호출을 각각 센다. 이번 성공 실행에서는 service에서 실제 읽고 쓴 body와 action/round/direction별로 독립 대조했다. HTTP header/TCP 제외. 실패한 연결의 부분 송신은 wire counter로 해석하지 않는다. |
| 최초 external seed 입력 | client endpoint에서 octetStream payload + 4-byte framing | 각 연결의 한쪽 endpoint에서 송수신을 센다. Pre-TLS client identifier와 domain/등록 tag도 포함. TLS handshake/record/TCP overhead 제외. Native 내부 Player counter와 구분한다. |

늦은 Flower reply는 도착한 라운드가 아니라 **원래 요청 라운드**에 귀속한다. 관측하지 못한 late/dropout reply나 조회되지 않은 runtime 객체까지 전송된 byte라고 주장하지 않는다. 계측 결과에는 공개 category·counter만 보존하며, seed/share/개별 norm·선택 bit·raw update를 담지 않는다.

## 실제 native 결과

표의 값은 모두 네 party의 합이며 decimal bytes다. 각 실행은 새 세션·fresh seed, compile 1회, client별 seed 입력 1회다.

| 실행 | 차원·라운드 | 등록 및 추적된 셋업 | 라운드별 내부 송신 | 추적된 종료 | 전체 |
|---|---|---:|---|---:|---:|
| V2 정상/위반 입력 fixture | 65 / 3 | 188,960 | 1,718,868 / 1,118,580 / 1,118,580 | 0 | 4,144,988 |
| V2 dropout fixture | 65 / 10 | 454,064 | 아래 표 | 0 | 13,641,144 |
| V2 소형 FMNIST | 170 / 3 | 301,280 | 2,808,836 / 2,808,836 / 2,208,996 | 0 | 8,127,948 |

정상 fixture의 CHECK 이후 SUM/count·모델은 참조와 모든 좌표에서 일치했다. 첫 라운드 4명 통과, 둘째 2명 통과, 셋째 1명만 유효해 인증 abort·모델 유지였다. Dropout fixture는 이전 10라운드 시나리오와 같은 receipt·absence·ACK 누락·복귀·partial·abort를 검증했고 receipt QC 28개가 유효했다. 소형 FMNIST는 client당 256장·테스트 1,024장·16 feature 선형 모델이며 독립 재학습·양자화·정수 합·모델·평가가 일치했다. **이번 계측 실행은 61,706파라미터 LeNet5의 재실행이 아니다.**

| Dropout round | Native 송신 bytes | Flower 그래프 요청+관측 응답 bytes | RPC JSON 요청+응답 bytes |
|---|---:|---:|---:|
| 등록 | 454,064 | 6,296 | 240 |
| 1 | 1,618,900 | 84,844 | 262,852 |
| 2 | 1,118,580 | 192,529 | 207,168 |
| 3 | 1,618,900 | 125,550 | 151,856 |
| 4 | 1,118,580 | 195,320 | 263,532 |
| 5 | 1,118,580 | 270,870 | 263,044 |
| 6 | 1,618,900 | 214,289 | 152,232 |
| 7 | 1,118,580 | 190,923 | 92,784 |
| 8 | 1,618,900 | 198,791 | 263,340 |
| 9 | 1,118,580 | 145,661 | 37,912 |
| 10 | 1,118,580 | 131,566 | 263,824 |
| 종료 | 0 | 0 | 8,060 |

Native의 라운드별 차이는 live preprocessing 배치 생성·소비에서 발생한다. 현재 회로는 absent slot도 고정 chunk 흐름으로 처리하므로 dropout 인원에 비례해 MPC 비용이 줄어들지 않는다. Round 7/9의 abort도 회로 계산 비용이 있다. 같은 round 슬롯 수·회로에서만 setup 값의 비교가 의미 있으며, 이 값이 모든 workload의 고정 셋업 상수는 아니다. Offline 비용 전체를 처음 셋업으로 차감하지 않았다.

Flower와 RPC 표는 각각의 정의로 읽어야 한다. 서로 다른 계층을 합쳐 실제 wire byte라고 표시하지 않는다. ACK 부재 시 다음 train 요청에 인증 suffix가 추가되므로 Flower 크기는 전달한 체인에 따라 달라진다. 일부 같은 content가 runtime에서 cache/dedup될 수 있으며 여기서는 메시지마다 직렬화된 표현 크기를 센다.

세 계측 profile 모두 external 입력은 client당 송신 244 bytes/수신 656 bytes였다. 네 client의 합은 송신 **976 bytes**, 수신 **2,624 bytes**다. 세션 초기 한 번이며 라운드마다 seed를 보내지 않았다. 여기에도 등록 서명·Flower 제어 메시지·native 내부 등록 비용은 따로 기록돼 있다.

## 시간과 회귀

| 실행 | Compile 1회 (초) | ServerApp wall (초) | 서비스 시작→Flower CLI→소유 프로세스 정리 (초) |
|---|---:|---:|---:|
| V2 정상 | 6.231 | 5.407 | 17.280 |
| V2 dropout | 6.834 | 14.071 | 25.899 |
| V2 소형 FMNIST | 6.382 | 9.489 | 21.294 |

서비스/native 세션 wall, Flower 자체 elapsed, 라운드별 execute+인증 시간, client-local 학습/양자화 및 마스킹/서명 counter도 [JSON](seed-mpc-meter-2026-10-11/summary.json)에 보존했다. Client 시간은 trusted test counter이며 데이터 load와 시험용 audit 기록 등이 포함되는 구간이다. 서로 겹치는 wall/CPU counter를 더하지 않는다. Harness wall은 stage/compile 및 사후 독립 oracle를 제외한다. Native-only 전체 순수 계산 시간 또는 WAN 지연이라고 해석하지 않는다.

Python 회귀 **351개**가 통과했다. 새 검사는 malformed/음수·감소·중복·누락 counter, CHECK/라운드 불일치, Global 불일치, Flower 배열 자식의 길이, late reply의 원래 round 귀속, RPC 성공/409 body 길이, observer source/binary/config/library/manifest 대체·loader override 거부를 포함한다. Native 실제 실행에서는 정수 합·모델과 RPC 양 endpoint 길이를 독립 대조했다.

기존 공식 binary의 **v1 정상 3라운드**도 별도 새 세션에서 통과했다. 기존 v1 공식 backend pin과 historical archive를 보존했다. [v1 증거](seed-mpc-meter-2026-10-11/legacy-v1/verification.json).

## 재현·공개 자료·남은 범위

해당 승인 observer build가 설치된 현재 WSL 환경에서 다음을 실행한다. 새 output directory가 필요하다.

```bash
cd /home/hacho/@WSL-Projects/trustlessFL
.venv/bin/python experiments/run_seed_mpc_meter.py \
  --output .cache/seed-mpc-meter-reproduction-new
```

별도 native build를 재생성하는 명령은 `.venv/bin/python experiments/build_seed_mpc_telemetry.py --jobs 2`다. 공식 archive를 읽고 dependency .deb를 user-local directory에 추출하므로 sudo나 공식 설치 변경은 필요 없다. 빌드 결과가 승인 hash와 다르면 원인 검토·명시적 repin 전까지 실행하지 않는다. 자동으로 새 빌드를 신뢰하는 기능은 없다.

단독 Flower 실행은 `experiments/run_seed_mpc_flower.py --mp-spdz-dir .cache/private-bound-mpc/mp-spdz-0.4.3-telemetry --communication-meter --snapshot-version 2 ...`로 가능하다. 기본 공식 설치/비계측 경로는 유지한다.

공개 archive는 whitelist로 생성한 **144개 artifact와 manifest**이며 [SHA256 manifest](seed-mpc-meter-2026-10-11/sha256-manifest.json)의 전부를 확인했다. Summary·검증·인증 자료·공개 모델·counter checkpoint·빌드 기록·source hashes를 보존한다. Client private directories, raw-update audit, seed/share·private signing/TLS keys는 복사하지 않았다.

단계 4의 application-counter 계측은 완료했다. 다음은 단계 5의 역할 격리와 실제 악성 경로 검증이며 전체 FMNIST dropout/추가 규모 검증은 단계 6이다. 같은 UID 시험, 고정 committee, native 4-party 동시 실행 필요, 허용 출력 역추론, share 재시작 복구 미구현이라는 기존 한계가 남아 있다. 기존 전체 LeNet5 5라운드의 4.12698GB를 이번 작은 모델 계측값으로 재분배하거나 규모에 선형 외삽하지 않는다.
