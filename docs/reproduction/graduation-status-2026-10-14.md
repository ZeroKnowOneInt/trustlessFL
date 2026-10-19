# 졸업작품 구현·실험 완료 현황

2026-10-14 · 주제: 악성 업데이트 방지를 위한 프라이버시 보존 연합학습

## 판단

발표의 핵심인 정상 학습 유지, 범위 초과 공격 완화, 비공개 검사·집계 정확성, 평문 대비 비용 비교는 완료했다. 이 범위로 발표 자료를 작성할 수 있다. 모든 공격에 대한 방어·대규모 실용성·독립 운영자 배포·전체 프라이버시 증명까지 완료한 시스템은 아니다.

최종 발표의 주장은 **“개별 업데이트를 직접 공개하지 않고 정적 바운더리를 검사하여, 범위를 초과하는 악성 업데이트를 집계에서 제외한다”**로 한정한다. Norm 내부의 poisoning은 설계 범위 밖이다. Carry/wrap 방지는 비공개 검사와 집계가 정확히 동작하기 위한 산술 기반으로 설명한다.

이 문서는 보존된 기록을 확인한 종합 현황이다. 학습을 재실행하지 않았으며 중단한 100명 실험도 재개하지 않았다. 주요 공개 artifact 11개의 hash가 기록된 manifest와 일치했다. [확인 기록](graduation-status-2026-10-14/evidence-check.json).

## 현재 구현

| 구성 | 구현 내용 | 상태·조건 |
|---|---|---|
| Flower 학습 연결 | 로컬 학습·양자화·마스킹·제출·인증 모델 갱신 | 실제 Flower/Rep4 실행 완료 |
| 고정 committee | A0=Flower 서버+party0, A1~A3=party1~3 | 4개 aggregator, 세션 전체 static 악성/공모 최대 1개 |
| Single mask | client별 seed component 4개, aggregator별 3개 수신, 로컬 PRG 확장·XOR mask | 최초 등록 후 같은 세션의 fresh round mask, client 간 pairwise mask 없음 |
| 비공개 입력 검사 | MPC에서 정확한 mask 제거·signed 복원, 좌표·전체 L2 검사 | 개별 update/norm/통과 비트를 직접 열지 않음 |
| 정확한 정수 집계 | 작은 wire modulus와 넓은 집계 ring 분리·정수 폭 검증 | signed 입력과 Q보다 큰 최종 합을 정확히 처리 |
| 입력·결과 인증 | 서명·context binding·3-of-4 QC·native CHECK·SQLite durable lock | 충돌 입력·불확실한 동일 세션 재실행·중복 모델 적용 제어 |
| Dropout·복귀 | 완전한 제출·receipt 집합을 마감에 고정, ACK 비동기, 인증 체인 catch-up | 초기 등록 뒤 이탈·복귀, roster 변경은 지원하지 않음 |
| 사용자 모델 | plugin/model.json·데이터·고정 정책 설정, 회로 cache | MLP·소형 CNN·LeNet5 실행; 무제한 임의 학습 hook 지원은 아님 |
| 역할별 배포·설치 | 수신자별 암호화 seed packet, mTLS·운영자 승인·앱 bytes 검사, backend 자동 준비 | Docker 역할 분리 실행; client는 MP-SPDZ/compiler/Ray 설치 불필요 |
| 비용 개선 | lane batching·checked native import·ACK 회수·manifest cache | 학습·정수 결과 일치 확인 및 비용 재측정 |
| 최근 대규모 준비 개선 | 공유 전송 객체·compact client loop·bounded RPC·prepared material reference·입력 batch 쓰기 | 관련 533 tests 및 작은 실제 native/Flower 검증, 100명 학습 완료 아님 |

현재 구현은 Aion의 HPRF/Feldman VSS 구조를 그대로 옮긴 것이 아니다. 검증된 MP-SPDZ 0.4.3 active Rep4와 승인된 holder-checked importer를 사용한다. 최신 핵심 경로는 [seed component 프로토콜](../aion-seeded-components-protocol.md), [native import](../aion-direct-rep4-import-protocol.md), [사용자 실행](../seed-mpc-user-runtime.md), [역할별 배포](../seed-mpc-independent-hosts.md)에 있다.

## 발표의 핵심 실험: 완료

조건: FMNIST train 60,000/test 10,000, LeNet5 61,706 parameters, client4·aggregator4, client당 15,000개 IID, seed42/43/44, 조건별 5 rounds. Local epoch1, batch64, SGD lr0.01/momentum0.9/weight decay0.0005. 양자화 S=10,000, wire Q=65,536, 좌표 B=20,000, squared L2 T=2,500,000,000, 최소 통과2.

비교군은 무필터 양자화 평균, 평문 동일 bound 검사, 실제 Flower·Rep4 비공개 bound 검사다. 같은 seed의 분할·초기 모델·학습·공격 규칙을 맞췄고 모델이 달라지면 각각 현재 모델에서 학습했다.

| 조건 | 무필터 평균 | 평문 bound | 비공개 MPC bound |
|---|---:|---:|---:|
| 정상: 3 seeds 평균 최종 정확도 | 86.24% | 86.24% | 86.24% |
| L2 범위 초과 공격: 평균 최종 정확도 | 19.58% | 86.03% | 86.03% |
| 공격 조건 악성 제출 제외 | 0/15 | 15/15 | 15/15 |
| 정상+공격 조건의 정상 제출 제외 | 0/105 | 0/105 | 0/105 |

공격자는 C0 한 명이며 자기 업데이트를 부호 반전·확대해 L2 반경 약10으로 만든다. 모든 좌표는 좌표 bound 안에 있어 global L2 검사가 차단 원인이다. 공격자에게 honest update를 주지 않았다. 실제 MPC 정상·공격 6회/30 rounds, 120 client-round 입력을 참조와 대조했다. 모든 라운드의 정수 SUM/count·모델·평가가 평문 동일 bound 및 별도 재학습과 정확히 일치했다.

![정상·공격 학습 비교](graduation-three-way-2026-10-12/accuracy.png)

[실험 상세와 공개 JSON](graduation-three-way-2026-10-12.md). 이 실험은 3-seed·한 모델·한 데이터셋·한 범위 초과 공격의 결과다. 모든 poisoning에 대한 방어 결과로 표현하지 않는다.

## 평문 대비 비용: 완료

공정한 비용 대조를 위해 공식 Flower 실행에서 동일 데이터·학습 조건의 평문 bound와 비공개 MPC를 새로 학습했다. 다음은 공격 조건 3 seeds의 **5 rounds 평균**이다. 준비/컴파일과 사후 oracle는 ServerApp 시간에서 제외한다.

| 지표 | 평문 bound | 비공개 MPC | 배율 |
|---|---:|---:|---:|
| ServerApp 전체 시간 | 36.44초 | 186.69초 | 5.12배 |
| 추적 계층 payload | 22.28MB | 2,164.74MB | 97.16배 |

비공개 MPC native 4-party 송신량은 5 rounds 합계1,369.29MB, 라운드 평균273.86MB다. Native setup은33,884 bytes이며 전체 초기 등록·Flower/RPC 통신을 뜻하지 않는다. 전체 payload는 Flower 논리 object graph/RPC body/native Player 계측의 합이고 TCP/TLS 전체 wire, 미추적 IPC를 포함하지 않는다. Flower의 메시지 간 cache 할인도 적용하지 않았다. ServerApp 시간은 순수 MPC 시간과 다르다.

ACK·동기화 개선 전후의 같은 조건에서 ServerApp518.61→186.69초(64.0% 감소), 추적 payload2,613.16→2,164.74MB(17.2% 감소)였다. Native MPC 통신량은 이 개선에서 줄지 않았다.

[평문 대비 비용](flower-cost-improved-2026-10-12.md), [개선 전후](flower-cost-improvement-2026-10-12.md).

위 공격·비용 수치는 2026-10-12 당시 기록된 source/backend 계약의 실측이다. 그 후 추가된 compact loop·reference RPC의 전체 LeNet5·100명 비용을 실측한 숫자로 재사용하지 않는다.

## 보조 검증: 완료한 범위

| 검증 | 완료 결과 | 발표에서의 역할 |
|---|---|---|
| Wire wrap·wide SUM | 4/8/16명 fixture에서 +80,000/+160,000/+320,000 및 음수 합 정확 복원 | 집계 산술 정확성 |
| Client 수 변경 | D53 합성 학습, 4/8/16명 실제 Flower·Rep4 각2 rounds | 설정 범용성; 대형 모델의 16명 검증은 아님 |
| Dropout·복귀 | 작은 native/Flower fixture 및 Docker에서 4→3→4 | 장애 처리 기능 |
| Native 악성 변조 | component·share·opening 등 지정한 변조 검출, 잘못된 결과 인증·갱신 없이 중단 | 구현 무결성 사례; 전체 보안 증명 아님 |
| 역할 분리 | Docker filesystem/network 분리, 다른 역할 비밀 파일 접근 차단 | 배포 기능; 네 독립 기관 검증 아님 |
| 설치 패키지 | wheel을 별도 client 환경에 설치, native backend 없는 client로 MLP/CNN 실행 | 설치·범용 사용자 경로 |
| 다른 모델 | D666 CNN 사용자 adapter, D53 MLP, Docker D435 CNN | LeNet 전용 구현이 아님을 확인 |
| Non-IID 정상 입력 | 선택한 L2 반경5에서 평문 모델과 실제 MPC15 rounds 일치 | 선택적 보충자료; 범용 threshold를 찾았다는 주장이 아님 |
| 범위 안의 공격 | 평문 다중 seed와 일부 실제 MPC 대조에서 악성 입력 통과 | 방어 범위 설명; 핵심 방어 성공과 분리 |

Norm 안의 방향 공격에서 평문 3-seed 평균 정확도가73.82%로 내려간 기록이 있다. 이는 우리의 입력 계약이 norm만 제한한다는 한계를 보여준다. 평문 3-seed 결과와 seed42 실제 MPC 결과를 구분한다. 주제의 범위를 명확히 설명할 때 사용할 수 있다.

관련 자료: [client 수](client-counts-2026-10-11.md), [변조·공격](seed-mpc-security-experiments-2026-10-11.md), [직접 import](direct-rep4-import-2026-10-11.md), [역할 분리](independent-hosts-2026-10-12.md), [설치](package-validation-2026-10-12.md), [다른 모델](small-cnn-adapter-2026-10-11.md), [Non-IID](noniid-threshold-2026-10-12.md).

## 미완료·보장하지 않는 부분

- **100명 실제 학습:** LeNet5와 소형 CNN 모두 완료하지 못했다. 소형 CNN100명 준비·컴파일은 완료했고 Flower 시작 뒤 WSL 오류로 중단됐다. 인증된 완료 result JSON은 없다. 사용자 지시로 중단했으며 이번 확인에서 재개하지 않았다. RAM 압박은 관측됐지만 모든 WSL 중단의 직접 원인이 입증된 것은 아니다.
- **대규모 확장성·메모리 실측:** 100/1,000명 수식 외삽을 완료한 벤치마크로 표현하지 않는다.
- **실제 네 독립 물리 호스트·운영자:** 네트워크 실행 경로와 Docker 검증은 있으나 서로 다른 네 기관에서의 운영·WAN 성능 검증은 없다.
- **최신 전체 코드의 최종 release 검증:** 최근 최적화는 533개 관련 회귀와 작은 native4/Flower2 rounds로 검증했다. 이전 wheel/Docker·전체 LeNet 실험에 최근 변경이 전부 포함되었다고 주장하지 않는다.
- **전체 보안 증명·가용성:** DP·등록부터 출력까지의 composition 증명·두 aggregator 공모 방어·BFT view change/중단 후 진행 보장은 없다. 최대1 static 악성 aggregator 계약이며 abort 가능성이 있다.
- **출력 역추론:** SUM/count/abort/모델은 허용된 공개값이다. Count에서 판정을 추론하거나 알려진 기여를 빼 개인 기여를 알아내는 가능성은 남는다. 최소 통과2가 honest2를 보장하지 않는다.
- **전체 프로젝트 테스트:** 최신 관련 suite533 passed이며 전체 repo suite 통과라는 뜻은 아니다. 과거 전체 suite는 외부 원본 Aion fixture 부재로 실패했다. 날짜별 테스트 수를 합산하지 않는다.
- **Flower Hub:** 업로드·계정 설정·최종 운영 배포는 수행하지 않았다.

## 발표 구성

1. 문제: 보안 집계만으로 범위 초과 악성 업데이트의 포함을 막을 수 없으며, 평문 검사는 개별 업데이트를 직접 드러낸다.
2. 구조: 고정4 aggregator·single mask·MPC 내부의 정적 좌표/전체 L2 검사·허용된 SUM/count 공개.
3. 정확성: 작은 wire residue를 signed 정수로 복원하고 넓은 ring에 집계하여 carry/wrap 오류를 피한다.
4. 핵심 결과: 정상86.24% 유지, 공격 시19.58%→86.03%, 악성15/15 제외·정상0/105 제외.
5. 비용: 동일 Flower 평문 bound 대비 시간5.12배·계측 payload97.16배와 개선 결과.
6. 적용 범위: norm 밖 공격 차단, static 최대1 aggregator 공모, 출력 추론·비용·100명 검증 미완료를 설명한다.

발표에 필요한 핵심 실험을 위해 threshold 탐색이나100명 실험을 반드시 추가할 필요는 없다. 대규모 실용성·모든 poisoning 방어를 발표의 주장에 추가하려면 별도 검증이 필요하다.
