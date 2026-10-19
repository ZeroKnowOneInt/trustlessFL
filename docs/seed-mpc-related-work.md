# 일반 PRG + seed MPC와 유사한 FL 선행연구

검토일: 2026-10-10  
대상: `aion-seed-mpc-protocol.md`의 single mask, 작은 seed 등록, aggregator 내부 비공개 검사와 정확한 정수 집계.  
범위: 논문 원문과 저자 공개 저장소 검토. 선행연구 구현을 실행하거나 성능을 재현하지 않았다.

## 판단

**유사한 연구가 있다.** 다중 서버의 비공개 norm 검사는 AlphaFL과 ELSA, AES-CTR 기반 다중 서버 마스킹은 Falkor가 가깝다. 따라서 MPC norm 검사나 FL의 overflow 방지 자체를 새로운 아이디어라고 설명하면 안 된다.

현재 확인한 문헌에서는 **클라이언트별 seed 하나를 처음에 공유하고, 그 seed로 MPC 내부에서 AES 마스크를 생성하며, 작은 전송 modulus에서 개별 값을 비밀 복원한 뒤 큰 계산 공간에서 검사·합산하는 전체 조합**과 동일한 구조를 찾지 못했다. 이는 신규성 증명이 아니다.

## 비교

| 연구 | 우리 설계와 가까운 부분 | 구분해야 할 차이 |
|---|---|---|
| AlphaFL, PoPETs 2025(4) | 2서버 MPC의 비공개 좌표/norm 검사와 통과 업데이트 선택 집계 | 업데이트 벡터를 인증 공유하는 입력 방식; 동적 norm bound; 일회 seed 등록형 AES-MPC가 아님 |
| ELSA, IEEE S&P 2023 | 2서버가 공유된 업데이트의 norm을 계산; 좌표 상한과 finite-ring overflow 관계를 명시 | 클라이언트가 비신뢰 correlation 공급과 transcript 검증에 참여; malicious privacy와 완전한 악성 정확성 구분 필요 |
| Falkor, WAHC 2023 | AES-CTR, 초기 키 설정, 다중 서버, 공개 masked vector를 이용한 통신 절감 | 클라이언트–서버별 키/마스크 성분을 합침; 각 서버의 AES 계산은 로컬 연산이며 비밀 seed의 MPC AES와 다름 |
| ScionFL | 여러 서버에 위탁한 MPC와 양자화 업데이트 집계 | 기본 서버 모델은 semi-honest; 비용 절감에 근사 변환을 사용하므로 exact 정수 SUM 요구와 구분 |

## AlphaFL에서 가져올 부분

[논문](https://petsymposium.org/popets/2025/popets-2025-0134.pdf) §3.2는 유한 ring의 norm 계산이 overflow 때문에 잘못될 수 있어 좌표별 상한도 필요하다고 설명한다. §4.1은 외부 클라이언트의 입력 인증과 서버–클라이언트 공모를 별도로 다룬다. §4.3의 silent select는 개별 검사 결과를 열지 않고 통과 입력을 집계한다.

우리의 정적 threshold 결정은 유지할 수 있다. 동적 threshold가 비공개 검사에 필수 조건은 아니다. 다만 논문의 전체 회로와 정적 변형이 동일하다고 주장할 수는 없다.

[저자 구현](https://github.com/Barkhausen-Institut/AlphaFL)은 MP-SPDZ 0.3.9 기반이며 입력 등록에 별도 코드가 있다. 현재 프로젝트의 MPC backend 선택만으로 악성 외부 입력의 인증이 해결됐다고 간주하지 말고, seed 등록 인터페이스가 선택한 공모 모델을 충족하는지 확인해야 한다. 이것은 우리 4서버 설계에서 취약점이 입증됐다는 뜻은 아니다.

## ELSA에서 가져올 부분

[논문 §1.2](https://par.nsf.gov/servlets/purl/10400324)의 L2 확장은 좌표 상한을 확보하고 제곱합을 계산한다. L2 검사를 위해 제곱합 계산 자체에 overflow가 없어야 한다고 명시한다. 우리 설계의 `좌표 검사 → invalid 좌표 sanitation → 충분히 넓은 공간의 제곱합`과 목적이 같다. 이는 HPRF 마스크의 rounded carry 복원 문제를 같은 방식으로 해결했다는 의미는 아니다.

클라이언트는 correlation 공유와 검증용 transcript 생성에도 참여하므로 단순히 업데이트만 보내는 클라이언트와 동일하지 않다.

[공개 코드 README](https://github.com/ucbsky/elsa)는 L2 enforcement 단계가 구현되지 않았고 일부 중간 검사 결과의 deferred opening도 미완료라고 밝힌다. 완성된 검증 시스템으로 바로 사용하기보다는 구성 요소와 설계를 참고해야 한다.

## Falkor에서 가져올 부분

[논문 §2](https://eprint.iacr.org/2023/804.pdf)의 마스크 구조는 다음과 같다. 연산 공간은 좌표별 modulo 2^64다.

`A_i = M_i + sum_j mask(sk_(i,j), r)`

각 클라이언트는 서버마다 별도 키를 공유한다. 전송하는 masked vector는 하나지만, 그 안에는 여러 독립 마스크 성분이 있다. 클라이언트 간 pairwise mask와도 구분한다. 우리 설계의 하나의 공유 seed에서 만든 single mask와는 다르다.

[저자 설명](https://pub.sandboxaq.com/publications/falkor-federated-learning-secure-aggregation-powered-by-aes-ctr-gpu-implementation)의 GPU AES 성능은 각 주체가 자신의 키로 실행하는 로컬 계산에 관한 것이다. 이를 비밀 키 AES-MPC의 성능으로 사용할 수 없다. 공개 masked vector로 통신량을 줄인다는 목적은 가깝지만, 우리에게 필요한 악성 입력 norm 검사까지 동일하게 포함됐다고 확인한 것은 아니다.

## ScionFL의 위치

[논문](https://arxiv.org/html/2210.07376) §II-B와 §III-B는 각각 semi-honest MPC 서버 모델과 근사 bit conversion을 설명한다. 다중 서버 위탁과 양자화의 비교 대상으로 적합하다. 우리 요구의 active security와 exact 정수 집계를 같은 조건으로 만족하는 기준선은 아니다.

## 현재 프로토콜에 주는 의미

1. 서버 내부 비공개 검사는 검토된 연구 방향이다. 클라이언트 norm ZKP가 유일한 방법은 아니다.
2. wrap 검토는 세 부분으로 나눠야 한다: 전송 residue의 개별 signed 복원, norm 제곱합의 폭, 최종 SUM의 폭. 앞의 두 논문이 finite-ring overflow를 인식했다는 사실만으로 우리 전체 조합의 정확성이 증명되지는 않는다.
3. 입력 비교 기준선은 AlphaFL 계열의 인증 벡터 공유가 적절하다. 작은 seed 등록이 클라이언트 통신을 줄이는 이득과 MPC AES가 추가하는 비용을 함께 비교해야 한다.
4. 현 후보의 기여 가능성은 작은 전송 word, 생성키 재사용, 정확한 비공개 검사·집계를 Flower에서 연결하는 데 있다. 보안 증명과 비용 검증 전에는 새로운 보안 프로토콜로 확정하지 않는다.

원문 접근 범위: AlphaFL·ScionFL 본문과 저자 저장소는 직접 열어 확인했다. ELSA의 해당 본문과 Falkor의 프로토콜 절은 원문 PDF의 검색 인덱스에서도 확인했다. 일부 PDF 직접 다운로드는 차단되어 전체 텍스트를 로컬에 확보하지 못했다.
