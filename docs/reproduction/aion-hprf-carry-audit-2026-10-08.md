# Aion HPRF carry 감사 — 2026-10-08

## 결론과 범위

원본 HPRF의 정수 대표값을 일반 정수로 더하면 `D = c*p + e`의
`c != 0` 사례가 실제로 존재한다. 그러나 **원본 SA 서버와 기존 Flower
비-MGF FixedPoint 경로는 이미 모듈러 합산/차감을 한다.** 따라서 그 경로에
미처리 carry 버그가 있다는 주장은 이번 검사 결과와 맞지 않는다.

집계 런타임은 변경하지 않았다. 독립 산술 감사와 회귀 테스트만 추가했다.
논문/MGF의 스케일된 실수 합산은 별도 경로이며 이번에 변경하지 않았다.
ZKP, MGF, VSS, share-mask 일관성, ASR 누출 정책, poisoning 방어도 변경하지 않았다.
정확한 산술 복원은 HPRF의 암호학적 안전성 검증을 뜻하지 않는다.

## 1. 현재 Aion/HPRF 코드 구조

| 작업 | 원본 또는 현재 구현 |
|---|---|
| 원본 HPRF | `../Aion/agent/Aion/HPRF/hprf.py`: `HPRF.G_batch`, `HPRF.hprf` |
| 정수 호환 포팅 | `trustlessfl/aion_original_hprf.py`: `OriginalAionHPRF.hprf` |
| 원본 클라이언트 마스킹 | `../Aion/agent/Aion/SA_ClientAgent.py`: `sendVectors` |
| 원본 마스킹 벡터 합산 | `../Aion/agent/Aion/SA_Aggregator.py`: `report_process` |
| 원본 ASR와 합계 마스크 | 같은 파일 `reconstruction_process`: `vss.reconstruct`, `hprf(seed_sum, ...)` |
| Flower 수치 처리 | `trustlessfl/numeric.py`: `FixedPoint.encode`, `mask`, `_mask`, `unmask` |
| Flower 프로토콜 ASR와 복원 | `trustlessfl/protocol.py`: `_reconstruct_key`, `Party.finalize` |
| 저자 코드 실행 포팅 | `trustlessfl/aion_source_asr.py`: `source_request`의 mask/select/reconstruct 분기 |
| 해당 포팅의 키 공유/복원 | `trustlessfl/aion_source_sharing.py`: `share_seed`, `sum_keys`, `recover_key_opening`, `recover_key` |
| 로컬 DMC/DMR 수치 참조 | `trustlessfl/paper_dmc.py`: `PaperDMC.mask`, `remove`, `remove_centered`, `remove_quantized_lift` |
| 별도 스케일된 MGF 수치 경로 | `trustlessfl/source_paper_numeric.py`: `mask_integer_wire`, `select_masked`, `recover` |

원본 `report_process`는 벡터를 더할 때마다 `% self.hprf_prime`을 수행한다.
`reconstruction_process`도 마스크 차감 후 `% self.hprf_prime`을 수행한 뒤
참여자 수로 정수 나눗셈한다. 따라서 대표값 carry 자체는 이 모듈러 연산에서 사라진다.
다만 원본 `sendVectors`는 마스크를 float64로 변환한다. 이로 인한 정밀도
손실과 원본 벤치마크의 signed/fixed-point 처리 부족은 **별개 문제**이다.

Flower `Party.finalize`의 비-MGF 경로는 `sum(values) % p` 뒤
`FixedPoint.unmask`를 호출한다. `aion_source_asr`의 비-paper 학습 경로는
클라이언트에서 `Delta*z + (h % p)`를 정수로 보낸다. 전송값 전체를 다시
`% p`하지는 않지만 원본 서버의 모듈러 합산과 codec의 모듈러 차감으로
산술 복원은 동일하다. 이번 감사는 이 wire 형태를 바꾸지 않았다.

## 2. HPRF modulus와 representative convention

이번 검사는 원본 `initialization_values`와 `matrix`를 그대로 읽었다.

- `n = 128`, 블록 출력 폭 `m = 512`.
- 출력 모듈러스 `p = 14760426300877770769` (64-bit).
- 내부 모듈러스 `q = 73802131504388853845` (67-bit), `q = 5*p`.
- `init.py`의 생성용 상수와 현재 저장된 초기화 파일의 상수는 다르다.
  이번 실험은 **저장된 파일의 값**을 사용하고 행렬을 재생성하지 않았다.

각 좌표는 다음 정수 계산을 한다. `a_j`는 공개 행렬의 열 합이다.

```
t_j = ((k * (round + block)) mod q) * a_j mod q
h_j = floor((p*t_j + floor(q/2)) / q)
```

원본과 포팅 모두 Python 정수 리스트를 반환한다. 반환 자체는 field 객체가
아니며 `0 <= h_j <= p`이다. 최종 `% p`가 없으므로 반올림 경계에서 `p`가
가능하다. Flower `_mask`는 wire 경계에서 `% p`하여 `[0,p)`로 정규화한다.
내부 `q`는 여기서 합성수이므로 모든 공간을 소수 유한체라고 부르는 것은
정확하지 않다. 필요한 성질은 모듈러 덧셈이며 출력 링 `Z_p`이면 충분하다.

기존 codec의 center는 `x > p//2`이면 `x-p`를 선택한다. 따라서 홀수 p는
`[-floor(p/2), floor(p/2)]`, 짝수 p는 `(-p/2, p/2]`이다. 새 감사 helper도
이 convention을 따랐다. 실제 안전 조건은 엄격한 `< p/2`이므로 짝수
midpoint는 허용된 입력에서는 나오지 않는다.

## 3. Carry 문제가 실제로 존재했는지

**정수 대표값의 차이에는 존재한다. 기존 모듈러 집계의 미처리 carry 버그로는
재현되지 않았다.** Seed `20261008`, 참여자 수 2/3/4/20/100, 각 8회,
무작위 키 `[1,100000]`, 무작위 라운드 `[1,1000]`으로 검사했다.
기본 길이는 1,025이며 4명 중 한 회는 61,706 좌표를 사용했다.
후자는 FMNIST 모델 크기의 산술 검사이지 FMNIST 학습 실험은 아니다.

총 101,681개 집계 좌표 중 93,301개에서 `c != 0`이었다.
각 개별 키와 합계 키에 대한 출력은 실제 저자 `HPRF.hprf`와 정확히 대조했다.
정수 복원 불일치와 원본/포팅 출력 불일치는 모두 0이었다.

분해는 단순히 `e = D mod p`라고 정의하는 방식에 의존하지 않는다.
내부 좌표 `t_i`, `t_A`를 계산해 `sum(t_i) = t_A + u*q`를 확인하고,
원시 출력의 차이에서 `u*p`를 빼서 **반올림 오차 e를 독립적으로** 얻었다.
이후 canonical representative에 맞는 carry를 계산해 `D = c*p+e`와
반올림 오차 상한을 각각 확인했다.

## 4. c != 0 재현 사례

키 `[38298,5945]`, 라운드 `450`, 좌표 index `1`:

```
h1       =  6462490784354796409
h2       = 11062755094057129863
H(k1+k2) =  2764819577534155503
D        = 14760426300877770769 = 1*p + 0
```

carry와 작은 오차가 동시에 있는 다른 사례:
키 `[52646,8718]`, 라운드 `586`, 좌표 `0`에서
`D = 14760426300877770768 = p - 1`, 즉 `c=1`, `e=-1`이었다.

별도 toy test의 `p=101`, 마스크 80/70, 합계 마스크 49는 `D=101`이다.
이 toy 결과를 원본 HPRF의 증거로 대신 사용하지 않았다.

## 5. 기존 error elimination의 처리 범위

- 원본 SA의 `% p`: carry `c*p`를 제거한다. 원본 벤치마크의 최종 정수
  나눗셈을 일반적인 fixed-point 오차 제거 보장으로 해석해서는 안 된다.
- 기존 Flower `FixedPoint`: 모듈러 차감으로 `c*p` 제거,
  center와 padding 뒤 정수 반올림으로 작은 `e` 제거.
- 로컬 `PaperDMC.remove`: 일반 차감/반올림만 수행한다. 조건에 맞는 작은
  `e`는 제거하지만 `c*p` 전체를 제거하지는 않는다. 위 실제 carry 사례를
  영 업데이트로 검사하면 `1476042630087777077/1000000`이 남았다.
- `PaperDMC.remove_centered`와 `remove_quantized_lift`는 이미 존재하는
  별도 조건부 처리이다. 전자는 scaled period의 용량 조건을 요구하며,
  후자는 후보가 유일하지 않으면 실패한다. 이번 작업에서 변경하거나
  MGF에 새 집계 경로를 연결하지 않았다.

## 6. Modular aggregation의 수학적 근거

`z_i = round(S*x_i)`, `C_i = (Delta*z_i+h_i) mod p`라 두면:

```
sum(C_i) - H(K_A,r) = Delta*sum(z_i) + c*p + e  (mod p)
R = center_p((sum(C_i)-H(K_A,r)) mod p)
```

`|Delta*sum(z_i)+e| < p/2`이면 `R = Delta*sum(z_i)+e`이다.
또한 `|e| < Delta/2`이면 `round(R/Delta) = sum(z_i)`이다.
마스크 자체의 정수 합이 p를 넘어도 상관없다. 용량 제한 대상은 **차감 후의
업데이트 합과 작은 오차**이다. 이번 검사는 `n_i=1`이며 alpha를 넣지 않았다.

## 7. 추가한 파일과 함수

- `experiments/audit_aion_hprf_carry.py`: `center`, `encode`, `decode`,
  `feasibility`, `check_capacity`, `modular_reference`, `decomposition`, `audit`.
- `tests/test_aion_hprf_carry.py`: carry/오차/음수/ASR/용량/양자화 회귀 검사.
- 본 보고서.

새 helper들은 독립 감사 참조이다. 런타임 `FixedPoint`, HPRF, ASR, MGF,
VSS 코드는 변경하지 않았다. 입력/출력 경계만 rational/float로 변환하고
모듈러 경로의 중간값은 Python 정수만 사용한다.

## 8. Fixed-point scale S

`S = 10^6`, 입력은 decimal spelling 기준 ties-to-even 양자화다.
기존 codec의 `encode`와 독립 helper를 대조했다. `decode`는 감사 참조에서
정확한 `Fraction(z,S)`를 반환하며 실제 모델 연산에는 마지막에 float로 변환한다.

## 9. HPRF error bound E_max

각 좌표의 nearest rounding residual은 절댓값 1/2 이하다. 따라서 N개 출력과
합계 키 출력의 차이에는 `|e| <= (N+1)/2`라는 독립 상한이 있다.
N_max=100에서 보수적인 정수 상한 `E_max=51`을 사용했다.
실제로 관측된 최대 `|e|`는 4였다. 실험값 4를 안전 상한으로 대체하지 않았다.
이 분석은 여기서 읽은 scalar/column-sum HPRF에 대한 것이며 다른 HPRF에
그대로 적용한다고 주장하지 않는다.

## 10. Delta와 선택 근거

`Delta=1000`은 N_max=100일 때 기존 codec이 사용하는 decimal padding이다.
이를 임의로 선택하지 않고 실제 p, B_z, N_max, E_max로 가능 구간을 확인했다.

```
minimum Delta = 2*51+1 = 103
maximum Delta = floor((p-1-2*51)/(2*100*10000000)) = 7380213150
```

기존 1000은 이 구간 안에 있으므로 교체가 필요하지 않다.

## 11. 최대 참여자 수와 update bound

`N_max=100`, 각 좌표 `|x_i| <= 10`, `|z_i| <= B_z=10000000`.
이는 이 감사의 명시적 설정이며 모든 프로젝트/학습에서 자동으로 성립하는
상한이 아니다. 모델이나 참여자 수를 바꾸면 용량을 다시 검사해야 한다.
weighted FedAvg는 추가하지 않았다.

## 12. Wrap-around 안전 조건

```
2*E_max = 102 < Delta = 1000
Delta*N_max*B_z + E_max = 1000000000051
2*(Delta*N_max*B_z+E_max) = 2000000000102 < p
```

표준 signed 복원에 충분한 엄격한 조건이다. ASR 키 합의 VSS 오버플로우와
출력 representative carry는 다른 문제다. 감사용 키 합은 기존 VSS의 ORDER보다
작으며 기존 Pedersen share 합산/복원으로 동일한 합계 키를 확인했다.

## 13. 평문 정수 합과 modular 복원 비교

101,681개 모든 좌표에서 다음 세 결과가 **정확히 동일**했다:

1. 평문 양자화 정수 합.
2. 독립 modular_reference 결과.
3. 기존 FixedPoint.unmask 결과.

unit test는 기존 `FixedPoint.mask`와 `encode`도 직접 통과시키며, 기존 VSS의
aggregate-share 복원으로 얻은 키를 사용한다. carry 사례에서는 정수 합
`6985905`가 그대로 복원됐고, `e=-1` 사례에서는 `5572710`이 그대로 복원됐다.

## 14. Float FedAvg와 quantization error

입력 양자화의 측정 최대 오차는 `49/100000000 = 4.9e-7`이었다.
이론 상한은 좌표당 `1/(2*S)=5e-7`이다. 양자화한 정수 합에는 추가적인
modular 복원 오차가 없었다. 일반 float 평균과 복원 평균 사이의 측정 최대
차이는 `4.866666660774399e-7`이었다. sum 오차는 최악 N/(2*S), unweighted mean
오차는 최악 1/(2*S)이다. 실제 float 연산의 별도 반올림은 이 수치와 구분한다.
이 실험은 학습 정확도/수렴률을 측정하지 않았다.

## 15. 실패 테스트와 실행 방법

- A: toy와 실제 HPRF의 carry 없는 좌표 정상 복원.
- B: 실제 원본 파일의 c != 0 사례 및 literal DMR 잔여값 확인.
- C/D: 음수 좌표, 다중 클라이언트, 블록 경계를 넘는 벡터 복원.
- E: 실제 e != 0이지만 Delta/2보다 작은 좌표의 정확 복원.
- F: 용량 조건 위반 설정 거부, client update bound 위반 거부;
  검사를 우회하면 centered decoding이 틀릴 수 있음을 별도 확인.
- G: Delta <= 2E 설정 거부; 실제 비영 e에서 Delta=1을 강제로 쓰면
  영 업데이트 합도 틀리는 사례 확인.
- H: 양수/음수/0/작은 값/경계값/ties-even 양자화 오차 측정.
- odd/even center의 0,1,p-1,p//2,p//2+1 경계와 기존 codec 용량 거부도 검사.

중요: 서버는 wrapped residue만 보고 모든 용량 위반을 탐지할 수 없다.
이번 capacity/client 검사는 honest-input 산술 조건이지 악성 클라이언트의
범위증명은 아니다. ZKP는 이번 범위에 없다.

저장소 루트에서 설치된 의존성에 맞춰 실행한다. 이 환경에서는:

```bash
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. python3 experiments/audit_aion_hprf_carry.py
env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. python3 -m pytest -q tests/test_aion_hprf_carry.py tests/test_aion_original_hprf.py tests/test_pedersen.py
```

키와 업데이트는 공개 seed로 만든 재현용 fixture이다. 운영 비밀을 출력하지 않는다.

## 16. 실제 Aion-ASR 적용 판단

이 원본 HPRF와 ASR의 합계 키에 대해, 조건을 만족하는 unweighted 정수 합의
모듈러 복원은 가능하다. Flower codec에는 이미 그 구조가 구현돼 있다.
기존 Flower ProcessGrid 통합 테스트도 통과했다. 두 설정(hotstuff False/True)에서
각 4라운드 모델이 평문 양자화 평균을 적용한 모델과 정확히 일치했다.
이는 기존 테스트의 소규모 학습 워크로드에 대한 결과이며 100-client 실네트워크
또는 장기 학습 실험을 수행했다는 뜻은 아니다.
ASR/VSS 복원은 선형 합계 키만 제공하고, 최종 출력 modulus p의 carry 제거는
수치 집계 경로가 담당한다. HPRF 보안성 또는 ASR 누출 문제는 이 결과로
해결되었다고 주장하지 않는다.

## 17. 추가 집계 변경이 불필요한 이유

기존 비-MGF 경로가 이미 동일 p에서 모듈러 합산/차감과 center/padding을
수행하며, 재현된 carry와 작은 오차 모두 정확히 제거했다. 따라서 가정을
맞추기 위해 런타임을 다시 작성하지 않았다. 스케일된 MGF/alpha를 같은
집계에 통합할 수 있다는 결론은 **이번 결과로부터 나오지 않는다**.

## 실행 기록

감사 seed: 20261008, 각 참여자 수별 8회.
첫 focused pytest 실행: 33 passed, 2 deselected (34.29s).
최종 명령: 54 passed, 2 warnings (39.05s). Warning 2개는 Flower 의존성
typer/click의 deprecated API 경고이며 테스트 실패가 아니다.
기존 Flower ProcessGrid 테스트 두 설정 각 4라운드 포함.
Float FedAvg 평균 차이: 최대 `4.866666660774399e-7`.
