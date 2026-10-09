# Aion-ASR scalar key domain 확장 검증 — 2026-10-09

## 범위와 결론

**주결론 B: HPRF를 바꾸지 않고 전체 Z_q의 키를 계산·공유·복원할 수 있지만,
현재 런타임의 작은 키 전용 정책 검사는 수정해야 한다.** 기존 JSON-bytes
전송 경로 자체를 교체할 필요는 없다. **128-bit privacy가 목표라면 C도 해당**한다.
특히 이번 scalar HPRF는 raw 출력 역산 취약점이 있어, 66-bit 엔트로피를
66-bit 보안이라고 부를 수도 없다. q만 키우면 보안이 해결된다는 결론이 아니다.

이번 변경은 experiments/와 tests/ 및 이 보고서뿐이다. 원본 Aion,
trustlessfl/의 런타임, p/q/matrix/rounding, MGF, VSS/ASR 알고리즘은 변경하지 않았다.
ZKP, MPC, 추가 mask share, share-mask inconsistency 해결을 구현하지 않았다.

최종 ledger: `.cache/full-domain-keys-20261009-v3/report.json`.
v1은 초기 측정, v2는 테스트와 동시 실행한 확장 pilot이다. **최종 비용 비교에는
다른 작업을 함께 실행하지 않은 v3만 사용**한다. JSON에 원시 수치·환경·해시를 보존한다.
키를 기록한 항목은 전부 새로 만든 공개 fixture이며 실제 client state를 읽지 않았다.

v3 report: 54585 bytes, 실행 71.027초,
SHA256 `e3a4140ff1fc236fd1db6b3c1c6c0a2c902a877520c4a35f25959e264bc66c99`.

## 1. 현재 key generation 코드

| 단계 | 파일 / 함수 | 확인 결과 |
|---|---|---|
| 원본 생성 | `Aion/agent/Aion/SA_ClientAgent.py:sendVectors` | `random.SystemRandom().randint(1, 100000)` |
| Flower 등록 | `trustlessfl/aion_source_asr.py:source_request`, enroll 분기 | 동일 생성식, 초기 한 번 공유 |
| 최초 mask fallback | 같은 함수의 learning/mask 분기 | 미등록 상태에만 동일 생성식 |
| 저장 | `state['mask_seed']`, `flower_source_request` | Python int → canonical JSON bytes → ConfigRecord snapshot |
| 재사용 | mask 분기 | 후속 라운드는 저장된 키 사용 |
| retry | replies/request digest 캐시 | 동일 요청에 동일 응답; 재추첨하지 않음 |
| VSS 전달 | `aion_source_sharing.share_seed` | `pedersen_split(secret, threshold, committee_size)` |
| share 집계 | `sum_keys` | Pedersen share와 commitment를 동일 members 집합으로 합산 |
| ASR 복원 | `recover_key_opening` | 검증된 share에서 정수 key sum, blind 복원 |
| HPRF 평가 | `OriginalAionHPRF.hprf` | scalar key를 내부 q로 줄여 계산 |

단위 테스트는 임시 fixture에서만 RNG 반환을 `q-1`로 주입하여 enroll → JSON 저장/
재로드 → 같은 enroll retry를 실행했다. 큰 키가 유지되고 두 번째 추첨이 없는지 검사한다.
이것은 runtime sampling이 바뀌었다는 뜻이 아니다.

별도 `protocol.py`의 aion-original backend에도 `secrets.randbelow(100000)+1` 및
`clients*100000 < ORDER` 가정이 있다. source-ASR 경로와 구분하며 이번에는 건드리지 않았다.

## 2. 현재 key space

양 끝을 포함한 `{1,...,100000}`, scalar Python int다. 벡터 키가 아니다.
각 client가 OS RNG를 별도로 호출하지만 키의 유일성을 강제하지는 않는다.
한 client의 키는 라운드 간 재사용된다. 이 정책은 그대로 유지했다.

## 3. 현재 entropy

균일 추첨을 전제한 키 재료 엔트로피는 `log2(100000)=16.6096404744` bits다.
`SystemRandom`은 이미 OS 난수원을 사용하므로 RNG 이름만 `secrets`로 바꿔도
동일 범위라면 이 값은 늘지 않는다.

## 4. HPRF mathematically valid key domain

확인한 공개 setup은 다음과 같다.

```text
p = 14760426300877770769
q = 73802131504388853845 = 5p
n = 128, m = 512
```

출력 coordinate j에 대해 현재 코드는 아래 scalar 연산이다.

```text
b = j // m
a_j = (r+b) * column_sums[j % m] mod q
t_j = k*a_j mod q
h_j = floor((p*t_j + floor(q/2))/q)
```

따라서 `H(k+q,r)=H(k,r)`이고 자연스러운 key ring은 **Z_q**다.
q=5p는 합성수이므로 여기서 Z_q를 유한체라고 부르지 않는다.
키 생성에 대한 보안 증명 여부와, 이 수식에 넣을 수 있는 algebraic domain은 별개다.

`0 <= k < q` 전체가 계산상 유효하다. `k=0`은 모든 출력이 0인 약한 키이지만
오류를 발생시키는 invalid key는 아니다. 균일 Z_q에서 확률은 1/q다.
비영 키를 선택하는 옵션도 실험 helper에 제공하되, 이를 전체 보안 수리로 보지 않는다.

요청한 9개 boundary와 `2^53+1`을 추가한 10개에서 원본 `hprf()`와 포팅 결과가
동일했고, q-periodicity, VSS 검증/복원, JSON/Flower bytes 왕복이 정확했다.
원본 `G()`는 별도 int64 경로이며 `hprf()`가 사용하는 `G_batch()`와 다르다(18절).

## 5. VSS/ASR key domain

현재 encrypted-Pedersen profile의 scalar field는 RFC3526 group14의 subgroup order
`ORDER=(MODULUS-1)//2`이며 **2047 bits**다. HPRF 내부 q가 아니다.
`crypto.pedersen_split/sum_pedersen_shares/pedersen_reconstruct_pair`가 이 ORDER를 쓴다.

`n_max*(q-1) < ORDER`이면 ASR로 복원한 대표값은 키의 **정수 합**이다.
그 후 HPRF가 자연스럽게 mod q를 적용한다. `sum(k)`와 `sum(k)%q`로 평가한 출력의
동일성을 매 회귀에서 검사했다. n=100도 위 용량 조건을 충분히 만족한다.

encrypted transport fixture(20 clients, committee4, threshold2)에서는
등록 share의 암호화·서명·복호화·검증, aggregate share 합산·복호화까지 기존 함수로 수행했다.
full-domain fixture의 integer sum은 q를 여러 번 넘지만 ORDER를 넘지 않아 정확히 복원된다.

실측 integer key sum은 `387493430401262919396`, 이를 q로 줄이면
`18482772879318650171`이다. 양쪽 HPRF 출력은 동일했다.

주의: 원본 author VSS는 고정 다항식 계수 및 다른 modulus 취급이 있는 legacy 코드다.
이번 VSS 보안/비용 검사는 현재 포팅의 randomized encrypted Pedersen profile에 대한 것이다.
원본 legacy VSS가 안전하다는 주장으로 확장하지 않는다.

## 6. Full-domain sampling 가능 여부

실험용 `experiments/full_domain_keys.py:sample_full_domain`은 다음을 제공한다.

```python
secrets.randbelow(q)             # 정확히 0..q-1
1 + secrets.randbelow(q - 1)     # nonzero=True일 때 1..q-1
```

OS CSPRNG의 randbelow를 직접 사용하며 정수 난수를 `% q`로 줄이는 sampling을 하지 않는다.
도메인 양 끝 mapping, 잘못된 타입/범위 거부, OS sampler smoke test를 추가했다.
균일성은 API의 rejection-sampling 방식에 의존하며 128개 샘플의 모양으로 증명하지 않는다.
[Python secrets 문서](https://docs.python.org/3/library/secrets.html).

**전체 runtime은 아직 full-domain 키를 허용하지 않는다.**

- `aion_source_sharing.recover_key_opening`: `len(members) <= key <= len(members)*100000`.
- `aion_source_aggregate.validate`: 동일한 aggregate opening 범위 검사.
- `aion_source_server.provision_source`: manifest key_profile과 scope에 1..100000 고정.

실제 unchanged `recover_key_opening()`이 큰 키 fixture에
`source aggregate key outside author key domain`을 반환하는 것을 보존했다.
정상 primitive 복원을 성공한 runtime 라운드로 바꿔 보고하지 않는다.
정책 상한을 프로파일로 표현하면 VSS나 HPRF 수학을 바꾸지 않고 수용 가능하다.

## 7. Full-domain entropy

| 항목 | 값 |
|---|---:|
| 기존 후보 수 | 100000 |
| 전체 domain 후보 수 | 73802131504388853845 |
| 기존 entropy | 16.6096404744 bits |
| 전체 domain entropy | 66.0002962867 bits |
| 증가 | 49.3906558123 bits |
| 후보 수 배수 | 약 7.38021315×10^14 |
| 추가 후보 수 | 73802131504388753845 |

nonzero subset의 정확한 후보 수는 `q-1`이다. log2 값은 위 자릿수에서는 같지만
수학적으로는 조금 작다. q는 2^66을 약간 넘으므로 **저장에는 최대 67 bits**가 필요하다.
엔트로피 표는 보안 비트 수준을 뜻하지 않는다.

## 8. Small-key exhaustive recovery 재현 결과

기존 `audit_transmission_parameters.key_space_audit`의 20개 공개 fixture를 그대로 재실행했다.
M=32000/d100/S1e6/C100 및 M=8441/d21/S1e4/C.001, rounds1/4, 5개의 공개 키 조합이다.
M8441은 기존 공격 fixture이지 최소 필요 M이라고 주장하지 않는다.

각 fixture에서 100000개를 검사해 **20/20 true key 유일 복원, 20/20 개별 update 정수 벡터
정확 복원**, surviving candidate는 모두 1개였다. 기존 bound-only 통계도 JSON에 유지했다.
grid 불일치 시 조기 종료하는 동등한 검색 loop를 별도로 측정하여 fixture별 throughput을 기록했다.

기존 PoC 전체 시간은 **8.967초**. 조기 종료 버전은 client별 **0.10385~0.12054초**,
**829576~962934 keys/sec**다. 검사의 순서/단락 평가가 달라 두 시간은 같은 구현의
속도라고 섞어 비교하지 않는다. 최종 surviving set은 두 구현에서 정확히 일치했다.

## 9. Full-domain exhaustive search 예상 비용

전체 66-bit 공간을 실제로 탐색하지 않았다. 동일 작은 키 검색의 실측 keys/sec를 사용해
`q / throughput`(전체 열거), `(q+1)/(2*throughput)`(단일 표적 평균 탐색)을 외삽했다.
두 large-operand control은 `[q//2,q//2+100000)` **10만 개만** 검사한다.
그 subset에 후보 하나가 남는 것은 전체 Z_q에서 유일함을 증명하지 않는다.

small-operand throughput 외삽은 전체 열거 **243만~282만 년**, 평균 탐색은 그 절반이다.
large-operand control은 다음과 같다.

| 공개 fixture period | 10만 후보 시간 | keys/sec | full-domain 전체 열거 외삽 |
|---|---:|---:|---:|
| 32000 | 0.12493초 | 800456 | 약 292만 년 |
| 8441 | 0.11640초 | 859109 | 약 272만 년 |

따라서 현재 CPU loop로는 단순 exhaustive search가 매우 비싸지는 것은 맞다.
이 표의 수백만 년을 보안 강도의 인증 수치로 인용하면 안 된다.

이는 단일 CPU/Python loop의 선형 비용 추정일 뿐이다. 병렬화·최적화·하드웨어 공격의
하한이 아니며, 더 빠른 algebraic attack가 없음을 뜻하지 않는다. 특히 19절을 함께 봐야 한다.

## 10. HPRF runtime: small vs large

AMD Ryzen 5 5600G, WSL2 x86_64, Python3.12.3에서 round4, dimension61706,
group당 60회, warm-up 후 그룹 순서를 섞어 측정했다. matrix load/setup 시간은 제외한다.
mean/median/p95/p99/std와 별도 tracemalloc peak를 JSON에 기록한다.
모바일 기기를 측정하지 않았다. p99는 60개 표본의 기술통계이지 안정된 서비스 SLO가 아니다.

단위는 ms다.

| key group | mean | median | p95 | p99 | std |
|---|---:|---:|---:|---:|---:|
| 1..100000 | 17.2598 | 17.1904 | 18.4415 | 18.9367 | 0.5653 |
| 32-bit | 18.0391 | 18.0171 | 18.6922 | 20.1663 | 0.5796 |
| 48-bit | 18.9813 | 18.9346 | 19.8384 | 20.2176 | 0.5077 |
| 53-bit | 20.2851 | 20.0806 | 21.1874 | 24.9296 | 1.1889 |
| q/2 근처 | 19.6598 | 19.6153 | 20.4804 | 20.7628 | 0.4617 |
| q-1 근처 | 20.4863 | 20.4170 | 21.3395 | 21.6575 | 0.5187 |
| full-domain uniform fixtures | 20.6308 | 20.6263 | 21.6149 | 22.0224 | 0.5398 |

full uniform은 small 대비 평균 **+3.371ms, +19.5%**다. 절대 시간은 작지만
상대 증가를 “차이 없음”이라고 표현할 수 없다. setup/출력 dimension은 동일하다.
tracemalloc peak는 그룹별 평균 약 **3.206MB**로 비슷했다. 이는 호출 중 Python 할당
peak이며 전체 process RSS, matrix 공유 메모리, 모바일 에너지는 측정하지 않았다.

## 11. VSS runtime: small vs large

기존 randomized Pedersen을 사용했다. threshold2/committee4에서 split, 4 shares 검증을
각각 60회 측정한다. Python bigint라는 이유만으로 비용 증가를 가정하지 않는다.
다항식 난수와 blind는 작은 secret일 때도 ORDER 전체에 있으므로 연산의 대부분은
원래부터 큰 정수 연산이다. GMP backend와 warm group-element cache를 사용하는 현재 환경이다.

| 작업 | small mean ms | full mean ms |
|---|---:|---:|
| share 생성 1회 | 6.7924 | 6.8222 |
| share 4개 검증 | 22.4417 | 22.3005 |

이 실행에서 key-size 증가에 따른 큰 증가를 관측하지 않았다. 각 percentile/std도 ledger에 있다.

## 12. ASR runtime: small vs large

20 clients의 4 committee-index share sums, 20 commitment vectors의 합성,
2 verified shares로 key/blind reconstruction을 분리 측정했다.
아래 표는 component microbenchmark이며 BFT, RTT, Flower scheduling을 포함하지 않는다.
원래 재구성 검증과 opening 검증을 제거하지 않았다.

| 작업 | small mean ms | full mean ms |
|---|---:|---:|
| 20 clients × 4 index share 합산 | 0.08028 | 0.07617 |
| 20 clients의 commitment 합성 | 1.51223 | 1.49316 |
| 2 shares 검증 + key/blind 복원 | 11.34144 | 11.40548 |
| share bundle JSON 직렬화 | 0.08686 | 0.09079 |

작은 평균 차이는 측정 noise와 랜덤 VSS 값도 포함한다. 개선/악화를 일반화하지 않는다.

## 13. Serialization / payload 변화

20 clients의 encrypted enrollment packet 80개와 aggregate-share packet 4개를 실제 생성했다.
암호화 payload에는 작은 secret가 아니라 ORDER 크기의 랜덤화된 shares가 들어가므로
키 범위를 늘렸다고 share 크기가 16→66 bits 비율로 증가하지 않는다.
JSON decimal 자릿수의 작은 변동은 랜덤 share 값 때문이다.

로컬 mask_seed JSON은 최대 길이가 6자리에서 20자리로 늘어난다(최대 길이끼리 +14 bytes).
aggregate key/opening의 정수도 길어지지만 masked vector의 dimension/coordinate 수는 그대로다.
측정 packet byte 수는 application payload 크기이며 gRPC/TLS/IP 오버헤드는 포함하지 않는다.

| application payload | small | full |
|---|---:|---:|
| encrypted enrollment 80 packets 합 | 330946 bytes | 330996 bytes |
| 1 recipient packet 평균 | 4136.825 bytes | 4137.450 bytes |
| aggregate share 4 packets JSON 묶음 | 16845 bytes | 16843 bytes |
| plain randomized VSS bundle 평균 | 6225.733 bytes | 6226.350 bytes |

encrypted enrollment+receive도 각각 632.71ms / 627.25ms였다(한 fixture의 local 연산 시간).

## 14. HPRF error distribution 변화 여부

각 sampling profile에서 n=2/20/100, 5 cohort fixtures, rounds1/4/17/451,
dimension1025로 profile별/인원별 20500개 aggregate coordinates를 검증했다.

수학적으로 q=5p, p odd이면 `h=(t+2)//5`이고 한 번의 rounding residual 크기는 최대 2/5다.
따라서 raw integer error의 유효 상한은 `floor(2*(n+1)/5)`이며 키 magnitude와 무관하다.
transmission error bound도 기존 `transmission_error_bound()`를 그대로 적용한다.
n20/M32000에서 Emax10, dmin21은 바뀌지 않았다.

실험 error histogram은 두 sampling profile에서 완전히 같지 않다. 키의 작은 나머지와
공개 column coefficients가 오차에 영향을 주며, 좌표/라운드들이 독립 표본도 아니다.
따라서 histogram 차이를 숨기거나 분포 동일성을 증명했다고 하지 않는다.
확인한 것은 **양쪽 모두 동일 이론 상한을 만족**한다는 점이다.

| n | raw e 최대 절댓값 small/full | raw 이론 상한 | transmission E 최대 small/full | transmission 상한 |
|---|---:|---:|---:|---:|
| 2 | 1 / 1 | 1 | 1 / 1 | 1 |
| 20 | 3 / 2 | 8 | 5 / 5 | 10 |
| 100 | 7 / 5 | 40 | 11 / 12 | 50 |

carry 빈도는 n2에서 50.09% / 50.22%, n20과 n100에서는 둘 다 100%였다.
이는 raw representative의 합 carry이며, update decoding-range violation 빈도가 아니다.

## 15. Modular recovery correctness 변화 여부

random full-domain keys로 bounded synthetic n2/20/100 × 4 rounds 및 실제 FMNIST
frozen updates 20 clients × 4 rounds × S={1e4,1e5,1e6}를 검증했다.
총 **752772 aggregate coordinates**가 평문 quantized sum과 정확히 같았다.

FMNIST는 이전 audit의 공개 update cache를 재사용하고 checksum을 기록했다.
클리핑 없이 전 좌표가 C=.1 내인지 먼저 확인했다. d21에서 M은 기존 최소 period 식으로
840021 / 8400021 / 84000021을 쓴다. **해당 M에서 MGF가 20명을 선택한다는 주장은 아니다.**
이번 작업은 fixed update arithmetic regression이지 재학습/새 MGF 탐지율 실험이 아니다.

키 크기가 error bound, `scale(h+p)=scale(h)+M`, centered decoding 조건을 바꾸지 않았다.
기존 synthetic M32000/d100/S1e6의 decoding-range 문제는 **키 확대로 해결되지 않는다.**
기존 ambiguity regression을 그대로 유지하고 infeasible plan 거부 테스트도 추가했다.
large key 자체로 E=±10의 extremum을 찾은 공개 fixture에서 d20 실패/d21 성공을 검사했다.

## 16. Output distribution 변화 여부

small/full 각각 n=100 구간에서는 2050000개의 raw output을 측정했다.
정규화 h/p의 mean/variance, 16-bin histogram, h mod16 분포를 모두 JSON에 보존한다.
평균 약 .5, 분산 약 1/12에 가까운 것은 marginal 통계 결과일 뿐 PRF security test가 아니다.
기존 scalar 구조의 공개 선형 관계나 입력 충돌이 사라졌다고 해석하지 않는다.

| n=100 표본 | h/p mean | h/p variance |
|---|---:|---:|
| small | 0.499613983 | 0.083425620 |
| full | 0.500095349 | 0.083249155 |

이 표본에서는 큰 marginal 편향 변화가 관찰되지 않았다. statistical independence나
두 분포의 동등성을 검정해 인증한 것은 아니다.

## 17. MGF mask distribution 변화 여부

mask 대표값은 **uncentered 0..M (M 포함 가능)** 그대로다. 임의로 centered로 변경하지 않았다.
통계는 실제 FMNIST MGF projection `[60856:61696]`, 840차원을 사용한다.
긴 prefix를 만들지 않는 평가가 원본 full-length 평가 slice와 동일한지도 assert했다.

M32000에서 scalar scaled-mask mean/std/variance/histogram, norm과 squared-norm 통계를 측정했다.
연속 uniform 근사의 참고값은 다음과 같다(독립성을 보장하는 모델은 아님).

```text
E[m] = M/2 = 16000
Var(m) = M^2/12 ≈ 85333333.3333
E[||m||_2^2] = 840*M^2/3 = 286720000000
Std(||m||_2^2) ≈ sqrt(4*840/45)*M^2
```

MGF가 보는 물리 단위에는 좌표를 d*S, squared norm을 `(d*S)^2`로 나누면 된다.
이번 통계에서 큰 marginal 변화가 없더라도, **기존 높은 benign rejection이 해결됐다고
말하지 않는다.** MGF predicate, 초기 percentile, 임계값 갱신은 바꾸지 않았다.

| n=100의 2000개 mask vectors | small | full |
|---|---:|---:|
| coordinate mean | 15996.16335 | 15998.90444 |
| coordinate variance | 85384387.0466 | 85332946.9468 |
| mean squared L2 norm | 286659768283.8425 | 286690227755.5205 |
| std squared L2 norm | 8958638255.0818 | 9129186016.3287 |

## 18. Dangerous int64 / float / JSON conversion 위치

| 위치 | 결과 / 조치 제안 |
|---|---|
| `aion_original_hprf.py:hprf` | Python int; 큰 키/aggregate key 안전 |
| author `hprf.py:hprf/G_batch` | dtype=object; 원본과 port 출력 동일 |
| author `hprf.py:G`, `hprg` | `np.array([s], dtype=np.int64)`; q//2,q-2,q-1에서 OverflowError. 현재 hprf 경로는 이 함수를 호출하지 않음 |
| `client_app.records/payload` | JSON bytes→ConfigRecord→Python json; 큰 key/share 정확 |
| `aion_source_asr.flower_source_request` | 같은 방식의 snapshot bytes; retry 재로드 정확 |
| `ConfigRecord({'key': key})` 직접 사용 | q//2 이상 boundary에서 ValueError; 현재 wrapper를 제거하면 안 됨 |
| float64 / JavaScript Number | 2^53+1 이상을 일반적으로 정확히 보존하지 못함. 측정 boundary에서 실제 rounding 손실 확인 |
| NumPy int64 / uint64 | 일부 full-domain 값은 두 타입 모두 초과. object 또는 명시적 bytes/string 필요 |
| `crypto.encrypt/decrypt_pedersen_share` | canonical JSON pair를 AEAD plaintext로 사용, Python int로 복원하여 ORDER 검사 |
| `aion_source_asr._plain` | np.integer/mpz는 int로 보존; 이미 float로 들어오면 정밀도 손실을 복구할 수 없음 |
| author `SA_ClientAgent.sendVectors` | raw mask를 float64로 변환하는 legacy benchmark 경로; source learning의 integer wire와 구별 |

현재 source path에는 mask_seed를 작은 SQL INTEGER 열에 넣는 애플리케이션 코드가 없다.
Flower 저장소에는 snapshot bytes로 들어간다. 다른 언어의 JSON 파서나 외부 database 변환까지
보장하지 않으며, cross-language 확장에서는 decimal string/고정폭 big-endian을 프로파일로
명시하고 canonical signing encoding을 함께 버전 관리해야 한다.

## 19. 약 66-bit entropy의 보안 한계

128-bit key-search 목표보다 약 62 bits 부족하다. 그 이전에 **scalar primitive 자체의 문제**가 남는다.
`inverse_scalar_outputs`의 기존 공개-output 진단을 큰 키 32개와 작은 키 1개에 반복했다.
33/33에서 raw 출력의 앞 두 좌표로 키가 유일 복원됐다. 작은-key prior를 사용하지 않는다.
키 추론 함수만의 평균 시간은 **0.01189ms**였다(입력 output 생성 시간 제외).

원인은 `h=(t+2)//5`이므로 raw h 하나가 t를 대략 다섯 후보로 좁힌다는 점이다.
공개 coefficient가 q에서 invertible이면 각각을 곱셈 역원으로 k 후보에 매핑하고,
두 번째 좌표로 검사할 수 있다. 출력 0/p 경계도 기존 공격 함수가 처리한다.

**이 공격에는 raw HPRF 출력이 필요하다.** 현재 scaled masked update만 관측하는 서버가
full-domain individual key를 같은 방법으로 복구한다고 실증한 것은 아니다.
그렇지만 PRF 자체에 66-bit 보안이 있다고 주장하는 근거는 될 수 없다.
작은 키 exhaustive PoC 완화와 HPRF 보안 복구를 구분해야 한다.

BLMR 원문 §5는 vector key와 입력별 공개 행렬 곱의 구성이며, 이번 단일 scalar/column-sum
구조에 보안 정리가 그대로 적용되지 않는다. 현재 artifact에 대한 LWE/LWR 보안 level과
lattice estimator 결과는 **확인되지 않았다**. 보안 정리의 존재가 구현의 정리 충족을 뜻하지 않는다.
[BLMR 원문 §5](https://crypto.stanford.edu/~dabo/pubs/papers/homprf.pdf).

또한 `r+block` 입력의 서로 다른 라운드/블록 충돌, ASR 집합 변화의 누출 정책은 그대로다.
이번에 고치지 않았으며 full-domain sampling으로 사라지지 않는다.

## 20. 128-bit 이상 대안 비교 — 분석만

아래 비용은 이번 측정이 아니라 구조에 따른 정성 분석이다. 구현하거나 보안 level을 인증하지 않았다.

| 대안 | HPRF 계산 | VSS/share/ASR | 보안·복원 영향 | cross-device 판단 |
|---|---|---|---|---|
| A. scalar q 확대 | 더 큰 bigint modular 곱 | ORDER 용량 내라면 share field 크기 유지 가능 | 키 후보 증가만으로 보안 증명 안 됨. q/p=5 유지 시 raw-output 역산 구조도 유지. q/p 변경 시 오차/출력 관계 재검증 | 벡터화보다 가벼울 수 있지만 안전한 해결책으로 승인 불가 |
| B. 검증된 vector-key 구성 | 차원·공개 행렬 구조에 따른 추가 비용 | 키 좌표별 공유/commitment가 필요하면 선형 증가; ASR도 좌표별 | 실제 PRF 정리/파라미터 검증 필요. 같은 ring/오차 상한이면 recovery 수식은 재사용 가능 | 정확한 backend와 목표 기기 실측 필요 |
| C. 독립 field elements 두 개 이상 | 단순 병렬은 대략 호출 수 증가 | 원소별 공유하면 payload와 복원 증가 | 출력 단순합이 합계 키 하나로 붕괴하면 entropy가 단순히 더해지지 않음. independent mask 조합도 별도 구성/증명 필요 | 2배 추정은 비용 참고일 뿐 보안 근거 아님 |
| D. HPRF parameter/backend set 교체 | 선택한 검증 구성에 의존 | 새 key-domain과 ORDER/threshold 호환 검토 | 입력 인코딩/rounding/residual/MGF 분포까지 재검증. q만 키우는 것보다 넓은 작업 | 목표128 bits를 먼저 고정한 뒤 평가해야 함 |

짧은 seed를 비선형 PRG로 확장한 vector를 키로 쓰는 것만으로는 ASR의 key-sum
homomorphism이 자동으로 유지되지 않는다. 해당 shortcut을 구현하지 않았다.

## 21. Cross-device에서 가장 가벼운 현실적 수정안

**Q1. 작은-key exhaustive search를 완화하는가?** 후보 공간만 보면 확실히 늘어난다.
그러나 현재 scalar HPRF의 raw-output 취약점까지 해결하지는 않는다.

**Q2. 비용 증가가 큰가?** 현재 로컬 실측에서 HPRF는 수 ms의 증가가 있고,
VSS/ASR 및 전송량은 비교적 비슷하다. 상대 증가율을 무시하지 않으며,
mobile CPU·배터리·네트워크 비용은 측정하지 않아 판단을 유보한다.

**Q3. 연구 prototype에서 66 bits를 받아들일 수 있는가?** 수치/포팅 재현 실험이라면
명시적 insecure-artifact profile로 비교할 수 있다. 128-bit privacy나 일반적인
production Secure Aggregation 보안 주장을 목표로 삼으면 충분하지 않다.
보안 목표를 대신 낮추거나 이 변경을 보안 완료로 승인하지 않는다.

가장 가벼운 *호환성* 변경은 기존 HPRF를 유지하고 full-domain sampling과 key-profile
범위 검사를 함께 버전화하는 것이다. 가장 가벼운 *보안상 충분한* 변경이 무엇인지는
현재 결과만으로 확정할 수 없다.

## 22. Integration recommendation

이번에는 연결하지 않았다. 후속 integration 승인 시 필요한 최소 범위는 다음과 같다.

1. manifest에 old-author / full-q 실험용 key profile, q, zero policy를 명시한다.
2. 등록/최초 mask 생성 두 곳이 같은 sampler를 쓰게 한다. 기존 task의 작은 키를 자동 교체하지 않는다.
3. sharing 복원과 aggregate-opening 검증의 bounds를 같은 profile로 계산한다.
   Z_q라면 `0 <= K <= n*(q-1)`이며 nonzero라면 lower bound n이다.
4. provisioning에서 `n_max*(q-1) < ORDER`를 검사한다. 현재 VSS를 q field로 바꾸지 않는다.
5. Python JSON-bytes 전송을 유지하고 key/aggregate key를 int64/float로 축소하지 않는다.
6. 기존 retry와 one-time sharing을 유지한다. 프로파일 변경은 새 task/setup에서 수행한다.
7. source HPRF의 별도 보안 문제와 MGF false rejection이 미해결이라는 경계를 유지한다.
   full-domain sampling을 production privacy fix로 표시하지 않는다.

**선택 분류: B.** 산술을 바꾸는 D에 해당하지 않고, 비용만으로 E라고 판정할 근거도 없다.
하지만 아무 runtime 변경 없이 sampler 한 줄만 갈아 끼우면 되는 A도 아니다.
128-bit target에서는 C 경고가 추가되며, 원시 출력 역산 때문에 단순 parameter 크기만
올리면 충분하다고 단정하지 않는다.

### 재현 방법과 변경 파일

```bash
env PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 experiments/audit_full_domain_keys.py \
  --output .cache/full-domain-keys-REPEAT --repetitions 60

env PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 -m pytest -q tests/test_full_domain_keys.py
```

출력 디렉터리는 새 이름이어야 한다. 기존 보고서를 덮어쓰지 않는다.
FMNIST cache가 없는 환경은 `--workload`로 이전 audit의 real-update cache를 지정해야 한다.
이 파일의 통계는 로컬 artifact 의존성이 있고, sampler/산술 unit tests와 구분한다.

- `experiments/full_domain_keys.py`: OS sampler, VSS sum capacity validator.
- `experiments/audit_full_domain_keys.py`: boundary/transport/cost/distribution/recovery/security audit.
- `tests/test_full_domain_keys.py`: 대응 unit/regression tests, 기존 runtime 거부도 보존.
- 이 보고서. 원본/런타임 파일의 시작·종료 SHA256 동일성을 audit에서 assert한다.

### 테스트 결과

최종 실행 **907 passed, 0 skipped, 2 warnings, 116.32초**.
warnings는 외부 typer/click의 deprecation 알림이다. 새 파일의 42개 parameterized tests와
기존 transmission/centered recovery/source ASR/VSS/selection/BFT/원본 HPRF/출력 역산
회귀를 함께 실행했다. 새 large-key 테스트만 통과시킨 결과가 아니다.

```bash
env PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
  python3 -m pytest -q \
  tests/test_full_domain_keys.py tests/test_transmission_numeric.py \
  tests/test_modular_recovery.py tests/test_modular_mgf_recovery.py \
  tests/test_aion_hprf_carry.py tests/test_scaled_ring.py \
  tests/test_source_paper_numeric.py tests/test_source_aggregate_validation.py \
  tests/test_source_filtered_bft.py tests/test_source_selection_authorization.py \
  tests/test_source_encrypted_sharing.py tests/test_source_asr_official.py \
  tests/test_split_wire_amr_audit.py tests/test_aion_original_hprf.py
```

원본/런타임 48개 파일을 최종 단계에서 다시 hash 대조하여 동일함을 확인했다.
`git diff --check` 및 새 Python 파일 AST 검사를 통과했다. commit/push는 하지 않았다.
