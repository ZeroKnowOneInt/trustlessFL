# 추가 share 없는 원본 HPRF·DMC/DMR 수치 감사

후속으로 [quantized-lift 조건부 복원](quantized-lift-2026-10-01.md)을 시험했다.
아래 세 초기 후보의 실패를 모든 수치 어댑터의 불가능성으로 확대하지 않는다.
조건부 성공은 확인했으나 bootstrap을 포함한 end-to-end 검증은 미완료다.

사용자가 지정한 조건: 원본 HPRF, 초기 일회성 키 공유 유지, 추가 mask share
금지. 기존 키·share·실험 파일은 변경하지 않았다. 새 참조 구현은 키 공유를
수행하지 않는 공개 fixture 수치 감사다. Flower 학습 검증으로 표시하지 않는다.

## 구현과 실행

`trustlessfl/paper_dmc.py`는 [논문](https://www.usenix.org/system/files/usenixsecurity25-liu-yizhong.pdf)의
Algorithms 6–8을 대조하기 위한 정확한 유리수 참조 구현이다. Algorithm 6의
inclusive masked L2 판정, Algorithm 7/8의 extra digits, 동일 정밀도에서의
mask 제거와 반올림을 구현했다. 모델 입력은 먼저 지정 정밀도로 양자화한다.
논문이 tie-breaking을 지정하지 않아 half-even을 명시적으로 선택했다.

논문은 두 모듈을 결합한 wire 수치 표현을 충분히 지정하지 않는다. 따라서
`h_max=p`(raw)와 `h_max=p/D`(DMC-normalized)를 **검증할 후보 해석**으로
구분한다. 어느 것도 저자의 확인된 end-to-end 구현이라고 주장하지 않는다.

```sh
PYTHONPATH=.cache/author-asr-deps:.cache/flower-deps:.cache/torch-deps:. \
python3 -m experiments.audit_paper_dmc \
  --source ../Aion/agent/Aion/HPRF \
  --output .cache/paper-dmc-no-extra-share-wire-audit-20261001.json
```

실행 완료. 출력 경로는 새 파일만 생성하므로 재실행 시 다른 이름을 지정한다.
원본 저장 행렬·initialization hash는 JSON에 포함한다. 공개 fixture 키 10개,
20라운드, 840좌표, 전체/필터 선택/변동 부분집합을 비교했다. 각 클라이언트의
입력값은 fixture 생성기가 가진 검증 oracle이며 aggregator API 입력은
마스킹된 값과 합산 키에서 생성한 HPRF뿐이다. 학습 데이터는 읽지 않는다.

## 관측 결과

입력 소수 6자리, extra digits 2, `D=10^8`, 공개 이전 L∞=0.1,
beta=0.2. 세 모드의 선택 부분집합은 다르므로 실패 개수를 비율처럼 직접
비교하지 않는다.

| 후보 수치 경로 | Literal DMR 집계 | 명시적 modular 복원 | wire 반올림만으로 원래 값 복구 |
|---|---|---|---|
| DMC만, `h/D` | 30,731좌표 불일치 | 시험된 33,600좌표 모두 일치 | 0/168,000좌표 |
| normalized MGF+DMC, `0.02*h/p` | 47,529좌표 불일치 | 60회 복원 요청 모두 범위 조건으로 거부 | 2/168,000좌표 |
| raw hmax에 DMC 추가, `0.02*h/(pD)` | 시험된 좌표 모두 일치 | 60회 복원 요청 모두 범위 조건으로 거부 | **168,000/168,000좌표** |

`centered_mismatch_coordinates=0`만 보고 normalized/raw 경로가 성공했다고
해석하면 안 된다. 해당 두 경로는 모두 centered 복원을 실행 전에 거부했다.
literal 결과와 centered 결과는 다른 복원 방식이다.

DMC-only는 마스크가 거대해 작은 업데이트를 norm으로 구별하기 어렵다.
raw 해석은 mask가 2e-10 이하이므로 양자화 정밀도 1e-6보다 작다.
집계가 맞아도 wire만 반올림하여 평문이 드러나는 방식은 채택하지 않는다.
0좌표 복구도 개인정보 보호의 보안 증명은 아니다.

## carry와 작은 오차의 분리

원본 HPRF에서 `sum(h_i)-h(sum(keys)) = carry*p + e`를 직접 측정했다.
첫 좌표의 실제 결과는 `5*p-2`였다. 33,600개 시험 좌표 중 carry가 0이
아닌 좌표는 30,731개였고, centered 작은 오차의 최대 절댓값은 2였다.
extra precision으로 작은 e는 제거됐으나 literal 실수 뺄셈에서는 carry가
남았다. DMC-only의 centered modular 복원은 명시적 수정이며 Algorithm 8
그대로라고 부르지 않는다. 독립적인 SUM bound가 ring 반주기보다 작을 때만
허용하고, 반올림 오차 조건도 검사한다.

normalized 후보에는 정확한 유리수 반례도 있다. 원본 HPRF의 첫 좌표에서
키 `(4,16)`와 `(1,19)`의 마스크 합 차이가 정확히 p다. 따라서 이전 L∞=0.1인
후보 표현에서 `(1,19)`의 평문 합 0.02와 `(4,16)`의 평문 합 0은 동일한
masked total, 동일한 합산 키 20을 만든다. DMC의 추가 소수 자릿수를
변경해도 이 표현의 유효 계수 `0.02/p`는 그대로다. 이는 **해당 표현의**
모호성을 입증할 뿐, 논문의 모든 가능한 구현이 불가능하다는 주장이 아니다.

## 이 수치 경로의 판정

현재 성공한 후보 중 MGF의 작은 마스크와 개별 업데이트 비공개 조건까지
동시에 충족했다고 검증한 경로는 없다. 따라서 기존 Flower 학습 경로를
실패한 후보로 교체하지 않았다. 추가 share로 우회하지 않는다.

공개 저자 소스나 논문에 finite-field/실수 대표값의 누락된 결합 규칙이
추가로 확인되면 같은 감사에 넣어 다시 검증할 수 있다. 현재 포팅 목표는
그 규칙을 새로 발명하는 암호 프로토콜 설계를 완료 조건으로 삼지 않는다.
따라서 이 후보를 억지로 성공 경로에 연결하지 않고, 검증된 source-ASR
경로와 중앙 학습 artifact MGF를 분리해 실행하며 이 논문 wire 경로는
**공개 자료로 재현되지 않음**으로 남긴다.

## 논문 길이·참여 규모 수치 재검증

후속으로 CLI에 `--clients`를 추가하고 저자 학습 설정의 라운드 참여자
100명, 논문 입력 검증 길이 60라운드, classifier 840좌표로 같은 감사를
확대했다. 결과는
`.cache/paper-dmc-q100-60round-840-audit-20261001.json`이다.

```bash
PYTHONPATH=.cache/author-asr-deps:.cache/flower-deps:.cache/torch-deps:. \
python3 -m experiments.audit_paper_dmc \
  --source ../Aion/agent/Aion/HPRF \
  --rounds 60 --clients 100 --dimension 840 \
  --output .cache/paper-dmc-q100-60round-840-audit-20261001.json
```

q=100에서는 `l_ex=3`, `D=10^9`다. 100개 공개 fixture key의 전체
cohort 및 변동 부분집합에서 HPRF 차이를 측정한 100,800좌표 모두에
nonzero carry가 있었고, 최대 centered 작은 오차는 3이었다. 첫 좌표의
carry는 51, 작은 오차는 -3이었다.

| 후보 | literal 불일치 | centered 처리 | 개별 wire 단순 반올림 복구 |
| --- | ---: | --- | ---: |
| DMC-only | 100,800좌표 | 100,800좌표 일치 | 0 / 5,040,000 |
| normalized MGF | 151,200좌표 | 180회 모두 범위 모호성 거부 | 100 / 5,040,000 |
| raw-hmax 이중 scaling | 0좌표 | 180회 모두 범위 모호성 거부 | **5,040,000 / 5,040,000** |

DMC-only의 centered 결과는 독립적인 합계 bound를 요구하는 별도 modular
adaptation이며 literal Algorithm 8이 아니다. normalized 후보의 모든
복원 요청이 거부됐다는 것은 오답 수용보다 안전하지만 end-to-end 학습
완료도 아니다. raw 후보는 집계 수치만 맞고 wire 평문이 전부 드러나므로
채택하지 않는다. 따라서 작은 q의 우연한 fixture가 아니라 논문 길이와
q=100에서도 같은 공개 구현 경계가 확인됐다.
