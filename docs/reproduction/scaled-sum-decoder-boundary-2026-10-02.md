# 8좌표 합계 충돌과 기존 ASR 증거의 carry 한계

## 무엇을 새로 확인했나

기존 1좌표 반례에 이어 원본 저장 HPRF와 현재 decimal wire로 **8좌표 전체의
masked SUM과 합계 키가 같은데 실제 업데이트 SUM이 다른** 두 공개 fixture를
만들었다. 두 실행 모두 새 inclusive MGF numeric 판정을 통과한다.

같은 aggregate Pedersen opening과 aggregate share까지 만들 수 있는지도
별도 테스트했다. 합계 다항식의 상수/계수를 일치시키면 모든 aggregate
commitment와 share, opening이 같아도 실제 decimal mask SUM의 carry는
달라질 수 있었다. 따라서 현재 decoder의 입력에 기존 **합계** opening/share를
더하는 것만으로 이 모호성을 제거할 수는 없다.

이는 전체 프로토콜이나 논문의 불가능성 증명이 아니다. **개별 signed VECTOR와
개별 VSS commitment/share는 두 실행에서 다르다.** 그 차이를 활용하는
새로운 비공개 계산까지 불가능하다고 주장하지 않는다. 특히 개인 키를 탐색해
찾는 방법은 원본 키 도메인의 알려진 비공개성 문제이지 private aggregate
decoder의 완료 방법이 아니다.

## 정확한 fixture

원본 저장 matrix/setup의 HPRF round는 4, candidates 20, selected 2,
dimension 8, model decimals 6, wire denominator 100,000,000이다.
이 감사의 공개 previous magnitude는 0.1, beta는 0.2, effective period는
`P=0.02`다. 검증용 동일 numeric history term으로 같은 bound `0.96`을 사용했다.
진짜 과거 round certificate나 실제 FMNIST history를 만들어낸 것으로
표시하지 않는다.

| 항목 | 실행 A | 실행 B |
| --- | --- | --- |
| 공개 fixture 개인 키 | 7, 19994 | 10, 19991 |
| 합계 키 | 20001 | 20001 |
| 3번째 좌표의 실제 업데이트 SUM | 0.06 | 0.08 |
| 나머지 7좌표의 실제 업데이트 SUM | 각각 0.06 | 각각 0.06 |
| 선택 순서 | [1,0] | [1,0] |
| 전체 masked SUM | 동일한 8좌표 | 동일한 8좌표 |
| aggregate HPRF | 동일 | 동일 |

두 업데이트의 차이는 3번째 좌표에서 정확히 한 scaled period다.
각 클라이언트 masked VECTOR는 서로 다르지만 합산하면 모든 좌표가 같아진다.
18개의 동일 filler는 bound 밖이며 두 정상 fixture 입력만 통과한다.
본 예의 private 키/업데이트는 모두 공개 숫자로 구성한 시험 데이터다.

`experiments/audit_scaled_sum_collision.py`는 고정된 공개 key sum에 대해
최대 512쌍만 확인해 같은 mask-rounding residue를 가진 공개 fixture를 찾는다.
이번 8좌표 결과는 10쌍 안에서 찾았다. 실제 실험의 Context/개인 키/학습 shard는
읽지 않으며 이 감사 모듈은 runtime decoder에서 import하거나 호출하지 않는다.
추가 share 또는 키 탐색 fallback을 실제 Flower 경로에 연결한 것이 아니다.

출력 `.cache/scaled-sum-eight-coordinate-r4-collision-20261002.json`에는
matrix/setup SHA-256, 공개 fixture 키·모델·masked VECTOR·masked SUM,
aggregate HPRF와 `ambiguous`를 함께 보관했다.

앞서 만든 `.cache/scaled-sum-eight-coordinate-collision-20261002.json`은
HPRF round 1의 초기 numeric prototype이고 새 primary 결과와 구분한다.
두 파일은 실제 Flower 학습 결과나 동일한 signed transcript가 아니다.

## 기존 opening과 aggregate share를 추가해도 같은 이유

별도 공개 Pedersen fixture에서는 aggregate constant blinding을 42,
두 client의 key slope 합을 579, blind slope 합을 975로 맞췄다.
두 실행의 aggregate 다항식은 동일하므로 committee index 1~4의 aggregate
share도 같고, 같은 commitment에 대한 opening은 모두 `(20001,42)`다.

테스트는 각 개별 share의 VSS 검증, commitment의 동형 합산, 각 aggregate
share의 합산, opening 검사, 기존 Pedersen 재구성을 실제 crypto API로 확인한다.
개별 polynomial은 공개 시험용으로 구성했으며 production randomness나
프라이버시 증명으로 표시하지 않는다. 실제 공유 알고리즘/키/원본 코드는
수정하지 않았다.

이 opening은 **원하는 합계 키가 맞다는 증거**다. 키를 적용한 원본 HPRF의
모듈러 값에서 개별 mask들의 정수 carry 합을 추가로 알려주는 증거는 아니다.
현재 `source_paper_numeric.recover`는 두 경우를 구분하지 못하므로
`ambiguous`로 거부한다. 잘못된 모델을 성공으로 받아들이지는 않는다.

## 공식 배포 재확인 범위

2026-10-02에 [Zenodo latest API](https://zenodo.org/api/records/15870338/versions/latest)를
다시 조회했다. latest record는 여전히 `15870338`, 파일은 `Aion.zip`,
403,162,679 bytes, 게시 checksum은 `md5:dadf60eeb3713398ef0d189ea9cec920`였다.
이는 이전에 조사한 v5와 같은 게시 metadata이며 전체 ZIP을 새로 다운로드해
다시 검증했다는 뜻은 아니다.

[공식 artifact appendix](https://www.usenix.org/system/files/usenixsecurity25-appendix-liu-yizhong.pdf)에
있는 E2 Docker tag `aionaion/input_validation:latest`도 확인했다.
Docker Hub tag API와 anonymous Registry manifest 요청 모두 HTTP 404였다.
이 환경에서 해당 공개 tag를 조회하지 못했다는 사실만 기록하며, image가
모든 위치에서 없거나 Docker 안에도 해당 코드가 없다고 주장하지 않는다.
컨테이너를 pull/실행하거나 계정 인증 정보를 요청·변경하지 않았다.

로컬 원본 ASR은 modulo-p 집계 복원이고 학습 artifact의 `aion()`은
`client_sum_hprg()`로 개별 seed의 mask를 합산한 뒤 선택된 plaintext update를
평균한다. 이 공개 중앙 경로를 추가 share 없는 private ASR+MGF wire의
해법으로 대신 사용하지 않는다.

## 재현과 다음 결정

### 후속: 공식 ZIP의 비-Python 문서·설정 확인

2026-10-02에 Python 소스 밖의 남은 설명도 확인했다. 기존 pinned inventory와
공식 ZIP central directory의 `.md`, `.txt`, `.toml`, `.cfg`, `.yaml`, `.yml`
member 집합을 비교했고, **13개로 정확히 일치**했다. 로컬 SHA-256·길이가
일치한 9개는 로컬 내용을 읽었다. 변경된 2개와 누락된 2개는 기존 `RangeZip`의
HTTP 206/Content-Range 검증으로 원격 내용을 읽고 inventory SHA-256·길이를
검증했다. 전체 ZIP을 다시 다운로드하거나 원본 파일을 교체하지 않았다.

| 원격으로 확인한 member | 로컬 상태 | 검증한 SHA-256 |
| --- | --- | --- |
| `Aion/README.md` | 변경됨 | `621ca630955706c3e9d6a9d14c2a508fe06d06cd48041698b771b4b84b035a97` |
| `Aion/input_validation/requirements.txt` | 변경됨 | `bf77425206099642676dc93169345a24313e469ad22ccdf255fc485275b820e8` |
| `Aion/input_validation/README.md` | 누락됨 | `8d443b8005876e044ae463e54084a3a7c32ece1738a42620ba2d45d3820b3f61` |
| `Aion/zkp/README.md` | 누락됨 | `629a3059ef68e12c7927e4850f10355376edfcf37c6772919994c21ad9697578` |

공식 root README에는 로컬 README에 없는 E1 평가 절차 등이 있었다. 입력 검증
README는 model-replacement 실험 실행법과 `weight`를 이전 global update의
L-infinity norm에 대한 최대 mask 크기 비율로 설명한다. combined private wire의
carry 복원 규칙은 이 설명에서 찾지 못했다.

`zkp/README.md`는 **실제로 존재하는 Bulletproofs 범위 증명 구현**의 API와
예제를 설명한다. 따라서 "원본에 ZKP 코드가 전혀 없다"고 해석하면 안 된다.
다만 이 문서의 일반 정수 범위 증명은 선택된 실제 update SUM의 bound를
현재 scaled period와 연결하거나 HPRF mask SUM의 carry를 계산하는 절차를
설명하지 않는다. 해당 README의 존재만으로 현재 ASR+MGF 복원이 해결됐다고
판정하지 않는다. 범위 증명을 새 wire에 연결하는 것도 별도 설계·검증이다.

inventory에는 C/C++/Rust/Go, notebook, shell script, Dockerfile member가 없었다.
30개의 `.pyc`에는 모두 이름상 대응하는 `.py` member가 있었다. 이는 inventory의
파일명 확인일 뿐 bytecode와 소스의 의미적 동일성 증명이 아니다. bytecode,
checkpoint, pickle, dataset archive, 중첩 Git pack은 실행·역직렬화·분석하지 않았다.
Docker 안의 내용이나 모든 비공개 구현의 부재를 이번 확인으로 증명하지 않는다.

이번 확인은 남은 공개 문서의 공백을 좁혔지만 runtime 복원 문제를 고치지는
못했다. 클라이언트 추가 share 없이 초기 key shares를 사용하는 위원회 공동
계산을 도입하려면 사용자의 프로토콜 확장 방향 결정이 여전히 필요하다.

```bash
PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m experiments.audit_scaled_sum_collision \
  --output .cache/NEW-scaled-sum-eight-coordinate.json

PYTHONPATH=.cache/flower-deps:.cache/author-asr-deps:.cache/torch-deps:. \
python3 -m pytest -q tests/test_scaled_sum_collision.py
```

새 감사 시험 9개가 통과했다. numeric `recover`에서 모호성을 그대로 거부하는
연결, 같은 aggregate opening/share, finite search budget, source 출력과 공개
모델의 마스킹 관계를 검증했다. 8좌표 counterexample 하나로 FMNIST의 모든
61,706좌표나 모든 다른 HPRF 구현의 정보 부족을 증명한 것은 아니다.
source numeric/aggregate 검증과 기존 scaled-ring/DMC까지 함께 묶은 회귀는
**146개 통과, 40.53초**다. runtime package에서 새 감사 모듈을 참조하지
않는 것도 확인했다. compileall과 `git diff --check`도 통과했다.

현재 목표를 완성하려면 private sum 복원을 정당화할 정보/절차가 더 필요하다.
원본 범위를 유지한다면 저자 측 combined wire/복원 설명의 확인이 필요하다.
다른 선택은 초기 key shares로 위원회가 carry 또는 정수 mask SUM을 비공개로
공동 계산하는 절차를 검토하는 것이다. 클라이언트가 새로운 mask share를
보내지 않도록 설계할 가능성은 있으나 별도 MPC 통신/중간값/검증이 필요하고,
원본 Aion-ASR의 단순 Flower 통신 포팅 범위를 넓힌다. 안전성이나 성능이
이미 검증됐다고 주장하지 않는다.

사용자의 방향 결정 없이 MPC, 개인 키 복원, plaintext fallback, 임의 scale
변경을 추가하지 않는다. 저자나 외부 사용자에게 메시지도 보내지 않았다.
전체 활성 목표는 미완료이며 이번 감사는 완료를 대신하는 작은 목표가 아니다.
