# 공식 v5와 현재 Aion 소스의 재대조

2026-10-01. MGF 연결 문제를 다른 공식 버전으로 해결할 수 있는지 확인했다.
[Zenodo v5](https://zenodo.org/records/15870338)의 latest/versions API는 여전히
15870338을 최신 버전으로 반환했다. 확인된 버전은 v1–v5의 5개이며, 최신 파일
`Aion.zip`의 게시 MD5는 `dadf60eeb3713398ef0d189ea9cec920`, 크기는
403,162,679 bytes다. 이 조회가 모든 비공개/미발견 구현의 부재를 증명하지는 않는다.

[공식 artifact appendix](https://www.usenix.org/system/files/usenixsecurity25-appendix-liu-yizhong.pdf)는
SA protocol simulation(E1)과 input validation evaluation(E2)를 별도 실험으로
설명한다. 실제 로컬 E2 코드의 `aion()`은 `client_sum_hprg()`로 개별 seed의
마스크를 생성·합산한다. sum seed만 쓰는 `server_sum_hprg()`를 이 위치에서
호출하지 않는다. 현재 ASR의 합계 키 복원과 같은 경로라고 해석하지 않는다.

## 로컬 파일과 공식 파일

로컬 ASR role 파일 두 개의 전체 SHA-256이 기존 공식 inventory와 달랐다.
HTTP range로 공식 ZIP의 해당 member를 직접 읽고 inventory SHA-256/크기를
검증한 뒤 대조했다. ZIP member 경로를 파일 시스템에 추출하거나 외부 코드를
실행하지 않았고, `/home/jisung/trustlessfl/Aion`도 변경하지 않았다.

| 파일 | 전체 파일 동일 | 포팅에 사용한 메서드 AST 동일 |
| --- | --- | --- |
| `SA_ClientAgent.py` | 아니오 | 예, 5개 |
| `SA_Aggregator.py` | 아니오 | 예, 3개 |

클라이언트 생성자는 공식 v5에서 `prime` 인자를 받지만 로컬에서는
`param.prime`을 사용한다. 집계자 생성자도 같은 차이가 있다. 생성자 signature와
해당 docstring/할당문 이외의 줄 단위 변경은 이 두 파일에서 발견하지 않았다.

대조 메서드는 다음과 같다:

- client: `sendVectors`, `share_mask_seed`, `vss_share`, `sum_shares`, `get_sum_shares`
- aggregator: `MMF`, `report_process`, `reconstruction_process`

`aion_source_asr.load_source()`는 이 메서드를 AST로 추출하고 simulator 생성자는
실행하지 않는다. 어댑터가 manifest의 명시적인 prime으로 VSS를 초기화하므로,
발견된 생성자 차이를 현재 포팅 계산의 차이로 바꾸어 주장하지 않는다.
반대로 전체 로컬 role 파일이 공식 v5와 동일하다고도 주장하지 않는다.

HPRF, 학습 SHPRG, `aggregation_rules.py`의 로컬 raw SHA-256/CRC는 기존
공식 inventory와 일치했다. 이 세 파일은 이번에 ZIP member를 다시 다운로드한
것이 아니라, 이전에 검증한 inventory와 현재 파일을 비교한 결과다.

## 재실행 및 검증 범위

```bash
python3 -m experiments.audit_source_identity \
  --source ../Aion \
  --output .cache/NEW-source-identity.json
```

output은 존재하지 않는 파일이어야 한다. 도구는 두 공식 role 파일의 raw hash와
8개 메서드의 AST hash를 각각 기록한다. remote ZIP의 부분 요청에 대해 HTTP
206·Content-Range·응답 길이를 검증한다. 외부 파일 import/pickle load는 하지 않는다.
전체 최신 archive를 이번에 다시 다운로드·CRC 감사한 것으로 표시하지 않는다.

실제 결과: `.cache/author-v5-recheck-20261001/source-identity.json`.
전체 다운로드는 범위 요청으로 전환하면서 중단했고, 받은 일부는 같은 디렉터리의
`Aion.zip.partial`에 보존했다. 완전한 ZIP 또는 무결성 검증 완료 archive가 아니다.

새 offline 감사 시험 6개가 통과했다. 포맷 차이와 계산 차이, 생성자만 달라진
파일, HTTP 범위 불일치·잘림·캐시를 확인한다. 기존 bounded carry/고정 키 차분
반례 시험 2개도 현재 트리에서 재실행하여 통과했다. 전체 저장소 회귀는 아니다.

## 남은 결정

다른 공개 최신 role 파일에서 누락된 bounded carry 복원 경로를 찾았다는 증거는
없다. 현재 sum-key 기반 decoder의 모호성은 기존
[반례와 완료 조건](../mgf-key-sharing-reduction.md)에 남아 있다. 동일한 합계 키와
masked 합에서 서로 다른 참 업데이트 합이 가능한 입력이 실제 원본 HPRF로
확인됐으므로, 단순 통신 어댑터 변경만으로 이를 정확히 복원했다고 표시하면 안 된다.

사용자에게 추가 share를 허용한 정확한 client-masked MGF, 원본 중앙 평문 학습
baseline, 또는 무추가-share MMF 유지 중 우선순위를 요청했다. 선택 없이 새
암호 프로토콜이나 개별 키 공개를 도입하지 않는다. 목표는 미완료다.
