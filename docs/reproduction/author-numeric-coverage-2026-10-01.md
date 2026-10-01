# 공식 v5 전체 Python 소스의 수치 경로 대조

## 왜 다시 확인했는가

이전 source identity 감사는 ASR role 파일 2개와 실제 포팅 메서드 8개의
동일성을 확인했다. 이를 전체 로컬 Aion 트리의 동일성으로 확대하면 안 된다.
새 감사는 pinned 공식 v5 ZIP의 Python 파일 **130개 전체**를 대상으로 한다.
로컬 hash가 일치한 119개는 해당 내용을 사용하고, 다른 10개 및 누락된 1개는
공식 ZIP HTTP byte-range로 가져와 기존 inventory의 SHA-256·길이를 확인했다.
ZIP의 Python member 집합도 inventory와 정확히 일치하는지 검사했다.

원본 Aion 파일을 수정·추출·교체하지 않았다. 원격 Python도 실행하지 않았다.
공식 v5 범위이며 최신 Docker 컨테이너나 별도 비공개 코드를 조사한 것은 아니다.

## 실행 결과

```sh
PYTHONPATH=.cache/author-asr-deps:.cache/flower-deps:.cache/torch-deps:. \
python3 -m experiments.audit_author_numeric_coverage \
  --output .cache/author-v5-all-python-numeric-coverage-20261001.json
```

완료 결과: `local_pinned=119`, `remote_changed=10`, `remote_missing=1`.
다시 실행할 때는 새로운 출력 파일명을 지정한다.

공식 내용과 다른 로컬 파일:

- `agent/Agent.py`
- `agent/Aion/SA_Aggregator.py`
- `agent/Aion/SA_ClientAgent.py`
- `agent/acorn/utils/batch_verifier.py`
- `config/acorn.py`
- `config/aion.py`
- `config/secagg_plus.py`
- `input_validation/configs.py`
- `pki_files/setup_pki.py`
- `util/crypto/secretsharing/vss.py`

누락된 로컬 파일: `input_validation/check_results.py`.
이 목록은 변경 이유나 의미까지 입증하지 않는다. 포팅 메서드의 AST 동일성은
앞선 별도 감사의 증거이며 전체 파일 동일성과 구분한다.

## MGF·DMC/DMR에 대해 확인한 범위

전체 공식 Python 내용에서 `DMC`, `DMR`, `l_dp`, `l_ex`, `ldp`, `lex`,
`dynamic mask coverage/removal`의 단어 경계 검색 결과는 0개였다.
이는 명시적인 식별자 구현을 발견하지 못했다는 증거다. 다른 이름이나 형태의
등가 알고리즘까지 의미론적으로 없음을 증명하지는 않는다.

AST로 `sum_hprg` 정의와 호출을 분리했다. `server_sum_hprg`와
`client_sum_hprg`는 학습·GradAttack SHPRG에 정의되지만 실제 학습 MGF의
`roles/aggregation_rules.py` 128행 호출은 **`client_sum_hprg`**다.
정의가 있다는 사실을 합산 키 복원 함수가 실제 사용된 증거로 취급하지 않는다.

검토한 원본 ASR 복원은 `sum_key`로 HPRF를 생성하고 mask를 뺀 다음 p로
modulo한다. 별도 학습 소스는 작은 마스크로 norm을 판정하되 선택된 평문
업데이트를 평균한다. 따라서 두 경로를 연결할 때 생기는 carry 문제에 대한
검증된 작은-mask 복원 함수를 이번 대조에서도 찾지 못했다.

[논문 artifact appendix](https://www.usenix.org/system/files/usenixsecurity25-appendix-liu-yizhong.pdf)는
E1 프로토콜 모의실험, E2 input validation, E3 gradient inversion을 구분한다.
별도 실험들의 존재를 하나의 비공개 end-to-end 학습 구현의 증거로 합치지 않는다.

## 참조 구현 후속 개선

`paper_dmc.py`에 Algorithm 6의 공개 SUM norm·해당 라운드의 aggregate
mask norm으로 만드는 history term과, 서로 다른 두 과거 term의 비율을
사용한 bound 갱신을 추가했다. 현재 후보 mask norm을 과거 항으로 대신하지
않고, SUM을 optimizer용 평균으로 자동 변환하지도 않는다. 일반 L2 sqrt는
60자리 Decimal을 사용하고 나머지 비율 계산은 Fraction을 유지한다.
bootstrap 값은 호출자가 명시해야 하며 임의 percentile·selection floor를
논문 수식에 끼워 넣지 않았다.

검증 명령:

```sh
PYTHONPATH=.cache/author-asr-deps:.cache/flower-deps:.cache/torch-deps:. \
python3 -m pytest -q tests/test_paper_dmc.py \
  tests/test_author_numeric_coverage.py tests/test_source_identity.py
```

**34 passed, 0.23s.** 수치 참조·소스 감사 시험이며 새 Flower 학습 결과가 아니다.
추가 share는 도입하지 않았다. 원본 HPRF의 작은-mask 복원 규칙은 아직
해결되지 않았으므로 목표는 미완료다.
