# Flower FMNIST: 마스킹된 classifier MGF와 전체 ASR 집계

공식 Flower 1.36.0 SuperLink/Ray CPU runtime에서 `aion_mgf_beta --mgf-projection` 경로의 1라운드를 완료하고 모델·roster 인증서를 검증했다. classifier 평문을 전달하는 `aion_mgf_oracle`을 사용하지 않았다.

## 구현과 검사 범위

원본 `Aion/input_validation/FL_Backdoor_CV/roles/aggregation_rules.py`의 입력 검증은 마지막 classifier weight의 norm을 검사한다. 새 projection 경로는 같은 FMNIST classifier 840개 좌표를 bounded mask로 가려 검사하고, 전체 61,706개 좌표는 라운드별 새 키로 modular AION-ASR 집계한다. mask share의 Pedersen 비용도 이 840개 좌표에만 발생한다.

선택된 집합의 bounded mask 합과 ASR key 합을 복원한 뒤, 검사 벡터에서 mask를 제거한 합이 실제 전체 ASR 결과의 classifier 좌표와 같은지 확인한다. 이 검사는 합계 일치성 검사이며 모든 악성 client의 개별 probe/update 일치 증명이 아니다. 여러 client의 상쇄 공격 및 bounded mask의 정보 노출 한계는 남아 있다.

## 실행 결과

- N=q=2, aggregator 4개, 공격 client 0명, seed 0, 1라운드
- 초기 alpha `0.001`, beta `0.5`, norm bound `10`, reference term `1`
- 두 client를 선택하고 정상 commit; 실행 시간 104.60초
- 전체 update 좌표 61,706개, `mgf_vector` 좌표 840개, `oracle_classifier` 필드 없음
- 실제 서명 update 크기: 5,793,870 bytes 및 5,793,819 bytes
- accuracy 88.56% → 87.97%; 공격 없는 기능 시험이므로 방어 성능 결과로 해석하지 않는다.

원시 실행은 `.cache/fmnist/official-mgf-projection-two-client-one-round-seed0`에 있으며, 이 폴더의 `verification.json`과 이 보고서의 `results.json`이 모델·실행 hash를 보존한다.

## 남은 차이

검사 좌표 범위는 원본 artifact에 맞췄지만, 현재 norm bound의 초기화는 명시한 bootstrap 값과 기존 bounded-MGF 상태 전이를 사용한다. 원본 첫 3라운드의 percentile 선택·최소 10%·최대 80% 규칙과 정확히 같은 선택을 보장하지 않는다. 이를 맞추고 N=500/q=100의 공격 실험을 수행해야 한다. 이번 실행은 HotStuff를 활성화하지 않았다.

3종 HPRF 연구 backend에서 projection 필터·전체 모델 복원 2라운드를 확인했고, 검사 벡터만 1단위 변조한 입력을 최종화에서 거부하는 시험을 추가했다. 관련 MGF wire·AION 시험은 87개 통과했다. 보안 파라미터 감사나 입력 프라이버시 증명은 제공하지 않는다.

별도 TCP 시험에서는 projection 경로를 선택형 HotStuff에 연결하고 Flower와 최초 리더가 중단된 뒤 나머지 피어가 모델 결정을 복구하는 사례를 통과했다. 이는 공식 FMNIST 실행에 HotStuff를 켠 결과나 전체 부분 동기 진행 증명이 아니다.
