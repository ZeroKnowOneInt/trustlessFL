# 원본 scalar 키 범위와 유한 wire의 공개 키 탐색 감사

## 범위

원본 `SA_ClientAgent.sendVectors`는 mask seed를 1..100000에서 생성한다.
`OriginalAionHPRF`는 해당 scalar 입력, 공개 저장 matrix와 원본 반올림을
유지한다. 이 감사는 그 키 범위와 소수 6자리 모델 표현을 사용하는 공개
fixture만 대상으로 한다. 모든 HPRF 구성이나 논문 보안성의 반증은 아니다.

private actor Context, shard, VSS share 또는 aggregate key는 읽지 않았다.
fixture 생성에만 secret seed를 사용하고, 공격 함수에는 masked integer
vector, 공개 codec/matrix, round 및 키 범위만 제공한다.

## 공격과 관측 결과

각 후보 seed에서 해당 좌표의 wire mask를 계산한다. 모델 격자 간격 E가
공개이므로 `(masked_value - candidate_mask) mod E == 0`인 seed만 남긴다.
seed가 하나 남으면 전체 vector를 검증하며 업데이트를 복원한다. 여러 seed가
남을 때 하나를 임의로 선택하지 않는다. 잘못된 전체 vector 정합성도 거부한다.

`.cache/source-key-search-wire-audit-20261001.json`:

| 표현 | 세 fixture에서 후보 수 변화 | 복원된 개별 업데이트 좌표 |
| --- | --- | ---: |
| 현재 decimal8 | 997→11→1 / 999→10→1 / 1000→7→1 | 2520/2520 |
| finite decimal16 + float32 norm 후보 | 각각 첫 좌표에서 1 | 2520/2520 |

fixture별 탐색과 840좌표 복원 시간은 약 0.059~0.063초였다.
이는 해당 로컬 fixture 관측값이지 모든 scale/key/wire의 공격 상한이 아니다.
840개는 fixture 좌표 수이며 실제 특정 client의 classifier를 읽은 것이 아니다.

결과는 exact-rational의 공개 역산과 다른 공격이다. wire를 반올림해도 원본의
작은 key domain과 공개 모델 격자에 대한 열거를 막지는 못했다.

## 구현에 반영한 경계

finite 후보는 Flower에 연결하지 않는다. 기존 source port는 원본 연구용
재현을 위해 보존하되 신규 manifest에 `key_profile`을 기록한다:
`author-scalar`, 1..100000, `production_privacy=false`.
scope에도 운영 비공개성을 주장하지 않는다고 표시한다. 키 범위, 원본 HPRF,
초기 VSS 및 추가 share 0개 조건 자체는 변경하지 않았다.

기존 학습/공격 결과의 정확도와 집계 일치 여부는 유지되지만 입력 비공개성이
증명된 결과로 승격하지 않는다. 기존 manifest/result 파일도 덮어쓰지 않는다.
다른 crypto backend나 저자 학습 E2의 SHPRG까지 이 공격 결과를 확대하지 않는다.

키 범위를 단순히 늘리면 이 100000개 열거 실험은 바뀌지만, HPRF의 PRF
보안성·다중 라운드 재사용·scaled 집계 정확성이 동시에 해결됐다는 근거는 없다.
보안 profile 변경은 원본 artifact의 통신 포팅과 다른 변경이므로 별도 범위와
검증 기준을 정해야 한다. 현재 목표의 모든 수치/비공개성 문제는 미완료다.

검증: 공개 공격/precision/source numeric/official 연결 79개와 기존
source/dynamic 18개 테스트 통과. `git diff --check` 및 변경 모듈 compile
검사도 통과했다. 전체 저장소 테스트 또는 모든 보안 조건의 검증은 아니다.
