# 원본 HPRF·초기 VSS·추가 share 없는 bounded-lift MGF 실험

## 구현 수정

양자화 조건만으로 복원 후보를 세면 실제 허용 mask 범위를 벗어나는 후보도
모호성으로 처리된다. decoder에서 후보 업데이트 합을 뺀 implied mask 합이
`[0, n*round(coefficient*p)/D]`에 있는지도 검사하도록 수정했다.
기존 grid-only preflight는 과도한 거부여서 제거했다.

scale, 모델 양자화 단위, 원본 HPRF, VSS 또는 client 메시지 수는 바꾸지 않았다.
클라이언트가 보낸 masked vector 하나와 위원회가 복원한 합산 키만 사용한다.
실제 허용 범위 내에 복원 후보가 둘 이상 있으면 계속 거부한다.

## 실제 FMNIST 학습

모든 실행은 clients 20, committee 4, local epochs 2, decimal places 6,
classifier 840개 좌표, beta 0.2, 고정 참여다. 공개 초기 checkpoint에서 시작한다.
4라운드 모두 새 실행의 키와 원본 초기 VSS를 사용하며 key-share 80개,
추가 mask-share 0개다. 원본과 다른 조건부 adapter/E2 bootstrap/초기 scale
구분은 manifest scope에 명시했다. 논문 전체 end-to-end 재현으로 표시하지 않는다.

| 실행 | 전송 | 완료 라운드 | 학습 runtime | 최종 정확도 | 최종 공격 성공률 |
| --- | --- | ---: | ---: | ---: | ---: |
| clean | 로컬 Flower Message worker pool 4 | 4 | 44.757초 | 88.81% | 측정하지 않음 |
| clean | 공식 Flower SuperLink/Ray worker 2 | 4 | 90.966초 | 88.49% | 측정하지 않음 |
| model replacement backdoor | 로컬 Flower Message worker pool 4 | 4 | 54.226초 | 88.68% | 0.5859375% |
| model replacement backdoor | 공식 Flower SuperLink/Ray worker 2 | 4 | 100.365초 | 88.60% | 0.390625% |

fresh 실행마다 원본 secret/mask가 달라 선택 집합과 곡선도 달라진다.
표의 차이를 전송 시스템이 학습 정확도를 바꾼다는 증거로 해석하지 않는다.
runtime은 결과 파일의 학습 workflow 시간이며 CLI startup/staging 전체 시간이 아니다.

공격은 20명 중 4명(0~3), 라운드 1~4의 model-replacement backdoor다.
현재 재현 설정의 poison batch 6, attack steps 120, boost 20을 사용했다.
로컬 선택 집합은 [15,10], [15,4], [15,4], [15,4]로 공격자를 모두 제외했다.
각 라운드 attack success rate는 0.78125%, 0.5859375%, 0.5859375%, 0.5859375%.
공식 runtime의 선택은 [6,19], [15,4], [15,4], [15,4]로 역시 공격자를
모두 제외했다. 공격 성공률은 네 라운드 모두 0.390625%다.
공격자가 실제 선택되지 않았다는 사실과, 모든 공격/장기 실험의 방어 증명은 다르다.

## 재학습 대조

위 네 실행 각각 선택된 client 학습 8회씩을 독립 재실행했다. quantized 선택 합,
optimizer 결과와 전체 모델의 최대 절대 오차는 모두 0(tolerance 1e-12)이다.
정상 경로 BFT 인증서, 입력 hash 바인딩, scale/next-linf 및 공개 history 관계도
확인했다. mask norm 자체는 verifier가 개별 key로 독립 재계산하지 않는다.
필터 soundness, 모든 Byzantine/부분 동기 조건의 liveness, 프라이버시 증명이 아니다.

## 결과 파일

저장소 루트 기준 경로:

- `.cache/source-paper-quantized-fmnist-mask-bounds-four-round-20261001/`
- `.cache/source-paper-quantized-official-mask-bounds-four-round-20261001/`
- `.cache/source-paper-quantized-fmnist-mask-bounds-attack-four-round-20261001/`
- `.cache/source-paper-quantized-official-mask-bounds-attack-four-round-20261001/`

각 디렉터리에 manifest.json/results.json/verification.json이 있다.
실패했던 이전 clean 실행은 삭제·덮어쓰지 않았다.

## 수치 감사와 남은 한계

`.cache/quantized-lift-mask-bounds-840-20261001.json`은 학습이 아닌 공개 fixture
20라운드·840좌표 검사다. 18개 profile/count 조합 총 360번 검사에서 틀린 합을
성공으로 받아들인 경우는 0이다. 그러나 고정 초기값 0.1/1은 계속 모호하고,
공개 checkpoint scale의 selected-count 10도 실패한다. 일부 profile/count 10은
20번 중 9번만 정확히 복원했다. 따라서 4라운드 성공을 장기·대규모의 보편적
복원 보장으로 확대하지 않는다. 선택 전 전체 cohort mask norm과 저자 중앙
E2 oracle 차이도 남아 있다.

### 10라운드 후속 검증: 미완료

`.cache/source-paper-quantized-fmnist-mask-bounds-clean-ten-round-20261001/`은
동일 규칙의 fresh clean 실행이다. 1라운드 commit 후 2라운드 reconstruct에서
`ambiguous`로 중단했다. failure.json에 완료 라운드와 공개 metadata가 남았고
results.json은 없다. 10라운드 완료나 전체 모델 재학습 대조를 주장하지 않는다.

공개 첫 라운드 next-linf는 `253/40000`이며 다음 mask period는
`0.001265`(model quantum의 정확히 1265배)다. 이 scale에서는 period만큼
다른 후보가 grid 조건과 실제 mask 합 범위를 모두 만족할 수 있다.
원본 공개 fixture 키 (4,16), 라운드 2로도 모호성을 재현했다. 임의 후보를
선택하거나 scale을 바꾸지 않았다. 범위 보강은 실제 개선이지만 모든
학습 history의 복원을 보장하는 해결책은 아니다.

수치/source/official 연결 테스트 69개 및 source/dynamic 기존 경로 18개 통과.
[수치 수정과 정정 이력](../../reproduction/source-paper-mgf-norm-2026-10-01.md).
