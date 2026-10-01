# 저자 SHPRG·MGF 계산의 Flower 포팅: 4라운드

공식 Flower SuperLink/Ray에서 저자 input-validation SHPRG와 레이어별
torch.float32 MGF를 사용하는 평문 학습 경로를 실행했다. 원본 ASR HPRF를
사용한 보안 집계 실행이 아니며, 기존 bounded masked-MGF 결과와 구분한다.

N=100, q=20, 집계자 등록 4개, seed=0, CPU worker 4개, 4라운드다.
공격 client 4명이 1·4라운드에 공격한다. 원본 Fashion-MNIST 데이터,
감사된 avg_300 checkpoint, 원본식 분할·poison RNG 정책 및 개별 참여
일정을 두 Flower run에 동일하게 적용했다. MGF는 weight=0.1,
min_threshold=0.1이며 선택 인원을 원본대로 제한한다.

| 라운드 | 저자 MGF 정확도 | 무방어 정확도 | 저자 MGF 공격 성공률 | 무방어 공격 성공률 |
|---|---:|---:|---:|---:|
| 0 | 88.56% | 88.56% | 0.390625% | 0.390625% |
| 1 | 88.62% | 10.03% | 0.976563% | 100% |
| 2 | 88.58% | 68.64% | 0.976563% | 94.726563% |
| 3 | 88.69% | 78.10% | 0.976563% | 94.921875% |
| 4 | 88.77% | 64.92% | 0.781250% | 46.484375% |

MGF는 정상 client 2·2·2·6명을 선택했고 공격 client는 선택하지 않았다.
MGF run ID는 `10386550134664049162`, 서버 케이스 측정 시간은
18.418646282초다. 무방어 run ID는 `14334760390262420724`,
26.446003852초다. 이 시간은 CLI 시작·스테이징·후속 평가를 포함한
벽시계 총 시간이 아니며 암호나 BFT 비용 비교도 아니다.

## 계산 동등성과 한계

- 원본 `shprg.py`와 마스크 정수·float 출력·합산을 직접 비교했다.
- 원본 `aggregation_rules.py::aion` 함수만 AST로 분리해 동일한 입력,
  행렬 및 seed transcript로 직접 실행했다. CUDA 호출만 CPU로 대체했다.
  4라운드 선택 집합, 레이어별 평균, threshold, norm 이력이 정확히 일치했다.
- 원본의 한 행 SHPRG p/q와 Python float 연산 순서를 보존했다.
  norm·sort·searchsorted·평균 및 bound 갱신은 torch.float32 CPU를 쓴다.
- 같은 RNG에서 행렬을 생성하는 방식은 보존하지만, 로컬 seed로 격리한
  transcript다. 원본 전체 프로그램의 학습·샘플링과 공유하는 RNG 호출
  순서, 기존 원본 matrix 파일의 값, CUDA 비트 단위 결과는 재현했다고
  주장하지 않는다. resume 분기도 아직 포팅하지 않았다.
- 무방어 경로는 소수점 6자리 양자화를 적용하고 MGF는 float32 평균을
  사용한다. 학습·공격·참여 조건은 같지만 수치 집계 방식은 다르다.
- 평문 개별 업데이트를 coordinator가 받는다. 개인 업데이트 보호,
  HPRF 기반 ASR과 MGF의 통합, 논문의 전체 보안 또는 장기 성능 증거가 아니다.
- 단일 seed의 축소 4라운드 시험이며 논문의 60라운드 곡선이 아니다.

원시 실행 위치는
`.cache/fmnist/official-author-shprg-mgf-four-round-seed0`다.
검증은 source/input/catalog/config hash와 학습 일정, 모델 변경과
norm history, float32 bound 및 선택 순서를 확인한다. 개별 평문 업데이트는
저장하지 않으므로 사후 verifier가 개별 masked norm을 원 학습에서 다시
생성하는 것은 아니다. [해시 연결된 결과](results.json)에 run ID,
model/result/provenance/verification 해시를 기록했다.

[포팅 기준과 실행 명령](../../aion-author-port-goal.md)을 따른다.

차등 시험에서 읽은 저자 소스의 SHA-256은 다음과 같다. 이는 실행 후
원본 트리를 확인한 해시이며 staged provenance의 일부라고 주장하지 않는다.

| 원본 파일 | SHA-256 |
|---|---|
| shprg/shprg.py | f1015c82996aaef147813bb773aeb12feff18fdfd9ffdd2b61b8d18521bd1d0f |
| roles/aggregation_rules.py | 3a5b48eb0ddd4305df2995fb4f851559cae1270d1d3d44527c8cca225945ae0b |
| shprg/initialization_values | 7f54772524fa46fb0568c604f44a6235dfabbdecbe298b78e8e18119ade27d3e |
