# 저자 소스 스냅샷 포함 공식 Flower 4라운드

`--author-reference-dir`로 원본 학습·SHPRG/MGF 소스 5개와 실제 SHPRG
initialization 파일 1개를 스냅샷으로 기록했다. 각각의 SHA-256과 실제
초기화 값 (1,8,173569775688864,5000999999999999)을 provenance와
results.json에 보존했다. Verifier와 exporter는 inventory·초기화·hash
변경을 거부한다. 이는 비교 기준 기록이며 원본 파일을 Flower worker가
직접 실행한다는 뜻은 아니다. classifier width는 별도로 840을 사용한다.

## 결과와 검증

FMNIST/LeNet5 avg_300 checkpoint, N=100/q=20, seed 0, CPU worker 4개,
4라운드, 공격 client 4명, 공격 라운드 1·4다. author-loader sampling으로
저자 SHPRG/MGF 평문 경로와 양자화 무방어 경로를 실행했다. 이 실행에는
원본 HPRF 보안 집계나 HotStuff가 없다.

| 실행 | 최종 정확도 | 최종 공격 성공률 | 평균 공격 성공률 | 평균 테스트 오류 |
|---|---:|---:|---:|---:|
| 저자 SHPRG/MGF | 88.69% | 0.78125% | 0.78125% | 11.335% |
| 양자화 무방어 | 63.50% | 43.945313% | 84.375% | 45.265% |

평균은 checkpoint round 0을 제외한 학습 라운드 1~4 전체에서 계산했다.
지표는 [기존 author-loader 실행](../fmnist-flower-author-shprg-loader-four-round-2026-09-30/report.md)과
같지만 별도 run·identity·source snapshot이며 기존 결과를 덮어쓰지 않았다.
MGF run ID는 14838675983062177732, 서버 케이스 시간 30.286초;
무방어 run ID는 3471427258239625220, 29.739초다. CLI 시작·staging·
후속 평가는 위 시간 밖에 있으며 순수 성능 비교가 아니다.

원본 소스 변경·initialization 불일치·예상 밖 inventory·pickle global
resolution 거부 등을 포함한 관련 시험 60개가 통과했다. Source hash는
전체 공유 RNG, CUDA 결과, 악성 client의 학습 또는 운영 보안의 증명이
아니다. 라이선스 확인 전 외부 재배포를 승인한다는 뜻도 아니다.

## 실행

실행 위치는 trustlessFL이며 기존 결과 디렉터리를 재사용하지 않는다.

```bash
PATH="$PWD/.cache/flower-deps/bin:$PATH" \
PYTHONPATH=.cache/flower-deps:.cache/torch-deps:. \
python3 -m experiments.run_fmnist_official --phase all \
  --output .cache/fmnist/official-author-reference-loader-four-round-seed0 \
  --modes mgf quantized --author-mgf --training-sampling author-loader \
  --author-reference-dir ../Aion/input_validation/FL_Backdoor_CV \
  --population 100 --participants 20 --aggregators 4 --rounds 4 --workers 4 \
  --attack-clients 4 --attack-rounds 1 4 --cohort-sampling individuals --timeout 600
```

[해시 연결된 결과](results.json), [포팅 기준](../../aion-author-port-goal.md)을 참고한다.
