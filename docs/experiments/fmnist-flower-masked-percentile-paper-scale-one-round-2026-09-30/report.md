# Flower FMNIST: 마스킹된 MGF의 q=100 공격 라운드

공식 Flower 1.36.0 SuperLink/Ray CPU runtime에서 `aion_mgf_beta --mgf-projection --mgf-percentile`의 1라운드를 완료했다. 전체 모델을 AION-ASR로 집계하면서, classifier 평문 대신 마스킹된 840개 좌표로 client를 선택했다.

## 조건과 결과

- 등록 client N=500, 라운드 후보 q=100, aggregator 8개, seed 0
- 공격 client 20명 모두 참여; model-replacement 공격을 1라운드에 명시적으로 활성화
- 원본 checkpoint 및 FashionMNIST 데이터, artifact식 분할·공격 이미지 RNG, 개별 client 추첨
- 전체 모델 61,706좌표; 초기 mask alpha `0.1`, beta `0.1`, bound 및 reference term `1`
- 첫 라운드 percentile 규칙으로 10명 선택, 선택된 공격 client **0명**
- 정확도 88.56% → 88.55%, 공격 성공률 0.5859375% → 0.5859375%
- Flower ServerApp 내부 측정 시간 737.34초, 약 12분 17초. 초기화·학습·집계·모델 저장을 포함하며 논문의 순수 집계 시간과 직접 비교하지 않는다. CLI/Ray 기동과 실행 후 평가·검증 시간은 별도다.
- 모델·roster 정족수 인증서, 후보 client 서명, 후보 집합과 staged schedule의 일치, percentile 선택 결과를 실행 후 verifier로 검증

원시 결과는 `.cache/fmnist/official-masked-percentile-paper-scale-one-round-retry-seed0`에 보존했다. `results.json`은 모델·실행·provenance·verification hash를 포함한다. 앞선 실패 실행은 참가자 순서 검사에서 중단됐으며, 그 로그도 별도 폴더에 유지했다.

## 재현 명령

```bash
python3 -m experiments.run_fmnist_official --phase all \
  --output .cache/fmnist/another-masked-percentile-run \
  --population 500 --participants 100 --aggregators 8 --rounds 1 \
  --attack-clients 20 --attack-rounds 1 --workers 8 \
  --modes aion_mgf_beta --mgf-projection --mgf-percentile \
  --mgf-beta 0.1 --mgf-initial-alpha 0.1 \
  --mgf-initial-bound 1 --mgf-initial-term 1 \
  --partition-rng artifact --poison-rng artifact --cohort-sampling individuals
```

Flower CLI와 Python 의존성이 설치된 환경에서 실행하며, output은 새 경로여야 한다. 기본 데이터·checkpoint 위치는 저장소 옆의 원본 Aion artifact를 가리킨다.

## 해석과 남은 작업

이 결과는 q=100의 실제 마스킹·선택·ASR 집계 경로가 동작했다는 증거다. 평문 classifier를 공개하는 `aion_mgf_oracle` 실행이 아니다. 하지만 공격 성공률이 초기값 그대로라는 단일 라운드 관찰만으로 방어 성능을 확정할 수 없다. 동일 조건의 무방어 대조군, 여러 seed, 공격·회복 다중 라운드 비교는 별도 필요하다.

이번 실행은 HotStuff를 활성화하지 않았다. 현재 첫 3라운드의 percentile 초기화·10~80% 선택 수 제한은 연결돼 있지만, 4라운드 이후 bound는 아직 기존 bounded-MGF 상태 전이를 사용한다. 원본의 두 과거 집계 norm과 전체 후보 mask norm을 쓰는 단계는 후속 구현 대상이다.

작은 bounded mask의 정보 노출, 연구용 HPRF의 보안 파라미터, 악성 client의 개별 mask/probe/ASR 일치 증명 한계는 남아 있다. 이 결과를 논문과 동등한 프라이버시 보장이나 전체 보안 구현 완료로 해석하지 않는다.
