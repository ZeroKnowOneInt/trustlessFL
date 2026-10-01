# 원본 HPRF와 클라이언트 마스킹 MGF의 Flower 연결

2026-10-01 추가: `--mgf-projection --mgf-single-view`는 검사 좌표를 전체 modular
벡터에서도 다시 전송하지 않는다. 해당 위치는 인증된 0 placeholder이며,
집계 시 bounded probe에서 복원한 좌표로 채운다. 다른 좌표만 기존 ASR로 복원한다.
Aggregator와 offline wire 감사는 0이 아닌 placeholder를 거부한다.
이 정책은 task config digest에 포함된다. 기본값은 false로 유지하여 과거 인증서와
실험을 그대로 검증할 수 있다. 향후 새 projection 실험에서는 이 옵션을 사용한다.

같은 좌표에 대해 서로 다른 스케일의 마스킹 표현 두 개를 관찰하는 경로를
제거한 것이며, bounded mask의 일반적인 입력 정보 노출이나 원본 HPRF의
암호 안전성까지 해결한 것은 아니다. 좌표별 mask share와 fresh key는 여전히 필요하다.
기존 FMNIST 4라운드 결과는 single-view 옵션 적용 전 결과이다.
별도 [single-view 공식 Flower FMNIST 4라운드](experiments/fmnist-flower-original-single-view-mgf-four-round-2026-10-01/report.md)도
완료했다. 후보 40개·선택 8개, 1·4라운드 공격자 배제와 실제 evolving bound를
검증했고, 네 라운드 전체 모델 재학습 대조 오차는 0이었다.
후속 [single-view 공식 Flower FMNIST 1라운드](experiments/fmnist-flower-original-single-view-mgf-one-round-2026-10-01/report.md)에서
후보 10개 모두의 single-view 정책과 평문 필드 부재를 확인했고,
전체 모델은 선택된 업데이트의 양자화 평균과 오차 0으로 일치했다.
기존 두 표현만으로 양자화 좌표 하나를 복원할 수 있는 구체적인 예도
회귀 시험으로 고정했다. 새 경로는 직접 Party 필터·복원과 Flower ProcessGrid
4라운드(HotStuff 활성/비활성)에서 양자화 대조와 일치했다.

2026-10-01 후속 회귀: 원본 HPRF의 Flower ProcessGrid 검증을 20라운드로
늘렸다. full/single-view × HotStuff 활성/비활성 × 4/20라운드의 8개 조합에서
각 라운드의 전체 모델이 **인증된 선택 집합**의 양자화 평균과 일치했다.
관련 파일의 최종 실행은 21개 시험 통과(91.09초)였다. 후반 MGF가 정상 client도
선택에서 제외할 수 있으므로 전체 참여자의 무필터 평균과 비교하지 않는다.
이는 작은 합성 모델의 다중 라운드 시험이며, FMNIST 20라운드 실행이 아니다.
반복 실행에서는 좁은 bootstrap bound=10의 single-view/HotStuff 20라운드
조합이 `MGF retained fewer than two client updates`로 중단됐다.
장기 **집계 정확성** 시험은 초기 bound=30, 선언된 max_abs=100으로 분리하고,
4라운드는 기존 bound=10/max_abs=10을 유지한다. 장기 시험은 각 라운드의
전체 모델뿐 아니라 다음 진폭도 선택된 양자화 평균으로 독립 대조한다.
이는 프로토콜의 자동 fallback이나 필터 수렴 보장이 아니며,
모든 초기화·마스크 난수에서 20라운드가 진행한다고 주장하지 않는다.

2026-09-30. 기존 저자 구현 포팅의 oracle 실험과 구분되는 프로토콜 수정이다.
기준은 [Aion 논문](https://www.usenix.org/system/files/usenixsecurity25-liu-yizhong.pdf)의
Algorithm 3/6이다. 핵심 요구인 클라이언트 측 마스킹과 마스킹된 값의 norm 필터를 연결했다.
논문의 모든 알고리즘·통신량·보안 보장을 재현했다는 뜻은 아니다.

## 현재 동작

클라이언트가 로컬 학습 후 원본 HPRF로 마스크를 만들고 signed fixed-point
`y = encode(delta) + round(scale * amplitude * HPRF / p)`를 전송한다.
`amplitude = beta * ||previous mean gradient||∞`이며, 코드의 `alpha` 필드는
이 최대 마스크 진폭이다. 논문에서 HPRF 출력에 직접 곱하는 alpha와 같은
단위가 아니다. 출력 링의 상한 `p`로 정규화한다.

Flower coordinator는 공개 masked vector로 후보를 고른다. aggregator는
서명·norm·자신에게 암호화된 share를 검증하고, 선택 roster에 합의한다.
선택된 클라이언트의 share만 합산·복원하여 정확한 bounded mask 합을 뺀다.
원본 HPRF의 합계 키와 복원한 마스크 합의 일치성도 carry/반올림 허용 범위에서
검사한다. 다음 라운드의 진폭·bound·이전 norm 항은 결과 인증서에 포함된다.

원본 HPRF의 실제 출력 모듈러스가 기본 연구 백엔드의 `2**128`과 다르므로,
마스크 양자화·출력 검증·aggregate consistency·bound evolution에 동일한
`p`를 사용하도록 수정했다. 원본 백엔드는 scalar key share 경로를 사용한다.
`experiments/run_fmnist_official.py`도 원본 HPRF와 `aion_mgf_beta` 조합을 허용한다.

이 경로는 `oracle_classifier`와 `oracle_key`를 만들지 않는다.
`--mgf-projection`을 생략하면 classifier만이 아니라 전체 업데이트를 필터링한다.
기존 oracle/SHPRG 경로와 이전 결과는 비교용으로 보존한다.

## 빠른 기능 검증

저자 HPRF 파일이 `../Aion/agent/Aion/HPRF`에 있을 때:

```bash
uv run aion-demo \
  --mask-backend aion-original \
  --original-hprf-dir ../Aion/agent/Aion/HPRF \
  --mgf-beta 0.2 --mgf-initial-alpha 0.1 \
  --mgf-initial-bound 10 --mgf-initial-term 0.1 \
  --hotstuff --rounds 4 --dimension 8
uv run pytest tests/test_paper_mgf_original.py -q
```

실제 검증은 캐시된 Flower/PyTorch 의존성을 `PYTHONPATH`로 지정하여 실행했다.
4클라이언트·4독립 aggregator 프로세스의 위 데모가 4라운드 완료했고,
합성 데이터 loss는 초기 2.393118에서 0.970674로 감소했다.
이는 Flower 앱·Message 직렬화·로컬 ProcessGrid 시험이지 공식 Ray 런타임,
원격 네트워크 시험이나 FMNIST 논문 길이의 성능 실험은 아니다.

새 회귀 시험 10개가 통과했다. 직접 Party 2라운드에서 큰 악성 업데이트를
배제하고 선택된 업데이트 평균을 정확히 복원한다. 전체 벡터와 projection을
모두 검사한다. Flower ProcessGrid 4라운드는 HotStuff 활성/비활성 양쪽에서
평문 양자화 대조 계산과 일치한다. 추가로 원본 링 스케일링, carry 복원,
잘못된 마스크 합과 잘못된 링 입력의 거부를 검사한다.
선택형 percentile 경로의 cohort mask norm도 원본 링으로 계산하는지 검증했다.
기존 관련 시험을 포함한 별도 실행은 61개 통과했다(추가 링 시험 작성 전 실행).
전체 회귀 실행은 367개 통과·GPU 관련 2개 skip, 376.56초였다.
전체 실행의 collection 이후 추가한 cohort norm 시험은 별도 10개 실행으로 확인했다.

공식 Flower FMNIST 실행 파일 생성도 다음 설정으로 완료했다:

```bash
python experiments/run_fmnist_official.py \
  --output .cache/fmnist/official-original-client-mgf-full-stage-20260930 \
  --phase stage --modes aion_mgf_beta \
  --population 4 --participants 4 --aggregators 4 --rounds 1 \
  --attack-clients 0 --original-hprf-dir ../Aion/agent/Aion/HPRF \
  --training-sampling author-loader --mgf-beta 0.2 --hotstuff --workers 2
```

생성된 manifest를 다시 읽어 dimension=61,706, 원본 출력 링
`p=14760426300877770769`, `oracle_mgf=false`, projection 없음,
MGF/HotStuff 활성화를 확인했다. **stage만 완료했으며 FMNIST 학습 실행·정확도
측정 결과가 아니다.** 실제 실행 전 큰 마스크 share의 계산·통신 비용을 검토해야 한다.

## 논문과 남은 차이

- 논문은 키를 한 번 공유한다. 현재 bounded MGF는 매 라운드 새 키와
  실제 마스크 좌표의 Pedersen share를 공유한다. 실수 스케일링 후의 링 carry와
  양자화 오차를 정확하게 없애기 위한 추가 경로이며, 논문의 경량 통신량과 다르다.
- Algorithm 6은 집계 합으로 서술된다. 학습 코드는 선택된 업데이트의 평균을
  모델에 더하고, 다음 MGF 상태도 그 평균을 사용한다. 합/평균 convention과
  초기 bound·진폭·참조 norm의 공개 bootstrap을 명시한 연구용 선택이다.
- 원본 HPRF 계산의 재사용은 새로운 암호 안전성 증명이 아니다. 작은 bounded
  mask는 원본 업데이트의 범위 정보를 노출할 수 있다. 개별 mask-key 관계 증명,
  모든 부분 동기 상황의 HotStuff 진행 보장, CCS/VRF·EMA와의 결합은 완료되지 않았다.
- 전체 LeNet5 61,706좌표의 per-coordinate share 비용은 classifier 840좌표
  경로보다 크다. 이번 수정의 전체 벡터 검증은 작은 합성 모델이며,
  기존 oracle 10라운드 정확도/ASR을 새 경로에 전용하지 않는다.

추가 보안 경계는 [security-completion-criteria.md](security-completion-criteria.md)에 있다.
일회성 키 공유와 추가 share 제거의 실제 원본 HPRF 반례 및 완료 조건은
[mgf-key-sharing-reduction.md](mgf-key-sharing-reduction.md)에 있다.
다음 작업은 원본 키 공유/집계 오류 보정에 맞춰 추가 mask share를 줄이는 것과,
새 경로의 FMNIST 축소 실험을 별도로 검증하는 것이다.

후속으로 [원본 HPRF·masked classifier MGF·HotStuff 공식 Flower 1라운드](experiments/fmnist-flower-original-client-mgf-projection-one-round-2026-09-30/report.md)를
실행했다. 실제 학습·공격·signed-wire 검사와 선택된 클라이언트의 학습 replay를
검증했으며, 전체 모델의 양자화 평균 오차는 0이었다. full-vector MGF가 아니라
classifier projection 시험이라는 점과 추가 share의 차이는 계속 유지한다.

추가한 `--replay-selected`는 `--phase verify`에서도 사용할 수 있다.
로컬 staged 데이터를 이용해 모든 라운드의 선택된 클라이언트를 다시 학습하고,
인증 모델이 그 양자화 평균인지 검사한다. 검사는 secure wire와 별도이며,
통과 시 `verification.json`과 sanitized export에 `selected_replay`를 기록한다.
마스크 진폭과 실제 선택 bound의 라운드별 변화도 `masked_round_state`로 기록한다.

[후속 공식 Flower 4라운드](experiments/fmnist-flower-original-client-mgf-projection-four-round-2026-10-01/report.md)도
완료했다. 동적 참여, 1·4라운드 공격, 4라운드의 evolving bound, 40개 signed
update와 선택된 8개 업데이트의 재학습을 검증했다. 네 라운드 전체 모델의
양자화 평균 오차는 0이었다. replay는 Flower worker와 동일하게 CPU thread를
1개로 맞추며, 검사 후 host 설정을 복원한다.
