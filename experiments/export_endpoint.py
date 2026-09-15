"""Export small public metrics, not raw data, split row IDs or model checkpoints."""

import argparse
import json
from pathlib import Path
import statistics

from experiments.run_endpoint import write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary = json.loads((args.run / "summary.json").read_text())
    audit = json.loads((args.run / "data-audit.json").read_text())
    config = json.loads((args.run / "config.json").read_text())
    tuning = json.loads((args.run / "tuning.json").read_text())
    seeds = config["seeds"]
    if len(summary) != len(seeds) * len(config["mus"]) * 2:
        raise ValueError("Incomplete run matrix")
    args.output.mkdir(parents=True, exist_ok=False)
    for name, value in (("summary.json", summary), ("data-audit.json", audit),
                        ("config.json", config), ("tuning.json", tuning)):
        write_json(args.output / name, value)
    curves = {r["run"]: json.loads((args.run / f'{r["run"]}.json').read_text()) for r in summary}
    write_json(args.output / "rounds.json", curves)

    def formatted(values):
        sd = statistics.stdev(values) if len(values) > 1 else 0
        return f"{statistics.mean(values) * 100:.2f} ± {sd * 100:.2f}"

    rows = []
    for poisoned in (False, True):
        for mu in config["mus"]:
            selected = [r for r in summary if r["poison"] == poisoned and r["mu"] == mu]
            method = "일반 평균" if mu == 0 else f"FedProx μ={mu:g}"
            cells = [formatted([r[key] for r in selected]) for key in
                     ("macro_f1", "normal_false_positive_rate", "malware_false_negative_rate", "device_macro_f1_min")]
            rows.append(f"| {'25% label-flip' if poisoned else '정상'} | {method} | " + " | ".join(cells) + " |")
    comparisons = []
    for mu in config["mus"]:
        clean = {r["seed"]: r for r in summary if r["mu"] == mu and not r["poison"]}
        attack = {r["seed"]: r for r in summary if r["mu"] == mu and r["poison"]}
        drops = [(clean[s]["macro_f1"] - attack[s]["macro_f1"]) * 100 for s in seeds]
        comparisons.append(f"- μ={mu:g}: clean 대비 공격 시 macro-F1 평균 {statistics.mean(drops):.2f} pp 감소.")
    tuning_rows = [f"| {r['learning_rate']:g} | {r['history'][-1]['metrics']['validation']['pooled']['macro_f1']:.6f} |"
                   for r in tuning["runs"]]
    per_seed = [f"| {r['seed']} | {r['mu']:g} | {r['attackers']} | {r['macro_f1']:.6f} | {r['malware_false_negative_rate']:.6f} |"
                for r in summary]
    duplicates = audit["duplicates"]
    counts = {split: sum(s["rows"] for s in audit["split_stats"] if s["split"] == split)
              for split in ("train", "validation", "test")}
    text = f"""# Crowdsensing 평문 학습 탐색 실험

실행일: 2026-09-13. AION/Flower 전송·보안집계를 실행하지 않은 학습 시뮬레이션이다.
현재 목적은 이 데이터에서 학습 품질과 poisoning 문제를 먼저 계측하는 것이다.

## 데이터 감사 결과

- 출처: [Science Data Bank 공식 V2 배포]({audit['record']}), DOI `10.57760/sciencedb.25380`, CC BY 4.0.
- `32d-feature data/device/0.csv`–`7.csv`만 사용. 총 87,742,914 bytes, 배포처 MD5 전부 검증; SHA-256은 `data-audit.json`에 기록.
- 실제 {audit['rows']:,}행, 입력 {audit['inputs']}개 + label 1열. 논문의 342,106행/32개 입력 특징과 일치하지 않는다. 행 복제나 임의 특징 추가로 맞추지 않았다.
- 파일별 클라이언트 소유권을 유지했지만 파일 번호와 물리 장치 ID의 대응은 확인되지 않았다. `merged_df.csv`나 원시 로그는 합치지 않았다.
- 서로 다른 특징 벡터는 {duplicates['unique_feature_groups']:,}개. 반복으로 추가된 행은 {duplicates['duplicate_excess_rows']:,}개다. 같은 특징의 상충 label {duplicates['conflicting_label_groups']}개 그룹/{duplicates['conflicting_label_rows']:,}행은 제거하지 않고 유지했다.
- 파일 간 동일 특징 그룹은 {duplicates['cross_file_groups']}개. 동일 특징 그룹 전체를 한 split에 넣어 train/validation/test 간 정확한 중복 누수를 막았다.
- 분할: {counts}. 시간/세션 메타데이터가 없으므로 비시간적 그룹 분할이다. 근접 윈도 상관관계까지 제거했다는 뜻은 아니다.
- 공개 특징은 이미 선택·정규화되어 있다. 엄밀한 미래 데이터 일반화나 train-only 전처리 평가로 해석하지 않는다.
- 숫자 label은 [연결된 공식 encoder]({audit['label_mapping_source']})에 따라 0 Normal, 1 Ransomware, 2 TheTick, 3 Bashlite, 4 HttpBackdoor, 5 Beurk, 6 Backdoor, 7 Bdvl, 8 XMRig로 해석한다. 배포 CSV 자체에는 의미 mapping이 내장되어 있지 않다.

## 고정한 비교 조건

- 모델: {config['model']['inputs']}→128 ReLU→9 MLP, {config['model']['parameters']:,} parameters, NumPy float64 CPU.
- 8 clients 전원 참여, 동일 가중 평균. 데이터 수 가중 FedAvg와는 다르다.
- {config['rounds']} rounds × local {config['epochs']} epochs, batch {config['batch_size']}, SGD, momentum/weight decay 없음.
- seeds `{seeds}`. 동일 seed에서 초기 모델·batch 순서·공격자는 방법 간 동일.
- FedProx: 매 round 시작 모델에 대한 `μ/2 * ||w-w_global||²`, μ `{config['mus']}`. μ=0은 일반 평균의 로컬 학습이다.
- 각 seed의 공격자 2명은 난수로 사전 선정. train label만 `(y+1)%9`로 한 번 바꾼 뒤 모든 round에서 사용. validation/test는 변조하지 않는다.
- learning rate는 seed42/clean/μ=0의 마지막 round validation macro-F1로 선택했다. test 값으로 학습률이나 μ를 선택하지 않았다.
- μ 값들은 사전 지정 민감도 탐색이며, 최적 FedProx 또는 새로운 방어 알고리즘의 결과가 아니다.

| 후보 learning rate | validation macro-F1 |
| --- | --- |
{chr(10).join(tuning_rows)}

선택 learning rate: `{tuning['selected_learning_rate']}`.

## 마지막 round 결과

모든 값은 %, 평균 ± seed 간 표본 표준편차다. macro-F1·최저 장치 F1은 높을수록, 오탐·미탐률은 낮을수록 좋다.
미탐률은 실제 악성의 Normal 예측 비율이며 악성 계열끼리의 오분류는 포함하지 않는다.

| 조건 | 방법 | macro-F1 ↑ | 정상 오탐률 ↓ | 악성 미탐률 ↓ | 최저 장치 F1 ↑ |
| --- | --- | --- | --- | --- | --- |
{chr(10).join(rows)}

{chr(10).join(comparisons)}

## 해석 제한

- 위 값은 실제 파일에 대한 관측치이며 논문 실험 재현 판정이 아니다.
- 정상과 공격의 비교는 label 오염 효과를, μ 간 비교는 proximal local training 효과를 보여준다. FedProx를 Byzantine 방어로 간주하지 않는다.
- 일반 평균보다 특정 μ가 좋아도 사전 고정된 전체 조건과 seed별 결과를 함께 해석해야 한다. 세 seed만으로 유의성을 주장하지 않는다.
- 그룹 분할을 했지만 반복 행의 학습 가중치는 유지했다. 중복 제거/상충 label 처리와 원본 전처리 재구축에 대한 민감도는 후속 작업이다.
- 평문 환경은 서버가 개별 update를 볼 수 있다. 이 실험은 프라이버시, 악성 서버 내성, 보안집계 비용의 증거가 아니다.
- CPU 단일 프로세스의 순차 클라이언트 실행 시간은 AION 병렬 실행의 overhead 비교에 사용하지 않는다.

## Seed별 원시 지표

F1·미탐률은 0–1 단위. 공격자 `[]`는 clean이다.

| seed | μ | 공격 클라이언트 | macro-F1 | 악성 미탐률 |
| --- | --- | --- | --- | --- |
{chr(10).join(per_seed)}

## 재실행

```bash
.venv/bin/python -m experiments.download_endpoint
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \\
  .venv/bin/python -m experiments.run_endpoint \\
  --output .cache/endpoint/runs/plaintext-new --seeds 42 43 44 --rounds 10
.venv/bin/python -m experiments.export_endpoint \\
  --run .cache/endpoint/runs/plaintext-new \\
  --output docs/experiments/endpoint-plaintext-new
```

출력은 새 경로여야 한다. `config.json`에 구현 소스 hash·환경, `rounds.json`에 라운드별/장치별 지표·confusion matrix를 기록했다.
원본 CSV, split 인덱스, 모델 checkpoint는 `.cache/endpoint/`에 유지하며 이 공개 요약에는 복제하지 않았다.
"""
    with (args.output / "report.md").open("x") as stream:
        stream.write(text)


if __name__ == "__main__":
    main()
