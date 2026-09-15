"""Export public AION experiment metrics; never copy party secrets/transcripts."""

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from experiments.run_endpoint import write_json
from experiments.run_endpoint_aion import result_for


def export(run, output, smoke):
    verification = json.loads((run / "verification.json").read_text())
    provenance = json.loads((run / "provenance.json").read_text())
    smoke_verification = json.loads((smoke / "verification.json").read_text())
    if not verification["passed"] or not smoke_verification["passed"]:
        raise ValueError("All verification must pass before export")
    previous = Path(".cache/endpoint/runs/public-recipe-2026-09-13-v2")
    if json.loads((run / "data-audit.json").read_text()) != json.loads((previous / "data-audit.json").read_text()):
        raise ValueError("Changed data compared with public-recipe baseline")
    with np.load(run / "split.npz", allow_pickle=False) as a, np.load(previous / "split.npz", allow_pickle=False) as b:
        if any(not np.array_equal(a[key], b[key]) for key in ("split", "group", "client")):
            raise ValueError("Changed split")
    attempts = {}
    for mode in provenance["modes"]:
        items = list((run / mode).glob("attempt-*/run-status.json"))
        if len(items) != 1:
            raise ValueError("Expected one successful attempt per mode")
        attempt = items[0].parent
        attempts[mode] = {name: json.loads((attempt / f"{name}.json").read_text()) for name in
                          ("run-status", "timing", "commands", "cuda-preflight")}
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "summary.json", {"run_ids": verification["run_ids"], "summary": verification["summary"],
        "metrics": verification["metrics"], "checks": verification["checks"], "smoke": smoke_verification})
    write_json(output / "provenance.json", {**provenance, "attempts": attempts, "data_and_split_match_previous": True,
        "exporter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "verification_sha256": hashlib.sha256((run / "verification.json").read_bytes()).hexdigest()})
    from trustlessfl.endpoint_aion import model_arrays
    from trustlessfl.endpoint_public import evaluate_arrays
    with np.load(run / "test.npz", allow_pickle=False) as data:
        xx, yy = data["x"], data["y"]
    curves = []
    for case in verification["metrics"]:
        for mode in provenance["modes"]:
            result_path, _ = result_for(run, mode)
            with np.load(result_path.parent / f"{case['case']}-models.npz", allow_pickle=False) as data:
                offsets = data["offsets"]
            curve = []
            for r, offset in enumerate(offsets):
                metrics = evaluate_arrays(model_arrays(offset, xx.shape[1], case["seed"]), xx, yy)
                curve.append({"round": r, **{key: metrics[key] for key in
                    ("macro_f1", "accuracy", "normal_false_positive_rate", "malware_false_negative_rate", "cross_entropy")}})
            curves.append({"seed": case["seed"], "mode": mode, "history": curve})
    write_json(output / "curves.json", {"selection": "Post-hoc descriptive test curves; fixed final round; not checkpoint selection", "curves": curves})
    def pct(mode, key):
        item = verification["summary"][mode][key]
        spread = f" ± {100 * item['sample_std']:.2f}" if item["sample_std"] is not None else ""
        return f"{100 * item['mean']:.2f}{spread}"
    rows = [f"| {mode} | {pct(mode, 'macro_f1')} | {pct(mode, 'normal_false_positive_rate')} | {pct(mode, 'malware_false_negative_rate')} |"
            for mode in provenance["modes"]]
    per_seed = [f"| {m['seed']} | {m['modes']['aion']['test']['macro_f1'] * 100:.2f} | {m['modes']['float']['test']['macro_f1'] * 100:.2f} |"
                for m in verification["metrics"]]
    run_rows = [f"| {mode} | {verification['run_ids'][mode]} | {attempts[mode]['timing']['flwr_cli_wall_seconds']:.2f} |"
                for mode in provenance["modes"]]
    meta = [m for c in verification["checks"] for m in c["aion_training_meta"]]
    allocated = max(m["peak_allocated_bytes"] for m in meta) / 2**20
    reserved = max(m["peak_reserved_bytes"] for m in meta) / 2**20
    report = f"""# Crowdsensing: 연구용 AION FL / 공식 Flower Runtime

실행일: 2026-09-13. 3 seeds × 10 rounds × 8 clients, 단일 RTX 5060 GPU 실행 완료.

우리 AION FL의 독립 test macro-F1은 **{pct('aion', 'macro_f1')}%**다.
동일 양자화 평문 FL과 모든 라운드 모델이 정확히 일치했다.
이 결과는 Crowdsensing의 DFL 논문 결과 재현이나 production 보안성 증명이 아니다.

## 조건

- ServerApp 1 + 학습 역할 8 + 독립 논리 aggregator 역할 4, f=1, certificate quorum3.
- 공개 V2 31 features / 171,053 rows. train102,509, validation34,227(미사용), test34,317.
- 원본 파일별 client 소유권과 중복 feature-group 차단 분할은 이전 중앙집중 실험과 정확히 일치.
- 공개 recipe 모델 31→30→30→9, 2,169 parameters, float32, Adam .01, batch500, 로컬3epochs.
- Adam은 매 라운드 재설정. 전체10rounds 고정, early stopping·test 기반 모델 선택 없음.
- client 동일 가중치 평균, delta 소수6자리 양자화. float 대조군만 양자화 없음.
- 공식 flwr run / SuperLink / Ray. 각 비교군은 별도 FAB. 실행 순서 aion→quantized→float.

자세한 설정·실행 명령·보안 한계는 [설계/실행 문서](../../endpoint-aion-runtime.md)를 참고한다.

## 독립 test 결과

단위 %, seed42/43/44 평균 ± 표본 표준편차. 정상 오탐률은 Normal을 악성으로 분류한 비율,
악성 미탐률은 악성을 Normal로 분류한 비율이다.

| 집계 | Macro-F1 ↑ | 정상 오탐률 ↓ | 악성 미탐률 ↓ |
| --- | ---: | ---: | ---: |
{chr(10).join(rows)}

| Seed | AION F1 | float 평문 FL F1 |
| --- | ---: | ---: |
{chr(10).join(per_seed)}

이전 중앙집중 공개 recipe의 F1 93.43 ± 0.47%는 참고값일 뿐 직접 대조군이 아니다.
분산 local step, 동일 client 가중치, Adam reset, 학습 길이 및 checkpoint 선택이 다르다.
중앙집중과의 차이를 AION 암호화 때문이라고 해석하지 않는다. 보안집계의 직접 대조군은
이번의 같은 학습 조건을 사용한 quantized/float FL이다.

## 검증

- 모든 seed의 round0..10 AION/quantized offset 최대 오차 **0**; 최종 confusion matrix 일치.
- 평문 정수 합과 AION 모델 차분에서 복원한 정수 합 오차는 사전 기준1e-5 정수 단위 이하.
- 총 {len(meta)}개 AION 로컬 학습 기록 모두 cuda:0 / torch.float32.
  학습 worker PID: {sorted({m['pid'] for m in meta})}.
- AION 노드별 상태 파일 권한0600, client별 round 상태 보존, aggregator4개 최종 committed model 일치.
  aggregator는 학습 shard를 받지 않으며 로컬 학습 기록이 없다.
- 사전 CPU 합성 Runtime run `{smoke_verification['run_ids']['aion']}`: 정상, 재요청,
  aggregator1개 응답 억제는 oracle과 일치. client탈락/서버 모델 본문 변조는 share 이전 abort.
- 상태 확인은 같은 호스트의 테스트 harness가 수행한 검사다. 실제 외부 공격자 격리나 crash/rollback 복구 증명이 아니다.

## Runtime 및 자원

| 비교군 | Flower run ID | CLI wall seconds |
| --- | --- | ---: |
{chr(10).join(run_rows)}

각 run은 3 seeds 전체를 포함한다. CPU1/GPU1 worker 하나가 12개 논리 역할을 순차 실행했다.
GPU peak allocated {allocated:.2f} MiB / reserved {reserved:.2f} MiB는 PyTorch allocator 값이며 총 VRAM이 아니다.
aggregator 암호 연산은 CPU에서 수행했다. 시간에는 Runtime 시작·학습·프로토콜·상태 저장 등이 포함되고
사전 provisioning과 사후 평가는 제외된다. 각 조건1회, 고정 실행 순서이므로 암호화만의 비용이나
논문 speedup 재현으로 해석하지 않는다.

## 한계와 산출물

현재 AION masking은 연구용 surrogate이며 production privacy를 보장하지 않는다.
HotStuff/AMR/CCS/MGF는 추가하지 않았다. Endpoint 본 실험은 정상 참여자 조건이며
정상 서명한 poisoning update를 방어한다는 근거가 아니다.
독립 aggregator는 논리적 신원 분리이며 단일 호스트·OS 사용자·worker의 보안 격리가 아니다.

- [summary.json](./summary.json): seed별 pooled/client 지표 및 검증.
- [curves.json](./curves.json): 학습 완료 후 계산한 test 곡선. 최종 round 선택에 사용하지 않음.
- [provenance.json](./provenance.json): 소스·데이터 hash, 명령, 버전, run 상태, GPU preflight.
- 키/share/개별 masked update/노드 상태는 `.cache`에만 보관하며 문서에 복사하지 않는다.

초기 합성 smoke 시도2개는 실행 전 Python 문법/Flower 정적 진입점 검사에서 실패했다.
수정 후 새 경로의 v3 smoke가 통과했으며 실제 Endpoint 학습은 단일 시도로 완료했다.
"""
    with (output / "report.md").open("x") as stream:
        stream.write(report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--smoke", type=Path, default=Path(".cache/endpoint/runs/aion-runtime-smoke-2026-09-13-v3"))
    args = parser.parse_args()
    export(args.run, args.output, args.smoke)


if __name__ == "__main__":
    main()
