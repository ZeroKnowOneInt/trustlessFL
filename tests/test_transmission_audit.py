"""Validate the actual local experiment ledger; never runs model training."""
import json
from pathlib import Path

import pytest

REPORT=Path('.cache/transmission-parameter-audit-20261008-v4/report.json')


@pytest.fixture(scope='module')
def report():
    if not REPORT.is_file():
        pytest.skip('local offline experiment ledger unavailable')
    return json.loads(REPORT.read_text())


def test_all_grid_rows_including_failures_are_preserved(report):
    rows=report['parameters']
    assert len(rows)==432
    assert sum(r['feasible'] for r in rows)==337
    assert all(r['exact_match'] for r in rows if r['feasible'])
    expected={i for i,r in enumerate(rows) if r['feasible']}
    assert {r['parameter_index'] for r in report['mgf']['results']}==expected
    assert {r['max_clients'] for r in rows}=={2,20,100}
    assert not report['runtime_integrated']


def test_full_model_exactness_and_stalls_are_not_conflated(report):
    events=[r for c in report['mgf']['results'] for r in c['rounds']]
    assert sum(e['exact_modular_model_coordinates'] for e in events)==66395656
    assert all(e['plaintext_sum_exact_match'] is True for e in events if e['status']=='success')
    failures=[e for e in events if e['status']!='success']
    assert failures and all(e['plaintext_sum_exact_match'] is None for e in failures)
    assert {e['status'] for e in failures}=={'insufficient-valid','selected-count-exceeds-envelope'}


def test_actual_heldout_accuracy_ablation_covers_all_scales(report):
    curves=report['quantization_training']['curves']
    assert set(curves)=={'float','10000','100000','1000000'}
    assert all(len(c)==4 for c in curves.values())
    for s in [10000,100000,1000000]:
        assert all(e['quantization_error']['max']<=.5/s for e in curves[str(s)])
    assert report['quantization_training']['validation_rows']==1000
    assert report['quantization_training']['test_rows']==9000


def test_low_entropy_attack_uses_local_public_fixtures_and_recovers_updates(report):
    keys=report['key_space']
    assert keys['unique_fraction']==1
    assert len(keys['rows'])==20
    assert all(e['tested_seeds']==100000 for e in keys['rows'])
    assert all(e['unique_true_key'] and e['plaintext_quanta_exact'] for e in keys['rows'])
    assert report['conclusion']=='F'
