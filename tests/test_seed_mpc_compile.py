"""Cache keys include arithmetic/security inputs; corrupt entries fail closed."""
from copy import deepcopy
import json
from pathlib import Path
import pytest
from trustlessfl.crypto import ProtocolError, canonical, digest
from trustlessfl.seed_mpc_compile import recipe, artifacts, validate_entry, compile_circuit


def config():
    return {'runtime_client_port': True, 'client_port': 10000, 'dimension': 53,
            'coordinate_cap': 20000, 'squared_threshold': 2500000000, 'scale': 10000,
            'backend_pin_hash': 'pinned', 'clients': 4, 'round_slots': 2,
            'component_input': 'holder-checked-direct-v1', 'chunk_blocks': 4}


def test_cache_reuses_only_port_independent_bytecode():
    cfg = config(); before = recipe(cfg, {'main': 'source'}, 'aes')
    assert before == recipe({**cfg, 'client_port': 20000}, {'main': 'source'}, 'aes')
    for key, value in [('dimension', 54), ('coordinate_cap', 19000), ('squared_threshold', 100),
        ('scale', 1000), ('backend_pin_hash', 'other'), ('round_slots', 3), ('clients', 5),
        ('component_input', 'stock-private-v1'), ('chunk_blocks', 8)]:
        assert before != recipe({**cfg, key: value}, {'main': 'source'}, 'aes')
    assert before != recipe({**cfg,'client_loop':'compact-runtime-v1'},{'main':'source'},'aes')
    assert before != recipe(cfg, {'main': 'changed'}, 'aes')
    assert before != recipe(cfg, {'main': 'source'}, 'changed')
    with pytest.raises(ProtocolError): recipe({**cfg, 'runtime_client_port': False}, {}, 'aes')


def entry(tmp_path):
    rec = recipe(config(), {'main': 'source'}, 'aes'); p = tmp_path/digest(rec); p.mkdir()
    for relative in ('Bytecode/main.bc', 'Schedules/main.sch'):
        target = p/'Programs'/relative; target.parent.mkdir(parents=True); target.write_bytes(b'compiled')
    (p/'compile-resource.txt').write_text('User time (seconds): 1\nSystem time (seconds): 0\nMaximum resident set size (kbytes): 100\nExit status: 0\n')
    manifest = {'recipe': rec, 'key': digest(rec), 'artifacts': artifacts(p), 'compile_seconds': 1.0}
    (p/'manifest.json').write_bytes(canonical(manifest))
    return p, rec


@pytest.mark.parametrize('fault', ['bytecode', 'missing', 'recipe', 'key', 'extra', 'symlink', 'resource'])
def test_corrupt_cache_cannot_be_used(tmp_path, fault):
    p, rec = entry(tmp_path); target = p/'Programs/Bytecode/main.bc'
    if fault == 'bytecode': target.write_bytes(b'changed')
    if fault == 'missing': target.unlink()
    if fault == 'extra': (target.parent/'extra.bc').write_bytes(b'extra')
    if fault == 'symlink': target.unlink(); target.symlink_to(p/'Programs/Schedules/main.sch')
    if fault == 'resource': (p/'compile-resource.txt').write_text('Exit status: 1')
    if fault in ('recipe', 'key'):
        m = json.loads((p/'manifest.json').read_text())
        if fault == 'recipe': m['recipe']['config']['dimension'] = 999
        else: m['key'] = 'other'
        (p/'manifest.json').write_bytes(canonical(m))
    with pytest.raises(ProtocolError): validate_entry(p, rec)


def test_cache_hit_copies_validated_public_artifacts_without_compilation(tmp_path, monkeypatch):
    root = tmp_path/'cache'; root.mkdir(); p, rec = entry(root)
    workspace = tmp_path/'run'; workspace.mkdir()
    def unexpected(*args, **kwargs): raise AssertionError('compiler ran on cache hit')
    monkeypatch.setattr('trustlessfl.seed_mpc_compile.subprocess.run', unexpected)
    report = compile_circuit(workspace, tmp_path/'backend', config(), {'main':'source'}, 'aes', root)
    assert report['hit'] and report['compile_invocations'] == 0
    assert artifacts(workspace) == artifacts(p)


@pytest.mark.parametrize('seconds',[True,0,-1,7201,180.0])
def test_invalid_compile_timeout_fails_before_workspace_changes(tmp_path,seconds):
    workspace=tmp_path/'run'
    with pytest.raises(ProtocolError):
        compile_circuit(workspace,tmp_path/'backend',config(),{},'aes',build_timeout=seconds)
    assert not workspace.exists()
