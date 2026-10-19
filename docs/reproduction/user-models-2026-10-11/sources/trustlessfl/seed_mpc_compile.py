"""Content-addressed public circuit cache. Runtime ports/secrets never enter bytecode."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from .crypto import ProtocolError, canonical, digest
from .seed_mpc_resources import read_resources

CACHE_VERSION = 'seed-mpc-compile-cache-v1'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def recipe(config, sources, aes_sha):
    if config.get('runtime_client_port') is not True:
        raise ProtocolError('compile cache requires agreed runtime client port')
    effective = {k: v for k, v in config.items() if k != 'client_port'}
    return {'version': CACHE_VERSION, 'config': effective, 'sources': sources, 'aes': aes_sha,
            'compiler_options': ['-R', '64', '-Z', '4', '-M'],
            'program': 'seed_mpc_chunked_session-policy.json'}


def artifacts(workspace):
    root = Path(workspace)/'Programs'
    result = {}
    for folder in ('Bytecode', 'Schedules'):
        for p in sorted((root/folder).rglob('*')):
            if p.is_symlink():
                raise ProtocolError('symlink in compiled artifacts')
            if p.is_file():
                result[p.relative_to(root).as_posix()] = sha(p)
        if not any(k.startswith(folder+'/') for k in result):
            raise ProtocolError('compiled artifact set incomplete')
    return result


def validate_entry(entry, expected_recipe):
    if entry.is_symlink():
        raise ProtocolError('symlinked compile cache entry')
    try:
        manifest = json.loads((entry/'manifest.json').read_text())
        if (manifest['recipe'] != expected_recipe or manifest['key'] != digest(expected_recipe)
                or manifest['artifacts'] != artifacts(entry)):
            raise ProtocolError('compile cache manifest/artifacts differ')
        read_resources(entry/'compile-resource.txt')
    except (OSError, ValueError, KeyError) as exc:
        raise ProtocolError('invalid/incomplete compile cache entry') from exc
    return manifest


def compile_circuit(workspace, installation, config, sources, aes_sha, cache_root=None):
    workspace, installation = Path(workspace), Path(installation)
    def build():
        started = time.monotonic()
        with (workspace/'compile.log').open('x') as log:
            subprocess.run(['/usr/bin/time', '-v', '-o', str(workspace/'compile-resource.txt'),
                sys.executable, str(installation/'compile.py'), '-R', '64', '-Z', '4', '-M',
                'seed_mpc_chunked_session', 'policy.json'], cwd=workspace,
                stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
        return round(time.monotonic()-started, 3)
    if cache_root is None:
        seconds = build()
        return {'hit': False, 'key': None, 'compile_invocations': 1, 'compile_seconds': seconds}
    expected = recipe(config, sources, aes_sha)
    key = digest(expected)
    root = Path(cache_root).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    entry = root/key
    started = time.monotonic()
    # Same-key concurrent preparations publish exactly one complete entry.
    with (root/(key+'.lock')).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if entry.exists():
            manifest = validate_entry(entry, expected)
            for relative in manifest['artifacts']:
                target = workspace/'Programs'/relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(entry/'Programs'/relative, target)
            shutil.copyfile(entry/'compile-resource.txt', workspace/'compile-resource.txt')
            (workspace/'compile.log').write_text('Validated compile cache hit: '+key+'\n')
            return {'hit': True, 'key': key, 'compile_invocations': 0, 'compile_seconds': 0.0,
                    'load_seconds': round(time.monotonic()-started, 3),
                    'original_compile_seconds': manifest['compile_seconds']}
        seconds = build()
        files = artifacts(workspace)
        temp = Path(tempfile.mkdtemp(prefix=key+'.pending-', dir=root))
        try:
            for relative in files:
                target = temp/'Programs'/relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(workspace/'Programs'/relative, target)
            shutil.copyfile(workspace/'compile-resource.txt', temp/'compile-resource.txt')
            (temp/'manifest.json').write_bytes(canonical({'key': key, 'recipe': expected,
                'artifacts': files, 'compile_seconds': seconds}))
            validate_entry(temp, expected)
            os.rename(temp, entry)
        finally:
            if temp.exists(): shutil.rmtree(temp)
        return {'hit': False, 'key': key, 'compile_invocations': 1, 'compile_seconds': seconds}
