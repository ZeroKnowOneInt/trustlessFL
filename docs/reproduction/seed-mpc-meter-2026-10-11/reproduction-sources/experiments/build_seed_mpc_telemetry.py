"""Build an isolated observer binary. Does not alter the official installation."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from trustlessfl.seed_mpc_backend import ARCHIVE_SHA256, sha
from trustlessfl.seed_mpc_telemetry_patch import PATCH_ID, patched_source

PACKAGES = ['libboost1.83-dev', 'libboost-filesystem1.83-dev',
            'libboost-filesystem1.83.0', 'libboost-iostreams1.83-dev',
            'libboost-iostreams1.83.0', 'libboost-atomic1.83-dev',
            'libboost-atomic1.83.0', 'libboost-system1.83-dev',
            'libboost-system1.83.0', 'libboost-regex1.83-dev',
            'libboost-regex1.83.0', 'libsodium-dev', 'libsodium23']


def build(jobs=2):
    parent = ROOT / '.cache/private-bound-mpc'
    archive = parent / 'mp-spdz-0.4.3.tar.xz'
    if sha(archive) != ARCHIVE_SHA256:
        raise ValueError('official archive differs')
    target = parent / 'mp-spdz-0.4.3-telemetry'
    deps = parent / 'telemetry-build-deps'
    debs = deps / 'debs'; debs.mkdir(parents=True, exist_ok=True)
    prefix = deps / 'root'; prefix.mkdir(exist_ok=True)
    if not (prefix / 'usr/include/boost/version.hpp').exists():
        subprocess.run(['apt', 'download', *PACKAGES], cwd=debs, check=True)
        for deb in sorted(debs.glob('*.deb')):
            subprocess.run(['dpkg-deb', '-x', str(deb), str(prefix)], check=True)
    if not target.exists():
        target.mkdir()
        with tarfile.open(archive) as distribution:
            for member in distribution:
                if not member.name.startswith('mp-spdz-0.4.3/'):
                    continue
                member.name = member.name[len('mp-spdz-0.4.3/'):]
                if member.name:
                    distribution.extract(member, target, filter='data')
    source = target / 'Processor/BaseMachine.cpp'
    with tarfile.open(archive) as distribution:
        original = distribution.extractfile('mp-spdz-0.4.3/Processor/BaseMachine.cpp').read().decode()
    source.write_text(patched_source(original))
    lib = prefix / 'usr/lib/x86_64-linux-gnu'
    config = ('CXX = g++\nOPTIM = -O2\nGDEBUG =\n'
              'ARCH = -msse4.2 -maes -mpclmul -mavx2 -mbmi2 -madx\n'
              f'MY_CFLAGS = -I{prefix}/usr/include -Wno-error=deprecated-declarations\n'
              f'MY_LDLIBS = -L{lib} -Wl,-rpath,{lib}\n')
    (target / 'CONFIG.mine').write_text(config)
    log = parent / 'telemetry-build.log'
    with log.open('w') as output:
        subprocess.run(['make', f'-j{jobs}', 'rep4-ring-party.x'], cwd=target,
                       stdout=output, stderr=subprocess.STDOUT, check=True)
    record = {'patch_id': PATCH_ID, 'archive_sha256': ARCHIVE_SHA256,
              'command': ['make', f'-j{jobs}', 'rep4-ring-party.x'],
              'compiler': subprocess.check_output(['g++', '--version'], text=True).splitlines()[0],
              'compiler_sha256': sha('/usr/bin/g++'),
              'config_mine': config, 'config_sha256': sha(target / 'CONFIG.mine'),
              'patch_source_sha256': sha(source),
              'binary_sha256': sha(target / 'rep4-ring-party.x'),
              'shared_library_sha256': sha(target / 'libSPDZ.so'),
              'dependencies': {p.name: sha(p) for p in sorted(debs.glob('*.deb'))}}
    listing=subprocess.check_output(['ldd',str(target/'rep4-ring-party.x')],text=True)
    if 'not found' in listing: raise ValueError('native runtime library missing')
    paths=re.findall(r'(?:=>\s+)?(/[^\s]+)\s+\(',listing)
    record['runtime_libraries']={str(Path(p).resolve()):sha(p) for p in sorted(set(paths))}
    (target / 'telemetry-build.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--jobs', type=int, default=2)
    build(parser.parse_args().jobs)
