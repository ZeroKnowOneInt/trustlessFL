"""Build a separate checked-share importer; preserve both official/observer installs."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
from experiments.build_seed_mpc_telemetry import ROOT
from trustlessfl.seed_mpc_backend import ARCHIVE_SHA256, sha, resolved_libraries
from trustlessfl.seed_mpc_telemetry_patch import PATCH_ID as OBSERVER_PATCH, patched_source as observer_source
from trustlessfl.seed_mpc_direct_patch import PATCH_ID, patched_source


def build(jobs=1):
    if jobs not in (1,2): raise ValueError('limited build parallelism required')
    parent=ROOT/'.cache/private-bound-mpc'
    original=parent/'mp-spdz-0.4.3-telemetry'
    archive=parent/'mp-spdz-0.4.3.tar.xz'
    target=parent/'mp-spdz-0.4.3-direct-rep4-v1'
    if sha(archive)!=ARCHIVE_SHA256: raise ValueError('official archive differs')
    if not target.exists(): shutil.copytree(original,target,symlinks=True)
    # Re-derive every modified source; never trust a local patch manifest alone.
    patches={'Processor/BaseMachine.cpp':observer_source,
             'GC/Rep4Secret.h':lambda s:patched_source('GC/Rep4Secret.h',s),
             'GC/Rep4Secret.cpp':lambda s:patched_source('GC/Rep4Secret.cpp',s)}
    with tarfile.open(archive) as distribution:
        for relative,apply in patches.items():
            text=distribution.extractfile('mp-spdz-0.4.3/'+relative).read().decode()
            patched=apply(text)
            path=target/relative
            if path.read_text()!=patched: path.write_text(patched)
    # Copied manifests describe the observer binary and are not used for this build.
    copied=target/'telemetry-build.json'
    if copied.exists(): copied.unlink()
    log=parent/'direct-rep4-build.log'
    with log.open('w') as out:
        subprocess.run(['make',f'-j{jobs}','rep4-ring-party.x'],cwd=target,
                       stdout=out,stderr=subprocess.STDOUT,check=True)
    record={'patch_id':PATCH_ID,'observer_patch_id':OBSERVER_PATCH,'archive_sha256':ARCHIVE_SHA256,
        'command':['make',f'-j{jobs}','rep4-ring-party.x'],
        'compiler':subprocess.check_output(['g++','--version'],text=True).splitlines()[0],
        'compiler_sha256':sha('/usr/bin/g++'),'config_sha256':sha(target/'CONFIG.mine'),
        'patch_sources_sha256':{r:sha(target/r) for r in patches},
        'binary_sha256':sha(target/'rep4-ring-party.x'),'shared_library_sha256':sha(target/'libSPDZ.so'),
        'runtime_libraries':{p:sha(p) for p in sorted(resolved_libraries(target/'rep4-ring-party.x'))}}
    (target/'direct-build.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'target':str(target),'manifest_sha256':sha(target/'direct-build.json')},indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--jobs',type=int,default=1)
    build(parser.parse_args().jobs)
