"""TEST ONLY: one custom native party; never an approved product backend.

Corrupt a replicated multiplication share or opening wire; terminate at a
public round boundary. No secret contents are logged. Honest parties retain
the exact approved observer build. This is attack coverage, not a proof.
"""
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from trustlessfl.seed_mpc_backend import sha


def replace(path,before,after):
    text=path.read_text()
    if text.count(before)!=1: raise ValueError('attack source anchor differs')
    path.write_text(text.replace(before,after))


def build():
    base=ROOT/'.cache/private-bound-mpc/mp-spdz-0.4.3-telemetry'
    target=ROOT/'.cache/private-bound-mpc/mp-spdz-0.4.3-adversary-test'
    if not target.exists(): shutil.copytree(base,target)
    # Fresh anchors permit exactly one application; no silent re-patching.
    for name in ('Protocols/Rep4.hpp','Protocols/Rep4MC.hpp','Processor/BaseMachine.cpp'):
        shutil.copyfile(base/name,target/name)
    p=target/'Processor/BaseMachine.cpp'
    replace(p,'  timer[n].start(total_stats());',
        '  if (n == 8) { setenv("SEED_TEST_NATIVE_PHASE", "round", 1);\n'
        '    const char* mode = getenv("SEED_TEST_NATIVE_ATTACK");\n'
        '    if (mode && string(mode) == "round-abort") { cerr << "SEED_TEST_ATTACK round-abort" << endl; _Exit(77); } }\n'
        '  timer[n].start(total_stats());')
    p=target/'Protocols/Rep4.hpp'
    replace(p,'#include "Rep4.h"','#include "Rep4.h"\n#include <cstdlib>\n#include <cstring>\n#include <iostream>')
    prefix='void Rep4<T>::prepare_mul(const T& x, const T& y, int n_bits)\n{\n'
    replace(p,prefix+'    auto a = get_addshares(x, y);\n    for (int i = 0; i < 5; i++)',
        prefix+'    auto a = get_addshares(x, y);\n'
        '    const char* mode = std::getenv("SEED_TEST_NATIVE_ATTACK");\n'
        '    static bool injected = false;\n'
        '    if (!injected && std::getenv("SEED_TEST_NATIVE_PHASE") && mode &&\n'
        '        ((!T::clear::binary && std::strcmp(mode,"arithmetic-mul")==0) ||\n'
        '         (T::clear::binary && std::strcmp(mode,"binary-mul")==0))) {\n'
        '      a[get_player(0)] += open_type(1); injected = true;\n'
        '      std::cerr << "SEED_TEST_ATTACK " << mode << std::endl;\n'
        '    }\n'
        '    for (int i = 0; i < 5; i++)')
    p=target/'Protocols/Rep4MC.hpp'
    replace(p,'#include "Rep4MC.h"','#include "Rep4MC.h"\n#include <cstdlib>\n#include <cstring>\n#include <iostream>')
    replace(p,'    P.pass_around(right, 1);',
        '    const char* mode = std::getenv("SEED_TEST_NATIVE_ATTACK");\n'
        '    static bool injected = false;\n'
        '    if (!injected && std::getenv("SEED_TEST_NATIVE_PHASE") && mode &&\n'
        '        std::strcmp(mode,"opening-wire")==0 && right.get_length()) {\n'
        '      right.get_data()[0] ^= 1; injected = true;\n'
        '      std::cerr << "SEED_TEST_ATTACK opening-wire" << std::endl;\n'
        '    }\n'
        '    P.pass_around(right, 1);')
    with (target/'adversary-build.log').open('w') as log:
        subprocess.run(['make','-j2','rep4-ring-party.x'],cwd=target,stdout=log,stderr=subprocess.STDOUT,check=True)
    record={'scope':'test-only malicious P0; forbidden by product backend pin',
        'binary_sha256':sha(target/'rep4-ring-party.x'),'library_sha256':sha(target/'libSPDZ.so'),
        'parent_observer_binary_sha256':sha(base/'rep4-ring-party.x'),
        'patches':{name:sha(target/name) for name in ('Protocols/Rep4.hpp','Protocols/Rep4MC.hpp','Processor/BaseMachine.cpp')},
        'modes':['arithmetic-mul','binary-mul','opening-wire','round-abort']}
    (target/'adversary-build.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2),flush=True)


if __name__=='__main__': build()
