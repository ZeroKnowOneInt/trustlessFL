"""TEST ONLY native import equivocation; rejected by the production backend pin."""
import json
from pathlib import Path
import shutil
import subprocess
from trustlessfl.seed_mpc_backend import pin_backend, sha
ROOT=Path(__file__).resolve().parents[1]


def replace(path,before,after):
    text=path.read_text()
    if text.count(before)!=1:raise ValueError('test fault anchor differs')
    patched=text.replace(before,after)
    if patched!=text:path.write_text(patched)


def build():
    base=ROOT/'.cache/private-bound-mpc/mp-spdz-0.4.3-direct-rep4-v1'
    pin_backend(base)
    target=ROOT/'.cache/private-bound-mpc/mp-spdz-0.4.3-direct-adversary-test'
    if not target.exists():shutil.copytree(base,target,symlinks=True)
    for name in ('GC/Rep4Secret.cpp','Networking/Player.cpp','Networking/CryptoPlayer.cpp'):
        shutil.copyfile(base/name,target/name)
    p=target/'GC/Rep4Secret.cpp'
    replace(p,'#include "Rep4Secret.h"','#include "Rep4Secret.h"\n#include <cstdlib>')
    replace(p,'    P.send_receive_all(sends, received);',
        '    const char* attack = std::getenv("SEED_TEST_DIRECT_ATTACK");\n'
        '    bool first = current == 0 and me == 0;\n'
        '    if (first and attack and string(attack) == "native-digest-equivocation") {\n'
        '        sends[1].get_data()[0] ^= 1;\n'
        '        cerr << "SEED_TEST_DIRECT_ATTACK native-digest-equivocation" << endl;\n'
        '    }\n    P.send_receive_all(sends, received);')
    replace(p,'    P.Broadcast_Receive(statuses);',
        '    if (first and attack and string(attack) == "native-status-equivocation")\n'
        '        setenv("SEED_TEST_DIRECT_STATUS", "1", 1);\n'
        '    P.Broadcast_Receive(statuses);')
    replace(p,'    size_t k = 0;\n    for (auto x : InputArgList(args))\n        processor.S[x.dest] = pending[k++];',
        '    if (first and attack and string(attack) == "native-postcheck-share") {\n'
        '        pending[0][0] += BitVec(1);\n'
        '        cerr << "SEED_TEST_DIRECT_ATTACK native-postcheck-share" << endl;\n'
        '    }\n'
        '    size_t k = 0;\n    for (auto x : InputArgList(args))\n        processor.S[x.dest] = pending[k++];')
    p=target/'Networking/CryptoPlayer.cpp'
    anchor='void CryptoPlayer::Broadcast_Receive_no_stats(vector<octetStream>& os) const\n{\n'
    text=p.read_text();start=text.index(anchor);end=text.index('\n}',start)+2
    block=text[start:end]
    changed=block.replace(anchor,anchor+
        '    vector<octetStream> attack_streams(num_players());\n'
        '    bool attack_status = std::getenv("SEED_TEST_DIRECT_STATUS") and my_num() == 0\n'
        '        and os[my_num()].get_length() == 17;\n'
        '    for (int peer = 0; peer < num_players(); peer++) {\n'
        '        attack_streams[peer] = os[my_num()];\n'
        '        if (attack_status and peer == 1) {\n'
        '            attack_streams[peer].get_data()[16] ^= 1;\n'
        '            cerr << "SEED_TEST_DIRECT_ATTACK native-status-equivocation" << endl;\n'
        '        }\n'
        '    }\n')
    changed=changed.replace('request(os[my_num()])','request(attack_streams[other])')
    changed=changed.replace('wait(os[my_num()])','wait(attack_streams[other])')
    if changed==block:raise ValueError('native status attack anchor differs')
    p.write_text(text[:start]+changed+text[end:])
    with (target/'adversary-build.log').open('w') as log:
        subprocess.run(['make','-j1','rep4-ring-party.x'],cwd=target,stdout=log,stderr=subprocess.STDOUT,check=True)
    record={'scope':'test-only malicious P0; never accepted as product backend',
            'binary_sha256':sha(target/'rep4-ring-party.x'),'library_sha256':sha(target/'libSPDZ.so'),
            'parent_binary_sha256':sha(base/'rep4-ring-party.x'),
            'patches':{name:sha(target/name) for name in ('GC/Rep4Secret.cpp','Networking/Player.cpp','Networking/CryptoPlayer.cpp')}}
    (target/'adversary-build.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))
if __name__=='__main__':build()
