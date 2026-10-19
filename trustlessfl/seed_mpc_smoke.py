"""Synthetic native setup self-test. No learning data, production seeds or Flower."""
from importlib.resources import files
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import time

from .crypto import ProtocolError, canonical
from .seed_mpc_assets import configure_tls, free_port_base
from .seed_mpc_backend import pin_backend, native_command
from .seed_mpc_direct_patch import PATCH_ID

SOURCE = r"""
import json
from Compiler.types import sint, regint
from Compiler.GC.types import sbitvec, sbitintvec
from Compiler.library import print_ln, check_point
from Compiler.program import Program
exec(open('Programs/Source/seed_mpc_candidate_primitives.py').read())
Program.prog.active = True
cfg=json.load(open('smoke.json'))
word=sbitintvec.get_type(16)
for r,case in enumerate(cfg['cases'],1):
    rows=[]
    accepted=[]
    for i in range(4):
        masks=(import_checked_native_mask(16,2,1) if cfg['direct'] else input_checked_mask_components(16,2,1))
        values=[]
        bits=[]
        for j in range(2):
            signed=word(case['wire'][i][j])-masks[j]
            coordinate_ok=(signed>=-20000)&(signed<=20000)
            safe_bits=[b&coordinate_ok.v[0] for b in signed.v]
            value=sint(sbitvec.from_vec(safe_bits))-(1<<16)*sint(sbitvec.from_vec([safe_bits[-1]]))
            values.append(value)
            bits.append(sint(sbitvec.from_vec([coordinate_ok.v[0]])))
        norm=sum(x*x for x in values)
        passed=case['presence'][i]*bits[0]*bits[1]*norm.less_equal(400000000,bit_length=34)
        accepted.append(passed)
        rows.append(values)
    count=sum(accepted)
    ok=count.greater_equal(2,bit_length=5)
    total=[sum(bit*row[j] for bit,row in zip(accepted,rows)) for j in range(2)]
    opened=[ok.reveal(),(ok*count).reveal()]+[(ok*x).reveal() for x in total]
    check_point()
    print_ln('SETUP_SMOKE round=%s ok=%s count=%s sum0=%s sum1=%s',r,*[regint.conv(x)[0] for x in opened])
check_point()
"""


def smoke(installation,output,*,fault=False,timeout=120):
    installation=Path(installation).resolve()
    pin=pin_backend(installation)
    direct=PATCH_ID in pin['applied_patches']
    output=Path(output).resolve();output.mkdir(parents=True,exist_ok=False,mode=0o700)
    source=output/'Programs/Source';source.mkdir(parents=True)
    (source/'setup_smoke.mpc').write_text(SOURCE)
    (source/'seed_mpc_candidate_primitives.py').write_bytes(files('trustlessfl.mpc_sources').joinpath('seed_mpc_candidate_primitives.py').read_bytes())
    # Fixed public expected updates; random synthetic components used only here.
    cases=[([[20000,0]]*4,[1]*4),([[20001,0],[20000,20000],[-20000,0],[-20000,0]],[1]*4),
           ([[20000,0],[0,0],[0,0],[0,0]],[1,0,0,0])]
    inputs=[[] for _ in range(4)];public=[]
    for case_index,(rows,presence) in enumerate(cases):
        wire=[]
        for slot,row in enumerate(rows):
            components=[[secrets.randbelow(65536) for _ in range(2)] for _ in range(4)]
            mask=[components[0][j]^components[1][j]^components[2][j]^components[3][j] for j in range(2)]
            wire.append([(v+m)%65536 for v,m in zip(row,mask)])
            for party in range(4):
                for component in range(4):
                    if party!=component:
                        values=list(components[component])
                        if fault and case_index==0 and slot==3 and party==0 and component==1:values[0]^=1
                        inputs[party].extend(values)
        public.append({'wire':wire,'presence':presence})
    (output/'smoke.json').write_bytes(canonical({'direct':direct,'cases':public}))
    (output/'Programs/Bytecode').mkdir();(output/'Programs/Schedules').mkdir()
    env={'PATH':'/usr/bin:/bin','HOME':str(Path.home()),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
    with (output/'compile.log').open('x') as log:
        subprocess.run([sys.executable,str(installation/'compile.py'),'-R','64','-Z','4','-M','setup_smoke'],
                       cwd=output,env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=180)
    actors=configure_tls(output,4,0)
    processes=[];logs=[]
    started=time.monotonic();port=free_port_base(4)
    try:
        for party in range(4):
            path=actors[f'P{party}']/'Player-Data'/f'Input-P{party}-0'
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as stream:stream.write('\n'.join(map(str,inputs[party]))+'\n')
            log=(actors[f'P{party}']/'native.log').open('x');logs.append(log)
            processes.append(subprocess.Popen(native_command(installation/'rep4-ring-party.x',port,party,'setup_smoke'),
                cwd=actors[f'P{party}'],env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True))
        deadline=time.monotonic()+timeout
        exits=[p.wait(timeout=max(1,deadline-time.monotonic())) for p in processes]
        texts=[(actors[f'P{party}']/'native.log').read_text() for party in range(4)]
        if fault:
            marker='inconsistent native mask components' if direct else 'inconsistent local mask components'
            if not all(marker in text for text in texts) or any('SETUP_SMOKE round=' in text for text in texts):
                raise ProtocolError('native self-test holder mismatch did not fail before output')
            result={'fault_rejected':True,'public_results':0}
        else:
            expected=[(1,1,4,80000,0),(2,1,2,-40000,0),(3,0,0,0,0)]
            observed=[[tuple(map(int,row)) for row in re.findall(
                r'SETUP_SMOKE round=(\d+) ok=(\d+) count=(\d+) sum0=(-?\d+) sum1=(-?\d+)',text)] for text in texts]
            # Each party observes the same checked public result.
            if any(code!=0 for code in exits) or any(rows!=expected for rows in observed):
                raise ProtocolError('native setup self-test output/check/exit differs')
            result={'rounds':[{'round':r,'ok':ok,'count':count,'sum':[a,b]} for r,ok,count,a,b in expected],
                    'wrap_exact':True,'boundary_exclusion_exact':True,'abort_hides_sum_count':True}
        report={'passed':True,'aggregators':4,'mode':'direct' if direct else 'stock',
            'seconds':round(time.monotonic()-started,3),'scope':'synthetic native installation test; no FL/privacy proof',**result}
        (output/'verification.json').write_bytes(canonical(report));return report
    finally:
        for process in processes:
            if process.poll() is None:
                try:os.killpg(process.pid,signal.SIGTERM)
                except ProcessLookupError:pass
        for process in processes:
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
        for log in logs:log.close()
