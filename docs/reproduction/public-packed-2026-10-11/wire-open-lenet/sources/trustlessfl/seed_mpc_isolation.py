"""Closed local role filesystem/PID namespaces; shared loopback network.

The host bootstrap/administrator is trusted. This is not a VM boundary or
defense against the host administrator/kernel, network denial of service,
or a malicious MPC protocol implementation's permitted output leakage.
"""
import os
from pathlib import Path
import sys

from .crypto import ProtocolError

ROOT=Path(__file__).resolve().parents[1]


class RoleSandbox:
    def __init__(self,output,role):
        self.output=Path(output).resolve(); self.role=role
        if role not in ['server',*[f'C{i}' for i in range(4)],*[f'P{i}' for i in range(4)]]:
            raise ProtocolError('unknown isolated role')
        self.home=self.output/'role-runtime'/role
        self.home.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.writable=[self.home]
        if role=='server':
            result=self.output/'runtime-results'; result.mkdir(exist_ok=True,mode=0o700)
            self.writable.append(result)
        else:
            actor=self.output/'mpc'/role
            if actor.exists(): self.writable.append(actor)
            if role.startswith('C'):
                directory=self.output/'clients'/role
                directory.mkdir(parents=True,exist_ok=True,mode=0o700)
                self.writable.append(directory)
        # Fixed runtime/public mounts only. Never bind the repository, host
        # home, output root, all clients, or entire MPC workspace.
        public=[Path('/usr'),Path('/bin'),Path('/sbin'),Path('/lib'),Path('/lib64'),Path(sys.base_prefix),ROOT/'.venv',ROOT/'trustlessfl',
                Path('/etc/ssl'),Path('/etc/hosts'),Path('/etc/resolv.conf'),Path('/etc/nsswitch.conf'),
                Path('/etc/passwd'),Path('/etc/group'),Path('/etc/localtime')]
        for name in ('deployment.json','client-preparation.json','public-test.npz','app'):
            public.append(self.output/name)
        for name in ('policy.json','Programs/Bytecode','Programs/Schedules','Programs/Circuits'):
            public.append(self.output/'mpc'/name)
        parent=ROOT/'.cache/private-bound-mpc'
        public.extend(parent/name for name in ('mp-spdz-0.4.3.tar.xz','telemetry-build-deps/root'))
        for installation in ('mp-spdz-0.4.3','mp-spdz-0.4.3-telemetry'):
            # Do not expose installation Player-Data or runtime/preprocessing files.
            public.extend(parent/installation/name for name in ('Compiler','Protocols','GC','Processor','Math','Tools',
                'Networking','Machines','ExternalIO','deps','compile.py','Makefile','CONFIG','CONFIG.mine',
                'rep4-ring-party.x','libSPDZ.so','telemetry-build.json','Programs/Circuits'))
        self.public=[p for p in public if p.exists()]

    def command(self,argv,*,cwd=None,env=None):
        if not argv: raise ProtocolError('empty sandbox command')
        command=['/usr/bin/bwrap','--unshare-user','--unshare-pid','--unshare-ipc','--unshare-uts',
                 '--die-with-parent','--new-session','--cap-drop','ALL','--clearenv',
                 '--proc','/proc','--dev','/dev','--tmpfs','/tmp','--dir','/tmp/home']
        # bwrap creates missing parent directories in the otherwise empty root.
        for p in self.public:
            if str(p) in ('/bin','/sbin','/lib','/lib64') and p.is_symlink():
                command.extend(['--symlink',os.readlink(p),str(p)])
            else: command.extend(['--ro-bind',str(p),str(p)])
        for p in self.writable: command.extend(['--bind',str(p),str(p)])
        values={'PATH':str(ROOT/'.venv/bin')+':/usr/bin:/bin','PYTHONPATH':str(ROOT),
                'HOME':'/tmp/home','FLWR_HOME':str(self.home/'flower-home'),
                'FLWR_TELEMETRY_ENABLED':'0','FLWR_DISABLE_UPDATE_CHECK':'1',
                'OPENBLAS_NUM_THREADS':'1','OMP_NUM_THREADS':'1','MKL_NUM_THREADS':'1',
                'TRUSTLESSFL_SEED_CLIENT_ROOT':str(self.output/'clients')}
        if env:
            if set(env)-{'FLWR_HOME','FLWR_TELEMETRY_ENABLED','FLWR_DISABLE_UPDATE_CHECK'}:
                raise ProtocolError('unapproved sandbox environment override')
            values.update(env)
        for key,value in values.items(): command.extend(['--setenv',key,value])
        command.extend(['--chdir',str(cwd or self.home),'--',*map(str,argv)])
        return command
