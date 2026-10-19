"""Client-owned gate for Flower 1.36 FAB installation and ClientApp loading.

TLS authenticates A0 but does not authorize A0 to send executable client code.
This gate compares downloaded package bytes with the locally installed package,
disables runtime dependency installation, and loads the client-owned ClientApp.
It is not a sandbox for a user-authorized model plugin.
"""
import hashlib
from importlib.metadata import version
from io import BytesIO
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tomllib
import zipfile

from .crypto import ProtocolError

COMPONENTS={'serverapp':'trustlessfl.seed_mpc_server_app:app','clientapp':'trustlessfl.seed_mpc_client_app:app'}


def package_manifest():
    root=Path(__file__).resolve().parent
    return {p.relative_to(root.parent).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob('*')) if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc'}


def validate_fab(content,expected):
    if not isinstance(content,bytes): content=Path(content).read_bytes()
    if len(content)>32*1024*1024: raise ProtocolError('oversized client app bundle')
    try:
        with zipfile.ZipFile(BytesIO(content)) as archive:
            names=archive.namelist()
            if len(names)!=len(set(names)): raise ProtocolError('duplicate FAB members')
            actual={}
            for entry in archive.infolist():
                name=entry.filename; path=PurePosixPath(name)
                if (path.is_absolute() or '..' in path.parts or '\\' in name
                        or stat.S_ISLNK(entry.external_attr>>16)):
                    raise ProtocolError('unsafe FAB path')
                if entry.is_dir(): continue
                if entry.file_size>8*1024*1024: raise ProtocolError('oversized FAB member')
                if name in ('pyproject.toml','.info/CONTENT'): continue
                if name not in expected: raise ProtocolError('unapproved executable bundle member')
                actual[name]=hashlib.sha256(archive.read(entry)).hexdigest()
            if actual!=expected: raise ProtocolError('downloaded app differs from client-installed code')
            config=tomllib.loads(archive.read('pyproject.toml').decode())
            if config['tool']['flwr']['app']['components']!=COMPONENTS:
                raise ProtocolError('unapproved Flower application entrypoint')
            if (config.get('project',{}).get('name')!='trustlessfl'
                    or config['project'].get('version')!='0.1.0'
                    or config['tool']['flwr']['app'].get('publisher')!='trustlessfl'):
                raise ProtocolError('unapproved application install identity')
            # Flower's CONTENT reader hashes named paths. Constrain it before
            # installation so A0 cannot query hashes of private local files.
            listed={}
            for line in archive.read('.info/CONTENT').decode().strip().splitlines():
                name,expected_sha,size=line.split(',')
                if name not in {*expected,'pyproject.toml'} or name in listed:
                    raise ProtocolError('unapproved FAB metadata path')
                raw=archive.read(name)
                if expected_sha!=hashlib.sha256(raw).hexdigest() or size!=str(len(raw)*8):
                    raise ProtocolError('invalid FAB metadata hash')
                listed[name]=expected_sha
            if set(listed)!={*expected,'pyproject.toml'}:
                raise ProtocolError('incomplete FAB metadata')
    except (zipfile.BadZipFile,KeyError,ValueError) as exc:
        if isinstance(exc,ProtocolError): raise
        raise ProtocolError('invalid client app bundle') from exc


def install(role_file):
    """Installed by client-owned sitecustomize before the Flower task starts."""
    if version('flwr')!='1.36.0': raise ProtocolError('client runtime version differs')
    role=json.loads(Path(role_file).read_text())
    deployment=json.loads(Path(role['deployment']).read_text())
    plan=json.loads((Path(deployment['public_bundle'])/'plan.json').read_text())
    from .crypto import digest
    if digest(plan)!=deployment['contract_hash']: raise ProtocolError('client app contract changed')
    expected=package_manifest()
    if expected!=plan['app_sources']: raise ProtocolError('client-installed package differs from approved contract')
    from .seed_mpc_client_app import app
    from flwr.supernode.runtime import run_clientapp
    original=run_clientapp.install_from_fab
    def checked_install(content,*args,**kwargs):
        validate_fab(content,expected)
        return original(content,*args,**kwargs)
    def local_loader(*args,**kwargs):
        # Ignore A0's object reference and path. Already imported trusted local app.
        return lambda *unused_args,**unused_kwargs:app
    def no_dependencies(*args,**kwargs):
        raise ProtocolError('client runtime dependency installation forbidden')
    run_clientapp.install_from_fab=checked_install
    run_clientapp.get_load_client_app_fn=local_loader
    run_clientapp.install_app_dependencies=no_dependencies


def bootstrap(directory,env):
    directory=Path(directory)
    root=directory/'client-runtime-bootstrap'; root.mkdir(exist_ok=True)
    # This directory is owned by the client; it is never part of a server FAB.
    (root/'sitecustomize.py').write_text(
        'import os\n'
        'if os.environ.get("TRUSTLESSFL_CLIENT_GUARD_ROLE"):\n'
        '    try:\n'
        '        from trustlessfl.seed_mpc_app_guard import install\n'
        '        install(os.environ["TRUSTLESSFL_CLIENT_GUARD_ROLE"])\n'
        '    except BaseException:\n'
        '        os._exit(78)\n')
    env['TRUSTLESSFL_CLIENT_GUARD_ROLE']=str(directory/'role.json')
    env['PYTHONPATH']=str(root)+os.pathsep+str(Path(__file__).resolve().parent.parent)
