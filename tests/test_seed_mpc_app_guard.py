from io import BytesIO
import json
from pathlib import Path
import zipfile

import pytest
import tomli_w

from trustlessfl.crypto import ProtocolError
from trustlessfl.seed_mpc_app_guard import COMPONENTS,package_manifest,validate_fab


def bundle(files,components=COMPONENTS,extra=None):
    out=BytesIO()
    with zipfile.ZipFile(out,'w') as archive:
        for name,body in files.items(): archive.writestr(name,body)
        config=tomli_w.dumps({'project':{'name':'trustlessfl','version':'0.1.0'},'tool':{'flwr':{'app':{'publisher':'trustlessfl','components':components}}}}).encode()
        archive.writestr('pyproject.toml',config)
        import hashlib
        metadata=''.join(f'{name},{hashlib.sha256(body).hexdigest()},{len(body)*8}\n' for name,body in {**files,'pyproject.toml':config}.items())
        archive.writestr('.info/CONTENT',metadata)
        if extra:
            for name,body in extra.items(): archive.writestr(name,body)
    return out.getvalue()


@pytest.fixture
def approved():
    import hashlib
    files={'trustlessfl/__init__.py':b'','trustlessfl/seed_mpc_client_app.py':b'app = "locally installed"\n'}
    return files,{k:hashlib.sha256(v).hexdigest() for k,v in files.items()}


def test_approved_client_package_bytes(approved):
    files,expected=approved
    validate_fab(bundle(files),expected)


def test_a0_cannot_replace_client_code_even_with_same_entrypoint(approved,tmp_path):
    files,expected=approved
    files['trustlessfl/seed_mpc_client_app.py']=b'raise RuntimeError("steal private seeds")\n'
    with pytest.raises(ProtocolError,match='differs'): validate_fab(bundle(files),expected)


def test_a0_cannot_select_another_entrypoint(approved):
    files,expected=approved
    with pytest.raises(ProtocolError,match='entrypoint'):
        validate_fab(bundle(files,{**COMPONENTS,'clientapp':'malicious:app'}),expected)


@pytest.mark.parametrize('extra',['evil.py','sitecustomize.py','evil.pth','../client.json','/tmp/evil.py','trustlessfl\\evil.py'])
def test_extra_executable_and_path_traversal_rejected(approved,extra):
    files,expected=approved
    with pytest.raises(ProtocolError): validate_fab(bundle(files,extra={extra:b'attack'}),expected)


def test_missing_local_dependency_rejected(approved):
    files,expected=approved
    files.pop('trustlessfl/__init__.py')
    with pytest.raises(ProtocolError): validate_fab(bundle(files),expected)


def test_duplicate_member_rejected(approved):
    files,expected=approved
    with pytest.warns(UserWarning):
        data=bundle(files,extra={'trustlessfl/__init__.py':b'shadow'})
    with pytest.raises(ProtocolError,match='duplicate'): validate_fab(data,expected)


def test_manifest_never_uses_pycache():
    manifest=package_manifest()
    assert 'trustlessfl/seed_mpc_app_guard.py' in manifest
    assert not any('__pycache__' in name or name.endswith('.pyc') for name in manifest)


def test_invalid_archive_rejected(approved):
    with pytest.raises(ProtocolError): validate_fab(b'not a zip',approved[1])


@pytest.mark.parametrize('path',['/home/operator/workspace/role/train.npz','../client.json'])
def test_metadata_cannot_probe_private_file_hashes(approved,path):
    files,expected=approved; original=bundle(files)
    out=BytesIO()
    with zipfile.ZipFile(BytesIO(original)) as source,zipfile.ZipFile(out,'w') as target:
        for entry in source.infolist():
            raw=source.read(entry)
            if entry.filename=='.info/CONTENT': raw+=f'{path},{"0"*64},123\n'.encode()
            target.writestr(entry,raw)
    with pytest.raises(ProtocolError,match='metadata path'): validate_fab(out.getvalue(),expected)


def test_official_flower_builder_metadata_interoperates(approved):
    from flwr.cli.build import build_fab_from_files
    files,expected=approved
    config={'project':{'name':'trustlessfl','version':'0.1.0','description':'MPC test','license':'MIT',
        'requires-python':'>=3.12','dependencies':['flwr==1.36.0']},
        'tool':{'flwr':{'app':{'publisher':'trustlessfl','components':COMPONENTS,'config':{}}}}}
    fab,_=build_fab_from_files({**files,'pyproject.toml':tomli_w.dumps(config).encode()})
    validate_fab(fab,expected)
