"""Artifact substitution and insecure argv must fail before native launch."""
import io
import json
from pathlib import Path
import tarfile

import pytest

from trustlessfl.crypto import ProtocolError
from trustlessfl import seed_mpc_backend as backend


@pytest.fixture
def installation(tmp_path,monkeypatch):
    root=tmp_path/f'mp-spdz-{backend.VERSION}'; root.mkdir()
    files={'compile.py':b'# compiler fixture\n','Protocols/Rep4.hpp':b'checked multiplication',
           'Protocols/Rep4MC.hpp':b'checked opening','bin/Linux-adx/rep4-ring-party.x':b'official fixture binary'}
    archive=tmp_path/f'mp-spdz-{backend.VERSION}.tar.xz'
    with tarfile.open(archive,'w:xz') as t:
        for name,data in files.items():
            p=root/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(data)
            info=tarfile.TarInfo(f'mp-spdz-{backend.VERSION}/{name}'); info.size=len(data)
            t.addfile(info,io.BytesIO(data))
    (root/'rep4-ring-party.x').write_bytes(files['bin/Linux-adx/rep4-ring-party.x'])
    monkeypatch.setattr(backend,'ARCHIVE_SHA256',backend.sha(archive))
    return root


def test_pin_matches_archive_sources_and_release_binary(installation):
    pin=backend.pin_backend(installation)
    assert pin['official_binary_members']==['bin/Linux-adx/rep4-ring-party.x']
    assert pin['applied_patches']==[]
    backend.validate_pin(installation,pin)


@pytest.mark.parametrize('fault',['source','extra-source','binary','archive','fake-pin'])
def test_backend_substitution_is_rejected(installation,fault):
    pin=backend.pin_backend(installation)
    if fault=='source': (installation/'Protocols/Rep4.hpp').write_bytes(b'delayed unchecked multiplication')
    if fault=='extra-source': (installation/'Protocols/injected.hpp').write_bytes(b'extra')
    if fault=='binary': (installation/'rep4-ring-party.x').write_bytes(b'custom insecure binary')
    if fault=='archive': installation.parent.joinpath(f'mp-spdz-{backend.VERSION}.tar.xz').write_bytes(b'fake archive')
    if fault=='fake-pin':
        pin['sources']['Protocols/Rep4.hpp']='00'*32
        pin['source_manifest_hash']=backend.digest(pin['sources'])
    with pytest.raises(ProtocolError): backend.validate_pin(installation,pin)


@pytest.mark.parametrize('program',['--semi-honest','program --insecure','../program','/tmp/program',''])
def test_native_command_rejects_security_flag_injection(program):
    with pytest.raises(ProtocolError): backend.native_command('/pinned/rep4-ring-party.x',18000,0,program)


def test_native_command_has_no_optional_security_overrides():
    assert backend.native_command('/pinned/rep4-ring-party.x',18000,0,'seed_mpc_chunked_session-policy.json')==[
        '/pinned/rep4-ring-party.x','-pn','18000','-h','127.0.0.1','-R','64','-p','0',
        'seed_mpc_chunked_session-policy.json','-OF','.','-v']
    with pytest.raises(ProtocolError): backend.native_command('/pinned/semi-party.x',18000,0,'program')
    with pytest.raises(ProtocolError): backend.native_command('/pinned/rep4-ring-party.x',18000,True,'program')


@pytest.fixture
def observer_installation(installation,monkeypatch):
    root=installation
    original=('  timer[n].start(total_stats());\n  timer[n].stop(total_stats());\n'
              '  cerr << "Global data sent = "')
    archive=root.parent/f'mp-spdz-{backend.VERSION}.tar.xz'
    with tarfile.open(archive) as t:
        files={m.name:t.extractfile(m).read() for m in t if m.isfile()}
    files[f'mp-spdz-{backend.VERSION}/Processor/BaseMachine.cpp']=original.encode()
    with tarfile.open(archive,'w:xz') as t:
        for name,data in files.items():
            info=tarfile.TarInfo(name); info.size=len(data); t.addfile(info,io.BytesIO(data))
    monkeypatch.setattr(backend,'ARCHIVE_SHA256',backend.sha(archive))
    source=root/'Processor/BaseMachine.cpp'; source.parent.mkdir(); source.write_text(backend.patched_source(original))
    (root/'rep4-ring-party.x').write_bytes(b'known observer binary')
    (root/'libSPDZ.so').write_bytes(b'known observer library')
    (root/'CONFIG.mine').write_text('approved compile config')
    runtime=root/'runtime-lib.so'; runtime.write_bytes(b'known runtime dependency')
    record={'patch_id':backend.PATCH_ID,'binary_sha256':backend.sha(root/'rep4-ring-party.x'),
            'shared_library_sha256':backend.sha(root/'libSPDZ.so'),'config_sha256':backend.sha(root/'CONFIG.mine'),
            'runtime_libraries':{str(runtime):backend.sha(runtime)}}
    manifest=root/'telemetry-build.json'; manifest.write_text(json.dumps(record))
    monkeypatch.setattr(backend,'APPROVED_BUILD_SHA256',backend.sha(manifest))
    monkeypatch.setattr(backend,'resolved_libraries',lambda binary:{str(runtime)})
    return root


def test_approved_observer_patch_and_build(observer_installation):
    pin=backend.pin_backend(observer_installation)
    assert pin['applied_patches']==[backend.PATCH_ID]
    assert pin['official_binary_members']==[]
    backend.validate_pin(observer_installation,pin)


@pytest.mark.parametrize('name',['Processor/BaseMachine.cpp','rep4-ring-party.x','libSPDZ.so',
                                  'CONFIG.mine','runtime-lib.so','telemetry-build.json'])
def test_observer_substitution_rejected_even_with_forged_pin(observer_installation,name):
    pin=backend.pin_backend(observer_installation)
    p=observer_installation/name; p.write_bytes(p.read_bytes()+b'\nchanged')
    pin['binary_sha256']=backend.sha(observer_installation/'rep4-ring-party.x')
    with pytest.raises(ProtocolError): backend.validate_pin(observer_installation,pin)


@pytest.mark.parametrize('name',['LD_PRELOAD','LD_LIBRARY_PATH','LD_AUDIT'])
def test_observer_loader_override_rejected(observer_installation,monkeypatch,name):
    monkeypatch.setenv(name,'unrecorded-loader-override')
    with pytest.raises(ProtocolError): backend.pin_backend(observer_installation)


def test_observer_other_runtime_resolution_rejected(observer_installation,monkeypatch):
    monkeypatch.setattr(backend,'resolved_libraries',lambda binary:{'/different/libSPDZ.so'})
    with pytest.raises(ProtocolError): backend.pin_backend(observer_installation)
