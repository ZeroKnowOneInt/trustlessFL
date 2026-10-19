"""Installer provenance, tamper rejection and interruption boundaries."""
import io
import json
import os
from pathlib import Path
import tarfile

import pytest

from trustlessfl.crypto import ProtocolError,canonical,digest
from trustlessfl import seed_mpc_backend as backend
from trustlessfl import seed_mpc_setup as setup
from trustlessfl import seed_mpc_build_trust as trust


@pytest.fixture
def source_build(tmp_path,monkeypatch):
    root=tmp_path/'install';root.mkdir()
    originals={'compile.py':b'# official compiler\n','Protocols/Rep4.hpp':b'active multiply',
        'Protocols/Rep4MC.hpp':b'active check','CONFIG':b'official config','Makefile':b'official make',
        'Processor/BaseMachine.cpp':b'  timer[n].start(total_stats());\n  timer[n].stop(total_stats());\n  cerr << "Global data sent = "',
        'GC/Rep4Secret.h':b'    void load_clear(int n, const Integer& x);\n',
        'GC/Rep4Secret.cpp':b'#include "ShareSecret.hpp"\nnamespace GC {\n}\n\n#endif /* GC_REP4SECRET_CPP_ */'}
    archive=tmp_path/f'mp-spdz-{backend.VERSION}.tar.xz'
    with tarfile.open(archive,'w:xz') as stream:
        for relative,raw in originals.items():
            info=tarfile.TarInfo(f'mp-spdz-{backend.VERSION}/{relative}');info.size=len(raw)
            stream.addfile(info,io.BytesIO(raw))
            path=root/relative;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(setup.PATCHES[relative](raw.decode()).encode() if relative in setup.PATCHES else raw)
    monkeypatch.setattr(backend,'ARCHIVE_SHA256',backend.sha(archive))
    monkeypatch.setattr(setup,'ARCHIVE_SHA256',backend.sha(archive))
    monkeypatch.setattr(setup,'cpu_flags',lambda:set(setup.CPU_FLAGS))
    monkeypatch.setattr(trust,'trust_root',lambda:tmp_path/'operator-trust')
    (root/'rep4-ring-party.x').write_bytes(b'installer-built binary')
    (root/'libSPDZ.so').write_bytes(b'installer-built library')
    (root/'CONFIG.mine').write_text(setup.CONFIG)
    monkeypatch.setattr(backend,'resolved_libraries',lambda _: {str(root/'libSPDZ.so')})
    record={'protocol':trust.BUILD_PROTOCOL,'recipe':setup.recipe(),'recipe_hash':digest(setup.recipe()),
        'installation':str(root),'compiler_sha256':backend.sha('/usr/bin/g++'),'compiler':'fixture toolchain',
        'config_sha256':backend.sha(root/'CONFIG.mine'),'binary_sha256':backend.sha(root/'rep4-ring-party.x'),
        'shared_library_sha256':backend.sha(root/'libSPDZ.so'),
        'runtime_libraries':{str(root/'libSPDZ.so'):backend.sha(root/'libSPDZ.so')}}
    (root/'source-build.json').write_bytes(canonical(record))
    return root,record


def approve_fixture(root,record):
    trust.approve(root,backend.sha(root/'source-build.json'),record['recipe_hash'])


def test_manifest_alone_is_not_operator_approval(source_build):
    root,_=source_build
    with pytest.raises(ProtocolError,match='trusted approval'):backend.pin_backend(root)


def test_approved_source_build_is_pinned_and_checked(source_build):
    root,record=source_build;approve_fixture(root,record)
    pin=backend.pin_backend(root)
    assert pin['applied_patches']==[setup.OBSERVER_ID,setup.DIRECT_ID]
    assert pin['source_build']==record
    backend.validate_pin(root,pin)


@pytest.mark.parametrize('path',['rep4-ring-party.x','libSPDZ.so','CONFIG.mine','compile.py',
    'GC/Rep4Secret.h','GC/Rep4Secret.cpp','Processor/BaseMachine.cpp','source-build.json'])
def test_substitution_fails_even_with_caller_forged_pin(source_build,path):
    root,record=source_build;approve_fixture(root,record)
    pin=backend.pin_backend(root)
    file=root/path;file.write_bytes(file.read_bytes()+b'changed')
    pin['binary_sha256']=backend.sha(root/'rep4-ring-party.x')
    with pytest.raises((ProtocolError,ValueError)):backend.validate_pin(root,pin)


def test_self_consistent_modified_manifest_needs_new_operator_approval(source_build):
    root,record=source_build;approve_fixture(root,record)
    (root/'rep4-ring-party.x').write_bytes(b'substituted')
    record['binary_sha256']=backend.sha(root/'rep4-ring-party.x')
    (root/'source-build.json').write_bytes(canonical(record))
    with pytest.raises(ProtocolError,match='operator approval'):backend.pin_backend(root)


@pytest.mark.parametrize('fault',['extra-source','unapproved-config','source','recipe','libraries','conflict'])
def test_operator_approval_does_not_bypass_source_recipe_checks(source_build,fault):
    root,record=source_build
    if fault=='extra-source':(root/'Protocols/injected.hpp').write_text('unapproved')
    if fault=='unapproved-config':
        (root/'CONFIG.mine').write_text('SECURE = -DINSECURE\n');record['config_sha256']=backend.sha(root/'CONFIG.mine')
    if fault=='source':(root/'Protocols/Rep4MC.hpp').write_text('unchecked')
    if fault=='recipe':record['recipe']['command'].append('--insecure');record['recipe_hash']=digest(record['recipe'])
    if fault=='libraries':record['runtime_libraries']={}
    if fault=='conflict':(root/'direct-build.json').write_text('{}')
    (root/'source-build.json').write_bytes(canonical(record));approve_fixture(root,record)
    with pytest.raises(ProtocolError):backend.pin_backend(root)


@pytest.mark.parametrize('fault',['mode','symlink','missing','owner'])
def test_approval_storage_must_be_private_regular_and_present(source_build,fault,monkeypatch):
    root,record=source_build;approve_fixture(root,record);path=trust.approval_path(root)
    if fault=='mode':path.chmod(0o644)
    if fault=='symlink':
        other=path.with_suffix('.other');path.rename(other);path.symlink_to(other)
    if fault=='missing':path.unlink()
    if fault=='owner':monkeypatch.setattr(trust.os,'getuid',lambda:999999)
    with pytest.raises(ProtocolError):backend.pin_backend(root)


def test_approval_cannot_be_silently_overwritten(source_build):
    root,record=source_build;approve_fixture(root,record)
    with pytest.raises(FileExistsError):approve_fixture(root,record)


@pytest.mark.parametrize('name',['LD_PRELOAD','LD_LIBRARY_PATH','LD_AUDIT'])
def test_loader_overrides_block_setup_and_approved_execution(source_build,monkeypatch,name):
    root,record=source_build;approve_fixture(root,record);monkeypatch.setenv(name,'untrusted')
    with pytest.raises(ProtocolError):backend.pin_backend(root)
    with pytest.raises(ProtocolError):setup.setup(root.parent/'new')
    assert not (root.parent/'new').exists()


def test_offline_archive_hash_checked_before_copy_or_extract(tmp_path,monkeypatch):
    invalid=tmp_path/'bad.tar.xz';invalid.write_bytes(b'not the official archive')
    with pytest.raises(ProtocolError):setup.obtain_archive(tmp_path,invalid)
    assert not list(tmp_path.glob('*.partial-*'))
    assert not (tmp_path/f'mp-spdz-{setup.VERSION}.tar.xz').exists()


def test_failed_download_removes_partial_file(tmp_path,monkeypatch):
    class Download:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def read(self,size):raise OSError('interrupted download')
    monkeypatch.setattr(setup.urllib.request,'urlopen',lambda *args,**kwargs:Download())
    with pytest.raises(OSError):setup.obtain_archive(tmp_path)
    assert not list(tmp_path.glob('*.partial-*'))


@pytest.mark.parametrize('name',['../escape','/absolute','mp-spdz-0.4.3/../../escape','other-root/file'])
def test_unsafe_archive_members_rejected(tmp_path,name):
    archive=tmp_path/'fixture.tar.xz'
    with tarfile.open(archive,'w:xz') as stream:
        info=tarfile.TarInfo(name);info.size=1;stream.addfile(info,io.BytesIO(b'x'))
    with pytest.raises(ProtocolError):setup.extract_verified(archive,tmp_path/'work')
    assert not (tmp_path/'escape').exists()


@pytest.mark.parametrize('path',['with space','with$variable','with;command','with#comment'])
def test_makefile_path_metacharacters_rejected_before_writing(tmp_path,path):
    with pytest.raises(ProtocolError):setup.setup(tmp_path/path)
    assert not (tmp_path/path).exists()


def test_partial_existing_installation_is_never_overwritten_or_rebuilt(tmp_path,monkeypatch):
    root=tmp_path/f'mp-spdz-{setup.VERSION}-checked-source-v1';root.mkdir();(root/'sentinel').write_text('preserve')
    monkeypatch.setattr(setup,'install_dependencies',lambda:pytest.fail('partial target installed dependencies'))
    monkeypatch.setattr(setup,'obtain_archive',lambda *args:pytest.fail('partial target fetched archive'))
    with pytest.raises(ProtocolError):setup.setup(tmp_path,install_system_deps=True)
    assert (root/'sentinel').read_text()=='preserve'


def test_installer_environment_does_not_inherit_make_or_compiler_overrides(monkeypatch):
    for key in ('CXX','CXXFLAGS','CPPFLAGS','MAKEFLAGS','SECURE','PYTHONPATH','LD_PRELOAD'):
        monkeypatch.setenv(key,'injected')
    env=setup.clean_environment()
    assert env['PATH']=='/usr/bin:/bin'
    assert not any(key in env for key in ('CXX','CXXFLAGS','CPPFLAGS','MAKEFLAGS','SECURE','PYTHONPATH','LD_PRELOAD'))


def test_normal_release_root_directory_extracts_safely(tmp_path):
    archive=tmp_path/'fixture.tar.xz'
    with tarfile.open(archive,'w:xz') as stream:
        root=tarfile.TarInfo(f'mp-spdz-{setup.VERSION}');root.type=tarfile.DIRTYPE;stream.addfile(root)
        raw=b'official fixture';member=tarfile.TarInfo(f'mp-spdz-{setup.VERSION}/file');member.size=len(raw)
        stream.addfile(member,io.BytesIO(raw))
    setup.extract_verified(archive,tmp_path/'work')
    assert (tmp_path/'work/file').read_bytes()==b'official fixture'


def test_trust_anchor_uses_os_account_not_caller_home_or_xdg(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setenv('HOME','/untrusted/home')
    monkeypatch.setenv('XDG_STATE_HOME','/untrusted/state')
    monkeypatch.setattr(trust.pwd,'getpwuid',lambda _:SimpleNamespace(pw_dir='/operator/home'))
    assert trust.trust_root()==Path('/operator/home/.local/state/trustlessfl/native-approvals')


def test_local_ports_avoid_the_os_outgoing_ephemeral_range(monkeypatch):
    from trustlessfl import seed_mpc_assets as assets
    monkeypatch.setattr(assets,'ephemeral_range',lambda:(10000,11000))
    candidates=iter([0,5000])
    monkeypatch.setattr(assets.secrets,'randbelow',lambda _:next(candidates))
    assert assets.free_port_base(4)==15000


def test_busy_rpc_port_fails_before_any_native_launch(monkeypatch):
    import socket
    from types import SimpleNamespace
    from trustlessfl.seed_mpc_policy import SeedMPCPolicy
    from trustlessfl import seed_mpc_service as service
    with socket.socket() as occupied:
        occupied.bind(('127.0.0.1',0));occupied.listen()
        port=occupied.getsockname()[1]
        committee=SimpleNamespace(policy=SeedMPCPolicy(53,4,20000,2500000000))
        monkeypatch.setattr(service,'load_deployment',lambda _:({'services':[f'http://127.0.0.1:{port}']},committee))
        monkeypatch.setattr(service,'LocalAggregator',lambda *args:pytest.fail('busy RPC port launched native'))
        monkeypatch.setattr(__import__('sys'),'argv',
            ['service','--deployment','unused','--private','unused','--slot','0'])
        with pytest.raises(OSError):service.main()
