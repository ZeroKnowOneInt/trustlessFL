"""Pin the official Rep4 distribution and construct a closed native argv.

This establishes artifact provenance, not a proof of the FL composition.
Only official prebuilt or explicitly pinned observer/checked-import builds are accepted.
The observer patch is rederived from the archive; its build/config/libraries
are anchored to a repository constant, never a caller's self-consistent map.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import tarfile
import subprocess
from .seed_mpc_telemetry_patch import patched_source,PATCH_ID,APPROVED_BUILD_SHA256

from .seed_mpc_direct_patch import PATCH_ID as DIRECT_PATCH_ID, APPROVED_BUILD_SHA256 as DIRECT_BUILD_SHA256, patched_source as direct_patched_source

from .crypto import ProtocolError, digest

VERSION = '0.4.3'
ARCHIVE_SHA256 = '4b5f4f7a79f31365288fe4498ba2b70afc314c028696929c8d259ef50ab2e759'
SOURCE_DIRS = {'Compiler','Protocols','GC','Processor','Math','Tools','Networking','Machines','ExternalIO','deps'}
SOURCE_SUFFIXES = {'.py','.cpp','.cc','.c','.h','.hpp','.inc'}


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def is_source(relative):
    p=Path(relative)
    return (relative in ('compile.py','Makefile','CONFIG') or
            p.parts[0] in SOURCE_DIRS and p.suffix in SOURCE_SUFFIXES)


def resolved_libraries(binary):
    try:
        listing=subprocess.check_output(['ldd',str(binary)],text=True,stderr=subprocess.DEVNULL)
    except (OSError,subprocess.CalledProcessError) as exc:
        raise ProtocolError('observer runtime dependency inspection failed') from exc
    if 'not found' in listing: raise ProtocolError('observer runtime library missing')
    return {str(Path(p).resolve()) for p in re.findall(r'(?:=>\s+)?(/[^\s]+)\s+\(',listing)}


def pin_backend(installation):
    installation=Path(installation).resolve()
    archive=installation.parent/f'mp-spdz-{VERSION}.tar.xz'
    if not archive.is_file() or sha(archive)!=ARCHIVE_SHA256:
        raise ProtocolError('backend official archive missing or digest differs')
    binary=installation/'rep4-ring-party.x'
    if not binary.is_file(): raise ProtocolError('Rep4 binary missing')
    binary_hash=sha(binary); sources={}; binary_matches=[]
    observer=None
    direct=None
    if (installation/'direct-build.json').exists():
        if any(os.environ.get(name) for name in ('LD_PRELOAD','LD_LIBRARY_PATH','LD_AUDIT')):
            raise ProtocolError('native import loader environment override forbidden')
        manifest=installation/'direct-build.json'
        if sha(manifest)!=DIRECT_BUILD_SHA256:
            raise ProtocolError('unapproved native import build; explicit repinning required')
        direct=json.loads(manifest.read_text())
        if (direct['patch_id']!=DIRECT_PATCH_ID or direct['observer_patch_id']!=PATCH_ID
                or direct['archive_sha256']!=ARCHIVE_SHA256 or direct['binary_sha256']!=binary_hash
                or sha(installation/'libSPDZ.so')!=direct['shared_library_sha256']
                or sha(installation/'CONFIG.mine')!=direct['config_sha256']):
            raise ProtocolError('native import build artifact differs')
        for path,expected in direct['runtime_libraries'].items():
            if sha(path)!=expected: raise ProtocolError('native import runtime library differs')
        if resolved_libraries(binary)!=direct['runtime_libraries'].keys():
            raise ProtocolError('native import loader resolves different libraries')
        if (installation/'telemetry-build.json').exists():
            raise ProtocolError('conflicting native build manifests')
    if (installation/'telemetry-build.json').exists():
        if any(os.environ.get(name) for name in ('LD_PRELOAD','LD_LIBRARY_PATH','LD_AUDIT')):
            raise ProtocolError('observer loader environment override forbidden')
        manifest=installation/'telemetry-build.json'
        if sha(manifest)!=APPROVED_BUILD_SHA256:
            raise ProtocolError('unapproved observer build; explicit repinning required')
        observer=json.loads(manifest.read_text())
        if (observer['patch_id']!=PATCH_ID or observer['binary_sha256']!=binary_hash
                or sha(installation/'libSPDZ.so')!=observer['shared_library_sha256']
                or sha(installation/'CONFIG.mine')!=observer['config_sha256']):
            raise ProtocolError('observer build artifact differs')
        for path,expected in observer['runtime_libraries'].items():
            if sha(path)!=expected: raise ProtocolError('observer runtime library differs')
        if resolved_libraries(binary)!=observer['runtime_libraries'].keys():
            raise ProtocolError('observer loader resolves different libraries')
    prefix=f'mp-spdz-{VERSION}/'
    with tarfile.open(archive,'r|xz') as distribution:
        for member in distribution:
            if not member.isfile() or not member.name.startswith(prefix): continue
            relative=member.name[len(prefix):]
            source=is_source(relative)
            native=relative.startswith('bin/') and relative.endswith('/rep4-ring-party.x')
            if not source and not native: continue
            with distribution.extractfile(member) as stream:
                if (observer or direct) and relative=='Processor/BaseMachine.cpp':
                    expected=hashlib.sha256(patched_source(stream.read().decode()).encode()).hexdigest()
                elif direct and relative in ('GC/Rep4Secret.h','GC/Rep4Secret.cpp'):
                    expected=hashlib.sha256(direct_patched_source(relative,stream.read().decode()).encode()).hexdigest()
                else: expected=hashlib.file_digest(stream,'sha256').hexdigest()
            if source:
                local=installation/relative
                if not local.is_file() or sha(local)!=expected:
                    raise ProtocolError('backend source differs from official archive')
                sources[relative]=expected
            elif expected==binary_hash:
                binary_matches.append(relative)
    if (not binary_matches and not observer and not direct) or not {'Protocols/Rep4.hpp','Protocols/Rep4MC.hpp','compile.py'}<=sources.keys():
        raise ProtocolError('backend not the verified official Rep4 build')
    # An injected source imported/compiled alongside official files is not pinned.
    actual={str(p.relative_to(installation)) for folder in SOURCE_DIRS
            for p in (installation/folder).rglob('*') if p.is_file() and is_source(str(p.relative_to(installation)))}
    actual.update(name for name in ('compile.py','Makefile','CONFIG') if (installation/name).is_file())
    if actual!=sources.keys(): raise ProtocolError('unrecorded backend source files')
    result={'protocol':'seed-mpc-backend-pin-v1','version':VERSION,'archive_sha256':ARCHIVE_SHA256,
            'sources':sources,'source_manifest_hash':digest(sources),'applied_patches':([PATCH_ID,DIRECT_PATCH_ID] if direct else [PATCH_ID] if observer else []),
            'binary_sha256':binary_hash,'official_binary_members':sorted(binary_matches),
            'build_provenance':'official release prebuilt; upstream exact build command not asserted',
            'compile_flags':['-R','64','-Z','4','-M'],'native_security':'malicious; no caller-supplied flags'}
    if observer:
        result.update(build_provenance='explicitly approved local observer build; source patch rederived from official archive; not upstream prebuilt',
                      observer_build=observer,observer_build_sha256=APPROVED_BUILD_SHA256)
    if direct:
        result.update(build_provenance='pinned local active Rep4 holder-checked share importer; source patches rederived from official archive',
                      direct_build=direct,direct_build_sha256=DIRECT_BUILD_SHA256)
    return result


def validate_pin(installation,pin):
    # Re-derive from the trusted archive, not a caller-supplied self-consistent map.
    expected=pin_backend(installation)
    if not isinstance(pin,dict) or digest(pin)!=digest(expected):
        raise ProtocolError('backend pin differs from official artifacts')


def native_command(binary,port,slot,program):
    if (Path(binary).name!='rep4-ring-party.x' or type(port) is not int or not 1024<=port<=65531
            or type(slot) is not int or slot not in range(4)
            or type(program) is not str or re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*',program) is None):
        raise ProtocolError('invalid pinned native command')
    # No --semi-honest, --insecure, or arbitrary protocol/security overrides.
    return [str(binary),'-pn',str(port),'-h','127.0.0.1','-R','64',
            '-p',str(slot),program,'-OF','.','-v']
