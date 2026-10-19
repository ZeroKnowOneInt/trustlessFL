"""Pinned MP-SPDZ setup/doctor for Linux/WSL; no experiment or Hub dependency."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
import uuid

from .crypto import ProtocolError, canonical, digest
from .seed_mpc_backend import VERSION, ARCHIVE_SHA256, sha, resolved_libraries, pin_backend
from .seed_mpc_telemetry_patch import PATCH_ID as OBSERVER_ID, patched_source as observer_patch
from .seed_mpc_direct_patch import PATCH_ID as DIRECT_ID, patched_source as direct_patch
from .seed_mpc_build_trust import BUILD_PROTOCOL, approve

URL=f"https://github.com/data61/MP-SPDZ/releases/download/v{VERSION}/mp-spdz-{VERSION}.tar.xz"
CPU_FLAGS={"sse4_2","aes","pclmulqdq","avx2","bmi2","adx"}
ARCH="-msse4.2 -maes -mpclmul -mavx2 -mbmi2 -madx"
CONFIG=f"CXX = /usr/bin/g++\nOPTIM = -O2\nGDEBUG =\nARCH = {ARCH}\nMY_CFLAGS = -Wno-error=deprecated-declarations\n"
SYSTEM_PACKAGES=["build-essential","python3","openssl","time","libgmp-dev","libssl-dev",
                 "libboost-dev","libboost-filesystem-dev","libboost-iostreams-dev","libsodium-dev"]
PATCHES={"Processor/BaseMachine.cpp":observer_patch,
         "GC/Rep4Secret.h":lambda s:direct_patch("GC/Rep4Secret.h",s),
         "GC/Rep4Secret.cpp":lambda s:direct_patch("GC/Rep4Secret.cpp",s)}


def recipe():
    return {"protocol":BUILD_PROTOCOL,"version":VERSION,"archive_sha256":ARCHIVE_SHA256,
        "patches":[OBSERVER_ID,DIRECT_ID],"config":CONFIG,"command":["/usr/bin/make","-j1","rep4-ring-party.x"],
        "patch_implementation_sha256":{name:sha(Path(__file__).with_name(name)) for name in
            ("seed_mpc_telemetry_patch.py","seed_mpc_direct_patch.py")},
        "platform":"Linux-x86_64","cpu_flags":sorted(CPU_FLAGS)}


def clean_environment():
    return {"PATH":"/usr/bin:/bin","HOME":str(Path.home()),"LANG":"C.UTF-8","LC_ALL":"C.UTF-8"}


def cpu_flags():
    try:
        lines=[set(line.split(":",1)[1].split()) for line in Path("/proc/cpuinfo").read_text().splitlines()
               if line.startswith("flags") and ":" in line]
        return set.intersection(*lines) if lines else set()
    except OSError:
        return set()


def doctor(mode="direct"):
    if mode not in ("direct","stock"):raise ProtocolError("unsupported backend setup mode")
    tools=["/usr/bin/openssl","/usr/bin/time"]+(["/usr/bin/make","/usr/bin/g++"] if mode=="direct" else [])
    missing=[p for p in tools if not Path(p).is_file()]
    errors=[]
    if sys.platform!="linux" or platform.machine()!="x86_64":errors.append("requires Linux/WSL x86_64")
    if sys.version_info<(3,12):errors.append("requires Python 3.12+")
    if mode=="direct" and not CPU_FLAGS<=cpu_flags():errors.append("missing CPU flags: "+",".join(sorted(CPU_FLAGS-cpu_flags())))
    errors.extend("missing executable: "+p for p in missing)
    if mode=="direct" and not missing:
        probe=subprocess.run(["/usr/bin/g++","-std=c++20","-fsyntax-only","-x","c++","-"],
            input="#include <gmpxx.h>\n#include <openssl/ssl.h>\n#include <boost/asio.hpp>\n#include <sodium.h>\nint main(){return 0;}\n",
            text=True,capture_output=True,env=clean_environment(),timeout=30)
        if probe.returncode:errors.append("native development headers/toolchain unavailable")
    return {"platform":platform.platform(),"python":platform.python_version(),"mode":mode,
            "ready":not errors,"errors":errors,"system_packages":SYSTEM_PACKAGES,
            "install_command":"sudo apt-get update && sudo apt-get install -y "+" ".join(SYSTEM_PACKAGES),
            "trust":"trusted local operator/installer/toolchain; fixed source and patches"}


def install_dependencies():
    prefix=[] if os.geteuid()==0 else ["sudo","-n"]
    if shutil.which("apt-get") is None:raise ProtocolError("automatic system dependencies require apt-get")
    for command in (["/usr/bin/apt-get","update"],["/usr/bin/apt-get","install","-y",*SYSTEM_PACKAGES]):
        subprocess.run([*prefix,*command],check=True,env={**clean_environment(),"DEBIAN_FRONTEND":"noninteractive"})


def obtain_archive(directory, offline=None):
    archive=directory/f"mp-spdz-{VERSION}.tar.xz"
    if archive.exists():
        if sha(archive)!=ARCHIVE_SHA256:raise ProtocolError("cached MP-SPDZ archive digest differs")
        return archive
    temporary=directory/(archive.name+".partial-"+uuid.uuid4().hex)
    try:
        if offline is not None:
            source=Path(offline).resolve()
            if sha(source)!=ARCHIVE_SHA256:raise ProtocolError("offline MP-SPDZ archive digest differs")
            shutil.copyfile(source,temporary)
        else:
            request=urllib.request.Request(URL,headers={"User-Agent":"TrustlessFL-backend-setup"})
            with urllib.request.urlopen(request,timeout=60) as response,temporary.open("xb") as stream:
                while block:=response.read(1024*1024):stream.write(block)
        if sha(temporary)!=ARCHIVE_SHA256:raise ProtocolError("downloaded MP-SPDZ archive digest differs")
        temporary.replace(archive)
        return archive
    finally:
        if temporary.exists():temporary.unlink()


def extract_verified(archive,target):
    # Verified upstream release only. Extract into a fresh sibling; do not overwrite.
    prefix=f"mp-spdz-{VERSION}/"
    with tarfile.open(archive,"r:xz") as distribution:
        for member in distribution:
            if member.isdir() and member.name.rstrip("/")==prefix.rstrip("/"):continue
            if not member.name.startswith(prefix):raise ProtocolError("unexpected archive root")
            relative=member.name[len(prefix):]
            if not relative:continue
            if Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise ProtocolError("unsafe MP-SPDZ archive member")
            member.name=relative
            distribution.extract(member,target,filter="data")


def setup(directory, *, mode="direct", offline_archive=None, install_system_deps=False):
    if mode not in ("direct","stock"):raise ProtocolError("unsupported backend setup mode")
    if any(os.environ.get(k) for k in ("LD_PRELOAD","LD_LIBRARY_PATH","LD_AUDIT")):
        raise ProtocolError("loader overrides forbidden during backend setup")
    directory=Path(directory).resolve()
    if re.fullmatch(r"/[A-Za-z0-9_./@+\-]+",str(directory)) is None:
        raise ProtocolError("backend setup path must have no whitespace or shell/Makefile metacharacters")
    if sys.platform!="linux" or platform.machine()!="x86_64":raise ProtocolError("run setup inside Linux/WSL x86_64")
    directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    target=directory/(f"mp-spdz-{VERSION}-checked-source-v1" if mode=="direct" else f"mp-spdz-{VERSION}-stock")
    with (directory/"setup.lock").open("a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if target.exists():
            pin=pin_backend(target)
            if (mode=="direct") != (DIRECT_ID in pin["applied_patches"]):
                raise ProtocolError("existing backend does not match requested setup mode")
            return setup_report(target,pin,reused=True)
        if install_system_deps:install_dependencies()
        health=doctor(mode)
        if not health["ready"]:raise ProtocolError("backend prerequisites missing: "+"; ".join(health["errors"])+". "+health["install_command"])
        archive=obtain_archive(directory,offline_archive)
        work=directory/(target.name+".building-"+uuid.uuid4().hex)
        work.mkdir(mode=0o700)
        started=time.monotonic()
        print(f"Extracting pinned MP-SPDZ {VERSION}: {work}",file=sys.stderr,flush=True)
        extract_verified(archive,work)
        if mode=="stock":
            profile="adx" if CPU_FLAGS<=cpu_flags() else "amd64"
            for file in (work/f"bin/Linux-{profile}").iterdir():
                if file.is_file():shutil.copy2(file,work/file.name)
            (work/"Player-Data").mkdir(exist_ok=True)
            # Native relative rpaths must refer to the final installation.
            work.rename(target)
            pin=pin_backend(target)
        else:
            for relative,apply in PATCHES.items():
                path=work/relative;path.write_text(apply(path.read_text()))
            (work/"CONFIG.mine").write_text(CONFIG)
            # Keep final path stable before linking. An interrupted/unapproved
            # target is never auto-rebuilt, executed or silently replaced.
            work.rename(target)
            log=directory/(target.name+".build.log")
            print(f"Building active checked Rep4 (-j1); log: {log}",file=sys.stderr,flush=True)
            with log.open("x") as output:
                subprocess.run(recipe()["command"],cwd=target,env=clean_environment(),
                               stdout=output,stderr=subprocess.STDOUT,check=True)
            record={"protocol":BUILD_PROTOCOL,"recipe":recipe(),"recipe_hash":digest(recipe()),
                "installation":str(target),"compiler_sha256":sha("/usr/bin/g++"),
                "compiler":subprocess.check_output(["/usr/bin/g++","--version"],text=True,env=clean_environment()).splitlines()[0],
                "config_sha256":sha(target/"CONFIG.mine"),"binary_sha256":sha(target/"rep4-ring-party.x"),
                "shared_library_sha256":sha(target/"libSPDZ.so"),
                "runtime_libraries":{path:sha(path) for path in sorted(resolved_libraries(target/"rep4-ring-party.x"))}}
            manifest=target/"source-build.json"
            manifest.write_bytes(canonical(record))
            # Inspect complete approved source/config/artifacts before approval.
            from .seed_mpc_backend import validate_source_build
            validate_source_build(target,record,require_approval=False)
            approve(target,sha(manifest),record["recipe_hash"])
            pin=pin_backend(target)
        return setup_report(target,pin,reused=False,seconds=round(time.monotonic()-started,3))


def setup_report(target,pin,*,reused,seconds=0):
    return {"installation":str(target),"version":VERSION,"reused":reused,"setup_seconds":seconds,
        "backend_pin_hash":digest(pin),"applied_patches":pin["applied_patches"],
        "component_input":"holder-checked-direct-v1" if DIRECT_ID in pin["applied_patches"] else "stock-private-v1",
        "communication_meter":OBSERVER_ID in pin["applied_patches"],"ready":True}


def _main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest="command",required=True)
    check=sub.add_parser("doctor");check.add_argument("--mode",choices=("direct","stock"),default="direct")
    prepare=sub.add_parser("setup");prepare.add_argument("--directory",type=Path,default=Path.home()/".cache/trustlessfl/mp-spdz")
    prepare.add_argument("--mode",choices=("direct","stock"),default="direct")
    prepare.add_argument("--archive",type=Path,dest="offline_archive")
    prepare.add_argument("--install-system-deps",action="store_true")
    verify=sub.add_parser("verify");verify.add_argument("--installation",type=Path,required=True)
    test=sub.add_parser("smoke");test.add_argument("--installation",type=Path,required=True)
    test.add_argument("--output",type=Path,required=True);test.add_argument("--fault",action="store_true",help="synthetic holder mismatch; no production inputs")
    args=parser.parse_args()
    if args.command=="smoke":
        from .seed_mpc_smoke import smoke
        print(json.dumps(smoke(args.installation,args.output,fault=args.fault),ensure_ascii=False));return 0
    if args.command=="doctor":
        report=doctor(args.mode);print(json.dumps(report,ensure_ascii=False));return 0 if report["ready"] else 1
    if args.command=="verify":
        pin=pin_backend(args.installation)
        report=setup_report(args.installation.resolve(),pin,reused=True)
    else:report=setup(args.directory,mode=args.mode,offline_archive=args.offline_archive,install_system_deps=args.install_system_deps)
    print(json.dumps(report,ensure_ascii=False));return 0


def main():
    try:return _main()
    except (ProtocolError,OSError,ValueError,subprocess.SubprocessError) as exc:
        print(json.dumps({"ready":False,"error":str(exc)},ensure_ascii=False),file=sys.stderr)
        return 2


if __name__=="__main__":sys.exit(main())
