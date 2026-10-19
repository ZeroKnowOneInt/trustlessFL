"""Operator-local approval for installer-built native artifacts.

The installation/deployment cannot supply this trust record. Trust is the local
OS user/administrator and the packaged installer, compiler and system libraries.
This does not authenticate an independent operator or prove protocol security.
"""
import json
import os
import pwd
from pathlib import Path
import stat

from .crypto import ProtocolError, canonical, digest

BUILD_PROTOCOL = "seed-mpc-local-source-build-v1"
APPROVAL_PROTOCOL = "seed-mpc-operator-approval-v1"


def trust_root():
    # HOME/XDG from a caller cannot redirect the operator trust anchor.
    return Path(pwd.getpwuid(os.getuid()).pw_dir)/".local/state/trustlessfl/native-approvals"


def approval_path(installation):
    return trust_root()/(digest(str(Path(installation).resolve()))+".json")


def _owned_private(path, *, directory=False):
    value = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(value.st_mode) or value.st_uid != os.getuid() or value.st_mode & 0o077:
        raise ProtocolError("native approval must be an owner-only regular file/directory")


def approve(installation, manifest_hash, recipe_hash):
    root=trust_root()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    _owned_private(root, directory=True)
    path=approval_path(installation)
    body={"protocol":APPROVAL_PROTOCOL,"installation":str(Path(installation).resolve()),
          "manifest_sha256":manifest_hash,"recipe_hash":recipe_hash}
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"wb") as stream:
        stream.write(canonical(body)); stream.flush(); os.fsync(stream.fileno())
    return path


def verify_approval(installation, manifest_hash, recipe_hash):
    root=trust_root();path=approval_path(installation)
    try:
        _owned_private(root,directory=True);_owned_private(path)
        actual=json.loads(path.read_text())
    except (OSError,ValueError) as exc:
        raise ProtocolError("installer build lacks this operator's trusted approval") from exc
    expected={"protocol":APPROVAL_PROTOCOL,"installation":str(Path(installation).resolve()),
              "manifest_sha256":manifest_hash,"recipe_hash":recipe_hash}
    if actual != expected:
        raise ProtocolError("source-build manifest differs from operator approval")
