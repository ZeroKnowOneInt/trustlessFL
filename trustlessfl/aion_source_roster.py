"""Post-filter BFT membership binding for new source-ASR runs.

Historical manifests without this profile retain their pre-filter online-set
certificate semantics. This changes protocol ordering, not HPRF arithmetic,
and does not add mask shares or a general BFT liveness guarantee.
"""

from .aion_source_cohort import round_clients
from .crypto import ProtocolError, digest
from .source_profiles import profile_tag

MODE = "post-filter-bft-v1"


def enabled(manifest):
    if "selection_consensus" not in manifest:
        return False
    profile = manifest["selection_consensus"]
    if not isinstance(profile, dict) or profile.get("kind") != MODE:
        raise ProtocolError("unsupported source selection consensus profile")
    return True


def statement(manifest, round_id, members, *, vectors_digest=None):
    """The paper's C_on after replacement with the filter's C_valid."""
    cohort = round_clients(manifest, round_id)
    if (not isinstance(members, list) or not members
            or any(type(i) is not int or i not in cohort for i in members)
            or len(set(members)) != len(members)):
        raise ProtocolError("invalid source filtered BFT members")
    body = dict(msg="ONLINE_CLIENTS", task=manifest["task"], iteration=round_id,
                online_clients=[int(i in members) for i in manifest["clients"]])
    if "source_profile" in manifest:
        if not isinstance(vectors_digest, str) or len(vectors_digest) != 64:
            raise ProtocolError("source profile BFT requires selected vector digest")
        body.update(profile_digest=profile_tag(manifest), vectors_digest=vectors_digest)
    return body


def check_proposal(manifest, state, request, sequence):
    """Paper-MGF voters only vote for their independently approved subset."""
    if not enabled(manifest) or sequence % 2:
        return
    round_id = request["round"]
    if sequence != 2 * round_id:
        raise ProtocolError("source filtered BFT sequence differs from round")
    members = request.get("selection_members")
    approved = state.get("source-selection", {})
    vector_tag = approved.get("response", {}).get("vectors_digest")
    value = digest(statement(manifest, round_id, members, vectors_digest=vector_tag))
    if request["value"] != value:
        raise ProtocolError("source filtered BFT proposal differs from members")
    from .aion_source_selection import enabled as replay_enabled
    if replay_enabled(manifest):
        if approved.get("round") != round_id or set(approved.get("members", [])) != set(members):
            raise ProtocolError("source filtered BFT requires masked MGF authorization")


def require_commit(manifest, state, request, members):
    """Never release a new-run key sum on an uncommitted or different subset."""
    if not enabled(manifest):
        return
    proof = request.get("selection_commit")
    registry = state.get("source-bft", {}).get("registry")
    if not isinstance(proof, dict) or not isinstance(registry, dict):
        raise ProtocolError("source key release requires filtered BFT commit")
    from .aion_source_bft import check_source_commit
    vector_tag = state.get("source-selection", {}).get("response", {}).get("vectors_digest")
    check_source_commit(manifest, proof, registry, 2 * request["round"],
                        digest(statement(manifest, request["round"], members, vectors_digest=vector_tag)))
