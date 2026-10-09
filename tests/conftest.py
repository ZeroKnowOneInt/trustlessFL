"""Test-only source BFT certificates with ephemeral committee signing keys."""

import pytest


@pytest.fixture
def make_source_commit():
    def factory(manifest, states):
        from dataclasses import asdict
        from types import SimpleNamespace
        from Cryptodome.PublicKey import ECC
        from trustlessfl.aion_source_bft import _module
        module = _module(manifest["source-root"])
        keys = {actor: ECC.generate(curve="P-256") for actor in manifest["committee"]}
        registry = {str(actor): key.public_key().export_key(format="PEM")
                    for actor, key in keys.items()}
        for actor, key in keys.items():
            states[actor]["source-bft"] = dict(registry=registry,
                private=key.export_key(format="PEM"))

        def proof(sequence, value):
            commits = []
            for actor, key in keys.items():
                message = module.BFTMessage(type="commit", value=value,
                    phase=module.BFTPhase.COMMIT, node_id=actor, sequence=sequence)
                message.signature = module.BFTProtocol._sign_message(SimpleNamespace(private_key=key), message)
                commits.append({**asdict(message), "phase": message.phase.value})
            return dict(registry=registry, sequence=sequence, value=value, commits=commits)
        return proof
    return factory
