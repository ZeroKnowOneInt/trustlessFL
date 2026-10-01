"""Explicit individual-client schedules for the source-ASR learning port.

Uses the author experiment's inclusion rule with an isolated seeded RNG, not
the author's complete interleaved training/randomness transcript or CCS/VRF.
"""

import random

from .crypto import ProtocolError


def make_cohorts(clients, participants, rounds, *, malicious=0, attack_rounds=(), seed=0):
    if (any(type(v) is not int for v in (clients, participants, rounds, malicious, seed))
            or not 7 <= participants <= clients or rounds < 1 or seed < 0
            or not 0 <= malicious <= participants or clients - malicious < participants
            or any(type(r) is not int or not 1 <= r <= rounds for r in attack_rounds)):
        raise ProtocolError("invalid source individual participation settings")
    rng = random.Random(seed)
    benign = range(malicious, clients)
    return {str(r): (list(range(malicious)) + rng.sample(benign, participants - malicious)
                    if r in attack_rounds else rng.sample(benign, participants))
            for r in range(1, rounds + 1)}


def round_clients(manifest, round_id):
    schedule = manifest.get("cohort_schedule")
    if schedule is None:
        return manifest["clients"]
    if set(schedule) != {str(r) for r in range(1, manifest["rounds"] + 1)}:
        raise ProtocolError("incomplete source participation schedule")
    members = schedule[str(round_id)]
    if (not isinstance(members, list) or len(members) < 7 or len(set(members)) != len(members)
            or any(type(i) is not int or i not in manifest["clients"] for i in members)):
        raise ProtocolError("invalid source round participants")
    return members
