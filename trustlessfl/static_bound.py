"""Frozen norm-threshold policy for the no-wrap learning profile."""
from .crypto import ProtocolError
from .private_bound import NoWrapPolicy


def static_learning_policy(config, *, dimension, clients):
    """Freeze T before training; never infer it from updates or public history."""
    if config.get("threshold-mode") != "static":
        raise ProtocolError("the active learning profile requires a static threshold")
    if any(key in config for key in ("boot-bound", "minimum-bound", "maximum-bound")):
        raise ProtocolError("dynamic boundary settings are not allowed in the static profile")
    return NoWrapPolicy(dimension, clients, config["coordinate-cap"], config["scale"],
                        1, 1, config["squared-threshold"], config.get("minimum-accepted", 2))
