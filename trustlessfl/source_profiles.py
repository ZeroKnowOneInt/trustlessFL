"""Opt-in research profiles for the Flower source adapter, not author code.

Absent profiles retain all legacy defaults. Full-q sampling is NOT a privacy
repair. Centered recovery requires honest bounded inputs and does not prove
share/mask consistency. See design-independent-review-2026-10-09.md.
"""

from dataclasses import dataclass
from fractions import Fraction
import random
import secrets

import numpy as np

from .crypto import ORDER, ProtocolError, digest
from .modular_recovery import center_p, hprf_error_bound
from .paper_dmc import PaperDMC, rational, round_even

LEGACY = "legacy-quantized-lift"
CENTERED = "transmission-centered-v1"
DEFAULTS = dict(recovery=LEGACY, key_domain="author-small",
                period_policy="adaptive-rational", history="actual-mask-sum")


class SourceProfileError(ProtocolError):
    """Closed public parameter failures; never transmit private inputs."""

    CODES = frozenset({"period-noninteger", "spacing-infeasible", "capacity-infeasible",
                       "history-unsupported"})

    def __init__(self, code, message):
        if code not in self.CODES:
            raise ValueError("unknown source profile failure category")
        self.code = code
        super().__init__(message)


def profile(manifest):
    if "source_profile" not in manifest:
        return dict(DEFAULTS)
    value = manifest["source_profile"]
    if not isinstance(value, dict) or not set(DEFAULTS) <= set(value):
        raise ProtocolError("incomplete source profile")
    choices = dict(recovery=(LEGACY, CENTERED), key_domain=("author-small", "author-full-q"),
                   period_policy=("adaptive-rational", "fixed-integer"),
                   history=("actual-mask-sum", "paper-hprf"))
    if any(value[k] not in choices[k] for k in choices):
        raise ProtocolError("unsupported source profile choice")
    if value.get("mgf_scope", "projection") not in ("projection", "full-vector"):
        raise ProtocolError("unsupported source MGF scope")
    if value["history"] == "paper-hprf":
        raise SourceProfileError("history-unsupported", "paper-hprf history is explicitly unsupported; not actual-mask-sum")
    if value.get("aggregation", "unweighted") != "unweighted":
        raise ProtocolError("source profile supports unweighted aggregation only")
    if value["recovery"] == LEGACY:
        if set(value) - (set(DEFAULTS) | {"aggregation", "mgf_scope"}) or value["period_policy"] != "adaptive-rational":
            raise ProtocolError("legacy profile requires unchanged adaptive-rational parameters")
    else:
        required = set(DEFAULTS) | {"S", "d", "nmax", "C", "aggregation", "rounding"}
        if value["period_policy"] == "fixed-integer":
            required.add("M")
        if set(value) != required | ({"mgf_scope"} if "mgf_scope" in value else set()) or value["rounding"] != "nearest-even":
            raise ProtocolError("invalid transmission profile schema or rounding")
        for name in ("S", "d", "nmax"):
            if type(value[name]) is not int or value[name] <= 0:
                raise ProtocolError("transmission S, d and nmax must be positive integers")
        if rational(value["C"]) <= 0:
            raise ProtocolError("transmission coordinate bound must be positive")
        if value["period_policy"] == "fixed-integer" and (
                type(value["M"]) is not int or value["M"] < 2):
            raise ProtocolError("transmission M must be an integer >= 2")
    return dict(value)


def profile_tag(manifest):
    """Bind the entire immutable task, including setup, history and projection."""
    return digest(manifest) if "source_profile" in manifest else None


def pin_profile(manifest, state):
    tag = profile_tag(manifest)
    if "source-profile-digest" in state:
        if state["source-profile-digest"] != tag:
            raise ProtocolError("source profile/task changed after initialization")
    elif tag is not None:
        if "mask_seed" in state or state.get("replies") or state.get("last_round"):
            raise ProtocolError("cannot enable source profile on an existing legacy state")
        state["source-profile-digest"] = tag


def key_bounds(manifest, hprf=None):
    options = profile(manifest)
    if "source_profile" not in manifest:
        return 1, 100000
    policy = manifest.get("key_profile", {})
    if options["key_domain"] == "author-small":
        low, high = 1, 100000
    else:
        q = policy.get("modulus")
        if type(q) is not int or q <= 1 or (hprf is not None and q != hprf.q):
            raise ProtocolError("full-q key profile differs from HPRF modulus")
        low, high = 0, q - 1
    if (policy.get("kind") != "author-scalar" or policy.get("production_privacy") is not False
            or type(policy.get("minimum")) is not int or type(policy.get("maximum")) is not int
            or policy["minimum"] != low or policy["maximum"] != high):
        raise ProtocolError("source key profile bounds disagree with key_domain")
    if len(manifest["clients"]) * high >= ORDER:
        raise ProtocolError("source key sum exceeds VSS integer capacity")
    return low, high


def key_sum_valid(manifest, key, count):
    low, high = key_bounds(manifest)
    return type(key) is int and type(count) is int and count > 0 and low * count <= key <= high * count


def sample_key(manifest, hprf):
    low, high = key_bounds(manifest, hprf)
    if profile(manifest)["key_domain"] == "author-full-q":
        return secrets.randbelow(high + 1)
    return random.SystemRandom().randint(low, high)


def scale_mask(h, p, period):
    # Odd p: 2*M*h=(2*a+1)*p is impossible. No .5 ties, including h=p.
    return (2 * period * h + p) // (2 * p)


def transmission_error(n, p, q, period):
    raw = hprf_error_bound(n, p=p, q=q)
    return 0 if n == 1 else ((n + 1) * (p - 1) + 2 * period * raw) // (2 * p)


@dataclass(frozen=True)
class TransmissionCodec:
    modulus: int
    q: int
    scale: int
    spacing: int
    transmission_period: int
    max_clients: int
    real_bound: Fraction
    clients: int
    binding: str | None = None

    def __post_init__(self):
        values = (self.modulus, self.q, self.scale, self.spacing, self.transmission_period,
                  self.max_clients, self.clients)
        if any(type(x) is not int for x in values) or min(values) < 1:
            raise ProtocolError("transmission parameters must be positive integers")
        if self.modulus < 3 or self.modulus % 2 != 1 or self.q <= self.modulus or self.transmission_period < 2:
            raise ProtocolError("invalid transmission modulus or odd HPRF modulus")
        object.__setattr__(self, "real_bound", rational(self.real_bound))
        if self.real_bound <= 0:
            raise ProtocolError("transmission coordinate bound must be positive")
        if self.spacing <= 2 * self.error:
            raise SourceProfileError("spacing-infeasible", "transmission spacing infeasible: d <= 2*E_bar")
        if 2 * (self.spacing * self.max_clients * self.max_integer + self.error) >= self.transmission_period:
            raise SourceProfileError("capacity-infeasible", "transmission centered capacity infeasible")

    @property
    def error(self):
        return transmission_error(self.max_clients, self.modulus, self.q, self.transmission_period)

    @property
    def max_integer(self):
        return round_even(self.scale * self.real_bound)

    @property
    def padding(self):
        return self.spacing

    @property
    def denominator(self):
        return self.spacing * self.scale

    @property
    def coefficient(self):
        return Fraction(self.transmission_period, self.modulus)

    @property
    def period(self):
        """Physical/model-unit period, as in PaperDMC; NOT the integer modulus."""
        return Fraction(self.transmission_period, self.denominator)

    def encode(self, values):
        array = np.asarray(values)
        if array.ndim != 1 or array.dtype.kind not in "fiu" or not np.isfinite(array).all():
            raise ProtocolError("expected finite one-dimensional update")
        values = [rational(str(float(x))) for x in array]
        if any(abs(x) > self.real_bound for x in values):
            raise ProtocolError("local value exceeds transmission coordinate bound")
        return [round_even(self.scale * x) for x in values]

    def _check_masks(self, values, masks):
        if len(values) != len(masks) or any(type(h) is not int or not 0 <= h <= self.modulus for h in masks):
            raise ProtocolError("invalid transmission mask shape or representative")

    def residual(self, values, masks):
        # Adapter used only by the existing MGF norm/history helper.
        self._check_masks(values, masks)
        return [rational(y) - self.coefficient * h / self.denominator for y, h in zip(values, masks, strict=True)]

    def mask(self, encoded, masks):
        self._check_masks(encoded, masks)
        if any(type(u) is not int or abs(u) > self.max_integer for u in encoded):
            raise ProtocolError("encoded update exceeds transmission coordinate bound")
        return [self.spacing * u + scale_mask(h, self.modulus, self.transmission_period)
                for u, h in zip(encoded, masks, strict=True)]

    def recover(self, total, masks, count):
        self._check_masks(total, masks)
        if type(count) is not int or not 1 <= count <= self.max_clients or any(type(y) is not int for y in total):
            raise ProtocolError("invalid transmission aggregate count or integer wire")
        result = []
        for y, h in zip(total, masks, strict=True):
            r_mod = (y - scale_mask(h, self.modulus, self.transmission_period)) % self.transmission_period
            r = center_p(r_mod, self.transmission_period)
            u = round_even(Fraction(r, self.spacing))
            if abs(r - self.spacing * u) > self.error or abs(u) > count * self.max_integer:
                raise ProtocolError("transmission residual or decoded sum exceeds declared bounds")
            result.append(u)
        return result


@dataclass(frozen=True)
class ProfiledLegacyCodec(PaperDMC):
    binding: str | None = None


def centered_codec(manifest, hprf, clients, linf=None):
    opts = profile(manifest)
    if opts["recovery"] != CENTERED:
        raise ProtocolError("centered codec requires explicit centered recovery")
    if not 2 <= opts["nmax"] <= len(manifest["clients"]):
        raise ProtocolError("invalid transmission selected-count envelope")
    if rational(opts["C"]) != rational(manifest["max_abs"]):
        raise ProtocolError("transmission C differs from manifest max_abs")
    paper = manifest["paper_numerics"]
    if paper.get("scale_source") != "quantized-sum":
        raise ProtocolError("centered profile requires explicit quantized-sum history units")
    if opts["period_policy"] == "fixed-integer":
        period = opts["M"]
    else:
        magnitude = rational(paper["initial_linf"] if linf is None else linf)
        period = rational(paper["beta"]) * opts["d"] * opts["S"] * magnitude
        if period.denominator != 1:
            raise SourceProfileError("period-noninteger", "adaptive transmission period is non-integer; infeasible")
        period = int(period)
    return TransmissionCodec(hprf.p, hprf.q, opts["S"], opts["d"], period,
        opts["nmax"], rational(opts["C"]), clients, profile_tag(manifest))


def validate_profile(manifest, hprf, *, transport=True):
    opts = profile(manifest)
    if "source_profile" not in manifest:
        return
    if (manifest.get("research-only") is not True or manifest.get("workload") not in ("synthetic", "fmnist")
            or "paper_numerics" not in manifest):
        raise ProtocolError("explicit source profiles require research paper-MGF learning path")
    paper = manifest["paper_numerics"]
    projection = paper.get("projection", [])
    if (not isinstance(projection, list) or len(projection) != 2
            or any(type(v) is not int for v in projection)
            or not 0 <= projection[0] < projection[1] <= manifest["dimension"]
            or rational(paper["beta"]) != rational("0.2")
            or rational(paper["initial_linf"]) <= 0
            or paper.get("wire_encoding", "decimal") != "decimal"):
        raise ProtocolError("invalid source profile MGF context")
    key_bounds(manifest, hprf)
    if opts["recovery"] == CENTERED:
        centered_codec(manifest, hprf, len(manifest["clients"]))
    if transport:
        from .aion_source_aggregate import enabled
        if not enabled(manifest):
            raise ProtocolError("source profiles require encrypted shares and committee aggregate replay")


def update_codec(manifest, hprf):
    if profile(manifest)["recovery"] == CENTERED:
        return centered_codec(manifest, hprf, len(manifest["clients"]))
    from .numeric import FixedPoint
    return FixedPoint(manifest["decimals"], manifest["max_abs"], len(manifest["clients"]),
                      mask_backend="aion-original", original_hprf_setup=hprf.public_setup())
