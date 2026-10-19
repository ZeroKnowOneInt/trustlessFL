"""Frozen integer contract for seed-MPC; no HPRF or mask spacing."""
from dataclasses import asdict, dataclass

from .crypto import ProtocolError, digest

BACKEND_PRIMES = (2**127 - 1, 2**255 - 19)


@dataclass(frozen=True)
class SeedMPCPolicy:
    dimension: int
    max_clients: int
    coordinate_cap: int
    squared_threshold: int
    scale: int = 10000
    minimum_accepted: int = 2
    word_bits: int = 16
    statistical_security: int = 40

    def __post_init__(self):
        if any(type(v) is not int for v in asdict(self).values()):
            raise ProtocolError("policy fields must be integers")
        if self.word_bits not in (16, 32):
            raise ProtocolError("unsupported wire word width")
        if (self.dimension < 1 or self.max_clients < 1 or self.scale < 1
                or not 1 <= self.minimum_accepted <= self.max_clients
                or not 0 < self.coordinate_cap < self.modulus // 2
                or self.squared_threshold < 0 or self.statistical_security < 40):
            raise ProtocolError("invalid seed-MPC policy")

    @property
    def modulus(self):
        return 1 << self.word_bits

    @property
    def norm_capacity(self):
        return self.dimension * self.coordinate_cap**2

    @property
    def sum_capacity(self):
        return self.max_clients * self.coordinate_cap

    @property
    def policy_hash(self):
        return digest({"protocol": "seed-mpc-v1", **asdict(self)})

    def widths(self):
        return {"wire": self.word_bits + 2,
                "norm": max(self.norm_capacity, self.squared_threshold).bit_length() + 2,
                "sum": self.sum_capacity.bit_length() + 2,
                "count": self.max_clients.bit_length() + 2}

    def backend_prime(self):
        required = max(self.widths().values()) + self.statistical_security + 2
        for prime in BACKEND_PRIMES:
            if required <= prime.bit_length():
                return prime
        raise ProtocolError("integer widths exceed supported backend field")

    def validate_backend(self, prime, application_bits):
        if (type(prime) is not int or prime not in BACKEND_PRIMES
                or type(application_bits) is not int
                or application_bits < max(self.widths().values())
                or application_bits + self.statistical_security + 2 > prime.bit_length()):
            raise ProtocolError("backend field/comparison width does not fit policy")

    def validate_ring(self, ring_bits):
        """Application capacity, including values before client selection.

        Does not by itself prove a backend's comparison or external I/O security.
        """
        if type(ring_bits) is not int or ring_bits not in (64, 128):
            raise ProtocolError("unsupported candidate ring width")
        if max(self.widths().values()) > ring_bits - 1:
            raise ProtocolError("ring/comparison width does not fit policy")
        half = 1 << (ring_bits - 1)
        if max(self.norm_capacity, self.squared_threshold, self.sum_capacity,
               self.max_clients, self.modulus) >= half:
            raise ProtocolError("ring signed capacity insufficient")

    def validate_update(self, update):
        if len(update) != self.dimension or any(
                type(v) is not int or abs(v) > self.coordinate_cap for v in update):
            raise ProtocolError("update outside canonical coordinate range")

    def validate_wire(self, values, *, offset=0, full=True):
        if type(offset) is not int or offset < 0:
            raise ProtocolError("invalid coordinate offset")
        if (not values or offset + len(values) > self.dimension
                or (full and (offset != 0 or len(values) != self.dimension))
                or any(type(v) is not int or not 0 <= v < self.modulus for v in values)):
            raise ProtocolError("noncanonical wire shape/value")
