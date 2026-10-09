"""Integer-only arithmetic for OFFLINE transmission-period experiments.

Not imported by the Flower protocol. The sufficient clipping/SUM premises are
experiment inputs, not inferred from MGF or verified for malicious clients.
"""

from dataclasses import dataclass
from fractions import Fraction

from trustlessfl.crypto import ProtocolError
from trustlessfl.modular_recovery import center_p, hprf_error_bound


def nearest_ratio(numerator, denominator):
    """Signed nearest integer, ties-even, with no floating arithmetic."""
    if type(numerator) is not int or type(denominator) is not int or denominator < 1:
        raise ValueError("integer numerator and positive denominator required")
    low, remainder = divmod(numerator, denominator)
    twice = 2*remainder
    return low + int(twice > denominator or (twice == denominator and low % 2 != 0))


def scale_mask(h, *, p, period):
    """Round(M*h/p) exactly. Odd p precludes .5 ties for ANY integer M,h.

    2*M*h=(2*j+1)*p would equate an even number and an odd number.
    Consequently this equals floor((2*M*h+p)/(2*p)); translation by M is
    exact even for odd M (ties-even translation would otherwise need care).
    Extended integer h is accepted to test scale(h+p)=scale(h)+M.
    """
    if (any(type(v) is not int for v in (h, p, period)) or p < 3 or p % 2 != 1
            or period < 1):
        raise ValueError("odd HPRF p and positive integer period required")
    return (2*period*h+p)//(2*p)


def transmission_error_bound(n, *, p, q, period):
    """Certified upper bound, not an experimentally estimated maximum.

    Odd p gives |delta| <= (p-1)/(2p), and E is an integer. Thus
      |E| <= floor(((n+1)*(p-1)+2*M*E_H)/(2*p)).
    This can exceed floor((n+1)/2) when M*E_H/p is not small. n=1 is 0.
    """
    if type(period) is not int or period < 1 or p % 2 != 1:
        raise ValueError("positive integer period and odd p required")
    eh = hprf_error_bound(n, p=p, q=q)
    return 0 if n == 1 else ((n+1)*(p-1)+2*period*eh)//(2*p)


def integer_update_bound(scale, real_bound):
    bound = Fraction(str(real_bound))
    if type(scale) is not int or scale < 1 or bound < 0:
        raise ValueError("invalid quantization bound")
    # Monotonic nearest ties-even: exact maximum for x in [-C_real,C_real].
    return nearest_ratio((bound*scale).numerator, (bound*scale).denominator)


def minimum_period(*, p, q, n, spacing, scale, real_bound):
    bound = integer_update_bound(scale, real_bound)
    # Recompute the M-dependent error; the least integer satisfying strict
    # M > 2*(d*n*C+E) is exactly that RHS plus ONE, not an arbitrary margin.
    period = max(2, 2*spacing*n*bound+1)
    for _ in range(100):
        error = transmission_error_bound(n, p=p, q=q, period=period)
        required = max(2, 2*(spacing*n*bound+error)+1)
        if required == period:
            return dict(period=period, error=error, integer_bound=bound,
                        feasible=spacing > 2*error and period < p)
        period = required
    raise ValueError("parameter fixed point did not converge")


@dataclass(frozen=True)
class TransmissionParameters:
    p: int
    q: int
    period: int
    spacing: int
    scale: int
    max_clients: int
    real_bound: str

    def __post_init__(self):
        if (any(type(v) is not int for v in (self.p, self.q, self.period,
                self.spacing, self.scale, self.max_clients)) or self.period < 2
                or min(self.spacing, self.scale, self.max_clients) < 1):
            raise ValueError("invalid transmission parameters")
        self.bound
        self.error

    @property
    def bound(self):
        return integer_update_bound(self.scale, self.real_bound)

    @property
    def error(self):
        return transmission_error_bound(self.max_clients, p=self.p, q=self.q, period=self.period)

    @property
    def feasible(self):
        return (self.period < self.p and self.spacing > 2*self.error
                and 2*(self.spacing*self.max_clients*self.bound+self.error) < self.period)

    def recover(self, total, aggregate_hprf, count):
        if not self.feasible or not 1 <= count <= self.max_clients:
            raise ProtocolError("infeasible transmission parameters")
        if len(total) != len(aggregate_hprf):
            raise ProtocolError("transmission shape mismatch")
        error, sum_bound = self.error, count*self.bound
        result = []
        for y, h in zip(total, aggregate_hprf, strict=True):
            residual = center_p(y-scale_mask(h, p=self.p, period=self.period), self.period)
            value = nearest_ratio(residual, self.spacing)
            if abs(residual-self.spacing*value) > error:
                raise ProtocolError("transmission residual exceeds bound")
            if abs(value) > sum_bound:
                raise ProtocolError("transmission sum exceeds bound")
            result.append(value)
        return result


def worst_case_fixture(*, p, period):
    """20-input rounded-q-domain extremum, NOT keys in author scalar domain.

    Set t_i=5*h-2, so HPRF(t_i)=h and e=8 at n=20 (q=5p).
    All scale residuals are ~+0.475; aggregate residual ~-0.5; E=10.
    """
    h = 21*p//(40*period)
    ts = [5*h-2]*20
    q = 5*p
    hs = [(t*p+q//2)//q for t in ts]
    ta = sum(ts) % q
    ha = (ta*p+q//2)//q
    c = (sum(ts)-ta)//q
    e = sum(hs)-ha-c*p
    residual = sum(scale_mask(v, p=p, period=period) for v in hs)-scale_mask(
        ha, p=p, period=period)-c*period
    return dict(hs=hs, aggregate=ha, carry=c, hprf_error=e, transmission_error=residual)


def quantize(values, scale):
    # Match FixedPoint's decimal spelling convention. This boundary operation
    # is separate from the entirely integer mask/sum/subtract/round pipeline.
    result = []
    for value in values:
        rational = Fraction(str(float(value)))*scale
        result.append(nearest_ratio(rational.numerator, rational.denominator))
    return result
