"""Unit tests for the flood rate limiter (scenario S8)."""

import pytest

from vitalpath_c3.engines.flood_rate_limiter import RateLimitConfig, RateLimiter
from vitalpath_c3.rule_ids import Rule


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def limiter(clock) -> RateLimiter:
    return RateLimiter(RateLimitConfig(), clock=clock)


def test_s8_burst_of_fifty_in_one_second(limiter, clock):
    """S8: 50 packets within one second; the first 20 pass, 30 are discarded."""
    verdicts = []
    for i in range(50):
        clock.now = 1000.0 + i * 0.02
        verdicts.append(limiter.admit("amb-01"))
    assert sum(v.allowed for v in verdicts) == 20
    assert all(v.rule is Rule.RATE_LIMIT for v in verdicts if not v.allowed)


def test_normal_rate_never_limited(limiter, clock):
    for i in range(600):  # 10 minutes at 1 Hz
        clock.now = 1000.0 + i
        assert limiter.admit("amb-01").allowed


def test_limit_lifts_once_window_passes(limiter, clock):
    for _ in range(20):
        assert limiter.admit("amb-01").allowed
    assert not limiter.admit("amb-01").allowed
    clock.now += 0.999
    assert not limiter.admit("amb-01").allowed
    clock.now += 0.001
    assert limiter.admit("amb-01").allowed


def test_discarded_packets_do_not_extend_lockout(limiter, clock):
    for _ in range(20):
        limiter.admit("amb-01")
    for i in range(100):  # sustained flood during the window
        clock.now = 1000.0 + i * 0.009
        limiter.admit("amb-01")
    clock.now = 1001.0
    assert limiter.admit("amb-01").allowed


def test_devices_limited_independently(limiter):
    for _ in range(20):
        limiter.admit("amb-01")
    assert not limiter.admit("amb-01").allowed
    assert limiter.admit("amb-02").allowed


def test_configurable_limit(clock):
    limiter = RateLimiter(RateLimitConfig(max_packets=3, window_s=0.5), clock=clock)
    assert [limiter.admit("d").allowed for _ in range(4)] == [True, True, True, False]


@pytest.mark.parametrize("kwargs", [{"max_packets": 0}, {"window_s": 0}])
def test_invalid_config_rejected(kwargs):
    with pytest.raises(ValueError):
        RateLimitConfig(**kwargs)
