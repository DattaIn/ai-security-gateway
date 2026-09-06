from ai_security_gateway.model_manager.device_profile import (
    DeviceTier,
    classify_tier,
    profile_device,
)


def test_low_ram_classified_constrained():
    assert classify_tier(64) == DeviceTier.CONSTRAINED
    assert classify_tier(255) == DeviceTier.CONSTRAINED


def test_mid_ram_classified_standard_edge():
    assert classify_tier(256) == DeviceTier.STANDARD_EDGE
    assert classify_tier(2047) == DeviceTier.STANDARD_EDGE


def test_high_ram_classified_edge_server():
    assert classify_tier(2048) == DeviceTier.EDGE_SERVER
    assert classify_tier(16000) == DeviceTier.EDGE_SERVER


def test_profile_device_with_overrides_is_deterministic():
    profile = profile_device(ram_override_mb=1024, disk_override_mb=5000, cpu_override=4)
    assert profile.available_ram_mb == 1024
    assert profile.available_disk_mb == 5000
    assert profile.cpu_cores == 4
    assert profile.tier == DeviceTier.STANDARD_EDGE


def test_profile_device_as_dict_contains_tier_value_not_enum():
    profile = profile_device(ram_override_mb=64)
    d = profile.as_dict()
    assert d["tier"] == "constrained"
    assert isinstance(d["tier"], str)
