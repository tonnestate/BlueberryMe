from blueberryme.zone import ProbeStatus, ZoneProfile, build_srt_settings, sanitized_environment, zone_check_summary


def test_srt_profile_denies_home_and_allows_only_declared_network():
    settings = build_srt_settings(ZoneProfile(workspace=".", gateway_hosts=("https://bbm.example.internal:8787",), llm_hosts=("api.openai.com",)))
    assert "~" in settings["filesystem"]["denyRead"]
    assert settings["filesystem"]["allowWrite"]
    assert set(settings["network"]["allowedDomains"]) == {"bbm.example.internal", "api.openai.com"}


def test_environment_is_allowlist_based(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "secret")
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    monkeypatch.setenv("BBM_SAFE_TEST", "yes")
    env = sanitized_environment(["BBM_SAFE_TEST"])
    assert "DATABASE_URL" not in env
    assert "GITHUB_TOKEN" not in env
    assert env["BBM_SAFE_TEST"] == "yes"


def test_zone_summary_fails_only_on_fail():
    from blueberryme.zone import ZoneProbe
    assert zone_check_summary([ZoneProbe("a", ProbeStatus.PASS, "ok"), ZoneProbe("b", ProbeStatus.WARN, "unverified")])["pass"] is True
    assert zone_check_summary([ZoneProbe("a", ProbeStatus.FAIL, "reachable")])["pass"] is False
