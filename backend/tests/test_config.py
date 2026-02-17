from app.core.config import Settings


def test_settings_defaults() -> None:
    settings = Settings()
    assert settings.analysis_timeout_seconds == 30
    assert settings.debug is False
    assert settings.rate_limit_requests == 60
    assert settings.rate_limit_window_seconds == 60
    assert settings.cors_origins == ["http://localhost:3000"]


def test_settings_env_override(monkeypatch) -> None:
    monkeypatch.setenv(
        "WHA_CORS_ORIGINS",
        '["https://example.com", "http://localhost:3000"]',
    )
    monkeypatch.setenv("WHA_RATE_LIMIT_REQUESTS", "10")
    monkeypatch.setenv("WHA_RATE_LIMIT_WINDOW_SECONDS", "120")
    monkeypatch.setenv("WHA_ANALYSIS_TIMEOUT_SECONDS", "45")
    monkeypatch.setenv("WHA_DEBUG", "true")

    settings = Settings()

    assert settings.cors_origins == ["https://example.com", "http://localhost:3000"]
    assert settings.rate_limit_requests == 10
    assert settings.rate_limit_window_seconds == 120
    assert settings.analysis_timeout_seconds == 45
    assert settings.debug is True
