import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./data/siem.db"

    secret_key: str = "insecure-dev-key-change-me"
    access_token_expire_minutes: int = 480
    ingest_api_key: str = "dev-ingest-key"

    admin_username: str = "admin"
    admin_password: str = "admin"
    admin_email: str = "admin@example.com"

    syslog_udp_enabled: bool = True
    syslog_udp_port: int = 5514
    syslog_tcp_enabled: bool = True
    syslog_tcp_port: int = 5514
    syslog_bind_host: str = "0.0.0.0"

    detection_interval_seconds: int = 5

    ueba_interval_seconds: int = 15
    geoip_enabled: bool = True

    smtp_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: str = ""
    smtp_use_tls: bool = True

    webhook_enabled: bool = False
    webhook_url: str = ""

    event_retention_days: int = 90


settings = Settings()

os.makedirs("data", exist_ok=True)
