"""Configuración de la aplicación (variables de entorno) e inventario de hosts (YAML).

Las credenciales nunca van en el YAML: el inventario solo referencia el nombre
de la variable de entorno (`username_env`, `password_env`, `key_file_env`).
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LOGAN_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///data/loganalyzer.db"
    inventory_path: Path = Path("config/hosts.yaml")
    rules_path: Path = Path("config/rules.yaml")
    schedule_minutes: int = 5
    # Ventana hacia atrás que evalúa cada corrida de detección. Debe ser mayor a
    # la ventana más larga de las reglas para no perder bursts entre corridas.
    detection_lookback_minutes: int = 60
    max_bytes_per_read: int = 5 * 1024 * 1024

    webhook_url: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "loganalyzer@localhost"
    smtp_to: str | None = None
    smtp_starttls: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()


class Credentials(BaseModel):
    username_env: str | None = None
    password_env: str | None = None
    key_file_env: str | None = None

    def resolve(self) -> tuple[str | None, str | None, str | None]:
        def env(name: str | None) -> str | None:
            return os.environ.get(name) if name else None

        return env(self.username_env), env(self.password_env), env(self.key_file_env)


class FileSource(BaseModel):
    path: str
    format: Literal[
        "auth", "syslog", "nginx_access", "nginx_error", "journald_json", "windows_json"
    ]


class JournaldSource(BaseModel):
    enabled: bool = False
    units: list[str] = Field(default_factory=list)
    initial_since: str = "-1h"


class WindowsChannel(BaseModel):
    log: str
    event_ids: list[int] = Field(default_factory=list)
    levels: list[int] = Field(default_factory=list)


class HostConfig(BaseModel):
    name: str
    type: Literal["local", "ssh", "winrm"]
    address: str | None = None
    port: int | None = None
    timezone: str = "UTC"
    initial_position: Literal["beginning", "end"] = "beginning"
    sudo: bool = False
    strict_host_keys: bool = True
    transport: str = "ntlm"
    verify_tls: bool = True
    credentials: Credentials = Field(default_factory=Credentials)
    files: list[FileSource] = Field(default_factory=list)
    journald: JournaldSource = Field(default_factory=JournaldSource)
    channels: list[WindowsChannel] = Field(default_factory=list)
    enabled: bool = True

    @field_validator("timezone")
    @classmethod
    def _valid_tz(cls, value: str) -> str:
        try:
            ZoneInfo(value)  # falla temprano si la zona no existe
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"zona horaria desconocida: {value}") from exc
        return value

    @property
    def tz(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)


class Inventory(BaseModel):
    hosts: list[HostConfig]


def load_inventory(path: str | Path) -> Inventory:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    defaults = data.get("defaults", {})
    hosts = [{**defaults, **h} for h in data.get("hosts", [])]
    inventory = Inventory(hosts=hosts)
    names = [h.name for h in inventory.hosts]
    duplicated = {n for n in names if names.count(n) > 1}
    if duplicated:
        raise ValueError(f"hosts duplicados en el inventario: {sorted(duplicated)}")
    return inventory
