from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DISKHUNT_", env_file=".env")
    data_dir: Path = Path("data")
    max_upload_bytes: int = 10 * 1024**3
    job_ttl_hours: int = 24
    workers: int = 2
    nbd_enabled: bool = False
    nbd_allowlist: str = ""

    @property
    def database(self) -> Path:
        return self.data_dir / "diskhunt.sqlite3"


settings = Settings()

