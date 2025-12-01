"""Configuration settings for the security scan service."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database settings
    db_host: str = "mariadb"
    db_port: int = 3306
    db_database: str = "laravel"
    db_username: str = "sail"
    db_password: str = "password"

    # Laravel APP_KEY for decryption
    app_key: str = ""

    # RabbitMQ settings
    rabbitmq_host: str = "rabbitmq"
    rabbitmq_port: int = 5672
    rabbitmq_user: str = "guest"
    rabbitmq_password: str = "guest"
    rabbitmq_queue: str = "security-scans"

    # Prowler settings
    prowler_output_dir: str = "/tmp/prowler"

    @property
    def database_url(self) -> str:
        """Get the SQLAlchemy database URL."""
        return (
            f"mysql+pymysql://{self.db_username}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_database}"
        )

    @property
    def rabbitmq_url(self) -> str:
        """Get the RabbitMQ connection URL."""
        return (
            f"amqp://{self.rabbitmq_user}:{self.rabbitmq_password}"
            f"@{self.rabbitmq_host}:{self.rabbitmq_port}/"
        )


settings = Settings()
