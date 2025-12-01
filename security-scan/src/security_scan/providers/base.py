"""Base provider interface."""

from abc import ABC, abstractmethod
from typing import Any, TYPE_CHECKING

from ..db.encryption import LaravelDecryptor

if TYPE_CHECKING:
    from ..db.models import CloudAccount


class BaseProvider(ABC):
    """Abstract base class for cloud providers."""

    def __init__(self, cloud_account: "CloudAccount", app_key: str):
        """Initialize the provider.

        Args:
            cloud_account: CloudAccount model instance
            app_key: Laravel APP_KEY for decrypting credentials
        """
        self.cloud_account = cloud_account
        self.decryptor = LaravelDecryptor(app_key) if app_key else None
        self._credentials: dict[str, Any] | None = None

    def get_credentials(self) -> dict[str, Any]:
        """Get decrypted credentials.

        Returns:
            Decrypted credentials dictionary

        Raises:
            ValueError: If credentials cannot be decrypted
        """
        if self._credentials is not None:
            return self._credentials

        if not self.cloud_account.credentials:
            return {}

        if not self.decryptor:
            raise ValueError("No APP_KEY provided for credential decryption")

        self._credentials = self.decryptor.decrypt(self.cloud_account.credentials)
        return self._credentials

    @abstractmethod
    def setup_environment(self, credentials: dict[str, Any]) -> dict[str, str]:
        """Set up environment variables for the provider.

        Args:
            credentials: Decrypted credentials dictionary

        Returns:
            Dictionary of environment variables
        """
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Get the provider name for Prowler.

        Returns:
            Provider name (aws, gcp, azure)
        """
        pass


class ProviderFactory:
    """Factory for creating cloud provider instances."""

    _providers: dict[str, type[BaseProvider]] = {}

    @classmethod
    def register(cls, name: str, provider_class: type[BaseProvider]) -> None:
        """Register a provider class.

        Args:
            name: Provider name (aws, gcp, azure)
            provider_class: The provider class
        """
        cls._providers[name] = provider_class

    @classmethod
    def create(
        cls,
        cloud_account: "CloudAccount",
        app_key: str,
    ) -> BaseProvider | None:
        """Create a provider instance.

        Args:
            cloud_account: CloudAccount model instance
            app_key: Laravel APP_KEY for decryption

        Returns:
            A provider instance or None if provider not supported
        """
        provider_name = cloud_account.provider
        if provider_name not in cls._providers:
            return None
        return cls._providers[provider_name](cloud_account, app_key)

    @classmethod
    def is_supported(cls, provider_name: str) -> bool:
        """Check if a provider is supported.

        Args:
            provider_name: Provider name to check

        Returns:
            True if supported, False otherwise
        """
        return provider_name in cls._providers
