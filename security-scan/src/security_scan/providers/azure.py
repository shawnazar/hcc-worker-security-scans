"""Azure provider implementation."""

import logging
from typing import Any

from .base import BaseProvider, ProviderFactory

logger = logging.getLogger(__name__)


class AzureProvider(BaseProvider):
    """Microsoft Azure provider implementation."""

    @property
    def provider_name(self) -> str:
        """Get the provider name for Prowler."""
        return "azure"

    def setup_environment(self, credentials: dict[str, Any]) -> dict[str, str]:
        """Set up environment variables for Azure.

        Args:
            credentials: Decrypted credentials dictionary containing:
                - tenant_id: Azure AD tenant ID
                - client_id: Service principal application ID
                - client_secret: Service principal secret
                - subscription_id: Azure subscription ID

        Returns:
            Dictionary of Azure environment variables
        """
        env = {}

        # Azure AD / Entra ID authentication
        if "tenant_id" in credentials:
            env["AZURE_TENANT_ID"] = credentials["tenant_id"]

        if "client_id" in credentials:
            env["AZURE_CLIENT_ID"] = credentials["client_id"]

        if "client_secret" in credentials:
            env["AZURE_CLIENT_SECRET"] = credentials["client_secret"]

        # Subscription for scoping the scan
        if "subscription_id" in credentials:
            env["AZURE_SUBSCRIPTION_ID"] = credentials["subscription_id"]

        # Region from cloud account (used for some Azure services)
        if self.cloud_account.region:
            env["AZURE_REGION"] = self.cloud_account.region

        logger.info(
            f"Azure credentials configured for tenant: {credentials.get('tenant_id')}, "
            f"subscription: {credentials.get('subscription_id')}"
        )

        return env


# Register the Azure provider
ProviderFactory.register("azure", AzureProvider)
