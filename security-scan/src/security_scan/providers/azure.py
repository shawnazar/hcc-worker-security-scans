"""Azure provider implementation."""

import json
import logging
import tempfile
from typing import Any

from .base import BaseProvider, ProviderFactory
from ..config import settings

logger = logging.getLogger(__name__)


class AzureProvider(BaseProvider):
    """Microsoft Azure provider implementation."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the Azure provider."""
        super().__init__(*args, **kwargs)
        self._temp_cred_file: str | None = None

    @property
    def provider_name(self) -> str:
        """Get the provider name for Prowler."""
        return "azure"

    def setup_environment(self, credentials: dict[str, Any]) -> dict[str, str]:
        """Set up environment variables for Azure.

        Args:
            credentials: Decrypted credentials dictionary containing either:
                - Service Principal: tenant_id, client_id, client_secret, subscription_id
                - OR Federated Identity: tenant_id, client_id, subscription_id (no client_secret)

        Returns:
            Dictionary of Azure environment variables
        """
        # Check if this is Federated Identity (no client_secret)
        if "client_secret" not in credentials:
            return self._setup_federated_identity(credentials)

        # Otherwise, use Service Principal
        return self._setup_service_principal(credentials)

    def _setup_service_principal(self, credentials: dict[str, Any]) -> dict[str, str]:
        """Set up environment for Service Principal authentication."""
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
            f"Azure Service Principal configured for tenant: {credentials.get('tenant_id')}, "
            f"subscription: {credentials.get('subscription_id')}"
        )

        return env

    def _setup_federated_identity(self, credentials: dict[str, Any]) -> dict[str, str]:
        """Set up environment for Federated Identity authentication.

        This creates a credential configuration file that allows Azure SDK to
        authenticate using AWS credentials via Workload Identity Federation.
        """
        env = {}

        tenant_id = credentials["tenant_id"]
        client_id = credentials["client_id"]
        subscription_id = credentials["subscription_id"]

        # Azure SDK supports federated identity via environment variables
        # We need to set up the AZURE_FEDERATED_TOKEN_FILE or use
        # a credential configuration approach

        # For Azure, the approach is different than GCP
        # Azure expects a JWT token from the federated identity provider
        # We'll use the azure-identity SDK's WorkloadIdentityCredential

        # Set basic Azure environment variables
        env["AZURE_TENANT_ID"] = tenant_id
        env["AZURE_CLIENT_ID"] = client_id
        env["AZURE_SUBSCRIPTION_ID"] = subscription_id

        # For federated identity from AWS, we need to:
        # 1. Get an AWS STS token
        # 2. Exchange it for an Azure AD token
        # This is typically handled by azure-identity SDK when configured properly

        # Set HCC's AWS credentials for the federation exchange
        if settings.aws_access_key_id and settings.aws_secret_access_key:
            env["AWS_ACCESS_KEY_ID"] = settings.aws_access_key_id
            env["AWS_SECRET_ACCESS_KEY"] = settings.aws_secret_access_key
            env["AWS_REGION"] = "us-east-1"

        # Create a federated credential configuration file
        # This tells the Azure SDK how to authenticate via AWS federation
        federated_config = {
            "type": "federated_identity",
            "tenant_id": tenant_id,
            "client_id": client_id,
            "token_exchange": {
                "type": "aws",
                "region": "us-east-1",
            },
        }

        # Write the configuration to a temporary file
        self._temp_cred_file = self._write_config_file(federated_config)
        env["AZURE_FEDERATED_CREDENTIAL_CONFIG"] = self._temp_cred_file

        # Region from cloud account
        if self.cloud_account.region:
            env["AZURE_REGION"] = self.cloud_account.region

        logger.info(
            f"Azure Federated Identity configured for tenant: {tenant_id}, "
            f"client: {client_id}, subscription: {subscription_id}"
        )

        return env

    def _write_config_file(self, config_data: dict[str, Any]) -> str:
        """Write configuration to a temporary file.

        Args:
            config_data: The configuration dictionary

        Returns:
            Path to the temporary config file
        """
        temp_file = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            prefix="azure_federated_",
            delete=False,
        )

        json.dump(config_data, temp_file)
        temp_file.close()

        logger.debug(f"Wrote Azure federated config file to: {temp_file.name}")

        return temp_file.name

    def cleanup(self) -> None:
        """Clean up temporary files."""
        import os

        if self._temp_cred_file and os.path.exists(self._temp_cred_file):
            try:
                os.remove(self._temp_cred_file)
                logger.debug(f"Removed temporary config file: {self._temp_cred_file}")
            except OSError as e:
                logger.warning(f"Failed to remove temporary config file: {e}")


# Register the Azure provider
ProviderFactory.register("azure", AzureProvider)
