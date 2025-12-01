"""AWS provider implementation."""

from typing import Any

from .base import BaseProvider, ProviderFactory


class AwsProvider(BaseProvider):
    """AWS cloud provider implementation."""

    @property
    def provider_name(self) -> str:
        """Get the provider name for Prowler."""
        return "aws"

    def setup_environment(self, credentials: dict[str, Any]) -> dict[str, str]:
        """Set up environment variables for AWS.

        Args:
            credentials: Decrypted credentials dictionary

        Returns:
            Dictionary of AWS environment variables
        """
        env = {}

        # IAM credentials
        if "access_key_id" in credentials:
            env["AWS_ACCESS_KEY_ID"] = credentials["access_key_id"]

        if "secret_access_key" in credentials:
            env["AWS_SECRET_ACCESS_KEY"] = credentials["secret_access_key"]

        # Session token (for temporary credentials)
        if "session_token" in credentials:
            env["AWS_SESSION_TOKEN"] = credentials["session_token"]

        # Default region from cloud account
        if self.cloud_account.region:
            env["AWS_DEFAULT_REGION"] = self.cloud_account.region

        return env


# Register the AWS provider
ProviderFactory.register("aws", AwsProvider)
