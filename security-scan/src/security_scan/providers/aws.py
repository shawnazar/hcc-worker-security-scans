"""AWS provider implementation."""

import logging
from typing import Any

from .base import BaseProvider, ProviderFactory

logger = logging.getLogger(__name__)


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

        # Check auth_type to determine how to get credentials
        auth_type = self.cloud_account.auth_type

        if auth_type == "assume_role":
            # Cross-account role assumption
            temp_creds = self._assume_role(
                role_arn=credentials["role_arn"],
                external_id=credentials.get("external_id"),
            )
            env["AWS_ACCESS_KEY_ID"] = temp_creds["AccessKeyId"]
            env["AWS_SECRET_ACCESS_KEY"] = temp_creds["SecretAccessKey"]
            env["AWS_SESSION_TOKEN"] = temp_creds["SessionToken"]
        else:
            # IAM credentials (iam_credentials auth type)
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

    def _assume_role(
        self, role_arn: str, external_id: str | None = None
    ) -> dict[str, Any]:
        """Assume a cross-account IAM role and return temporary credentials.

        Args:
            role_arn: The ARN of the role to assume
            external_id: Optional external ID for confused deputy protection

        Returns:
            Dictionary with AccessKeyId, SecretAccessKey, and SessionToken
        """
        import boto3

        logger.info(f"Assuming role: {role_arn}")

        sts = boto3.client("sts")
        params: dict[str, Any] = {
            "RoleArn": role_arn,
            "RoleSessionName": f"hcc-scan-{self.cloud_account.id}",
            "DurationSeconds": 3600,  # 1 hour
        }
        if external_id:
            params["ExternalId"] = external_id

        response = sts.assume_role(**params)
        logger.info(f"Successfully assumed role: {role_arn}")

        return response["Credentials"]


# Register the AWS provider
ProviderFactory.register("aws", AwsProvider)
