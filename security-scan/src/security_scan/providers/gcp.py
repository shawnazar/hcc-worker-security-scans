"""GCP provider implementation."""

import json
import logging
import tempfile
from typing import Any

from .base import BaseProvider, ProviderFactory
from ..config import settings

logger = logging.getLogger(__name__)


class GcpProvider(BaseProvider):
    """Google Cloud Platform provider implementation."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the GCP provider."""
        super().__init__(*args, **kwargs)
        self._temp_key_file: str | None = None

    @property
    def provider_name(self) -> str:
        """Get the provider name for Prowler."""
        return "gcp"

    def setup_environment(self, credentials: dict[str, Any]) -> dict[str, str]:
        """Set up environment variables for GCP.

        Args:
            credentials: Decrypted credentials dictionary containing either:
                - key_json: Service account key JSON
                - OR workload identity federation fields: project_id, project_number,
                  workload_identity_pool_id, workload_identity_provider_id, service_account_email

        Returns:
            Dictionary of GCP environment variables
        """
        # Check if this is Workload Identity Federation
        if "workload_identity_pool_id" in credentials:
            return self._setup_workload_identity_federation(credentials)

        # Otherwise, use service account key
        return self._setup_service_account_key(credentials)

    def _setup_service_account_key(self, credentials: dict[str, Any]) -> dict[str, str]:
        """Set up environment for service account key authentication."""
        env = {}

        # Get the service account key JSON
        key_json = credentials.get("key_json")
        if not key_json:
            raise ValueError("Missing service account key JSON in credentials")

        # Parse the key JSON if it's a string
        if isinstance(key_json, str):
            key_data = json.loads(key_json)
        else:
            key_data = key_json

        # Write the key to a temporary file
        # Prowler needs GOOGLE_APPLICATION_CREDENTIALS pointing to a file
        self._temp_key_file = self._write_key_file(key_data)
        env["GOOGLE_APPLICATION_CREDENTIALS"] = self._temp_key_file

        # Set the project ID if available
        if "project_id" in key_data:
            env["CLOUDSDK_CORE_PROJECT"] = key_data["project_id"]
            env["GOOGLE_CLOUD_PROJECT"] = key_data["project_id"]

        logger.info(f"GCP credentials configured for project: {key_data.get('project_id')}")

        return env

    def _setup_workload_identity_federation(self, credentials: dict[str, Any]) -> dict[str, str]:
        """Set up environment for Workload Identity Federation authentication.

        This creates a credential configuration file that allows GCP client libraries
        to authenticate using AWS credentials via Workload Identity Federation.
        """
        env = {}

        project_id = credentials["project_id"]
        project_number = credentials["project_number"]
        pool_id = credentials["workload_identity_pool_id"]
        provider_id = credentials["workload_identity_provider_id"]
        service_account_email = credentials["service_account_email"]

        # GCP Workload Identity Federation requires the numeric project number in the audience
        audience = f"//iam.googleapis.com/projects/{project_number}/locations/global/workloadIdentityPools/{pool_id}/providers/{provider_id}"

        # Create the credential configuration JSON for external account credentials
        # This tells GCP client libraries how to authenticate via AWS
        credential_config = {
            "type": "external_account",
            "audience": audience,
            "subject_token_type": "urn:ietf:params:aws:token-type:aws4_request",
            "service_account_impersonation_url": f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{service_account_email}:generateAccessToken",
            "token_url": "https://sts.googleapis.com/v1/token",
            "credential_source": {
                "environment_id": "aws1",
                "region_url": "http://169.254.169.254/latest/meta-data/placement/availability-zone",
                "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials",
                "regional_cred_verification_url": "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15",
            },
        }

        # For non-EC2 environments, use environment variables for AWS credentials
        # This is the case when running in containers with explicit credentials
        if settings.aws_access_key_id and settings.aws_secret_access_key:
            # Override credential_source to use environment variables
            credential_config["credential_source"] = {
                "environment_id": "aws1",
                "regional_cred_verification_url": "https://sts.us-east-1.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15",
            }
            # Set AWS credentials in environment
            env["AWS_ACCESS_KEY_ID"] = settings.aws_access_key_id
            env["AWS_SECRET_ACCESS_KEY"] = settings.aws_secret_access_key
            env["AWS_REGION"] = "us-east-1"

        # Write the credential configuration to a temporary file
        self._temp_key_file = self._write_key_file(credential_config)
        env["GOOGLE_APPLICATION_CREDENTIALS"] = self._temp_key_file

        # Set the project ID
        env["CLOUDSDK_CORE_PROJECT"] = project_id
        env["GOOGLE_CLOUD_PROJECT"] = project_id

        logger.info(
            f"GCP Workload Identity Federation configured for project: {project_id}, "
            f"pool: {pool_id}, provider: {provider_id}"
        )

        return env

    def _write_key_file(self, key_data: dict[str, Any]) -> str:
        """Write the service account key to a temporary file.

        Args:
            key_data: The service account key dictionary

        Returns:
            Path to the temporary key file
        """
        # Create a temporary file that won't be auto-deleted
        temp_file = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            prefix="gcp_key_",
            delete=False,
        )

        json.dump(key_data, temp_file)
        temp_file.close()

        logger.debug(f"Wrote GCP key file to: {temp_file.name}")

        return temp_file.name

    def cleanup(self) -> None:
        """Clean up temporary files."""
        import os

        if self._temp_key_file and os.path.exists(self._temp_key_file):
            try:
                os.remove(self._temp_key_file)
                logger.debug(f"Removed temporary key file: {self._temp_key_file}")
            except OSError as e:
                logger.warning(f"Failed to remove temporary key file: {e}")


# Register the GCP provider
ProviderFactory.register("gcp", GcpProvider)
