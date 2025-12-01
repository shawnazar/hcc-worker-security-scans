"""GCP provider implementation."""

import json
import logging
import tempfile
from typing import Any

from .base import BaseProvider, ProviderFactory

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
            credentials: Decrypted credentials dictionary containing key_json

        Returns:
            Dictionary of GCP environment variables
        """
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
