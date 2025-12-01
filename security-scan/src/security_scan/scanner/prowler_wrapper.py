"""Prowler wrapper for security scanning."""

import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class OutputOptions:
    """Minimal output options for Prowler check execution."""

    only_logs: bool = True
    verbose: bool = False
    fixer: bool = False
    status: list[str] | None = None


class ProwlerWrapper:
    """Wrapper around Prowler library for security scanning.

    This class provides a high-level interface to Prowler's scanning capabilities.
    It uses Prowler as a library for native access to Finding objects.
    """

    def __init__(
        self,
        provider: str,
        output_dir: str = "/tmp/prowler",
        regions: list[str] | None = None,
    ):
        """Initialize the Prowler wrapper.

        Args:
            provider: Cloud provider name (aws, gcp, azure)
            output_dir: Directory for Prowler output files
            regions: Optional list of regions to scan (e.g., ['us-east-1', 'us-west-2'])
        """
        self.provider = provider
        self.output_dir = output_dir
        self.regions = regions

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

    def run_scan(
        self,
        credentials: dict[str, Any],
        checks: list[str] | None = None,
        services: list[str] | None = None,
    ) -> list[Any]:
        """Run a Prowler security scan.

        Args:
            credentials: Provider credentials dictionary (for env setup - should be done by caller)
            checks: Optional list of specific checks to run
            services: Optional list of services to scan

        Returns:
            List of Prowler finding objects
        """
        try:
            logger.info(f"Initializing Prowler for provider: {self.provider}")

            # Create provider instance based on provider type
            prowler_provider = self._create_prowler_provider()

            # Import check loading function
            from prowler.lib.check.checks_loader import load_checks_to_execute

            # Load checks to execute
            # Note: Prowler 5.x uses check_list and service_list parameters
            checks_to_run = load_checks_to_execute(
                provider=prowler_provider.type,
                check_list=checks if checks else None,
                service_list=services if services else None,
            )

            total_checks = len(checks_to_run)
            logger.info(f"Loaded {total_checks} checks to execute")

            if total_checks == 0:
                logger.warning("No checks to run")
                return []

            # Use Prowler's execute_checks function which handles provider context properly
            from prowler.lib.check.check import execute_checks

            # Create minimal output options - only_logs=True uses simpler execution path
            output_options = OutputOptions(only_logs=True, verbose=False)

            # Execute all checks
            logger.info("Starting check execution...")
            findings = execute_checks(
                checks_to_execute=list(checks_to_run),
                global_provider=prowler_provider,
                custom_checks_metadata=None,
                config_file="",
                output_options=output_options,
            )

            logger.info(f"Scan complete. Executed {total_checks} checks, found {len(findings)} findings")
            return findings

        except ImportError as e:
            logger.error(f"Failed to import Prowler: {e}")
            raise RuntimeError("Prowler is not properly installed") from e
        except Exception as e:
            logger.exception(f"Scan failed: {e}")
            raise

    def _create_prowler_provider(self) -> Any:
        """Create a Prowler provider instance.

        Returns:
            Prowler provider object

        Raises:
            NotImplementedError: If provider is not supported
        """
        if self.provider == "aws":
            from prowler.providers.aws.aws_provider import AwsProvider as ProwlerAwsProvider

            # Prowler will use environment variables for credentials
            # AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and optionally AWS_SESSION_TOKEN
            # should be set in the environment before calling this

            # If regions are specified, limit the scan to those regions
            if self.regions:
                logger.info(f"Limiting scan to regions: {self.regions}")
                return ProwlerAwsProvider(scan_regions=self.regions)

            return ProwlerAwsProvider()
        elif self.provider == "gcp":
            # GCP support to be added
            raise NotImplementedError("GCP provider not yet implemented")
        elif self.provider == "azure":
            # Azure support to be added
            raise NotImplementedError("Azure provider not yet implemented")
        else:
            raise NotImplementedError(f"Provider {self.provider} not supported")


class ProwlerScanner(ProwlerWrapper):
    """Alias for backwards compatibility."""

    pass
