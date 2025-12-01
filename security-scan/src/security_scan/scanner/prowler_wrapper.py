"""Prowler wrapper for security scanning."""

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class ProwlerWrapper:
    """Wrapper around Prowler library for security scanning.

    This class provides a high-level interface to Prowler's scanning capabilities.
    It uses Prowler as a library for native access to Finding objects.
    """

    def __init__(
        self,
        provider: str,
        output_dir: str = "/tmp/prowler",
    ):
        """Initialize the Prowler wrapper.

        Args:
            provider: Cloud provider name (aws, gcp, azure)
            output_dir: Directory for Prowler output files
        """
        self.provider = provider
        self.output_dir = output_dir

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
            # Import Prowler components
            # Note: Prowler's API may vary between versions
            # This is designed for Prowler 5.x
            from prowler.lib.check.check import execute_checks
            from prowler.lib.check.checks_loader import load_checks_to_execute

            logger.info(f"Initializing Prowler for provider: {self.provider}")

            # Create provider instance based on provider type
            prowler_provider = self._create_prowler_provider()

            # Load checks to execute
            checks_to_run = load_checks_to_execute(
                checks_to_execute=checks if checks else None,
                service_list=services if services else None,
                provider=prowler_provider.type,
            )

            total_checks = len(checks_to_run)
            logger.info(f"Loaded {total_checks} checks to execute")

            # Execute checks
            findings = []
            for i, check in enumerate(checks_to_run):
                try:
                    check_findings = execute_checks(
                        checks=[check],
                        provider=prowler_provider,
                    )
                    findings.extend(check_findings)

                    if (i + 1) % 10 == 0 or (i + 1) == total_checks:
                        logger.info(f"Progress: {i + 1}/{total_checks} checks completed")

                except Exception as e:
                    logger.warning(f"Check {check} failed: {e}")

            logger.info(f"Scan complete. Found {len(findings)} findings")
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
            return ProwlerAwsProvider(
                assumed_role_info=None,
                audit_config=None,
            )
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
