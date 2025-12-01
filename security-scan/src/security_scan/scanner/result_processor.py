"""Result processor for converting Prowler findings to database records."""

import logging
from typing import Any

from sqlalchemy.orm import Session

from ..db.models import Scan, ScanFinding

logger = logging.getLogger(__name__)


class ResultProcessor:
    """Process Prowler findings and store them in the database."""

    def __init__(self, session: Session, scan: Scan):
        """Initialize the result processor.

        Args:
            session: SQLAlchemy session
            scan: The scan record to associate findings with
        """
        self.session = session
        self.scan = scan

    def process_findings(self, findings: list[Any]) -> tuple[int, int, int]:
        """Process a list of Prowler findings.

        Args:
            findings: List of Prowler finding objects

        Returns:
            Tuple of (total_checks, passed_checks, failed_checks)
        """
        total_checks = len(findings)
        passed_checks = 0
        failed_checks = 0

        for finding in findings:
            try:
                db_finding = ScanFinding.from_prowler_finding(self.scan.id, finding)
                self.session.add(db_finding)

                # Count pass/fail
                status = getattr(finding, "status", "INFO")
                if status == "PASS":
                    passed_checks += 1
                elif status == "FAIL":
                    failed_checks += 1

            except Exception as e:
                logger.warning(f"Failed to process finding: {e}")

        # Commit the findings
        self.session.flush()

        logger.info(
            f"Processed {total_checks} findings: "
            f"{passed_checks} passed, {failed_checks} failed"
        )

        return total_checks, passed_checks, failed_checks

    def process_batch(
        self,
        findings: list[Any],
        batch_size: int = 100,
    ) -> tuple[int, int, int]:
        """Process findings in batches for better performance.

        Args:
            findings: List of Prowler finding objects
            batch_size: Number of findings per batch

        Returns:
            Tuple of (total_checks, passed_checks, failed_checks)
        """
        total_checks = len(findings)
        passed_checks = 0
        failed_checks = 0

        for i in range(0, total_checks, batch_size):
            batch = findings[i : i + batch_size]

            for finding in batch:
                try:
                    db_finding = ScanFinding.from_prowler_finding(self.scan.id, finding)
                    self.session.add(db_finding)

                    status = getattr(finding, "status", "INFO")
                    if status == "PASS":
                        passed_checks += 1
                    elif status == "FAIL":
                        failed_checks += 1

                except Exception as e:
                    logger.warning(f"Failed to process finding: {e}")

            # Commit each batch
            self.session.flush()
            logger.debug(f"Processed batch {i // batch_size + 1}")

        logger.info(
            f"Processed {total_checks} findings in batches: "
            f"{passed_checks} passed, {failed_checks} failed"
        )

        return total_checks, passed_checks, failed_checks
