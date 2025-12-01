"""RabbitMQ consumer for security scan jobs."""

import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from typing import Any

import pika
from pika.adapters.blocking_connection import BlockingChannel
from pika.spec import Basic, BasicProperties
from sqlalchemy.orm import Session

from ..config import settings
from ..db.connection import get_session
from ..db.models import CloudAccount, Scan
from ..providers import ProviderFactory
from ..scanner.prowler_wrapper import ProwlerWrapper
from ..scanner.result_processor import ResultProcessor

logger = logging.getLogger(__name__)


class ScanConsumer:
    """Consumer for processing security scan jobs from RabbitMQ."""

    def __init__(self) -> None:
        """Initialize the consumer."""
        self.connection: pika.BlockingConnection | None = None
        self.channel: BlockingChannel | None = None
        self.should_stop = False

    def connect(self) -> None:
        """Establish connection to RabbitMQ."""
        parameters = pika.URLParameters(settings.rabbitmq_url)
        parameters.heartbeat = 600
        parameters.blocked_connection_timeout = 300

        self.connection = pika.BlockingConnection(parameters)
        self.channel = self.connection.channel()

        # Declare the queue (creates if doesn't exist)
        self.channel.queue_declare(queue=settings.rabbitmq_queue, durable=True)

        # Set prefetch count to 1 to ensure fair dispatch
        self.channel.basic_qos(prefetch_count=1)

        logger.info(f"Connected to RabbitMQ, listening on queue: {settings.rabbitmq_queue}")

    def disconnect(self) -> None:
        """Close the RabbitMQ connection."""
        if self.connection and self.connection.is_open:
            self.connection.close()
            logger.info("Disconnected from RabbitMQ")

    def process_message(
        self,
        channel: BlockingChannel,
        method: Basic.Deliver,
        properties: BasicProperties,
        body: bytes,
    ) -> None:
        """Process a scan job message.

        Args:
            channel: The channel object
            method: Delivery method
            properties: Message properties
            body: The message body
        """
        try:
            message = json.loads(body.decode("utf-8"))
            logger.info(f"Received message: {message}")

            # Laravel queue job format
            job_data = self._parse_laravel_job(message)
            if job_data is None:
                logger.warning("Invalid job format, acknowledging and skipping")
                channel.basic_ack(delivery_tag=method.delivery_tag)
                return

            scan_id = job_data.get("scan_id")
            if not scan_id:
                logger.warning("No scan_id in job data, acknowledging and skipping")
                channel.basic_ack(delivery_tag=method.delivery_tag)
                return

            # Process the scan
            self._run_scan(scan_id)

            # Acknowledge successful processing
            channel.basic_ack(delivery_tag=method.delivery_tag)
            logger.info(f"Successfully processed scan {scan_id}")

        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode message: {e}")
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
        except Exception as e:
            logger.exception(f"Error processing message: {e}")
            # Requeue the message for retry
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=True)

    def _parse_laravel_job(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Parse Laravel queue job format.

        Laravel serializes jobs with a specific format including the command
        class and serialized data.

        Args:
            message: The raw message from RabbitMQ

        Returns:
            Parsed job data or None if invalid
        """
        try:
            # Laravel queue format has a 'data' field with the serialized command
            if "data" not in message:
                return None

            data = message["data"]

            # The command is serialized as a JSON string
            if "command" in data:
                command = data["command"]
                # Laravel serializes the command - we need to extract scan_id
                # The format depends on how the job was serialized
                if isinstance(command, str):
                    # Try to parse as JSON first
                    try:
                        command_data = json.loads(command)
                        return command_data
                    except json.JSONDecodeError:
                        # It might be PHP serialized - extract scan_id with regex
                        import re

                        match = re.search(r'"scan_id";i:(\d+)', command)
                        if match:
                            return {"scan_id": int(match.group(1))}

                        # Try another common format
                        match = re.search(r's:7:"scan_id";i:(\d+)', command)
                        if match:
                            return {"scan_id": int(match.group(1))}

                        # Also check for scan model reference
                        match = re.search(r'"scan";O:.*?"id";i:(\d+)', command)
                        if match:
                            return {"scan_id": int(match.group(1))}

                elif isinstance(command, dict):
                    if "scan_id" in command:
                        return command
                    if "scan" in command and isinstance(command["scan"], dict):
                        return {"scan_id": command["scan"].get("id")}

            # Fallback: check if scan_id is directly in data
            if "scan_id" in data:
                return {"scan_id": data["scan_id"]}

            return None

        except Exception as e:
            logger.warning(f"Error parsing Laravel job format: {e}")
            return None

    def _run_scan(self, scan_id: int) -> None:
        """Execute the security scan.

        Args:
            scan_id: The ID of the scan to run
        """
        session: Session = get_session()

        try:
            # Get the scan record
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                logger.error(f"Scan {scan_id} not found in database")
                return

            # Get the cloud account
            cloud_account = (
                session.query(CloudAccount)
                .filter(CloudAccount.id == scan.cloud_account_id)
                .first()
            )
            if not cloud_account:
                logger.error(f"Cloud account {scan.cloud_account_id} not found")
                self._mark_scan_failed(session, scan, "Cloud account not found")
                return

            # Mark scan as running
            scan.status = "running"
            scan.started_at = datetime.now(timezone.utc)
            session.commit()
            logger.info(f"Started scan {scan_id} for cloud account {cloud_account.id}")

            # Get the provider
            provider = ProviderFactory.create(cloud_account, settings.app_key)
            if not provider:
                self._mark_scan_failed(session, scan, f"Unsupported provider: {cloud_account.provider}")
                return

            # Set up credentials
            credentials = provider.get_credentials()
            env_vars = provider.setup_environment(credentials)

            # Actually set the environment variables for Prowler to use
            for key, value in env_vars.items():
                os.environ[key] = value
                logger.debug(f"Set environment variable: {key}")

            logger.info(f"Set {len(env_vars)} AWS environment variables")

            # Parse regions_filter - may be a JSON string or already a list
            regions = scan.regions_filter
            if isinstance(regions, str):
                import json as json_module

                try:
                    regions = json_module.loads(regions)
                except json_module.JSONDecodeError:
                    logger.warning(f"Failed to parse regions_filter: {regions}")
                    regions = None

            logger.info(f"Regions filter: {regions}")

            # Create and run Prowler scan
            prowler = ProwlerWrapper(
                provider=cloud_account.provider,
                output_dir=settings.prowler_output_dir,
                regions=regions,
            )

            # Determine scan parameters based on scan_type
            checks = scan.checks_filter
            services = scan.services_filter
            compliance = None

            # Map scan_type to Prowler arguments
            scan_type = scan.scan_type
            if scan_type.startswith("focus_"):
                # Focus packs map to specific services
                services = self._get_focus_pack_services(scan_type)
            elif scan_type.startswith("compliance_"):
                # Compliance packs map to Prowler compliance frameworks
                compliance = self._get_compliance_framework(scan_type)

            # Run the scan
            findings = prowler.run_scan(
                credentials=credentials,
                checks=checks,
                services=services,
                compliance=compliance,
            )

            # Process findings
            processor = ResultProcessor(session, scan)
            total_checks, passed_checks, failed_checks = processor.process_findings(findings)

            # Mark scan as completed
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.total_checks = total_checks
            scan.passed_checks = passed_checks
            scan.failed_checks = failed_checks
            session.commit()

            logger.info(
                f"Completed scan {scan_id}: "
                f"{total_checks} total, {passed_checks} passed, {failed_checks} failed"
            )

        except Exception as e:
            logger.exception(f"Error running scan {scan_id}: {e}")
            try:
                scan = session.query(Scan).filter(Scan.id == scan_id).first()
                if scan:
                    self._mark_scan_failed(session, scan, str(e))
            except Exception:
                logger.exception("Failed to mark scan as failed")
        finally:
            session.close()

    def _mark_scan_failed(self, session: Session, scan: Scan, error: str) -> None:
        """Mark a scan as failed.

        Args:
            session: Database session
            scan: The scan record
            error: Error message
        """
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_message = error[:1000] if error else None  # Truncate if too long
        session.commit()
        logger.error(f"Scan {scan.id} failed: {error}")

    def start(self) -> None:
        """Start consuming messages from the queue."""
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        while not self.should_stop:
            try:
                self.connect()

                # Start consuming
                self.channel.basic_consume(
                    queue=settings.rabbitmq_queue,
                    on_message_callback=self.process_message,
                )

                logger.info("Waiting for messages...")
                self.channel.start_consuming()

            except pika.exceptions.AMQPConnectionError as e:
                logger.error(f"Connection error: {e}")
                if not self.should_stop:
                    logger.info("Reconnecting in 5 seconds...")
                    time.sleep(5)
            except Exception as e:
                logger.exception(f"Unexpected error: {e}")
                if not self.should_stop:
                    logger.info("Reconnecting in 5 seconds...")
                    time.sleep(5)
            finally:
                self.disconnect()

    def stop(self) -> None:
        """Stop consuming messages."""
        self.should_stop = True
        if self.channel:
            self.channel.stop_consuming()
        logger.info("Stopping consumer...")

    def _signal_handler(self, signum: int, frame: Any) -> None:
        """Handle shutdown signals.

        Args:
            signum: Signal number
            frame: Current stack frame
        """
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()

    def _get_focus_pack_services(self, scan_type: str) -> list[str] | None:
        """Map focus pack scan type to Prowler services.

        Args:
            scan_type: The scan type (e.g., 'focus_identity', 'focus_network')

        Returns:
            List of Prowler service names or None
        """
        focus_pack_services = {
            "focus_identity": ["iam", "accessanalyzer", "sso", "cognito"],
            "focus_network": ["vpc", "ec2", "elb", "elbv2", "cloudfront", "waf", "wafv2", "shield"],
            "focus_compute": ["ec2", "ecs", "eks", "lambda", "ssm"],
            "focus_data": ["s3", "rds", "dynamodb", "redshift", "elasticache", "backup"],
            "focus_logging": ["cloudwatch", "cloudtrail", "config", "guardduty", "securityhub"],
            "focus_secrets": ["kms", "secretsmanager", "acm"],
        }
        return focus_pack_services.get(scan_type)

    def _get_compliance_framework(self, scan_type: str) -> str | None:
        """Map compliance pack scan type to Prowler compliance framework.

        Args:
            scan_type: The scan type (e.g., 'compliance_cis', 'compliance_soc2')

        Returns:
            Prowler compliance framework name or None
        """
        compliance_frameworks = {
            "compliance_cis": "cis_2.0_aws",
            "compliance_soc2": "soc2_aws",
            "compliance_pci": "pci_3.2.1_aws",
            "compliance_hipaa": "hipaa_aws",
            "compliance_nist": "nist_800_53_revision_5_aws",
            "compliance_gdpr": "gdpr_aws",
        }
        return compliance_frameworks.get(scan_type)
