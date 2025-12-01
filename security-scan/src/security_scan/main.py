"""Main entry point for the security scan worker."""

import logging
import sys

from .config import settings
from .worker import ScanConsumer


def setup_logging() -> None:
    """Configure logging for the application."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )

    # Set specific log levels for noisy libraries
    logging.getLogger("pika").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.WARNING)


def main() -> None:
    """Start the security scan worker."""
    setup_logging()
    logger = logging.getLogger(__name__)

    logger.info("Starting security scan worker...")
    logger.info(f"RabbitMQ host: {settings.rabbitmq_host}")
    logger.info(f"Queue: {settings.rabbitmq_queue}")
    logger.info(f"Database host: {settings.db_host}")

    consumer = ScanConsumer()

    try:
        consumer.start()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        consumer.stop()
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
