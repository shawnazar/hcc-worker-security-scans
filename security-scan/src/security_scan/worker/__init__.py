"""Worker module for consuming security scan jobs from RabbitMQ."""

from .consumer import ScanConsumer

__all__ = ["ScanConsumer"]
