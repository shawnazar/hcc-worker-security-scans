"""SQLAlchemy models matching Laravel's database schema."""

import json
from datetime import datetime
from enum import Enum
from typing import Any

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


class ScanStatus(str, Enum):
    """Scan status enum matching Laravel's ScanStatus."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingStatus(str, Enum):
    """Finding status enum matching Laravel's FindingStatus."""

    PASS = "PASS"
    FAIL = "FAIL"
    INFO = "INFO"
    MANUAL = "MANUAL"


class FindingSeverity(str, Enum):
    """Finding severity enum matching Laravel's FindingSeverity."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class CloudAccount(Base):
    """Cloud account model matching Laravel's CloudAccount."""

    __tablename__ = "cloud_accounts"

    id = Column(Integer, primary_key=True)
    # These reference Laravel-managed tables, so we don't define FK constraints
    organization_id = Column(Integer, nullable=False)
    created_by = Column(Integer, nullable=False)
    name = Column(String(255), nullable=False)
    provider = Column(String(50), nullable=False)  # aws, gcp, azure
    auth_type = Column(String(50), nullable=False)
    credentials = Column(Text, nullable=True)  # Encrypted JSON
    account_id = Column(String(255), nullable=True)
    region = Column(String(50), nullable=True)
    status = Column(String(50), default="pending")
    status_message = Column(Text, nullable=True)
    last_validated_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    scans = relationship("Scan", back_populates="cloud_account")


class Scan(Base):
    """Scan model matching Laravel's Scan."""

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    # organization_id and initiated_by reference Laravel-managed tables
    organization_id = Column(Integer, nullable=False)
    cloud_account_id = Column(Integer, ForeignKey("cloud_accounts.id"), nullable=False)
    initiated_by = Column(Integer, nullable=False)
    status = Column(String(50), default=ScanStatus.PENDING.value)
    provider = Column(String(50), nullable=False)
    scan_type = Column(String(50), default="full")
    checks_filter = Column(JSON, nullable=True)
    services_filter = Column(JSON, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    total_checks = Column(Integer, default=0)
    passed_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    cloud_account = relationship("CloudAccount", back_populates="scans")
    findings = relationship("ScanFinding", back_populates="scan", cascade="all, delete-orphan")

    def mark_as_running(self) -> None:
        """Mark the scan as running."""
        self.status = ScanStatus.RUNNING.value
        self.started_at = datetime.utcnow()

    def mark_as_completed(
        self, total_checks: int, passed_checks: int, failed_checks: int
    ) -> None:
        """Mark the scan as completed."""
        self.status = ScanStatus.COMPLETED.value
        self.completed_at = datetime.utcnow()
        self.total_checks = total_checks
        self.passed_checks = passed_checks
        self.failed_checks = failed_checks

    def mark_as_failed(self, error_message: str) -> None:
        """Mark the scan as failed."""
        self.status = ScanStatus.FAILED.value
        self.completed_at = datetime.utcnow()
        self.error_message = error_message


class ScanFinding(Base):
    """Scan finding model matching Laravel's ScanFinding."""

    __tablename__ = "scan_findings"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    check_id = Column(String(255), nullable=False)
    status = Column(String(50), nullable=False)  # PASS, FAIL, INFO, MANUAL
    severity = Column(String(50), nullable=False)  # critical, high, medium, low, informational
    service = Column(String(100), nullable=True)
    region = Column(String(50), nullable=True)
    resource_id = Column(String(255), nullable=True)
    resource_arn = Column(Text, nullable=True)
    resource_name = Column(String(255), nullable=True)
    status_extended = Column(Text, nullable=True)
    risk = Column(Text, nullable=True)
    remediation_recommendation = Column(Text, nullable=True)
    remediation_url = Column(Text, nullable=True)
    compliance = Column(JSON, nullable=True)
    raw_finding = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    @classmethod
    def from_prowler_finding(cls, scan_id: int, finding: Any) -> "ScanFinding":
        """Create a ScanFinding from a Prowler finding object.

        Args:
            scan_id: The ID of the scan this finding belongs to
            finding: A Prowler finding object

        Returns:
            A new ScanFinding instance
        """
        # Safely serialize raw_finding to JSON-compatible dict
        raw_finding = None
        if hasattr(finding, "__dict__"):
            raw_finding = cls._serialize_to_json(finding.__dict__)

        # Extract check_metadata for nested properties
        check_metadata = getattr(finding, "check_metadata", None)

        # Extract check_id from check_metadata.CheckID or fallback to finding attribute
        check_id = "unknown"
        if check_metadata and hasattr(check_metadata, "CheckID"):
            check_id = check_metadata.CheckID
        elif hasattr(finding, "check_id"):
            check_id = finding.check_id

        # Extract severity from check_metadata.Severity or fallback
        severity = "informational"
        if check_metadata and hasattr(check_metadata, "Severity"):
            severity = check_metadata.Severity.lower() if check_metadata.Severity else "informational"
        elif hasattr(finding, "severity"):
            severity = finding.severity.lower() if finding.severity else "informational"

        # Extract service from check_metadata.ServiceName or fallback
        service = None
        if check_metadata and hasattr(check_metadata, "ServiceName"):
            service = check_metadata.ServiceName
        elif hasattr(finding, "service_name"):
            service = finding.service_name

        # Extract resource info from finding.resource
        resource = getattr(finding, "resource", None)
        resource_id = None
        resource_arn = None
        resource_name = None
        if resource:
            resource_id = getattr(resource, "name", None) or getattr(resource, "entity", None)
            resource_arn = getattr(resource, "arn", None)
            resource_name = getattr(resource, "name", None)

        # Extract region
        region = getattr(finding, "region", None)

        # Extract remediation info from check_metadata.Remediation
        remediation_recommendation = None
        remediation_url = None
        if check_metadata and hasattr(check_metadata, "Remediation"):
            remediation = check_metadata.Remediation
            if remediation and hasattr(remediation, "Recommendation"):
                rec = remediation.Recommendation
                remediation_recommendation = getattr(rec, "Text", None)
                remediation_url = getattr(rec, "Url", None)

        # Extract risk from check_metadata
        risk = None
        if check_metadata and hasattr(check_metadata, "Risk"):
            risk = check_metadata.Risk

        return cls(
            scan_id=scan_id,
            check_id=check_id,
            status=getattr(finding, "status", "INFO"),
            severity=severity,
            service=service,
            region=region,
            resource_id=resource_id,
            resource_arn=resource_arn,
            resource_name=resource_name,
            status_extended=getattr(finding, "status_extended", None),
            risk=risk,
            remediation_recommendation=remediation_recommendation,
            remediation_url=remediation_url,
            compliance=getattr(finding, "compliance", None),
            raw_finding=raw_finding,
        )

    @staticmethod
    def _serialize_to_json(obj: Any) -> Any:
        """Recursively convert an object to JSON-serializable format.

        Args:
            obj: Object to serialize

        Returns:
            JSON-serializable version of the object
        """
        if obj is None:
            return None
        if isinstance(obj, (str, int, float, bool)):
            return obj
        if isinstance(obj, (datetime,)):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, dict):
            return {k: ScanFinding._serialize_to_json(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [ScanFinding._serialize_to_json(item) for item in obj]
        if hasattr(obj, "__dict__"):
            return ScanFinding._serialize_to_json(obj.__dict__)
        # Fallback to string representation
        return str(obj)
