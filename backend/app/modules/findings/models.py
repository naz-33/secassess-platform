import enum
import uuid
from datetime import datetime
from typing import List, Optional
from sqlalchemy import String, Text, DateTime, ForeignKey, Index, Enum, Float, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class FindingSeverity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, enum.Enum):
    UNVERIFIED = "unverified"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    NEEDS_TESTING = "needs_testing"


class FindingSource(str, enum.Enum):
    TOOL = "tool"
    AI = "ai"


class FindingCategory(str, enum.Enum):
    SECURITY_HEADERS = "security_headers"
    EXPOSED_FILES = "exposed_files"
    INFORMATION_DISCLOSURE = "information_disclosure"
    SESSION_MANAGEMENT = "session_management"
    OTHER = "other"


class EvidenceType(str, enum.Enum):
    OUTPUT = "output"
    SCREENSHOT = "screenshot"
    REQUEST_RESPONSE = "request_response"


class Finding(Base):
    """Vulnerability finding discovered during security assessments."""
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessments.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity, native_enum=False),
        nullable=False,
    )
    original_severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity, native_enum=False),
        nullable=False,
        default=FindingSeverity.INFO,
    )
    final_severity: Mapped[Optional[FindingSeverity]] = mapped_column(
        Enum(FindingSeverity, native_enum=False),
        nullable=True,
    )
    severity_justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    verified_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    verified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    wstg_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    owasp_top10: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    cwe: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    affected_url: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, native_enum=False),
        default=FindingStatus.UNVERIFIED,
        nullable=False,
    )
    source: Mapped[FindingSource] = mapped_column(
        Enum(FindingSource, native_enum=False),
        default=FindingSource.TOOL,
        nullable=False,
    )
    ai_analysis_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ai_analyses.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    fingerprint: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=True,
    )

    evidences: Mapped[List["Evidence"]] = relationship(
        "Evidence",
        back_populates="finding",
        cascade="all, delete-orphan",
    )
    severity_changes: Mapped[List["SeverityChange"]] = relationship(
        "SeverityChange",
        back_populates="finding",
        cascade="all, delete-orphan",
        order_by="SeverityChange.changed_at",
    )

    @property
    def effective_severity(self) -> FindingSeverity:
        """Effective severity is final_severity if overridden, otherwise original_severity."""
        return self.final_severity if self.final_severity is not None else (self.original_severity or self.severity)

    __table_args__ = (
        Index("ix_findings_status_severity", "status", "severity"),
        Index("ix_findings_assessment_fingerprint", "assessment_id", "fingerprint"),
    )


class Evidence(Base):
    """Artifact, raw log snippet, or screenshot supporting a finding."""
    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    type: Mapped[EvidenceType] = mapped_column(
        Enum(EvidenceType, native_enum=False),
        nullable=False,
    )
    content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    uploaded_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    original_filename: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    finding: Mapped["Finding"] = relationship("Finding", back_populates="evidences")


class SeverityChange(Base):
    """Immutable audit record of assessor severity overrides."""
    __tablename__ = "severity_changes"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    old_severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity, native_enum=False),
        nullable=False,
    )
    new_severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity, native_enum=False),
        nullable=False,
    )
    old_cvss: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    new_cvss: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    changed_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        index=True,
        nullable=False,
    )
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    finding: Mapped["Finding"] = relationship("Finding", back_populates="severity_changes")
