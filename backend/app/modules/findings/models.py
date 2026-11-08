import enum
import uuid
from datetime import datetime
from typing import List, Optional
from sqlalchemy import String, Text, DateTime, ForeignKey, Index, Enum, func
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
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    evidences: Mapped[List["Evidence"]] = relationship(
        "Evidence",
        back_populates="finding",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_findings_status_severity", "status", "severity"),
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
    type: Mapped[EvidenceType] = mapped_column(
        Enum(EvidenceType, native_enum=False),
        nullable=False,
    )
    content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    finding: Mapped["Finding"] = relationship("Finding", back_populates="evidences")
