import enum
import uuid
from datetime import datetime
from typing import Optional, Any
from sqlalchemy import String, DateTime, ForeignKey, Integer, BigInteger, Enum, Text, JSON, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class ReportStatus(str, enum.Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


class ReportFormat(str, enum.Enum):
    DOCX = "docx"
    PDF = "pdf"


class Report(Base):
    """Generated vulnerability and assessment report document metadata."""
    __tablename__ = "reports"

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
    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
    )
    format: Mapped[ReportFormat] = mapped_column(
        Enum(ReportFormat, native_enum=False),
        nullable=False,
        default=ReportFormat.DOCX,
    )
    status: Mapped[ReportStatus] = mapped_column(
        Enum(ReportStatus, native_enum=False),
        nullable=False,
        default=ReportStatus.PENDING,
        index=True,
    )
    file_path: Mapped[Optional[str]] = mapped_column(
        String(1024),
        nullable=True,
    )
    filename: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    sha256: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    size_bytes: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True,
    )
    generated_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    generated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    template_version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="1.0.0",
    )
    generator_version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="1.0.0",
    )
    snapshot_json: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    unverified_count_at_generation: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    confirmed_count_at_generation: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    error: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
