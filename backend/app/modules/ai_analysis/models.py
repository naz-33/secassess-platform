import enum
import uuid
from datetime import datetime
from typing import Optional, Any
from sqlalchemy import String, Text, DateTime, Integer, ForeignKey, Enum, JSON, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class AIFunction(str, enum.Enum):
    INTERPRET = "interpret"
    PRIORITIZE = "prioritize"
    EXPLAIN = "explain"
    SUMMARIZE = "summarize"


class AIAnalysisStatus(str, enum.Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


class AIReviewStatus(str, enum.Enum):
    NOT_REVIEWED = "not_reviewed"
    APPROVED = "approved"
    REJECTED = "rejected"


class AIAnalysis(Base):
    """Immutable audit log of AI / LLM inferences, prompts, and structured reasoning outputs."""
    __tablename__ = "ai_analyses"

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
    finding_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    function: Mapped[AIFunction] = mapped_column(
        Enum(AIFunction, native_enum=False),
        nullable=False,
        index=True,
    )
    status: Mapped[AIAnalysisStatus] = mapped_column(
        Enum(AIAnalysisStatus, native_enum=False),
        default=AIAnalysisStatus.PENDING,
        nullable=False,
        index=True,
    )
    requested_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(50), nullable=False)
    prompt_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    redaction_report: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    response_json: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    input_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    output_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    review_status: Mapped[AIReviewStatus] = mapped_column(
        Enum(AIReviewStatus, native_enum=False),
        default=AIReviewStatus.NOT_REVIEWED,
        nullable=False,
        index=True,
    )
    reviewed_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    edited_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    review_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
