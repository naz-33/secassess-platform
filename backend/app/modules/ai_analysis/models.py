import enum
import uuid
from datetime import datetime
from typing import Optional, Any
from sqlalchemy import String, Text, DateTime, ForeignKey, Enum, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class AIFunction(str, enum.Enum):
    INTERPRET = "interpret"
    PRIORITIZE = "prioritize"
    REMEDIATE = "remediate"
    SUMMARIZE = "summarize"


class AIAnalysis(Base):
    """Audit log of AI / LLM inferences, prompts, and structured reasoning outputs."""
    __tablename__ = "ai_analyses"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
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
    )
    prompt_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    response_json: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
