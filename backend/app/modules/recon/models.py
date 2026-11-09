import enum
import uuid
from datetime import datetime
from typing import Optional, Any
from sqlalchemy import String, DateTime, ForeignKey, Enum, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class AssetType(str, enum.Enum):
    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    ENDPOINT = "endpoint"


class Asset(Base):
    """Discovered network or service asset from reconnaissance scans."""
    __tablename__ = "assets"

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
        ForeignKey("scans.id", ondelete="CASCADE"),
        index=True,
        nullable=True,
    )
    type: Mapped[AssetType] = mapped_column(
        Enum(AssetType, native_enum=False),
        nullable=False,
    )
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    details: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, default=dict, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
