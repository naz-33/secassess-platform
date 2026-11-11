import enum
import uuid
from datetime import datetime
from typing import Optional, Any, List
from sqlalchemy import String, DateTime, ForeignKey, Enum, Index, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class AssetType(str, enum.Enum):
    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    ENDPOINT = "endpoint"


class Asset(Base):
    """Discovered network or service asset from reconnaissance scans."""
    __tablename__ = "assets"
    __table_args__ = (
        Index("ix_assets_assessment_type_value", "assessment_id", "type", "value"),
    )

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
    discoveries: Mapped[List["AssetDiscovery"]] = relationship(
        "AssetDiscovery",
        back_populates="asset",
        cascade="all, delete-orphan",
        order_by="AssetDiscovery.created_at",
    )

    @property
    def scan_ids(self) -> List[uuid.UUID]:
        """Return every scan associated with this asset, including legacy rows."""
        scan_ids = [discovery.scan_id for discovery in self.discoveries]
        if self.scan_id is not None:
            scan_ids.append(self.scan_id)
        return list(dict.fromkeys(scan_ids))


class AssetDiscovery(Base):
    """Records each scan that discovered a deduplicated assessment asset."""
    __tablename__ = "asset_discoveries"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        primary_key=True,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    )
    details: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    asset: Mapped[Asset] = relationship("Asset", back_populates="discoveries")
