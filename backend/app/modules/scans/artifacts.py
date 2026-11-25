"""Helpers for capturing and persisting raw tool invocation artifacts."""
import hashlib
import uuid
from pathlib import Path
from typing import Optional
from sqlalchemy.orm import Session

from app.core.config import settings
from app.modules.scans.models import ScanArtifact


def to_raw_bytes(value: bytes | str | None) -> bytes:
    """Return raw bytes untouched, or encode a str fallback (e.g. mocked tests)."""
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8", errors="replace")


def _ensure_within_dir(path: Path, root: Path) -> Path:
    resolved_root = root.resolve()
    resolved_path = path.resolve()
    resolved_path.relative_to(resolved_root)
    return resolved_path


def save_raw_artifact(
    db: Session,
    *,
    scan_id: uuid.UUID,
    tool: str,
    stdout_bytes: bytes,
    stderr_bytes: bytes = b"",
    command: Optional[str] = None,
    target_url: Optional[str] = None,
    exit_code: Optional[int] = None,
    duration_ms: Optional[float] = None,
    invocation_id: Optional[uuid.UUID] = None,
) -> ScanArtifact:
    """
    Persist unmodified stdout (and non-empty stderr) bytes to ARTIFACT_DIR
    using exclusive-create mode so existing files are never overwritten,
    and record metadata + SHA-256 in scan_artifacts.
    """
    inv_id = invocation_id or uuid.uuid4()
    artifact_root = Path(settings.ARTIFACT_DIR).resolve()
    scan_dir = _ensure_within_dir(artifact_root / str(scan_id), artifact_root)
    scan_dir.mkdir(parents=True, exist_ok=True)

    stdout_path = _ensure_within_dir(scan_dir / f"{inv_id}.raw", artifact_root)
    with open(stdout_path, "xb") as fh:
        fh.write(stdout_bytes)

    if stderr_bytes:
        stderr_path = _ensure_within_dir(scan_dir / f"{inv_id}.stderr", artifact_root)
        with open(stderr_path, "xb") as fh:
            fh.write(stderr_bytes)

    digest = hashlib.sha256(stdout_bytes).hexdigest()
    artifact = ScanArtifact(
        id=inv_id,
        scan_id=scan_id,
        tool=tool,
        command=command,
        target_url=target_url,
        exit_code=exit_code,
        duration_ms=duration_ms,
        file_path=str(stdout_path),
        sha256=digest,
        size_bytes=len(stdout_bytes),
    )
    db.add(artifact)
    db.commit()
    db.refresh(artifact)
    return artifact
