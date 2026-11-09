"""PDF conversion utility using headless LibreOffice."""
import logging
import os
import shutil
import subprocess
from pathlib import Path
from app.core.config import settings
from app.core.exceptions import UnprocessableEntityException

logger = logging.getLogger(__name__)


def is_libreoffice_available() -> bool:
    """Check if LibreOffice binary exists and is executable."""
    cmd = settings.LIBREOFFICE_PATH
    return bool(shutil.which(cmd) or os.path.exists(cmd))


def convert_docx_to_pdf(docx_path: str, output_dir: str, timeout_seconds: int = 60) -> str:
    """
    Convert DOCX document to PDF using headless LibreOffice.

    Raises:
        UnprocessableEntityException: If LibreOffice is not installed or conversion fails.
    """
    if not is_libreoffice_available():
        raise UnprocessableEntityException(
            "PDF conversion not available: LibreOffice ('soffice') is not installed or configured on the system."
        )

    docx_p = Path(docx_path).resolve()
    if not docx_p.exists():
        raise FileNotFoundError(f"Source DOCX document not found: {docx_path}")

    out_p = Path(output_dir).resolve()
    out_p.mkdir(parents=True, exist_ok=True)

    cmd = [
        settings.LIBREOFFICE_PATH,
        "--headless",
        "--convert-to",
        "pdf",
        "--outdir",
        str(out_p),
        str(docx_p),
    ]

    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            timeout=timeout_seconds,
            check=True,
        )
        logger.info("LibreOffice PDF conversion succeeded: %s", res.stdout.decode("utf-8", errors="ignore"))
    except subprocess.TimeoutExpired:
        logger.error("LibreOffice conversion timed out after %s seconds", timeout_seconds)
        raise UnprocessableEntityException("PDF conversion timed out.")
    except Exception as exc:
        logger.error("LibreOffice conversion failed: %s", exc)
        raise UnprocessableEntityException(f"PDF conversion failed: {str(exc)}")

    pdf_path = out_p / f"{docx_p.stem}.pdf"
    if not pdf_path.exists():
        raise UnprocessableEntityException("PDF file was not created by LibreOffice.")

    return str(pdf_path)


class PdfReportGenerator:
    """Wrapper class for PDF report generation."""

    @staticmethod
    def convert(docx_path: str, output_dir: str, timeout_seconds: int = 60) -> str:
        return convert_docx_to_pdf(docx_path, output_dir, timeout_seconds=timeout_seconds)

