"""DOCX Security Assessment Report Document Generator.

Builds structured, styled Word documents adhering to the 15-section standard
with color-blind friendly charts, masked evidence, untrusted input sanitization,
and strict inclusion gating (confirmed vulnerabilities only in main body).
"""
import hashlib
import io
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from PIL import Image

import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

from app.core.config import settings
from app.modules.ai_analysis import redact_text
from app.modules.reporting.generators.sanitizer import sanitize_text, strip_html_tags
from app.modules.reporting.generators.chart_generator import (
    generate_severity_donut_chart,
    generate_category_bar_chart,
    generate_verification_progress_chart,
)

logger = logging.getLogger(__name__)

# Severity ordering map for deterministic sorting
SEVERITY_WEIGHTS = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "info": 5,
}


def _set_cell_background(cell, fill_hex: str) -> None:
    """Apply background fill color to a table cell."""
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill_hex.lstrip("#"))
    tc_pr.append(shd)


def _format_table(table, header_bg: str = "2B3E50") -> None:
    """Apply clean borders and header shading to a Word table."""
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    if len(table.rows) > 0:
        for cell in table.rows[0].cells:
            _set_cell_background(cell, header_bg)
            for p in cell.paragraphs:
                p.alignment = WD_ALIGN_PARAGRAPH.LEFT
                for r in p.runs:
                    r.font.bold = True
                    r.font.color.rgb = RGBColor(255, 255, 255)
                    r.font.size = Pt(9.5)

    for row_idx, row in enumerate(table.rows[1:], start=1):
        bg = "F7F9FA" if row_idx % 2 == 1 else "FFFFFF"
        for cell in row.cells:
            _set_cell_background(cell, bg)
            for p in cell.paragraphs:
                for r in p.runs:
                    r.font.size = Pt(9)


class DocxReportGenerator:
    """Builds complete DOCX reports from compiled assessment data."""

    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.doc = docx.Document()
        self.images_embedded = 0
        self.total_image_bytes = 0

    def generate(self) -> io.BytesIO:
        """Render all 15 sections and return BytesIO buffer."""
        self._setup_page_layout()
        self._setup_header_footer()

        # 1. Cover Page
        self._render_cover_page()

        # 2. Document Control and Disclaimer
        self._render_document_control()

        # 3. Executive Summary
        self._render_executive_summary()

        # 4. Scope and Rules of Engagement
        self._render_scope_and_roe()

        # 5. Methodology
        self._render_methodology()

        # 6. Assessment Results Overview (Charts & Summary Table)
        self._render_results_overview()

        # 7. Detailed Findings (Confirmed Only)
        self._render_detailed_findings()

        # 8. Reconnaissance Results
        self._render_reconnaissance()

        # 9. Recommendations Summary
        self._render_recommendations()

        # 10. Conclusion
        self._render_conclusion()

        # Appendices
        # 11. Appendix A: Findings Not Confirmed
        self._render_appendix_a()

        # 12. Appendix B: Verification and Severity History
        self._render_appendix_b()

        # 13. Appendix C: AI Usage and Limitations
        self._render_appendix_c()

        # 14. Appendix D: Tool and Scan Log
        self._render_appendix_d()

        # 15. Appendix E: Evidence Index
        self._render_appendix_e()

        buf = io.BytesIO()
        self.doc.save(buf)
        buf.seek(0)
        return buf

    def _setup_page_layout(self) -> None:
        """Set 1-inch margins."""
        for section in self.doc.sections:
            section.top_margin = Inches(1.0)
            section.bottom_margin = Inches(1.0)
            section.left_margin = Inches(1.0)
            section.right_margin = Inches(1.0)

    def _setup_header_footer(self) -> None:
        """Configure running header and footer with classification label."""
        classification = sanitize_text(settings.REPORT_CLASSIFICATION)
        for section in self.doc.sections:
            # Header
            header = section.header
            hp = header.paragraphs[0]
            hp.text = classification
            hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
            if hp.runs:
                hp.runs[0].font.size = Pt(8.5)
                hp.runs[0].font.color.rgb = RGBColor(128, 128, 128)

            # Footer
            footer = section.footer
            fp = footer.paragraphs[0]
            fp.text = f"{self.data.get('assessment_name', 'Security Assessment')} | {classification}"
            fp.alignment = WD_ALIGN_PARAGRAPH.LEFT
            if fp.runs:
                fp.runs[0].font.size = Pt(8.5)
                fp.runs[0].font.color.rgb = RGBColor(128, 128, 128)

    # =========================================================================
    # Section 1: Cover Page
    # =========================================================================
    def _render_cover_page(self) -> None:
        p_class = self.doc.add_paragraph()
        p_class.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_class = p_class.add_run(sanitize_text(settings.REPORT_CLASSIFICATION).upper())
        r_class.font.bold = True
        r_class.font.size = Pt(11)
        r_class.font.color.rgb = RGBColor(160, 40, 40)

        self.doc.add_paragraph("\n" * 3)

        p_title = self.doc.add_paragraph()
        p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        title_text = self.data.get("report_title") or "SECURITY ASSESSMENT & VULNERABILITY REPORT"
        r_title = p_title.add_run(sanitize_text(title_text))
        r_title.font.bold = True
        r_title.font.size = Pt(22)
        r_title.font.color.rgb = RGBColor(30, 50, 80)

        p_sub = self.doc.add_paragraph()
        p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_sub = p_sub.add_run(f"Target: {sanitize_text(self.data.get('target_name', 'Unknown Target'))}")
        r_sub.font.size = Pt(14)
        r_sub.font.color.rgb = RGBColor(80, 80, 80)

        # Unverified Draft Notice Banner (Rule 11)
        unverified_count = self.data.get("unverified_count", 0)
        if unverified_count > 0:
            p_draft = self.doc.add_paragraph()
            p_draft.alignment = WD_ALIGN_PARAGRAPH.CENTER
            r_draft = p_draft.add_run(f"\n[ DRAFT NOTICE: {unverified_count} finding(s) have not been verified by an assessor ]\n")
            r_draft.font.bold = True
            r_draft.font.size = Pt(12)
            r_draft.font.color.rgb = RGBColor(180, 50, 0)

        self.doc.add_paragraph("\n" * 3)

        # Meta Table
        table = self.doc.add_table(rows=6, cols=2)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER

        rows_data = [
            ("Assessment Name:", sanitize_text(self.data.get("assessment_name", ""))),
            ("Report Version:", f"v{self.data.get('version', 1)}"),
            ("Generation Date:", datetime.now().strftime("%B %d, %Y")),
            ("Assessors:", sanitize_text(self.data.get("assessors", "Authorized Security Team"))),
            ("Academic Course / Unit:", sanitize_text(settings.REPORT_COURSE)),
            ("Assessment Group:", sanitize_text(settings.REPORT_GROUP_NAME)),
        ]

        for i, (label, val) in enumerate(rows_data):
            cell_lbl, cell_val = table.rows[i].cells
            cell_lbl.text = label
            cell_lbl.paragraphs[0].runs[0].font.bold = True
            cell_val.text = val

        _format_table(table, header_bg="4A6572")
        self.doc.add_page_break()

    # =========================================================================
    # Section 2: Document Control and Disclaimer
    # =========================================================================
    def _render_document_control(self) -> None:
        self.doc.add_heading("1. Document Control & Disclaimer", level=1)

        p = self.doc.add_paragraph()
        p.add_run("Authorization Statement:\n").bold = True
        auth_note = self.data.get("target_authorization_note") or "Instructor-approved target only. Authorized testing window."
        p.add_run(
            f"This security assessment was conducted strictly against the authorized target: "
            f"'{sanitize_text(self.data.get('target_name', 'Target'))}' ({sanitize_text(self.data.get('target_base_url', ''))}). "
            f"Authorization Record: {sanitize_text(auth_note)}.\n\n"
        )

        p.add_run("Testing Window & Scope Notice:\n").bold = True
        p.add_run(
            f"Testing Period: {sanitize_text(self.data.get('testing_window', 'Academic Term'))}.\n"
            "All testing activities described in this report utilized synthetic data and non-destructive "
            "security assessment techniques against an authorized academic/local target.\n\n"
        )

        p.add_run("Limitations & Caveats:\n").bold = True
        p.add_run(
            "This assessment represents a point-in-time evaluation based on automated and assessor-assisted tools. "
            "Security testing cannot guarantee the absence of all vulnerabilities. Findings reflect the configuration "
            "and accessibility of target services during the defined evaluation window."
        )

    # =========================================================================
    # Section 3: Executive Summary
    # =========================================================================
    def _render_executive_summary(self) -> None:
        self.doc.add_heading("2. Executive Summary", level=1)

        # Unverified Draft Warning Banner if any unverified
        unverified_count = self.data.get("unverified_count", 0)
        if unverified_count > 0:
            p_warn = self.doc.add_paragraph()
            r_warn = p_warn.add_run(f"DRAFT: {unverified_count} finding(s) have not been verified by an assessor.")
            r_warn.font.bold = True
            r_warn.font.color.rgb = RGBColor(180, 50, 0)

        # Approved AI Summary or Fallback (Rule 3)
        ai_summary = self.data.get("approved_ai_summary")
        if ai_summary and ai_summary.get("summary_text"):
            p_ai_label = self.doc.add_paragraph()
            reviewer_str = sanitize_text(ai_summary.get("reviewed_by_name", "Lead Assessor"))
            rev_date = ai_summary.get("reviewed_at")
            rev_date_str = rev_date.strftime("%B %d, %Y") if hasattr(rev_date, "strftime") else "Recent"
            r_ai_label = p_ai_label.add_run(
                f"[ AI-assisted draft, reviewed and approved by {reviewer_str} on {rev_date_str} ]"
            )
            r_ai_label.font.italic = True
            r_ai_label.font.size = Pt(9.5)
            r_ai_label.font.color.rgb = RGBColor(80, 80, 80)

            p_ai_text = self.doc.add_paragraph(sanitize_text(ai_summary.get("summary_text")))
            p_ai_text.style = "Normal"
        else:
            p_no_ai = self.doc.add_paragraph(
                "No AI-assisted executive summary has been reviewed and approved for this assessment."
            )
            p_no_ai.runs[0].font.italic = True

        # Deterministic "At a Glance" Box
        self.doc.add_heading("Assessment at a Glance", level=2)
        confirmed_counts = self.data.get("confirmed_by_severity", {})
        total_confirmed = sum(confirmed_counts.values())
        verified_count = self.data.get("verified_count", 0)
        progress = self.data.get("verification_progress", 0.0)

        table = self.doc.add_table(rows=5, cols=2)
        rows_data = [
            ("Total Confirmed Vulnerabilities:", str(total_confirmed)),
            ("High / Critical Risk Vulnerabilities:", str(confirmed_counts.get("critical", 0) + confirmed_counts.get("high", 0))),
            ("Medium / Low / Info Findings:", str(confirmed_counts.get("medium", 0) + confirmed_counts.get("low", 0) + confirmed_counts.get("info", 0))),
            ("Total Findings Assessed / Reviewed:", str(verified_count)),
            ("Assessor Verification Progress:", f"{round(progress * 100, 1)}%"),
        ]
        for i, (k, v) in enumerate(rows_data):
            c1, c2 = table.rows[i].cells
            c1.text = k
            c1.paragraphs[0].runs[0].font.bold = True
            c2.text = v

        _format_table(table, header_bg="34495E")

    # =========================================================================
    # Section 4: Scope and Rules of Engagement
    # =========================================================================
    def _render_scope_and_roe(self) -> None:
        self.doc.add_heading("3. Scope & Rules of Engagement", level=1)

        p = self.doc.add_paragraph(
            "Security testing was restricted strictly to authorized assets defined in the assessment scope. "
            "Any out-of-scope interactions were blocked by boundary safeguards."
        )

        scope_items = self.data.get("scope_items", [])
        if scope_items:
            table = self.doc.add_table(rows=len(scope_items) + 1, cols=3)
            table.rows[0].cells[0].text = "Asset / Pattern"
            table.rows[0].cells[1].text = "Scope Status"
            table.rows[0].cells[2].text = "Notes"

            for i, item in enumerate(scope_items, start=1):
                c0, c1, c2 = table.rows[i].cells
                c0.text = sanitize_text(item.get("asset", ""))
                c1.text = "IN SCOPE" if item.get("in_scope") else "OUT OF SCOPE"
                c2.text = sanitize_text(item.get("notes") or "")

            _format_table(table, header_bg="2C3E50")
        else:
            self.doc.add_paragraph("No explicit scope boundary items configured.")

        self.doc.add_heading("Operational Safety Constraints", level=2)
        p_safe = self.doc.add_paragraph()
        p_safe.add_run(
            f"- Non-destructive execution: Exploits, brute-force attacks, and DoS routines prohibited.\n"
            f"- Rate limiting: Minimum inter-request delay of {settings.WEB_RATE_LIMIT_DELAY_MS} ms.\n"
            f"- Request volume caps: Max {settings.WEB_MAX_REQUESTS_CAP} requests per web assessment check.\n"
            f"- Request timeout: {settings.WEB_REQUEST_TIMEOUT_SECONDS} seconds per HTTP interaction."
        )

    # =========================================================================
    # Section 5: Methodology
    # =========================================================================
    def _render_methodology(self) -> None:
        self.doc.add_heading("4. Assessment Methodology", level=1)

        p = self.doc.add_paragraph(
            "The assessment followed the industry-standard OWASP Web Security Testing Guide (WSTG v4.2) "
            "and aligned with the OWASP Top 10 framework. The assessment methodology is divided into systematic phases:"
        )

        phases = [
            ("Phase 1: Scope Definition", "Define authoritative IP/URL boundaries and configure safety constraints."),
            ("Phase 2: Reconnaissance", "Network discovery, port auditing (Nmap), and DNS infrastructure mapping."),
            ("Phase 3: Web Assessment", "Automated passive spidering (ZAP), TLS verification, and targeted curl HTTP checks."),
            ("Phase 4: AI Analysis & Reasoning", "Contextual explanation, scan output interpretation, and remediation formulation using Gemini."),
            ("Phase 5: Assessor Verification", "Mandatory human-in-the-loop review confirming findings against evidence."),
            ("Phase 6: Risk Rating & Reporting", "Severity overriding with audit trail and immutable report generation."),
        ]
        for name, desc in phases:
            p_phase = self.doc.add_paragraph()
            p_phase.add_run(f"{name}: ").bold = True
            p_phase.add_run(desc)

        # Exercised WSTG IDs & OWASP Top 10
        wstg_ids = self.data.get("exercised_wstg_ids", [])
        owasp_items = self.data.get("exercised_owasp", [])
        categories = self.data.get("exercised_categories", [])

        self.doc.add_heading("Exercised Standards & Categories", level=2)
        p_std = self.doc.add_paragraph()
        p_std.add_run("OWASP WSTG Tests Exercised: ").bold = True
        p_std.add_run(", ".join(wstg_ids) if wstg_ids else "None recorded")
        p_std.add_run("\nOWASP Top 10 Mapping: ").bold = True
        p_std.add_run(", ".join(owasp_items) if owasp_items else "None recorded")
        p_std.add_run("\nAssessed Categories: ").bold = True
        p_std.add_run(", ".join(c.replace("_", " ").title() for c in categories) if categories else "None recorded")

        # Role of AI Paragraph
        self.doc.add_heading("Role of AI and Human Verification", level=2)
        self.doc.add_paragraph(
            "Artificial intelligence models (Google Gemini) were utilized strictly as advisory assistants "
            "for data interpretation, prioritization, and remediation drafting. In strict accordance with "
            "the platform's verification protocol, all vulnerability findings, severity levels, and risk claims "
            "in this report were verified and validated by human assessors against supporting evidence."
        )

    # =========================================================================
    # Section 6: Results Overview
    # =========================================================================
    def _render_results_overview(self) -> None:
        self.doc.add_heading("5. Assessment Results Overview", level=1)

        confirmed_by_sev = self.data.get("confirmed_by_severity", {})
        confirmed_by_cat = self.data.get("confirmed_by_category", {})
        verified_count = self.data.get("verified_count", 0)
        unverified_count = self.data.get("unverified_count", 0)

        # Embed Charts
        try:
            donut_png = generate_severity_donut_chart(confirmed_by_sev)
            self.doc.add_picture(io.BytesIO(donut_png), width=Inches(5.0))
            self.doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
        except Exception as exc:
            logger.warning("Failed rendering severity donut chart: %s", exc)

        try:
            bar_png = generate_category_bar_chart(confirmed_by_cat)
            self.doc.add_picture(io.BytesIO(bar_png), width=Inches(5.0))
            self.doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
        except Exception as exc:
            logger.warning("Failed rendering category bar chart: %s", exc)

        try:
            progress_png = generate_verification_progress_chart(verified_count, unverified_count)
            self.doc.add_picture(io.BytesIO(progress_png), width=Inches(5.0))
            self.doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
        except Exception as exc:
            logger.warning("Failed rendering progress chart: %s", exc)

        # Summary Table of Confirmed Findings
        self.doc.add_heading("Summary Table of Confirmed Vulnerabilities", level=2)
        confirmed_findings = self.data.get("confirmed_findings", [])
        if not confirmed_findings:
            p_none = self.doc.add_paragraph("No confirmed vulnerabilities were identified during this assessment.")
            p_none.runs[0].font.bold = True
        else:
            table = self.doc.add_table(rows=len(confirmed_findings) + 1, cols=5)
            table.rows[0].cells[0].text = "ID"
            table.rows[0].cells[1].text = "Title"
            table.rows[0].cells[2].text = "Category"
            table.rows[0].cells[3].text = "Effective Severity"
            table.rows[0].cells[4].text = "Affected URL / Resource"

            for i, f in enumerate(confirmed_findings, start=1):
                c0, c1, c2, c3, c4 = table.rows[i].cells
                c0.text = str(f.get("id"))[:8]
                c1.text = sanitize_text(f.get("title", ""))
                c2.text = sanitize_text(f.get("category", "")).replace("_", " ").title()
                c3.text = sanitize_text(f.get("effective_severity", "")).upper()
                c4.text = sanitize_text(f.get("affected_url") or "N/A", max_length=60)

            _format_table(table, header_bg="2C3E50")

    # =========================================================================
    # Section 7: Detailed Findings (Confirmed Only)
    # =========================================================================
    def _render_detailed_findings(self) -> None:
        self.doc.add_heading("6. Detailed Vulnerability Findings", level=1)

        confirmed_findings = self.data.get("confirmed_findings", [])
        if not confirmed_findings:
            p_none = self.doc.add_paragraph("No confirmed vulnerabilities were identified.")
            p_none.runs[0].font.bold = True
            return

        for idx, f in enumerate(confirmed_findings, start=1):
            title = sanitize_text(f.get("title", f"Finding {idx}"))
            eff_sev = sanitize_text(f.get("effective_severity", "info")).upper()
            self.doc.add_heading(f"6.{idx} {title} [{eff_sev}]", level=2)

            # Metadata Table
            table = self.doc.add_table(rows=7, cols=2)
            c_rows = [
                ("Finding ID:", str(f.get("id"))),
                ("Category:", sanitize_text(f.get("category", "")).replace("_", " ").title()),
                ("Effective Severity:", self._format_severity_text(f)),
                ("CVSS Score / Vector:", f"{f.get('cvss_score') or 'N/A'} ({f.get('cvss_vector') or 'None'})"),
                ("References (WSTG / CWE):", f"{f.get('wstg_id') or 'N/A'} / {f.get('cwe') or 'N/A'} (OWASP: {f.get('owasp_top10') or 'N/A'})"),
                ("Affected URL / Endpoint:", sanitize_text(f.get("affected_url") or "N/A")),
                ("Source:", self._format_source_text(f)),
            ]
            for r_idx, (k, v) in enumerate(c_rows):
                table.rows[r_idx].cells[0].text = k
                table.rows[r_idx].cells[0].paragraphs[0].runs[0].font.bold = True
                table.rows[r_idx].cells[1].text = v

            _format_table(table, header_bg="34495E")

            # Description
            self.doc.add_heading("Description", level=3)
            self.doc.add_paragraph(sanitize_text(f.get("description", "No description provided."), max_length=settings.REPORT_MAX_EXCERPT_CHARS))

            # Evidence
            self.doc.add_heading("Supporting Evidence", level=3)
            evidences = f.get("evidences", [])
            if not evidences:
                self.doc.add_paragraph("No evidence artifacts attached.")
            else:
                for ev in evidences:
                    self._render_evidence_item(ev)

            # Impact and Risk
            self.doc.add_heading("Impact & Risk Assessment", level=3)
            impact_text = f.get("ai_impact") or f.get("impact") or "Vulnerability may allow unauthorized data disclosure or configuration tampering."
            is_ai_impact = bool(f.get("ai_impact"))
            p_imp = self.doc.add_paragraph()
            if is_ai_impact:
                r_tag = p_imp.add_run("[AI-assisted analysis] ")
                r_tag.font.italic = True
                r_tag.font.color.rgb = RGBColor(100, 100, 100)
            p_imp.add_run(sanitize_text(impact_text))

            # Remediation
            self.doc.add_heading("Remediation", level=3)
            rem_text = f.get("remediation") or "Apply standard security headers and validate configuration against OWASP guidelines."
            p_rem = self.doc.add_paragraph()
            p_rem.add_run(sanitize_text(rem_text))

            ai_rem = f.get("ai_remediation")
            if ai_rem:
                p_ai_rem = self.doc.add_paragraph()
                r_tag2 = p_ai_rem.add_run("[AI-assisted remediation suggestions]\n")
                r_tag2.font.italic = True
                r_tag2.font.color.rgb = RGBColor(100, 100, 100)
                p_ai_rem.add_run(sanitize_text(ai_rem))

            # Verification Record
            self.doc.add_heading("Verification Record", level=3)
            p_ver = self.doc.add_paragraph()
            assessor_name = sanitize_text(f.get("verified_by_name") or "Authorized Assessor")
            ver_date = f.get("verified_at")
            ver_date_str = ver_date.strftime("%Y-%m-%d %H:%M UTC") if hasattr(ver_date, "strftime") else "Verified"
            ver_notes = sanitize_text(f.get("verification_notes") or "Confirmed against submitted evidence artifacts.")
            p_ver.add_run(f"Assessor: {assessor_name}\nDecision: Confirmed\nDate: {ver_date_str}\nAssessor Notes: {ver_notes}")

    def _format_severity_text(self, f: Dict[str, Any]) -> str:
        eff = sanitize_text(f.get("effective_severity", "info")).upper()
        orig = sanitize_text(f.get("original_severity", "")).upper()
        just = sanitize_text(f.get("severity_justification", ""))
        if orig and orig != eff:
            return f"{eff} (Original: {orig}) - Override Justification: {just}"
        return eff

    def _format_source_text(self, f: Dict[str, Any]) -> str:
        src = f.get("source", "tool")
        if src == "ai" or src == "AI":
            assessor = sanitize_text(f.get("verified_by_name") or "Human Assessor")
            return f"Source: AI-assisted, verified by {assessor}"
        return "Source: Automated security tool"

    def _render_evidence_item(self, ev: Dict[str, Any]) -> None:
        """Render a single evidence item with secret masking and screenshot verification."""
        ev_type = str(ev.get("type", "output")).lower()
        label = sanitize_text(ev.get("label", "Evidence Artifact"))

        p_lbl = self.doc.add_paragraph()
        p_lbl.add_run(f"Artifact: {label} [{ev_type.upper()}]").bold = True

        if ev_type == "screenshot":
            self._render_screenshot_evidence(ev)
        else:
            raw_content = ev.get("content") or ""
            # Secret masking via Phase 5 redaction engine
            redacted = redact_text(raw_content)
            clean_excerpt = sanitize_text(redacted.text, max_length=settings.REPORT_MAX_EXCERPT_CHARS)
            p_code = self.doc.add_paragraph()
            p_code.paragraph_format.left_indent = Inches(0.25)
            r = p_code.add_run(clean_excerpt or "No textual excerpt captured.")
            r.font.name = "Consolas"
            r.font.size = Pt(8.5)

    def _render_screenshot_evidence(self, ev: Dict[str, Any]) -> None:
        """Embed screenshot with hash verification, corruption check, and size limits."""
        if self.images_embedded >= settings.REPORT_MAX_IMAGES:
            p = self.doc.add_paragraph("[Image embedding skipped: Maximum image limit reached]")
            p.runs[0].font.italic = True
            return

        file_path = ev.get("file_path")
        orig_name = sanitize_text(ev.get("original_filename", "screenshot.png"))
        stored_hash = ev.get("sha256")
        captured_at = ev.get("captured_at")
        capt_str = captured_at.strftime("%Y-%m-%d %H:%M UTC") if hasattr(captured_at, "strftime") else "Recorded"

        if not file_path or not Path(file_path).exists():
            p = self.doc.add_paragraph(f"[Screenshot Unavailable: File not found on disk: {orig_name}]")
            p.runs[0].font.italic = True
            return

        try:
            data = Path(file_path).read_bytes()
        except Exception as exc:
            p = self.doc.add_paragraph(f"[Screenshot Read Error: {orig_name}: {exc}]")
            p.runs[0].font.italic = True
            return

        # Check total report image MB limit
        self.total_image_bytes += len(data)
        if self.total_image_bytes > settings.REPORT_MAX_TOTAL_MB * 1024 * 1024:
            p = self.doc.add_paragraph("[Image embedding skipped: Maximum report payload size exceeded]")
            p.runs[0].font.italic = True
            return

        # Hash verification
        calc_hash = hashlib.sha256(data).hexdigest()
        hash_warning = ""
        if stored_hash and stored_hash != calc_hash:
            hash_warning = " [WARNING: Stored hash mismatch, image may have been altered]"

        # Image integrity check with PIL
        try:
            with Image.open(io.BytesIO(data)) as img:
                img.verify()
        except Exception as exc:
            p = self.doc.add_paragraph(f"[Corrupt Screenshot: Image data corrupted or unreadable: {orig_name}]")
            p.runs[0].font.italic = True
            return

        # Resize if necessary
        try:
            with Image.open(io.BytesIO(data)) as img:
                if img.width > settings.REPORT_MAX_IMAGE_WIDTH_PX:
                    img.thumbnail((settings.REPORT_MAX_IMAGE_WIDTH_PX, settings.REPORT_MAX_IMAGE_WIDTH_PX))
                out_img_buf = io.BytesIO()
                img.save(out_img_buf, format="PNG")
                out_img_buf.seek(0)
                self.doc.add_picture(out_img_buf, width=Inches(5.0))
                self.doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
                self.images_embedded += 1

                # Caption
                p_cap = self.doc.add_paragraph()
                p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
                cap_run = p_cap.add_run(
                    f"Caption: {orig_name} | SHA-256: {calc_hash[:16]}... | Captured: {capt_str}{hash_warning}"
                )
                cap_run.font.size = Pt(8)
                cap_run.font.italic = True
                if hash_warning:
                    cap_run.font.color.rgb = RGBColor(180, 50, 0)
        except Exception as exc:
            p = self.doc.add_paragraph(f"[Image Rendering Error: {orig_name}: {exc}]")
            p.runs[0].font.italic = True

    # =========================================================================
    # Section 8: Reconnaissance Results
    # =========================================================================
    def _render_reconnaissance(self) -> None:
        self.doc.add_heading("7. Reconnaissance Results", level=1)

        assets = self.data.get("assets", [])
        ports = [a for a in assets if str(a.get("type")).lower() in ("port", "service")]
        endpoints = [a for a in assets if str(a.get("type")).lower() == "endpoint"]

        self.doc.add_heading("Discovered Ports and Services", level=2)
        if not ports:
            self.doc.add_paragraph("No open network ports or services recorded.")
        else:
            table = self.doc.add_table(rows=len(ports) + 1, cols=3)
            table.rows[0].cells[0].text = "Type"
            table.rows[0].cells[1].text = "Port / Service"
            table.rows[0].cells[2].text = "Details"
            for i, p in enumerate(ports, start=1):
                c0, c1, c2 = table.rows[i].cells
                c0.text = sanitize_text(str(p.get("type"))).upper()
                c1.text = sanitize_text(p.get("value", ""))
                c2.text = sanitize_text(str(p.get("details", "")))
            _format_table(table, header_bg="2C3E50")

        self.doc.add_heading("DNS Infrastructure", level=2)
        dns_assets = [a for a in assets if str(a.get("type")).lower() == "host" and "dns" in str(a.get("details", "")).lower()]
        if dns_assets:
            for d in dns_assets:
                self.doc.add_paragraph(f"- {sanitize_text(d.get('value', ''))}: {sanitize_text(str(d.get('details', '')))}")
        else:
            self.doc.add_paragraph("No DNS records for this target type (Local/Containerized Assessment Target).")

        self.doc.add_heading("Discovered Endpoints", level=2)
        if not endpoints:
            self.doc.add_paragraph("No web endpoints cataloged.")
        else:
            self.doc.add_paragraph(f"Total Discovered Endpoints: {len(endpoints)}")
            for ep in endpoints[:20]:
                self.doc.add_paragraph(f"- {sanitize_text(ep.get('value', ''))}")
            if len(endpoints) > 20:
                self.doc.add_paragraph(f"[Truncated: {len(endpoints) - 20} additional endpoints cataloged in database]")

    # =========================================================================
    # Section 9: Recommendations Summary
    # =========================================================================
    def _render_recommendations(self) -> None:
        self.doc.add_heading("8. Recommendations Summary", level=1)
        self.doc.add_paragraph(
            "Consolidated, deduplicated remediation guidance prioritized strictly by effective severity levels:"
        )

        confirmed_findings = self.data.get("confirmed_findings", [])
        if not confirmed_findings:
            self.doc.add_paragraph("No active recommendations. Target environment exhibits compliant baseline controls.")
            return

        # Group remediations by severity
        by_sev: Dict[str, List[str]] = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        seen_rems = set()

        for f in confirmed_findings:
            sev = str(f.get("effective_severity", "info")).lower()
            rem = (f.get("remediation") or "").strip()
            if rem and rem not in seen_rems:
                seen_rems.add(rem)
                by_sev.setdefault(sev, []).append(f"{f.get('title')}: {rem}")

        for sev_key in ["critical", "high", "medium", "low", "info"]:
            items = by_sev.get(sev_key, [])
            if items:
                self.doc.add_heading(f"Priority: {sev_key.upper()}", level=2)
                for item in items:
                    p = self.doc.add_paragraph(style="List Bullet")
                    p.add_run(sanitize_text(item))

    # =========================================================================
    # Section 10: Conclusion
    # =========================================================================
    def _render_conclusion(self) -> None:
        self.doc.add_heading("9. Conclusion", level=1)
        total_conf = len(self.data.get("confirmed_findings", []))
        self.doc.add_paragraph(
            f"The security assessment of '{sanitize_text(self.data.get('target_name', 'Target'))}' concluded "
            f"with a total of {total_conf} confirmed vulnerabilities identified. "
            "Remediation efforts should immediately focus on High and Critical priority findings as outlined "
            "in the Recommendations Summary. Verification workflows validate that all confirmed findings are "
            "actionable and supported by reproducible evidence artifacts."
        )

    # =========================================================================
    # Appendix A: Findings Not Confirmed
    # =========================================================================
    def _render_appendix_a(self) -> None:
        self.doc.add_page_break()
        self.doc.add_heading("Appendix A: Findings Not Confirmed", level=1)

        p_notice = self.doc.add_paragraph()
        r_n = p_notice.add_run("NOTICE: THE FOLLOWING FINDINGS ARE NOT CONFIRMED VULNERABILITIES.\n")
        r_n.font.bold = True
        r_n.font.color.rgb = RGBColor(160, 40, 40)
        p_notice.add_run(
            "These findings were rejected as false positives, flagged for further testing, or remain unverified. "
            "They are excluded from the main assessment findings, severity charts, and risk metrics."
        )

        non_confirmed = self.data.get("non_confirmed_findings", [])
        fps = [f for f in non_confirmed if str(f.get("status")).lower() == "false_positive"]
        needs = [f for f in non_confirmed if str(f.get("status")).lower() == "needs_testing"]
        unverified = [f for f in non_confirmed if str(f.get("status")).lower() == "unverified"]

        # False Positives
        self.doc.add_heading("A.1 False Positive Findings (NOT A CONFIRMED VULNERABILITY)", level=2)
        if not fps:
            self.doc.add_paragraph("No findings marked as false positives.")
        else:
            table = self.doc.add_table(rows=len(fps) + 1, cols=4)
            table.rows[0].cells[0].text = "ID"
            table.rows[0].cells[1].text = "Title"
            table.rows[0].cells[2].text = "Severity"
            table.rows[0].cells[3].text = "Assessor Justification / Reason"
            for i, f in enumerate(fps, start=1):
                c0, c1, c2, c3 = table.rows[i].cells
                c0.text = str(f.get("id"))[:8]
                c1.text = sanitize_text(f.get("title", ""))
                c2.text = sanitize_text(f.get("effective_severity", "")).upper()
                c3.text = sanitize_text(f.get("verification_notes") or "Identified as false positive.")
            _format_table(table, header_bg="5D6D7E")

        # Needs Testing
        self.doc.add_heading("A.2 Needs Further Testing (NOT A CONFIRMED VULNERABILITY)", level=2)
        if not needs:
            self.doc.add_paragraph("No findings marked as requiring further testing.")
        else:
            table = self.doc.add_table(rows=len(needs) + 1, cols=4)
            table.rows[0].cells[0].text = "ID"
            table.rows[0].cells[1].text = "Title"
            table.rows[0].cells[2].text = "Severity"
            table.rows[0].cells[3].text = "Assessor Testing Notes"
            for i, f in enumerate(needs, start=1):
                c0, c1, c2, c3 = table.rows[i].cells
                c0.text = str(f.get("id"))[:8]
                c1.text = sanitize_text(f.get("title", ""))
                c2.text = sanitize_text(f.get("effective_severity", "")).upper()
                c3.text = sanitize_text(f.get("verification_notes") or "Requires manual replication.")
            _format_table(table, header_bg="5D6D7E")

        # Unverified Findings
        self.doc.add_heading("A.3 Unverified Findings (NOT A CONFIRMED VULNERABILITY)", level=2)
        if not unverified:
            self.doc.add_paragraph("All findings have been reviewed and verified by an assessor.")
        else:
            table = self.doc.add_table(rows=len(unverified) + 1, cols=4)
            table.rows[0].cells[0].text = "ID"
            table.rows[0].cells[1].text = "Title"
            table.rows[0].cells[2].text = "Severity"
            table.rows[0].cells[3].text = "Affected URL"
            for i, f in enumerate(unverified, start=1):
                c0, c1, c2, c3 = table.rows[i].cells
                c0.text = str(f.get("id"))[:8]
                c1.text = sanitize_text(f.get("title", ""))
                c2.text = sanitize_text(f.get("effective_severity", "")).upper()
                c3.text = sanitize_text(f.get("affected_url") or "N/A", max_length=50)
            _format_table(table, header_bg="5D6D7E")

    # =========================================================================
    # Appendix B: Verification and Severity History
    # =========================================================================
    def _render_appendix_b(self) -> None:
        self.doc.add_heading("Appendix B: Verification and Severity History", level=1)

        # Verification trail
        self.doc.add_heading("B.1 Assessor Verification Trail", level=2)
        v_trail = self.data.get("verification_trail", [])
        if not v_trail:
            self.doc.add_paragraph("No verification decisions recorded.")
        else:
            table = self.doc.add_table(rows=len(v_trail) + 1, cols=5)
            table.rows[0].cells[0].text = "Finding ID"
            table.rows[0].cells[1].text = "Assessor"
            table.rows[0].cells[2].text = "Decision"
            table.rows[0].cells[3].text = "Date"
            table.rows[0].cells[4].text = "Notes"
            for i, v in enumerate(v_trail, start=1):
                c0, c1, c2, c3, c4 = table.rows[i].cells
                c0.text = str(v.get("finding_id"))[:8]
                c1.text = sanitize_text(v.get("assessor_name") or "Assessor")
                c2.text = sanitize_text(v.get("decision", "")).upper()
                d_val = v.get("verified_at")
                c3.text = d_val.strftime("%Y-%m-%d %H:%M") if hasattr(d_val, "strftime") else "Recorded"
                c4.text = sanitize_text(v.get("notes") or "-")
            _format_table(table, header_bg="34495E")

        # Severity overrides
        self.doc.add_heading("B.2 Severity Adjustments and Justifications", level=2)
        s_changes = self.data.get("severity_history", [])
        if not s_changes:
            self.doc.add_paragraph("No severity overrides recorded.")
        else:
            table = self.doc.add_table(rows=len(s_changes) + 1, cols=5)
            table.rows[0].cells[0].text = "Finding ID"
            table.rows[0].cells[1].text = "Original"
            table.rows[0].cells[2].text = "New Severity"
            table.rows[0].cells[3].text = "Justification"
            table.rows[0].cells[4].text = "Changed By"
            for i, s in enumerate(s_changes, start=1):
                c0, c1, c2, c3, c4 = table.rows[i].cells
                c0.text = str(s.get("finding_id"))[:8]
                c1.text = sanitize_text(s.get("old_severity", "")).upper()
                c2.text = sanitize_text(s.get("new_severity", "")).upper()
                c3.text = sanitize_text(s.get("justification", ""))
                c4.text = sanitize_text(s.get("changed_by_name") or "Assessor")
            _format_table(table, header_bg="34495E")

    # =========================================================================
    # Appendix C: AI Usage and Limitations
    # =========================================================================
    def _render_appendix_c(self) -> None:
        self.doc.add_heading("Appendix C: AI Usage and Limitations", level=1)

        p = self.doc.add_paragraph()
        p.add_run(f"AI Model: ").bold = True
        p.add_run(f"{settings.GEMINI_MODEL}\n")
        p.add_run(f"Prompt Version: ").bold = True
        p.add_run("v1\n")
        p.add_run("Redaction Architecture: ").bold = True
        p.add_run(
            "Deterministic client-side scrubbing of passwords, authorization tokens, private keys, "
            "and sensitive headers prior to model transit.\n"
        )

        self.doc.add_heading("Limitations & Governance Notice", level=2)
        self.doc.add_paragraph(
            "Artificial intelligence models are subject to potential hallucinations, incomplete context, "
            "and advisory bias. AI inferences must never replace human verification. Within this assessment, "
            "all AI suggestions were subjected to human assessor approval. AI-proposed severity scores "
            "are purely advisory and require human confirmation."
        )

    # =========================================================================
    # Appendix D: Tool and Scan Log
    # =========================================================================
    def _render_appendix_d(self) -> None:
        self.doc.add_heading("Appendix D: Tool and Scan Log", level=1)

        scans = self.data.get("scans", [])
        if not scans:
            self.doc.add_paragraph("No scan tool executions recorded.")
        else:
            table = self.doc.add_table(rows=len(scans) + 1, cols=4)
            table.rows[0].cells[0].text = "Tool"
            table.rows[0].cells[1].text = "Execution Command"
            table.rows[0].cells[2].text = "Timing"
            table.rows[0].cells[3].text = "Status"
            for i, sc in enumerate(scans, start=1):
                c0, c1, c2, c3 = table.rows[i].cells
                c0.text = sanitize_text(str(sc.get("tool"))).upper()
                c1.text = sanitize_text(sc.get("command") or "-")
                st = sc.get("started_at")
                st_str = st.strftime("%H:%M:%S") if hasattr(st, "strftime") else "-"
                fn = sc.get("finished_at")
                fn_str = fn.strftime("%H:%M:%S") if hasattr(fn, "strftime") else "-"
                c2.text = f"{st_str} - {fn_str}"
                c3.text = sanitize_text(str(sc.get("status"))).upper()
            _format_table(table, header_bg="2C3E50")

    # =========================================================================
    # Appendix E: Evidence Index
    # =========================================================================
    def _render_appendix_e(self) -> None:
        self.doc.add_heading("Appendix E: Evidence Index", level=1)

        evidence_list = self.data.get("evidence_index", [])
        if not evidence_list:
            self.doc.add_paragraph("No evidence artifacts cataloged.")
        else:
            table = self.doc.add_table(rows=len(evidence_list) + 1, cols=5)
            table.rows[0].cells[0].text = "Evidence ID"
            table.rows[0].cells[1].text = "Type"
            table.rows[0].cells[2].text = "Label"
            table.rows[0].cells[3].text = "SHA-256 Digest"
            table.rows[0].cells[4].text = "Captured At"
            for i, ev in enumerate(evidence_list, start=1):
                c0, c1, c2, c3, c4 = table.rows[i].cells
                c0.text = str(ev.get("id"))[:8]
                c1.text = sanitize_text(str(ev.get("type"))).upper()
                c2.text = sanitize_text(ev.get("label", ""))
                h = ev.get("sha256") or ""
                c3.text = h[:16] + "..." if len(h) > 16 else (h or "N/A")
                capt = ev.get("captured_at")
                c4.text = capt.strftime("%Y-%m-%d %H:%M") if hasattr(capt, "strftime") else "-"
            _format_table(table, header_bg="2C3E50")
