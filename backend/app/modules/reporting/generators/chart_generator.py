"""Matplotlib chart generation for security assessment reports.

Uses headless Agg backend and color-blind safe palettes with accessible text labels.
"""
import io
from typing import Dict
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Color-blind friendly palette (Okabe-Ito inspired)
SEVERITY_COLORS = {
    "critical": "#D55E00",  # Vermilion
    "high": "#E69F00",      # Orange
    "medium": "#F0E442",    # Yellow
    "low": "#56B4E9",       # Sky Blue
    "info": "#0072B2",      # Blue
}

CATEGORY_COLORS = [
    "#0072B2", "#D55E00", "#009E73", "#E69F00", "#56B4E9", "#CC79A7", "#F0E442"
]


def generate_severity_donut_chart(counts: Dict[str, int]) -> bytes:
    """
    Generate a color-blind accessible donut chart of confirmed findings by effective severity.
    Includes explicit count and percentage labels.
    """
    labels = []
    values = []
    colors = []

    ordered_keys = ["critical", "high", "medium", "low", "info"]
    for k in ordered_keys:
        cnt = counts.get(k, 0)
        labels.append(f"{k.capitalize()} ({cnt})")
        values.append(cnt)
        colors.append(SEVERITY_COLORS.get(k, "#999999"))

    total = sum(values)

    fig, ax = plt.subplots(figsize=(6, 4.2), dpi=150)
    if total == 0:
        # Empty placeholder state
        ax.text(
            0.5, 0.5, "No Confirmed Vulnerabilities",
            horizontalalignment="center", verticalalignment="center",
            transform=ax.transAxes, fontsize=12, color="#444444", fontweight="bold"
        )
        ax.axis("off")
    else:
        # Non-zero values for wedge display
        active_values = []
        active_labels = []
        active_colors = []
        for val, lbl, col in zip(values, labels, colors):
            if val > 0:
                active_values.append(val)
                active_labels.append(lbl)
                active_colors.append(col)

        wedges, texts, autotexts = ax.pie(
            active_values,
            labels=active_labels,
            colors=active_colors,
            autopct="%1.0f%%",
            startangle=90,
            pctdistance=0.75,
            textprops={"fontsize": 9, "fontweight": "medium"},
            wedgeprops={"width": 0.45, "edgecolor": "white", "linewidth": 2},
        )
        for at in autotexts:
            at.set_color("#222222")
            at.set_fontweight("bold")

        ax.set_title("Confirmed Vulnerabilities by Effective Severity", fontsize=11, fontweight="bold", pad=15)

    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format="png", bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return buf.getvalue()


def generate_category_bar_chart(counts: Dict[str, int]) -> bytes:
    """
    Generate horizontal bar chart of confirmed findings by category.
    """
    fig, ax = plt.subplots(figsize=(6, 3.5), dpi=150)

    if not counts or sum(counts.values()) == 0:
        ax.text(
            0.5, 0.5, "No Findings Recorded",
            horizontalalignment="center", verticalalignment="center",
            transform=ax.transAxes, fontsize=12, color="#444444", fontweight="bold"
        )
        ax.axis("off")
    else:
        # Sort by count ascending so highest is at top
        sorted_items = sorted(counts.items(), key=lambda x: x[1])
        categories = [k.replace("_", " ").title() for k, v in sorted_items]
        values = [v for k, v in sorted_items]

        bar_colors = [CATEGORY_COLORS[i % len(CATEGORY_COLORS)] for i in range(len(categories))]
        bars = ax.barh(categories, values, color=bar_colors, edgecolor="#333333", height=0.55)

        # Add explicit numeric labels on each bar
        for bar in bars:
            w = bar.get_width()
            ax.text(
                w + 0.1, bar.get_y() + bar.get_height() / 2,
                str(int(w)),
                va="center", ha="left", fontsize=9, fontweight="bold"
            )

        ax.set_xlabel("Number of Findings", fontsize=9, fontweight="bold")
        ax.set_title("Confirmed Vulnerabilities by Category", fontsize=11, fontweight="bold", pad=12)
        ax.xaxis.get_major_locator().set_params(integer=True)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format="png", bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return buf.getvalue()


def generate_verification_progress_chart(verified_count: int, unverified_count: int) -> bytes:
    """
    Generate horizontal progress bar chart for assessor verification status.
    """
    fig, ax = plt.subplots(figsize=(6, 1.8), dpi=150)
    total = verified_count + unverified_count

    if total == 0:
        ax.text(
            0.5, 0.5, "No Findings Discovered",
            horizontalalignment="center", verticalalignment="center",
            transform=ax.transAxes, fontsize=11, color="#444444"
        )
        ax.axis("off")
    else:
        pct_verified = round((verified_count / total) * 100, 1)

        ax.barh(["Verification"], [verified_count], color="#009E73", label=f"Verified: {verified_count}", height=0.45)
        ax.barh(["Verification"], [unverified_count], left=[verified_count], color="#E69F00", label=f"Unverified: {unverified_count}", height=0.45)

        ax.text(
            total / 2, 0, f"{pct_verified}% Verified ({verified_count}/{total})",
            ha="center", va="center", color="white", fontweight="bold", fontsize=10
        )
        ax.set_xlim(0, max(total, 1))
        ax.set_title("Assessor Verification Progress", fontsize=10, fontweight="bold", pad=10)
        ax.legend(loc="lower center", bbox_to_anchor=(0.5, -0.6), ncol=2, frameon=False, fontsize=8)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_visible(False)
        ax.get_yaxis().set_visible(False)

    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format="png", bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return buf.getvalue()

