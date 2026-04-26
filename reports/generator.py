"""
reports/generator.py - HTML Audit Report Generator

Takes a list of audit results and produces a self-contained HTML report
with a summary, a CSS-only pie chart, and a colour-coded results table.

No external libraries required — uses only Python builtins.
"""

import os
from datetime import datetime
from html import escape


# Path to the results/ directory (sibling of reports/)
RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results")


def generate_html_report(
    results: list[dict[str, str]],
    output_path: str | None = None,
) -> str:
    """
    Build an HTML report from audit results and write it to disk.

    Args:
        results:     List of dicts with keys check_name, status, details.
        output_path: Where to save the file. Defaults to results/audit_report.html.

    Returns:
        Absolute path of the saved report.
    """
    if output_path is None:
        os.makedirs(RESULTS_DIR, exist_ok=True)
        output_path = os.path.join(RESULTS_DIR, "audit_report.html")

    total   = len(results)
    passed  = sum(1 for r in results if r["status"] == "PASS")
    failed  = total - passed
    pct     = round((passed / total) * 100) if total else 0
    now     = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

    table_rows = _build_table_rows(results)
    html       = _TEMPLATE.format(
        date=now,
        total=total,
        passed=passed,
        failed=failed,
        pct_pass=pct,
        pct_fail=100 - pct,
        rows=table_rows,
    )

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    return os.path.abspath(output_path)


def _build_table_rows(results: list[dict[str, str]]) -> str:
    """Return HTML <tr> elements for every result."""
    rows: list[str] = []
    for idx, item in enumerate(results, start=1):
        status_class = "pass" if item["status"] == "PASS" else "fail"
        rows.append(
            f"  <tr class='{status_class}'>"
            f"<td>{idx}</td>"
            f"<td>{escape(item['check_name'])}</td>"
            f"<td class='badge'>{escape(item['status'])}</td>"
            f"<td>{escape(item['details'])}</td>"
            f"</tr>"
        )
    return "\n".join(rows)


# ── Self-contained HTML template ────────────────────────────────
_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CIS Benchmark Audit Report</title>
<style>
  /* ── Reset & base ────────────────────────────────── */
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #1e1e2e;
    color: #cdd6f4;
    padding: 32px 48px;
  }}

  /* ── Header ──────────────────────────────────────── */
  h1 {{
    text-align: center;
    font-size: 26px;
    margin-bottom: 4px;
  }}
  .subtitle {{
    text-align: center;
    color: #6c7086;
    margin-bottom: 28px;
  }}

  /* ── Summary cards ───────────────────────────────── */
  .summary {{
    display: flex;
    gap: 16px;
    justify-content: center;
    flex-wrap: wrap;
    margin-bottom: 32px;
  }}
  .card {{
    background: #313244;
    border-radius: 12px;
    padding: 18px 28px;
    min-width: 140px;
    text-align: center;
  }}
  .card .value {{
    font-size: 32px;
    font-weight: 700;
  }}
  .card .label {{
    font-size: 13px;
    color: #6c7086;
    margin-top: 4px;
  }}
  .card.pass .value {{ color: #a6e3a1; }}
  .card.fail .value {{ color: #f38ba8; }}
  .card.total .value {{ color: #89b4fa; }}

  /* ── Pie chart (pure CSS conic-gradient) ─────────── */
  .chart-section {{
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 24px;
    margin-bottom: 36px;
  }}
  .pie {{
    width: 140px;
    height: 140px;
    border-radius: 50%;
    background: conic-gradient(
      #a6e3a1 0% {pct_pass}%,
      #f38ba8 {pct_pass}% 100%
    );
    box-shadow: 0 0 0 6px #313244;
  }}
  .legend {{
    display: flex;
    flex-direction: column;
    gap: 8px;
  }}
  .legend-item {{
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 14px;
  }}
  .legend-dot {{
    width: 14px;
    height: 14px;
    border-radius: 4px;
  }}
  .legend-dot.green {{ background: #a6e3a1; }}
  .legend-dot.red   {{ background: #f38ba8; }}

  /* ── Table ───────────────────────────────────────── */
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
  }}
  thead th {{
    background: #45475a;
    padding: 10px 14px;
    text-align: left;
    font-weight: 600;
  }}
  thead th:nth-child(1) {{ width: 40px; text-align: center; }}
  thead th:nth-child(3) {{ width: 80px; text-align: center; }}

  tbody td {{
    padding: 9px 14px;
    border-bottom: 1px solid #313244;
  }}
  tbody td:nth-child(1) {{ text-align: center; color: #6c7086; }}

  /* Row colours */
  tr.pass {{ background: rgba(166, 227, 161, 0.10); }}
  tr.fail {{ background: rgba(243, 139, 168, 0.10); }}

  /* Status badge */
  td.badge {{
    text-align: center;
    font-weight: 700;
    font-size: 12px;
    letter-spacing: 0.5px;
  }}
  tr.pass td.badge {{ color: #a6e3a1; }}
  tr.fail td.badge {{ color: #f38ba8; }}

  /* ── Footer ──────────────────────────────────────── */
  footer {{
    text-align: center;
    margin-top: 32px;
    color: #6c7086;
    font-size: 12px;
  }}
</style>
</head>
<body>

<h1>🛡 CIS Benchmark Audit Report</h1>
<p class="subtitle">Generated on {date}</p>

<!-- Summary cards -->
<div class="summary">
  <div class="card total"><div class="value">{total}</div><div class="label">Total Checks</div></div>
  <div class="card pass"><div class="value">{passed}</div><div class="label">Passed</div></div>
  <div class="card fail"><div class="value">{failed}</div><div class="label">Failed</div></div>
</div>

<!-- Pie chart -->
<div class="chart-section">
  <div class="pie"></div>
  <div class="legend">
    <div class="legend-item"><span class="legend-dot green"></span> Passed — {pct_pass}%</div>
    <div class="legend-item"><span class="legend-dot red"></span> Failed — {pct_fail}%</div>
  </div>
</div>

<!-- Results table -->
<table>
  <thead>
    <tr><th>#</th><th>Check Name</th><th>Status</th><th>Details</th></tr>
  </thead>
  <tbody>
{rows}
  </tbody>
</table>

<footer>CIS Benchmark Audit Tool — Auto-generated report</footer>
</body>
</html>
"""
