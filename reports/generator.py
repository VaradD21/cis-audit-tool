
import os
from datetime import datetime
from html import escape
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

    total   = len(results) or 1  # Prevent division by zero
    passed  = sum(1 for r in results if r["status"] == "PASS")
    failed  = total - passed
    pct_pass = round((passed / total) * 100) if total else 0
    pct_fail = 100 - pct_pass
    now     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    table_rows = _build_table_rows(results)
    html       = _TEMPLATE.format(
        date=now,
        total=total,
        passed=passed,
        failed=failed,
        pct_pass=pct_pass,
        pct_fail=pct_fail,
        rows=table_rows,
    )

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    return os.path.abspath(output_path)


def generate_pdf_report(
    results: list[dict[str, str]],
    output_path: str | None = None,
) -> str:
    """
    Build a PDF report from audit results.
    """
    html_path = generate_html_report(results)
    
    if output_path is None:
        os.makedirs(RESULTS_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(RESULTS_DIR, f"audit_report_{timestamp}.pdf")

    try:
        from xhtml2pdf import pisa
        with open(html_path, "r", encoding="utf-8") as f:
            html_content = f.read()
        with open(output_path, "wb") as f:
            pisa_status = pisa.CreatePDF(html_content, dest=f)
        if pisa_status.err:
            raise RuntimeError("PDF generation failed with xhtml2pdf.")
        return os.path.abspath(output_path)
    except ImportError:
        try:
            from weasyprint import HTML
            HTML(filename=html_path).write_pdf(output_path)
            return os.path.abspath(output_path)
        except Exception as e:
            raise RuntimeError("PDF generation requires 'xhtml2pdf'. Please run: pip install xhtml2pdf")


def _build_table_rows(results: list[dict[str, str]]) -> str:
    """Return HTML <tr> elements for every result."""
    rows: list[str] = []
    for idx, item in enumerate(results, start=1):
        status_class = "pass" if item["status"] == "PASS" else "fail"
        severity = item.get('severity', 'Unknown')
        impact = item.get('impact', 'Unknown')
        rows.append(
            f"  <tr class='{status_class}'>"
            f"<td>{idx}</td>"
            f"<td>{escape(item['check_name'])}</td>"
            f"<td class='badge'>{escape(item['status'])}</td>"
            f"<td>{escape(severity)}</td>"
            f"<td>{escape(impact)}</td>"
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
    background: #ffffff;
    color: #000000;
    padding: 32px 48px;
  }}

  /* ── Header ──────────────────────────────────────── */
  h1 {{
    text-align: center;
    font-size: 26px;
    margin-bottom: 4px;
    color: #000000;
  }}
  .subtitle {{
    text-align: center;
    color: #666666;
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
    background: #f0f0f0;
    border-radius: 12px;
    padding: 18px 28px;
    min-width: 140px;
    text-align: center;
    border: 1px solid #dddddd;
  }}
  .card .value {{
    font-size: 32px;
    font-weight: 700;
  }}
  .card .label {{
    font-size: 13px;
    color: #666666;
    margin-top: 4px;
  }}
  .card.pass .value {{ color: #2e7d32; }}
  .card.fail .value {{ color: #c62828; }}
  .card.total .value {{ color: #1565c0; }}

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
      #4caf50 0% {pct_pass}%,
      #f44336 {pct_pass}% 100%
    );
    box-shadow: 0 0 0 6px #f0f0f0;
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
    color: #000000;
  }}
  .legend-dot {{
    width: 14px;
    height: 14px;
    border-radius: 4px;
  }}
  .legend-dot.green {{ background: #4caf50; }}
  .legend-dot.red   {{ background: #f44336; }}

  /* ── Table ───────────────────────────────────────── */
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
  }}
  thead th {{
    background: #e0e0e0;
    color: #000000;
    padding: 10px 14px;
    text-align: left;
    font-weight: 600;
    border: 1px solid #cccccc;
  }}
  thead th:nth-child(1) {{ width: 40px; text-align: center; }}
  thead th:nth-child(3) {{ width: 80px; text-align: center; }}

  tbody td {{
    padding: 9px 14px;
    border-bottom: 1px solid #dddddd;
    border-left: 1px solid #dddddd;
    border-right: 1px solid #dddddd;
  }}
  tbody td:nth-child(1) {{ text-align: center; color: #666666; }}

  /* Row colours */
  tr.pass {{ background: rgba(76, 175, 80, 0.05); }}
  tr.fail {{ background: rgba(244, 67, 54, 0.05); }}

  /* Status badge */
  td.badge {{
    text-align: center;
    font-weight: 700;
    font-size: 12px;
    letter-spacing: 0.5px;
  }}
  tr.pass td.badge {{ color: #2e7d32; }}
  tr.fail td.badge {{ color: #c62828; }}

  /* ── Footer ──────────────────────────────────────── */
  footer {{
    text-align: center;
    margin-top: 32px;
    color: #666666;
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
    <tr><th>#</th><th>Check Name</th><th>Status</th><th>Severity</th><th>Impact</th><th>Details</th></tr>
  </thead>
  <tbody>
{rows}
  </tbody>
</table>

<footer>CIS Benchmark Audit Tool — Auto-generated report</footer>
</body>
</html>
"""
