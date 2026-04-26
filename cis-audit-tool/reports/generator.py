"""
reports/generator.py - Audit Report Generator

Reads JSON results from the results/ directory and produces
formatted audit reports in PDF and HTML formats.

Responsibilities:
- Load and validate JSON audit result files
- Render an HTML report with pass/fail summary and detail tables
- Convert the HTML report to PDF (via weasyprint or similar)
- Include metadata: timestamp, target OS, auditor, overall score
- Save generated reports to a user-specified output path
"""
