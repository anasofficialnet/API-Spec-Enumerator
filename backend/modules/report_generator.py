from typing import Any, Dict, List


def _html_escape(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _render_steps(steps: List[str]) -> str:
    if not steps:
        return "<p>No verification steps recorded.</p>"
    return "<ol>" + "".join(f"<li>{_html_escape(step)}</li>" for step in steps) + "</ol>"


def generate_executive_report(scan_id: str, state: Any) -> str:
    """
    Generates an executive-grade HTML vulnerability report suitable for board-level review.
    Includes CVSS breakdowns, remediation guidance, and replay commands.
    """
    sev_colors = {
        "CRITICAL": "#FF4F4F",
        "HIGH": "#FF8C42",
        "MEDIUM": "#FFD166",
        "LOW": "#00E676",
        "INFO": "#4FC3F7",
    }
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    findings_html = ""
    sorted_findings = sorted(
        state.report_findings,
        key=lambda item: sev_order.index(item.get("severity", "INFO"))
        if item.get("severity") in sev_order
        else 99,
    )

    for finding in sorted_findings:
        color = sev_colors.get(finding.get("severity", "INFO"), "#4FC3F7")
        replay_curl = finding.get("replay_curl") or "Replay command unavailable for this finding."
        request_summary = finding.get("request_summary") or "No request summary recorded."
        response_summary = finding.get("response_summary") or "No response summary recorded."
        developer_notes = finding.get("developer_notes") or finding.get("recommendation", "")
        verification_steps = finding.get("verification_steps") or []

        findings_html += f"""
        <div class="finding">
          <div class="finding-header" style="border-left:4px solid {color}">
            <span class="badge" style="background:{color}20;color:{color};border:1px solid {color}40">{_html_escape(finding.get('severity', '?'))}</span>
            <span class="finding-title">{_html_escape(finding.get('type', 'Unknown'))}</span>
            <span class="finding-meta">{_html_escape(finding.get('method', ''))} {_html_escape(finding.get('endpoint', ''))} &nbsp;-&nbsp; {_html_escape(finding.get('host', ''))}</span>
            <span class="cvss" style="color:{color}">CVSS {finding.get('cvss', 0):.1f}</span>
            <span class="cwe">{_html_escape(finding.get('cwe', ''))}</span>
          </div>
          <div class="finding-body">
            <p class="evidence">{_html_escape(finding.get('evidence', ''))}</p>

            <div class="developer-grid">
              <details open><summary>Replay Command</summary>
                <pre style="border-color:#4FC3F730;color:#4FC3F7">{_html_escape(replay_curl)}</pre>
              </details>

              <details open><summary>Developer Notes</summary>
                <pre style="border-color:#FFD16630;color:#FDE68A">{_html_escape(developer_notes)}</pre>
              </details>
            </div>

            <div class="developer-grid">
              <details open><summary>Request Summary</summary>
                <pre>{_html_escape(request_summary)}</pre>
              </details>

              <details open><summary>Response Summary</summary>
                <pre>{_html_escape(response_summary)}</pre>
              </details>
            </div>

            <details open><summary>Verification Steps</summary>
              {_render_steps(verification_steps)}
            </details>

            <details open><summary>Recommended Fix</summary>
              <pre style="border-color:#00E67630;color:#00E676">{_html_escape(finding.get('recommendation', ''))}</pre>
            </details>

            <details><summary>Raw Request</summary><pre>{_html_escape(finding.get('request', ''))}</pre></details>
            <details><summary>Raw Response</summary><pre>{_html_escape(finding.get('response', ''))}</pre></details>
          </div>
        </div>"""

    total = len(state.report_findings)
    counts = {severity: sum(1 for finding in state.report_findings if finding.get("severity") == severity) for severity in sev_order}
    risk_score = (counts["CRITICAL"] * 10) + (counts["HIGH"] * 5) + (counts["MEDIUM"] * 2)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AASE Executive Security Report - {_html_escape(scan_id)}</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#080C0A;color:#E8F5E9;margin:0;padding:0}}
  .confidential{{background:#FF4F4F;color:#fff;text-align:center;padding:12px;font-weight:bold;font-size:12px;letter-spacing:6px;text-transform:uppercase}}
  .header{{background:linear-gradient(135deg, #0D1410 0%, #1A2E20 100%);border-bottom:1px solid #00E67640;padding:48px}}
  .header h1{{margin:0;font-size:32px;color:#00E676;letter-spacing:-0.5px}}
  .header p{{margin:8px 0 0;color:#85B396;font-size:14px;font-family:monospace}}
  .risk-badge{{display:inline-block;padding:8px 16px;background:#FF4F4F20;border:1px solid #FF4F4F;border-radius:4px;color:#FF4F4F;font-weight:bold;margin-top:16px}}
  .metrics-grid{{display:grid;grid-template-columns:repeat(5, 1fr);gap:16px;padding:32px 48px;background:#030504}}
  .sev-card{{background:#0D1410;border:1px solid #00E67620;border-radius:8px;padding:24px;text-align:center;box-shadow:0 4px 12px rgba(0,0,0,0.5)}}
  .sev-num{{font-size:48px;font-weight:900;line-height:1;font-family:monospace}}
  .sev-label{{font-size:12px;color:#85B396;text-transform:uppercase;letter-spacing:2px;margin-top:8px;font-weight:bold}}
  .findings{{padding:0 48px 48px}}
  .finding{{background:#0D1410;border:1px solid #00E67615;border-radius:8px;margin-bottom:16px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.3)}}
  .finding-header{{display:flex;align-items:center;gap:16px;padding:16px 24px;background:#15201A}}
  .badge{{font-size:11px;padding:4px 10px;border-radius:4px;font-weight:bold;text-transform:uppercase;letter-spacing:1px}}
  .finding-title{{font-weight:bold;font-size:15px;color:#fff}}
  .finding-meta{{color:#85B396;font-size:13px;flex:1;font-family:monospace}}
  .cvss{{font-size:14px;font-weight:bold;background:#000;padding:4px 8px;border-radius:4px}}
  .cwe{{font-size:12px;color:#5A7A65;font-family:monospace}}
  .finding-body{{padding:24px;border-top:1px solid #00E67610}}
  .evidence{{color:#E8F5E9;font-size:14px;margin:0 0 20px 0;line-height:1.5;background:#000;padding:16px;border-radius:6px;border-left:3px solid #6366F1}}
  .developer-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}}
  details{{margin:12px 0;background:#0A0F0C;border-radius:6px;border:1px solid #E8F5E910}}
  summary{{cursor:pointer;color:#85B396;font-size:12px;text-transform:uppercase;letter-spacing:1px;font-weight:bold;padding:12px 16px;background:#101813;border-radius:6px}}
  summary:hover{{background:#1A261E}}
  pre{{margin:0;padding:16px;font-size:12px;overflow-x:auto;white-space:pre-wrap;color:#A9C9B4;font-family:monospace}}
  ol{{margin:0;padding:16px 16px 16px 32px;color:#A9C9B4;font-size:12px;line-height:1.6}}
  li + li{{margin-top:8px}}
  .footer{{text-align:center;padding:32px;color:#5A7A65;font-size:12px;border-top:1px solid #00E67620;background:#030504}}
  @media (max-width: 960px){{.metrics-grid,.developer-grid{{grid-template-columns:1fr}} .header,.findings,.metrics-grid{{padding-left:20px;padding-right:20px}}}}
</style>
</head>
<body>
<div class="confidential">Strictly Confidential - Authorized Personnel Only</div>
<div class="header">
  <h1>Automated Attack Surface Report</h1>
  <p>Scan Target: {_html_escape(state.file_name)}</p>
  <p>Format: {_html_escape(state.format)} | Transactions: {state.cases_run}/{state.total_cases}</p>
  <div class="risk-badge">Overall Risk Score: {risk_score}</div>
</div>
<div class="metrics-grid">
  {"".join(f'<div class="sev-card"><div class="sev-num" style="color:{sev_colors[severity]}">{counts[severity]}</div><div class="sev-label">{severity}</div></div>' for severity in sev_order)}
</div>
<div class="findings">
  <h2 style="color:#00E676;font-size:16px;text-transform:uppercase;letter-spacing:2px;margin-bottom:24px;border-bottom:1px solid #00E67630;padding-bottom:12px">Detailed Findings ({total})</h2>
  {findings_html if findings_html else '<p style="color:#85B396;font-size:14px;padding:24px;background:#0D1410;border-radius:6px;text-align:center">No vulnerabilities discovered during this scan.</p>'}
</div>
<div class="footer">
  <p>Generated by AASE - Advanced API Security Engine</p>
  <p style="margin-top:8px;opacity:0.5">{_html_escape(state.started_at)}</p>
</div>
</body></html>"""

    return html
