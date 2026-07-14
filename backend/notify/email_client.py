"""
Email alerts for scheduled scans, over stdlib smtplib -- no extra dependency.

Only *new* findings are ever emailed (see scan_service.finalize_scan): re-sending
the same unchanged backlog every night is the fastest way to train someone to
ignore the alerts entirely.

SMTP credentials come from config and are never logged.
"""

import logging
import smtplib
from email.message import EmailMessage
from typing import List

from backend import config
from backend.models import Finding

logger = logging.getLogger(__name__)


def _plain_body(new_findings: List[Finding], total: int, score: dict) -> str:
    lines = [
        f"CloudSentinel found {len(new_findings)} new finding(s) in the latest scheduled scan.",
        "",
        f"Security score: {score['score']}% ({score['label']})",
        f"Total open findings: {total}",
        "",
        "New findings:",
    ]
    for f in new_findings:
        region = f.region or "global"
        lines.append(f"  [{f.severity.value}] {f.check_type} -- {f.resource_id} ({region})")
        lines.append(f"      {f.description}")
    lines += ["", "Open CloudSentinel to see full detail and remediation steps."]
    return "\n".join(lines)


def _html_body(new_findings: List[Finding], total: int, score: dict) -> str:
    rows = "".join(
        f"<tr>"
        f"<td style='padding:6px 10px'><strong>{f.severity.value}</strong></td>"
        f"<td style='padding:6px 10px'>{f.check_type}</td>"
        f"<td style='padding:6px 10px'>{f.resource_id}</td>"
        f"<td style='padding:6px 10px'>{f.region or 'global'}</td>"
        f"<td style='padding:6px 10px'>{f.description}</td>"
        f"</tr>"
        for f in new_findings
    )
    return f"""\
<html><body style="font-family:system-ui,sans-serif">
  <h2>CloudSentinel: {len(new_findings)} new finding(s)</h2>
  <p>Security score: <strong>{score['score']}%</strong> ({score['label']})<br>
     Total open findings: <strong>{total}</strong></p>
  <table border="0" cellspacing="0" style="border-collapse:collapse;font-size:14px">
    <thead><tr style="background:#f0f0f0">
      <th align="left" style="padding:6px 10px">Severity</th>
      <th align="left" style="padding:6px 10px">Check</th>
      <th align="left" style="padding:6px 10px">Resource</th>
      <th align="left" style="padding:6px 10px">Region</th>
      <th align="left" style="padding:6px 10px">Description</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body></html>"""


def send_new_findings_alert(new_findings: List[Finding], total: int, score: dict) -> bool:
    """Returns True if an email was sent. No-ops (returns False) when alerts aren't
    configured or there's nothing new -- callers don't need to pre-check."""
    if not new_findings:
        return False

    if not config.alerts_configured():
        logger.info("New findings detected but email alerts are not configured -- skipping.")
        return False

    message = EmailMessage()
    message["Subject"] = f"CloudSentinel: {len(new_findings)} new AWS finding(s)"
    message["From"] = config.SMTP_FROM
    message["To"] = ", ".join(config.ALERT_TO)
    message.set_content(_plain_body(new_findings, total, score))
    message.add_alternative(_html_body(new_findings, total, score), subtype="html")

    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=30) as smtp:
            if config.SMTP_USE_TLS:
                smtp.starttls()
            if config.SMTP_USER:
                smtp.login(config.SMTP_USER, config.SMTP_PASSWORD)
            smtp.send_message(message)
    except Exception as e:
        # Never let a mail failure kill the scan that produced the findings.
        logger.error("Failed to send alert email: %s", e)
        return False

    logger.info("Sent alert email for %d new finding(s) to %s", len(new_findings), config.ALERT_TO)
    return True
