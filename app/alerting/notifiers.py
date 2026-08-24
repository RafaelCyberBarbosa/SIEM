import asyncio
import logging
import smtplib
from email.mime.text import MIMEText

import httpx

from app.config import settings
from app.models import Alert

logger = logging.getLogger("siem.alerting")


def _send_email_sync(alert: Alert):
    body = (
        f"Alert: {alert.title}\n"
        f"Severity: {alert.severity.upper()}\n"
        f"Rule: {alert.rule_key}\n"
        f"MITRE ATT&CK: {alert.mitre}\n"
        f"Description: {alert.description}\n"
        f"Group key: {alert.group_key}\n"
        f"Affected events: {len(alert.event_ids)}\n"
        f"Created at: {alert.created_at}\n"
    )
    msg = MIMEText(body)
    msg["Subject"] = f"[SIEM][{alert.severity.upper()}] {alert.title}"
    msg["From"] = settings.smtp_from
    msg["To"] = settings.smtp_to

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
        if settings.smtp_use_tls:
            server.starttls()
        if settings.smtp_username:
            server.login(settings.smtp_username, settings.smtp_password)
        server.sendmail(settings.smtp_from, [settings.smtp_to], msg.as_string())


async def send_email_alert(alert: Alert):
    if not settings.smtp_enabled:
        return
    try:
        await asyncio.to_thread(_send_email_sync, alert)
    except Exception:
        logger.exception("Failed to send email alert for %s", alert.id)


async def send_webhook_alert(alert: Alert):
    if not settings.webhook_enabled or not settings.webhook_url:
        return
    payload = {
        "text": f"[{alert.severity.upper()}] {alert.title}",
        "alert_id": alert.id,
        "rule_key": alert.rule_key,
        "severity": alert.severity,
        "mitre": alert.mitre,
        "description": alert.description,
        "group_key": alert.group_key,
        "event_count": len(alert.event_ids),
        "created_at": alert.created_at.isoformat(),
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(settings.webhook_url, json=payload)
    except Exception:
        logger.exception("Failed to send webhook alert for %s", alert.id)


async def dispatch_alert_notifications(alert: Alert):
    await asyncio.gather(send_email_alert(alert), send_webhook_alert(alert))
