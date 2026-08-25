from __future__ import annotations

import asyncio
import json
import logging
import smtplib
import time
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

import httpx

from config import (
    Channel,
    EMAIL_FROM,
    EMAIL_RECIPIENTS,
    EMAIL_SMTP_HOST,
    EMAIL_SMTP_PORT,
    PAGERDUTY_EVENT_URL,
    PAGERDUTY_ROUTING_KEY,
    RATE_LIMITS,
    ROUTING_RULES,
    Severity,
    SLACK_WEBHOOK_URL,
)

logger = logging.getLogger(__name__)


class TokenBucket:
    """Simple per-channel token-bucket rate limiter."""

    def __init__(self, rate_per_minute: int):
        self._rate = rate_per_minute / 60.0
        self._tokens = float(rate_per_minute)
        self._max = float(rate_per_minute)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> bool:
        async with self._lock:
            now = time.monotonic()
            self._tokens = min(self._max, self._tokens + (now - self._last) * self._rate)
            self._last = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False


class NotificationDispatcher:
    def __init__(self) -> None:
        self._limiters = {ch: TokenBucket(limit) for ch, limit in RATE_LIMITS.items()}
        self._http = httpx.AsyncClient(timeout=10.0)

    async def dispatch(self, incident: Dict[str, Any]) -> Dict[str, bool]:
        severity = Severity(incident.get("severity", "low").lower())
        category = incident.get("category", "*")
        channels = self._resolve_channels(severity, category)
        results: Dict[str, bool] = {}
        for ch in channels:
            ok = await self._send_with_limit(ch, incident)
            results[ch.value] = ok
        return results

    def _resolve_channels(self, severity: Severity, category: str) -> List[Channel]:
        rules = ROUTING_RULES.get(severity, {})
        channels = rules.get(category) or rules.get("*", [Channel.SLACK])
        return list(channels)

    async def _send_with_limit(self, channel: Channel, incident: Dict[str, Any]) -> bool:
        bucket = self._limiters.get(channel)
        if bucket and not await bucket.acquire():
            logger.warning("Rate limited on %s for incident %s", channel.value, incident.get("id"))
            return False
        try:
            if channel == Channel.SLACK:
                return await self._send_slack(incident)
            if channel == Channel.PAGERDUTY:
                return await self._send_pagerduty(incident)
            if channel == Channel.EMAIL:
                return await self._send_email(incident)
        except Exception:
            logger.exception("Failed to dispatch via %s", channel.value)
            return False
        return False

    async def _send_slack(self, incident: Dict[str, Any]) -> bool:
        severity = incident.get("severity", "unknown").upper()
        title = incident.get("title", "Untitled Incident")
        payload = {
            "text": f":rotating_light: *[{severity}]* {title}",
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*[{severity}]* {title}"}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Category:* {incident.get('category', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Incident ID:* {incident.get('id', 'N/A')}"},
                ]},
            ],
        }
        resp = await self._http.post(SLACK_WEBHOOK_URL, json=payload)
        return resp.status_code == 200

    async def _send_pagerduty(self, incident: Dict[str, Any]) -> bool:
        payload = {
            "routing_key": PAGERDUTY_ROUTING_KEY,
            "event_action": "trigger",
            "payload": {
                "summary": incident.get("title", "Untitled Incident"),
                "severity": incident.get("severity", "low"),
                "source": incident.get("source", "incident-triage"),
                "component": incident.get("category", "unknown"),
                "custom_details": {"incident_id": incident.get("id"), "correlation_key": incident.get("correlation_key", "")},
            },
        }
        resp = await self._http.post(PAGERDUTY_EVENT_URL, json=payload)
        return resp.status_code in (200, 201, 202)

    async def _send_email(self, incident: Dict[str, Any]) -> bool:
        subject = f"[{incident.get('severity', 'low').upper()}] {incident.get('title', 'Incident')}"
        body = json.dumps(incident, indent=2, default=str)
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_FROM
        msg["To"] = ", ".join(EMAIL_RECIPIENTS)
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._smtp_send, msg)
        return True

    @staticmethod
    def _smtp_send(msg: MIMEText) -> None:
        with smtplib.SMTP(EMAIL_SMTP_HOST, EMAIL_SMTP_PORT) as srv:
            srv.starttls()
            srv.send_message(msg)

    async def close(self) -> None:
        await self._http.aclose()