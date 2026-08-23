from __future__ import annotations
import os
import logging
from datetime import datetime, timezone
from typing import Dict
import httpx
from fastapi import FastAPI, HTTPException, status
from app.models import AlertPayload, Incident, IncidentBrief, TriageUpdate, Severity, IncidentStatus

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("triage-api")

app = FastAPI(title="Incident Triage Service", version="0.1.0")

INCIDENTS: Dict[str, Incident] = {}
FINGERPRINT_INDEX: Dict[str, str] = {}

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
PAGERDUTY_ROUTING_KEY = os.getenv("PAGERDUTY_ROUTING_KEY", "")
PAGERDUTY_API_URL = "https://events.pagerduty.com/v2/enqueue"


def classify_severity(payload: AlertPayload) -> Severity:
    label_sev = payload.labels.get("severity", "").lower()
    if label_sev in Severity._value2member_map_:
        return Severity(label_sev)
    if "critical" in payload.description.lower() or "outage" in payload.description.lower():
        return Severity.critical
    if "error" in payload.description.lower() or payload.labels.get("priority") == "p1":
        return Severity.high
    if "warn" in payload.description.lower():
        return Severity.medium
    return Severity.low


async def dispatch_notifications(incident: Incident, action: str = "triggered") -> None:
    summary = f"[{incident.severity.upper()}] Incident {incident.id}: {incident.description} ({action})"
    if SLACK_WEBHOOK_URL:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(SLACK_WEBHOOK_URL, json={"text": summary})
        except Exception as exc:
            logger.warning("Slack dispatch failed: %s", exc)
    if PAGERDUTY_ROUTING_KEY and incident.severity in (Severity.critical, Severity.high):
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(PAGERDUTY_API_URL, json={
                    "routing_key": PAGERDUTY_ROUTING_KEY,
                    "event_action": action,
                    "payload": {"summary": summary, "severity": incident.severity,
                                "source": incident.source, "component": incident.rule_id},
                })
        except Exception as exc:
            logger.warning("PagerDuty dispatch failed: %s", exc)


@app.post("/incidents", response_model=IncidentBrief, status_code=status.HTTP_201_CREATED)
async def submit_alert(payload: AlertPayload):
    existing_id = FINGERPRINT_INDEX.get(payload.fingerprint)
    if existing_id and existing_id in INCIDENTS:
        inc = INCIDENTS[existing_id]
        inc.alert_count += 1
        inc.updated_at = datetime.now(timezone.utc)
        logger.info("Deduplicated alert for incident %s (count=%d)", inc.id, inc.alert_count)
        return IncidentBrief(**inc.dict())
    severity = classify_severity(payload)
    incident = Incident(fingerprint=payload.fingerprint, source=payload.source,
                        rule_id=payload.rule_id, description=payload.description,
                        labels=payload.labels, severity=severity, raw_payload=payload.raw_payload)
    INCIDENTS[incident.id] = incident
    FINGERPRINT_INDEX[payload.fingerprint] = incident.id
    await dispatch_notifications(incident)
    logger.info("Created incident %s severity=%s", incident.id, severity)
    return IncidentBrief(**incident.dict())


@app.get("/incidents/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str):
    inc = INCIDENTS.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@app.patch("/incidents/{incident_id}/triage", response_model=Incident)
async def update_triage(incident_id: str, update: TriageUpdate):
    inc = INCIDENTS.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    if update.severity is not None:
        inc.severity = update.severity
    if update.status is not None:
        inc.status = update.status
    if update.assignee is not None:
        inc.assignee = update.assignee
    if update.notes is not None:
        inc.notes = update.notes
    inc.updated_at = datetime.now(timezone.utc)
    action = "resolve" if inc.status == IncidentStatus.resolved else "acknowledge"
    await dispatch_notifications(inc, action)
    logger.info("Triage updated for %s: severity=%s status=%s assignee=%s",
                inc.id, inc.severity, inc.status, inc.assignee)
    return inc