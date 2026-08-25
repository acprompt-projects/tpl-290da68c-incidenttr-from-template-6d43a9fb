from enum import Enum
from typing import Dict, List, Set


class Channel(str, Enum):
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# (severity, category) -> list of channels
# category "*" acts as a wildcard fallback
ROUTING_RULES: Dict[str, Dict[str, List[Channel]]] = {
    Severity.CRITICAL: {
        "*": [Channel.SLACK, Channel.PAGERDUTY, Channel.EMAIL],
    },
    Severity.HIGH: {
        "*": [Channel.SLACK, Channel.PAGERDUTY],
        "security": [Channel.SLACK, Channel.PAGERDUTY, Channel.EMAIL],
    },
    Severity.MEDIUM: {
        "*": [Channel.SLACK],
        "security": [Channel.SLACK, Channel.EMAIL],
    },
    Severity.LOW: {
        "*": [Channel.SLACK],
    },
    Severity.INFO: {
        "*": [Channel.SLACK],
    },
}

RATE_LIMITS: Dict[Channel, int] = {
    # max notifications per minute per channel
    Channel.SLACK: 60,
    Channel.PAGERDUTY: 20,
    Channel.EMAIL: 30,
}

SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/PLACEHOLDER"
PAGERDUTY_ROUTING_KEY = "PLACEHOLDER"
PAGERDUTY_EVENT_URL = "https://events.pagerduty.com/v2/enqueue"

EMAIL_SMTP_HOST = "smtp.example.com"
EMAIL_SMTP_PORT = 587
EMAIL_FROM = "incidents@example.com"
EMAIL_RECIPIENTS: List[str] = ["oncall@example.com"]