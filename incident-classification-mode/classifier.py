import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class Category(Enum):
    INFRA = "infra"
    APP = "app"
    SECURITY = "security"
    NETWORK = "network"


@dataclass
class TriageLabel:
    severity: Severity
    category: Category
    confidence: float
    rule_ids: list[str] = field(default_factory=list)
    reasoning: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "category": self.category.value,
            "confidence": round(self.confidence, 3),
            "rule_ids": self.rule_ids,
            "reasoning": self.reasoning,
        }


@dataclass
class ThresholdConfig:
    error_rate_p1: float = 0.50
    error_rate_p2: float = 0.25
    error_rate_p3: float = 0.10
    latency_ms_p1: float = 5000.0
    latency_ms_p2: float = 2000.0
    latency_ms_p3: float = 1000.0
    cpu_pct_p1: float = 95.0
    cpu_pct_p2: float = 85.0
    cpu_pct_p3: float = 70.0
    disk_pct_p1: float = 95.0
    disk_pct_p2: float = 85.0
    affected_services_p1: int = 5
    affected_services_p2: int = 3
    min_confidence: float = 0.1


_KEYWORD_MAP: dict[Category, list[str]] = {
    Category.INFRA: [
        "cpu", "memory", "disk", "oom", "out of memory", "pod",
        "node", "cluster", "replica", "evicted", "iops", "storage",
        "provision", "capacity", "resource",
    ],
    Category.APP: [
        "exception", "error", "500", "502", "503", "504", "crash",
        "stacktrace", "timeout", "nullpointer", "segfault", "hang",
        "unhandled", "traceback", "panic",
    ],
    Category.SECURITY: [
        "breach", "unauthorized", "auth", "intrusion", "malware",
        "ddos", "exploit", "cve", "vulnerability", "phishing",
        "permission", "privilege", "token", "credential", "ssl",
        "certificate", "firewall", "waf",
    ],
    Category.NETWORK: [
        "dns", "latency", "packet loss", "connection refused",
        "timeout", "network", "routing", "bandwidth", "throughput",
        "tcp", "udp", "ping", "hop", "interface", "gateway",
        "unreachable", "blackhole",
    ],
}


class IncidentClassifier:
    def __init__(self, config: Optional[ThresholdConfig] = None):
        self.config = config or ThresholdConfig()
        self._keyword_re: dict[Category, re.Pattern] = {
            cat: re.compile("|".join(map(re.escape, kws)), re.IGNORECASE)
            for cat, kws in _KEYWORD_MAP.items()
        }

    def classify(self, incident: dict[str, Any]) -> TriageLabel:
        rule_ids: list[str] = []
        reasoning: list[str] = []
        severity_scores: list[Severity] = []
        category_scores: list[Category] = []

        sev, cat = self._classify_keywords(incident, rule_ids, reasoning)
        if sev:
            severity_scores.append(sev)
            category_scores.append(cat)

        sev = self._classify_metrics(incident, rule_ids, reasoning)
        if sev:
            severity_scores.append(sev)

        sev = self._classify_scope(incident, rule_ids, reasoning)
        if sev:
            severity_scores.append(sev)

        cat_kw = self._detect_category(incident)
        final_category = self._resolve_category(category_scores, cat_kw)
        final_severity = self._resolve_severity(severity_scores, incident)
        confidence = self._compute_confidence(severity_scores, category_scores, final_category, cat_kw)

        return TriageLabel(
            severity=final_severity,
            category=final_category,
            confidence=confidence,
            rule_ids=rule_ids,
            reasoning=reasoning,
        )

    def _classify_keywords(self, incident: dict, rule_ids: list, reasoning: list) -> tuple[Optional[Severity], Optional[Category]]:
        text = " ".join(
            str(incident.get(k, "")) for k in ("title", "description", "message", "alert_name")
        )
        if not text.strip():
            return None, None
        cat = self._detect_category_from_text(text)
        sev = Severity.P3
        critical_words = ["outage", "down", "breach", "intrusion", "data loss", "total failure"]
        high_words = ["degraded", "partial outage", "elevated errors", "slow"]
        text_lower = text.lower()
        if any(w in text_lower for w in critical_words):
            sev = Severity.P1
        elif any(w in text_lower for w in high_words):
            sev = Severity.P2
        rule_ids.append("KW-001")
        reasoning.append(f"Keyword analysis: severity={sev.value}, category={cat.value}")
        return sev, cat

    def _classify_metrics(self, incident: dict, rule_ids: list, reasoning: list) -> Optional[Severity]:
        metrics = incident.get("metrics", {})
        if not metrics:
            return None
        sev = Severity.P4
        cfg = self.config
        er = float(metrics.get("error_rate", 0))
        if er >= cfg.error_rate_p1:
            sev = Severity.P1
        elif er >= cfg.error_rate_p2:
            sev = Severity.P2
        elif er >= cfg.error_rate_p3:
            sev = Severity.P3

        lat = float(metrics.get("latency_ms", 0))
        lat_sev = None
        if lat >= cfg.latency_ms_p1:
            lat_sev = Severity.P1
        elif lat >= cfg.latency_ms_p2:
            lat_sev = Severity.P2
        elif lat >= cfg.latency_ms_p3:
            lat_sev = Severity.P3
        if lat_sev and (lat_sev.value < sev.value):
            sev = lat_sev

        cpu = float(metrics.get("cpu_percent", 0))
        if cpu >= cfg.cpu_pct_p1:
            sev = min(sev, Severity.P1, key=lambda s: s.value)
        elif cpu >= cfg.cpu_pct_p2:
            sev = min(sev, Severity.P2, key=lambda s: s.value)

        disk = float(metrics.get("disk_percent", 0))
        if disk >= cfg.disk_pct_p1:
            sev = min(sev, Severity.P1, key=lambda s: s.value)
        elif disk >= cfg.disk_pct_p2:
            sev = min(sev, Severity.P2, key=lambda s: s.value)

        rule_ids.append("MET-001")
        reasoning.append(f"Metric analysis: severity={sev.value}")
        return sev

    def _classify_scope(self, incident: dict, rule_ids: list, reasoning: list) -> Optional[Severity]:
        affected = incident.get("affected_services", [])
        count = len(affected) if isinstance(affected, list) else int(affected or 0)
        if count == 0:
            return None
        cfg = self.config
        if count >= cfg.affected_services_p1:
            sev = Severity.P1
        elif count >= cfg.affected_services_p2:
            sev = Severity.P2
        else:
            sev = Severity.P3
        rule_ids.append("SCP-001")
        reasoning.append(f"Scope analysis: {count} affected services -> severity={sev.value}")
        return sev

    def _detect_category(self, incident: dict) -> Optional[Category]:
        text = " ".join(
            str(incident.get(k, "")) for k in ("title", "description", "message", "alert_name")
        )
        return self._detect_category_from_text(text)

    def _detect_category_from_text(self, text: str) -> Category:
        scores: dict[Category, int] = {}
        for cat, pattern in self._keyword_re.items():
            scores[cat] = len(pattern.findall(text))
        best = max(scores, key=scores.get)
        if scores[best] == 0:
            return Category.APP
        return best

    def _resolve_severity(self, scores: list[Severity], incident: dict) -> Severity:
        if not scores:
            if incident.get("priority") in ("critical", "P1"):
                return Severity.P1
            if incident.get("priority") in ("high", "P2"):
                return Severity.P2
            return Severity.P4
        return min(scores, key=lambda s: s.value)

    def _resolve_category(self, category_scores: list[Category], kw_category: Optional[Category]) -> Category:
        if not category_scores and kw_category:
            return kw_category
        if category_scores:
            counts: dict[Category, int] = {}
            for c in category_scores:
                counts[c] = counts.get(c, 0) + 1
            if kw_category:
                counts[kw_category] = counts.get(kw_category, 0) + 1
            return max(counts, key=counts.get)
        return Category.APP

    def _compute_confidence(self, sev_scores, cat_scores, final_cat, kw_cat) -> float:
        confidence = 0.3
        if sev_scores:
            confidence += 0.25
        if cat_scores:
            confidence += 0.2
        if kw_cat and kw_cat == final_cat:
            confidence += 0.15
        if len(sev_scores) >= 2:
            confidence += 0.1
        return min(confidence, 1.0)