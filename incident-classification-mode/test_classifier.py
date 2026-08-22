import pytest
from classifier import IncidentClassifier, ThresholdConfig, Severity, Category, TriageLabel


@pytest.fixture
def clf():
    return IncidentClassifier()


def test_p1_security_breach(clf):
    incident = {
        "title": "Security breach detected in production",
        "description": "Unauthorized access to customer database",
        "metrics": {"error_rate": 0.6},
        "affected_services": ["api", "db", "auth", "gateway", "cache"],
    }
    result = clf.classify(incident)
    assert result.severity == Severity.P1
    assert result.category == Category.SECURITY
    assert result.confidence > 0.5
    assert len(result.rule_ids) >= 2


def test_p2_infra_cpu(clf):
    incident = {
        "title": "High CPU usage on cluster nodes",
        "description": "Node CPU utilization elevated",
        "metrics": {"cpu_percent": 88.0},
        "affected_services": ["worker-1", "worker-2", "worker-3"],
    }
    result = clf.classify(incident)
    assert result.severity == Severity.P2
    assert result.category == Category.INFRA


def test_p3_network_latency(clf):
    incident = {
        "title": "Network latency spike",
        "description": "DNS resolution slow across region",
        "metrics": {"latency_ms": 1500.0},
        "affected_services": ["dns-resolver"],
    }
    result = clf.classify(incident)
    assert result.severity == Severity.P3
    assert result.category == Category.NETWORK


def test_p4_minor_app_error(clf):
    incident = {
        "title": "Minor exception in log pipeline",
        "description": "Non-critical traceback observed",
        "metrics": {},
        "affected_services": [],
    }
    result = clf.classify(incident)
    assert result.severity == Severity.P4
    assert result.category == Category.APP


def test_custom_thresholds():
    cfg = ThresholdConfig(error_rate_p1=0.9, cpu_pct_p2=60.0)
    clf = IncidentClassifier(config=cfg)
    incident = {
        "title": "High CPU",
        "description": "CPU elevated",
        "metrics": {"cpu_percent": 65.0},
        "affected_services": ["svc-a"],
    }
    result = clf.classify(incident)
    assert result.severity == Severity.P2


def test_to_dict(clf):
    incident = {"title": "OOM on pod", "description": "Out of memory", "metrics": {"memory_percent": 98}}
    result = clf.classify(incident)
    d = result.to_dict()
    assert "severity" in d and d["severity"] in ("P1", "P2", "P3", "P4")
    assert "category" in d
    assert "confidence" in d
    assert isinstance(d["rule_ids"], list)
    assert isinstance(d["reasoning"], list)


def test_priority_fallback(clf):
    incident = {"title": "Alert", "description": "Something happened", "priority": "critical"}
    result = clf.classify(incident)
    assert result.severity == Severity.P1