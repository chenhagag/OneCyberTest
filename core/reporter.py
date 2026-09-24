"""Report generator for OneSyberTest.

Produces structured JSON and Hebrew RTL HTML reports from collected
test results.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from jinja2 import Environment

from core.logger import censor, get_logger

_logger = get_logger("onesyber.reporter")

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

StatusType = Literal[
    "exploited_verified",
    "blocked",
    "suspected_unverified",
    "not_tested",
]
SeverityType = Literal["critical", "high", "medium", "low", "info"]

_SEVERITY_ORDER: Dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass
class TestResult:
    test_name: str
    status: StatusType
    severity: SeverityType
    description: str
    test_module: str = ""
    target_url: str = ""
    expected_behavior: str = ""
    actual_behavior: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    evidence: str = ""  # request/response, already censored
    remediation: str = ""
    retest_description: str = ""


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Collects :class:`TestResult` objects and generates reports."""

    def __init__(
        self,
        *,
        target_url: str = "",
        output_dir: str = "./reports",
    ) -> None:
        self._results: List[TestResult] = []
        self._target_url = target_url
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._start_time: datetime = datetime.now()

    def add_result(self, result: TestResult) -> None:
        self._results.append(result)

    @property
    def results(self) -> List[TestResult]:
        return list(self._results)

    # -- JSON report ---------------------------------------------------

    def generate_json(self, path: Optional[str | Path] = None) -> str:
        """Write a structured JSON report and return the file path."""
        end_time = datetime.now()
        duration_seconds = (end_time - self._start_time).total_seconds()

        data: Dict[str, Any] = {
            "metadata": {
                "timestamp": end_time.isoformat(),
                "target": self._target_url,
                "duration_seconds": round(duration_seconds, 2),
                "scope": "automated penetration test",
                "total_findings": len(self._results),
                "findings_by_severity": self._count_by_severity(),
                "findings_by_status": self._count_by_status(),
            },
            "results": [asdict(r) for r in self._sorted_results()],
        }

        out_path = Path(path) if path else self._output_dir / f"report_{end_time.strftime('%Y%m%d_%H%M%S')}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        _logger.info("JSON report written to %s", out_path)
        return str(out_path)

    # -- HTML report ---------------------------------------------------

    def generate_html(self, path: Optional[str | Path] = None) -> str:
        """Render an RTL Hebrew HTML report and return the file path."""
        end_time = datetime.now()
        duration_seconds = (end_time - self._start_time).total_seconds()

        env = Environment(autoescape=True)
        template = env.from_string(_HTML_TEMPLATE)

        html = template.render(
            timestamp=end_time.strftime("%Y-%m-%d %H:%M:%S"),
            target=self._target_url,
            duration_minutes=round(duration_seconds / 60, 1),
            by_severity=self._count_by_severity(),
            by_status=self._count_by_status(),
            results=self._sorted_results(),
            total=len(self._results),
            prioritized_fixes=self._prioritized_fixes(),
        )

        out_path = Path(path) if path else self._output_dir / f"report_{end_time.strftime('%Y%m%d_%H%M%S')}.html"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(html, encoding="utf-8")
        _logger.info("HTML report written to %s", out_path)
        return str(out_path)

    # -- Compare reports -----------------------------------------------

    @staticmethod
    def compare_reports(json_path_1: str | Path, json_path_2: str | Path) -> Dict[str, Any]:
        """Compare two JSON reports and return a diff summary.

        Returns a dict with keys:
        - ``new_findings``: findings in report 2 but not in report 1
        - ``resolved_findings``: findings in report 1 but not in report 2
        - ``status_changes``: findings present in both but with a different status
        """
        r1 = json.loads(Path(json_path_1).read_text(encoding="utf-8"))
        r2 = json.loads(Path(json_path_2).read_text(encoding="utf-8"))

        def _key(result: Dict[str, Any]) -> str:
            return f"{result.get('test_module', '')}::{result.get('test_name', '')}"

        map1 = {_key(r): r for r in r1.get("results", [])}
        map2 = {_key(r): r for r in r2.get("results", [])}

        new_findings = [map2[k] for k in map2 if k not in map1]
        resolved = [map1[k] for k in map1 if k not in map2]
        status_changes = []
        for k in map1:
            if k in map2 and map1[k].get("status") != map2[k].get("status"):
                status_changes.append({
                    "test": k,
                    "old_status": map1[k].get("status"),
                    "new_status": map2[k].get("status"),
                })

        diff: Dict[str, Any] = {
            "report_1": str(json_path_1),
            "report_2": str(json_path_2),
            "new_findings": new_findings,
            "resolved_findings": resolved,
            "status_changes": status_changes,
        }
        _logger.info(
            "Report comparison: %d new, %d resolved, %d status changes",
            len(new_findings),
            len(resolved),
            len(status_changes),
        )
        return diff

    # -- helpers -------------------------------------------------------

    def _sorted_results(self) -> List[TestResult]:
        return sorted(self._results, key=lambda r: _SEVERITY_ORDER.get(r.severity, 99))

    def _count_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
        for r in self._results:
            counts[r.severity] = counts.get(r.severity, 0) + 1
        return counts

    def _count_by_status(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for r in self._results:
            counts[r.status] = counts.get(r.status, 0) + 1
        return counts

    def _prioritized_fixes(self) -> List[Dict[str, str]]:
        """Return findings that need fixing, ordered by severity."""
        actionable = [
            r for r in self._sorted_results()
            if r.status in ("exploited_verified", "suspected_unverified") and r.remediation
        ]
        return [
            {"test_name": r.test_name, "severity": r.severity, "remediation": r.remediation}
            for r in actionable
        ]


# ---------------------------------------------------------------------------
# Inline Jinja2 HTML template (Hebrew RTL)
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>דוח בדיקת חדירה - {{ target }}</title>
<style>
  :root {
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --muted: #94a3b8;
    --critical: #ef4444; --high: #f97316; --medium: #eab308;
    --low: #3b82f6; --info: #6b7280;
    --exploited: #ef4444; --blocked: #22c55e;
    --suspected: #f97316; --not-tested: #6b7280;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Tahoma, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; line-height: 1.6; }
  h1,h2,h3 { margin-bottom: .5rem; }
  h1 { font-size: 1.8rem; border-bottom: 2px solid var(--border); padding-bottom: .5rem; margin-bottom: 1.5rem; }
  .meta { background: var(--surface); border-radius: 8px; padding: 1rem 1.5rem; margin-bottom: 1.5rem; }
  .meta span { display: inline-block; margin-left: 2rem; color: var(--muted); }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .card { background: var(--surface); border-radius: 8px; padding: 1rem; text-align: center; border-top: 3px solid var(--border); }
  .card.critical { border-top-color: var(--critical); }
  .card.high { border-top-color: var(--high); }
  .card.medium { border-top-color: var(--medium); }
  .card.low { border-top-color: var(--low); }
  .card.info { border-top-color: var(--info); }
  .card .num { font-size: 2rem; font-weight: bold; }
  .card .label { color: var(--muted); font-size: .85rem; }
  .finding { background: var(--surface); border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; border-right: 4px solid var(--border); }
  .finding.critical { border-right-color: var(--critical); }
  .finding.high { border-right-color: var(--high); }
  .finding.medium { border-right-color: var(--medium); }
  .finding.low { border-right-color: var(--low); }
  .finding.info { border-right-color: var(--info); }
  .badge { display: inline-block; padding: .15rem .6rem; border-radius: 4px; font-size: .8rem; font-weight: 600; color: #fff; margin-left: .5rem; }
  .badge-critical { background: var(--critical); }
  .badge-high { background: var(--high); }
  .badge-medium { background: var(--medium); }
  .badge-low { background: var(--low); }
  .badge-info { background: var(--info); }
  .badge-exploited_verified { background: var(--exploited); }
  .badge-blocked { background: var(--blocked); }
  .badge-suspected_unverified { background: var(--suspected); }
  .badge-not_tested { background: var(--not-tested); }
  .field { margin-top: .5rem; }
  .field-label { font-weight: 600; color: var(--muted); font-size: .85rem; }
  pre { background: #0d1117; padding: .75rem; border-radius: 4px; overflow-x: auto; font-size: .85rem; margin-top: .25rem; direction: ltr; text-align: left; white-space: pre-wrap; }
  ol { padding-right: 1.5rem; }
  .section { margin-top: 2rem; }
  .fix-list { list-style: none; padding: 0; }
  .fix-list li { background: var(--surface); padding: .75rem 1rem; border-radius: 6px; margin-bottom: .5rem; }
  .scope-box { background: var(--surface); border-radius: 8px; padding: 1.5rem; margin-top: 2rem; }
</style>
</head>
<body>

<h1>דוח בדיקת חדירה</h1>

<div class="meta">
  <span><strong>יעד:</strong> {{ target }}</span>
  <span><strong>תאריך:</strong> {{ timestamp }}</span>
  <span><strong>משך:</strong> {{ duration_minutes }} דקות</span>
  <span><strong>סה"כ ממצאים:</strong> {{ total }}</span>
</div>

<h2>תקציר מנהלים</h2>
<div class="summary-grid">
  {% for sev in ['critical','high','medium','low','info'] %}
  <div class="card {{ sev }}">
    <div class="num">{{ by_severity.get(sev, 0) }}</div>
    <div class="label">{{ sev | upper }}</div>
  </div>
  {% endfor %}
</div>

{% if prioritized_fixes %}
<div class="section">
  <h2>רשימת תיקונים לפי עדיפות</h2>
  <ul class="fix-list">
    {% for fix in prioritized_fixes %}
    <li>
      <span class="badge badge-{{ fix.severity }}">{{ fix.severity | upper }}</span>
      <strong>{{ fix.test_name }}</strong>: {{ fix.remediation }}
    </li>
    {% endfor %}
  </ul>
</div>
{% endif %}

<div class="section">
  <h2>ממצאים מפורטים</h2>
  {% for r in results %}
  <div class="finding {{ r.severity }}">
    <h3>
      {{ r.test_name }}
      <span class="badge badge-{{ r.severity }}">{{ r.severity | upper }}</span>
      <span class="badge badge-{{ r.status }}">{{ r.status }}</span>
    </h3>
    <div class="field"><span class="field-label">מודול:</span> {{ r.test_module }}</div>
    <div class="field"><span class="field-label">תיאור:</span> {{ r.description }}</div>
    <div class="field"><span class="field-label">כתובת יעד:</span> <code>{{ r.target_url }}</code></div>
    <div class="field"><span class="field-label">התנהגות צפויה:</span> {{ r.expected_behavior }}</div>
    <div class="field"><span class="field-label">התנהגות בפועל:</span> {{ r.actual_behavior }}</div>
    {% if r.reproduction_steps %}
    <div class="field">
      <span class="field-label">שלבים לשחזור:</span>
      <ol>{% for step in r.reproduction_steps %}<li>{{ step }}</li>{% endfor %}</ol>
    </div>
    {% endif %}
    {% if r.evidence %}
    <div class="field"><span class="field-label">ראיות:</span><pre>{{ r.evidence }}</pre></div>
    {% endif %}
    {% if r.remediation %}
    <div class="field"><span class="field-label">המלצה לתיקון:</span> {{ r.remediation }}</div>
    {% endif %}
    {% if r.retest_description %}
    <div class="field"><span class="field-label">בדיקה חוזרת:</span> {{ r.retest_description }}</div>
    {% endif %}
  </div>
  {% endfor %}
</div>

<div class="scope-box">
  <h2>היקף ומגבלות</h2>
  <ul>
    <li>הבדיקה בוצעה באופן אוטומטי באמצעות כלי OneSyberTest.</li>
    <li>הבדיקה הוגבלת לדומיינים מורשים בלבד כפי שהוגדרו בקונפיגורציה.</li>
    <li>ממצאים בסטטוס "suspected_unverified" דורשים אימות ידני.</li>
    <li>הבדיקה אינה מהווה תחליף לבדיקת חדירה ידנית מקיפה.</li>
    <li>דוח זה מכיל מידע רגיש ומיועד לצוות הפיתוח והאבטחה בלבד.</li>
  </ul>
</div>

</body>
</html>"""
