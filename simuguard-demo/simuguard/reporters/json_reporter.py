"""JSON Artifact Exporter for SimuGuard AI pre-flight simulation reports."""

import json
from pathlib import Path
from typing import Optional, Union
from simuguard.models.report import PreFlightSimulationReport


class JsonReporter:
    """Exports PreFlightSimulationReport into standardized JSON format."""

    @staticmethod
    def to_json(report: PreFlightSimulationReport, indent: int = 2) -> str:
        """Convert a report model into a formatted JSON string."""
        data = report.model_dump(mode="json")
        return json.dumps(data, indent=indent, default=str)

    @classmethod
    def export_to_file(
        cls,
        report: PreFlightSimulationReport,
        output_path: Union[str, Path],
        indent: int = 2,
    ) -> Path:
        """Save a report to a JSON file on disk."""
        target = Path(output_path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        json_content = cls.to_json(report, indent=indent)
        target.write_text(json_content, encoding="utf-8")
        return target
