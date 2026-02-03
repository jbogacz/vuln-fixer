"""Parser for GitLab vulnerability reports."""

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class VulnType(Enum):
    DEPENDENCY = "dependency"
    SAST = "sast"
    DAST = "dast"
    SECRET = "secret"
    CONTAINER = "container"


@dataclass
class Location:
    file_path: str
    start_line: int | None = None
    end_line: int | None = None
    dependency: str | None = None  # For dependency vulns


@dataclass
class Vulnerability:
    id: str
    title: str
    description: str
    severity: Severity
    vuln_type: VulnType
    location: Location
    identifiers: list[str]  # CVE, CWE, etc.
    solution: str | None = None
    raw_data: dict | None = None


class VulnParser:
    """Parser for various vulnerability report formats."""

    def parse_gitlab_vulnerability(self, data: dict) -> Vulnerability:
        """Parse a single GitLab vulnerability object."""
        location_data = data.get("location", {})

        location = Location(
            file_path=location_data.get("file", "unknown"),
            start_line=location_data.get("start_line"),
            end_line=location_data.get("end_line"),
            dependency=location_data.get("dependency", {}).get("package", {}).get("name"),
        )

        # Extract identifiers (CVE, CWE, etc.)
        identifiers = []
        for ident in data.get("identifiers", []):
            identifiers.append(f"{ident.get('type', 'ID')}:{ident.get('value', 'unknown')}")

        return Vulnerability(
            id=str(data.get("id", "unknown")),
            title=data.get("title", data.get("name", "Unknown vulnerability")),
            description=data.get("description", ""),
            severity=self._parse_severity(data.get("severity", "unknown")),
            vuln_type=self._parse_vuln_type(data.get("report_type", "sast")),
            location=location,
            identifiers=identifiers,
            solution=data.get("solution"),
            raw_data=data,
        )

    def parse_dependency_report(self, report: dict) -> list[Vulnerability]:
        """Parse GitLab dependency scanning report."""
        vulnerabilities = []
        for vuln_data in report.get("vulnerabilities", []):
            vuln = self.parse_gitlab_vulnerability(vuln_data)
            vuln.vuln_type = VulnType.DEPENDENCY
            vulnerabilities.append(vuln)
        return vulnerabilities

    def parse_sast_report(self, report: dict) -> list[Vulnerability]:
        """Parse GitLab SAST report."""
        vulnerabilities = []
        for vuln_data in report.get("vulnerabilities", []):
            vuln = self.parse_gitlab_vulnerability(vuln_data)
            vuln.vuln_type = VulnType.SAST
            vulnerabilities.append(vuln)
        return vulnerabilities

    def filter_by_severity(
        self,
        vulns: list[Vulnerability],
        min_severity: list[Severity],
    ) -> list[Vulnerability]:
        """Filter vulnerabilities by severity levels."""
        return [v for v in vulns if v.severity in min_severity]

    def prioritize(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        """Sort vulnerabilities by priority (severity + fixability)."""
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
            Severity.UNKNOWN: 5,
        }
        return sorted(vulns, key=lambda v: severity_order.get(v.severity, 99))

    def _parse_severity(self, severity: str) -> Severity:
        """Parse severity string to enum."""
        try:
            return Severity(severity.lower())
        except ValueError:
            return Severity.UNKNOWN

    def _parse_vuln_type(self, report_type: str) -> VulnType:
        """Parse report type to vulnerability type enum."""
        mapping = {
            "dependency_scanning": VulnType.DEPENDENCY,
            "sast": VulnType.SAST,
            "dast": VulnType.DAST,
            "secret_detection": VulnType.SECRET,
            "container_scanning": VulnType.CONTAINER,
        }
        return mapping.get(report_type.lower(), VulnType.SAST)
