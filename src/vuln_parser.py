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
    """
    Vulnerability type, derived from GitLab's "report_type" field.

    GitLab calls it "report_type" because vulnerabilities are discovered through
    different security scanning jobs in CI/CD pipelines. Each scanner produces
    a report artifact (e.g., gl-dependency-scanning-report.json), and the
    "report_type" indicates which scanner/report the finding originated from.

    Types:
        DEPENDENCY: From "dependency_scanning" reports.
            Scans package manifests (requirements.txt, package.json, pom.xml,
            build.gradle.kts, etc.) for known vulnerable library versions.
            Fix strategy: upgrade package version in the manifest file.

        SAST: From "sast" (Static Application Security Testing) reports.
            Analyzes source code for vulnerabilities like SQL injection, XSS,
            insecure crypto, etc. without executing the application.
            Fix strategy: modify the vulnerable code pattern.

        DAST: From "dast" (Dynamic Application Security Testing) reports.
            Tests running applications by sending malicious requests to find
            vulnerabilities like injection flaws, auth issues, misconfigurations.
            Fix strategy: modify code/config to prevent the detected attack vector.

        SECRET: From "secret_detection" reports.
            Scans code and git history for exposed secrets like API keys,
            passwords, tokens, and certificates.
            Fix strategy: remove/rotate the secret, use env vars or vaults.

        CONTAINER: From "container_scanning" reports.
            Scans Docker images for OS-level package vulnerabilities in the
            base image or installed packages.
            Fix strategy: update base image or packages in Dockerfile.
    """
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

        # Extract file path from location or try to find it in other fields
        file_path = location_data.get("file", "unknown")
        if file_path == "unknown":
            # Try to extract from blob_path or other fields
            file_path = location_data.get("blob_path", data.get("blob_path", "unknown"))

        # Extract dependency package name
        dependency = location_data.get("dependency", {}).get("package", {}).get("name")
        if not dependency:
            # Try to extract from other common locations
            dependency = data.get("package", {}).get("name") if isinstance(data.get("package"), dict) else None

        location = Location(
            file_path=file_path,
            start_line=location_data.get("start_line"),
            end_line=location_data.get("end_line"),
            dependency=dependency,
        )

        # Extract identifiers (CVE, CWE, GHSA, etc.)
        identifiers = []
        for ident in data.get("identifiers", []):
            # GitLab uses external_type/external_id or name
            ident_type = ident.get("external_type", ident.get("type", "ID")).upper()
            ident_value = ident.get("external_id", ident.get("name", ident.get("value", "unknown")))
            identifiers.append(f"{ident_type}:{ident_value}")

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
        """
        Parse GitLab report_type string to VulnType enum.

        Maps GitLab's scanner report types (from the "report_type" field in
        vulnerability_findings API response) to internal VulnType enum values.
        """
        # GitLab report_type values from CI security scanner artifacts
        mapping = {
            "dependency_scanning": VulnType.DEPENDENCY,  # Package/library vulnerabilities
            "sast": VulnType.SAST,  # Source code analysis
            "dast": VulnType.DAST,  # Runtime/dynamic testing
            "secret_detection": VulnType.SECRET,  # Exposed credentials
            "container_scanning": VulnType.CONTAINER,  # Docker image vulnerabilities
        }
        # Default to SAST for unknown types (code-level fix approach)
        return mapping.get(report_type.lower(), VulnType.SAST)

    def get_cve(self, vuln: Vulnerability) -> str | None:
        """Extract CVE identifier from vulnerability."""
        for ident in vuln.identifiers:
            if ident.startswith("CVE:"):
                return ident.split(":", 1)[1]
        return None

    def get_package_name(self, vuln: Vulnerability) -> str | None:
        """Extract package name from vulnerability."""
        if vuln.location.dependency:
            return vuln.location.dependency
        # Try to extract from title (e.g., "QOS.CH logback-core ..." -> "logback-core")
        title = vuln.title.lower()
        if vuln.raw_data:
            for ident in vuln.raw_data.get("identifiers", []):
                url = ident.get("url", "")
                # Extract from gemnasium URL like .../maven/ch.qos.logback/logback-core/...
                if "/maven/" in url:
                    parts = url.split("/maven/")[1].split("/")
                    if len(parts) >= 2:
                        return f"{parts[0]}/{parts[1]}"
        return None

    def group_by_cve(self, vulns: list[Vulnerability]) -> dict[str, list[Vulnerability]]:
        """Group vulnerabilities by CVE identifier."""
        groups: dict[str, list[Vulnerability]] = {}
        no_cve_group: list[Vulnerability] = []

        for vuln in vulns:
            cve = self.get_cve(vuln)
            if cve:
                if cve not in groups:
                    groups[cve] = []
                groups[cve].append(vuln)
            else:
                no_cve_group.append(vuln)

        # Add vulnerabilities without CVE under a special key
        if no_cve_group:
            groups["NO_CVE"] = no_cve_group

        return groups

    def group_by_package(self, vulns: list[Vulnerability]) -> dict[str, list[Vulnerability]]:
        """Group vulnerabilities by package name."""
        groups: dict[str, list[Vulnerability]] = {}

        for vuln in vulns:
            package = self.get_package_name(vuln) or "unknown"
            if package not in groups:
                groups[package] = []
            groups[package].append(vuln)

        return groups
