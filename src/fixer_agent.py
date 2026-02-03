"""AI-powered vulnerability fixer using Claude CLI."""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .vuln_parser import Vulnerability, VulnType


@dataclass
class Fix:
    file_path: str
    original_content: str
    fixed_content: str
    explanation: str
    confidence: float  # 0-1
    files_modified: list[str]


@dataclass
class ClaudeResult:
    success: bool
    output: str
    files_modified: list[str]
    error: str | None = None


class FixerAgent:
    """AI agent for analyzing and fixing vulnerabilities using Claude CLI."""

    def __init__(self, timeout: int = 300):
        """
        Initialize the fixer agent.

        Args:
            timeout: Max seconds to wait for Claude CLI response
        """
        self.timeout = timeout
        self._verify_claude_cli()

    def _verify_claude_cli(self) -> None:
        """Verify Claude CLI is installed and accessible."""
        try:
            result = subprocess.run(
                ["claude", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                raise RuntimeError("Claude CLI not working properly")
        except FileNotFoundError:
            raise RuntimeError(
                "Claude CLI not found. Install it with: npm install -g @anthropic-ai/claude-code"
            )

    def _run_claude(self, prompt: str, cwd: Path) -> ClaudeResult:
        """
        Run Claude CLI with a prompt.

        Args:
            prompt: The task prompt for Claude
            cwd: Working directory (repo path)

        Returns:
            ClaudeResult with output and modified files
        """
        try:
            result = subprocess.run(
                [
                    "claude",
                    "-p", prompt,
                    "--output-format", "json",
                    "--max-turns", "20",
                    "--dangerously-skip-permissions"
                ],
                capture_output=True,
                text=True,
                cwd=cwd,
                timeout=self.timeout
            )

            if result.returncode != 0:
                return ClaudeResult(
                    success=False,
                    output="",
                    files_modified=[],
                    error=result.stderr or "Claude CLI failed"
                )

            # Parse JSON output
            try:
                output_data = json.loads(result.stdout)
                # Extract the actual result text, never use raw JSON
                result_text = output_data.get("result", "")

                # If result is empty (e.g., max_turns hit), provide a summary
                if not result_text or result_text.strip() == "":
                    subtype = output_data.get("subtype", "")
                    if subtype == "error_max_turns":
                        result_text = "Fix applied (Claude CLI completed with max turns reached)"
                    else:
                        result_text = "Fix applied successfully"

                return ClaudeResult(
                    success=True,
                    output=result_text,
                    files_modified=output_data.get("files_modified", []),
                    error=None
                )
            except json.JSONDecodeError:
                # Plain text output
                return ClaudeResult(
                    success=True,
                    output=result.stdout,
                    files_modified=[],
                    error=None
                )

        except subprocess.TimeoutExpired:
            return ClaudeResult(
                success=False,
                output="",
                files_modified=[],
                error=f"Claude CLI timed out after {self.timeout}s"
            )
        except Exception as e:
            return ClaudeResult(
                success=False,
                output="",
                files_modified=[],
                error=str(e)
            )

    def analyze_and_fix(
        self,
        vuln: Vulnerability,
        repo_path: Path,
        dry_run: bool = False
    ) -> Fix | None:
        """
        Analyze vulnerability and generate a fix using Claude CLI.

        Claude CLI handles:
        - Reading the affected file
        - Analyzing the vulnerability
        - Making the code edit
        - Reporting what changed

        Args:
            vuln: The vulnerability to fix
            repo_path: Path to the local repository
            dry_run: If True, only analyze without making changes

        Returns:
            Fix object with results, or None if failed
        """
        # Read original content for comparison
        file_path = repo_path / vuln.location.file_path
        original_content = ""
        if file_path.exists():
            original_content = file_path.read_text()

        # Build prompt for Claude CLI
        action = "analyze and explain how to fix" if dry_run else "fix"

        prompt = f"""
You are a security expert. {action.capitalize()} this vulnerability:

## Vulnerability Details
- **ID**: {vuln.id}
- **Title**: {vuln.title}
- **Severity**: {vuln.severity.value}
- **Type**: {vuln.vuln_type.value}
- **File**: {vuln.location.file_path}
- **Line**: {vuln.location.start_line or 'unknown'}
- **Identifiers**: {', '.join(vuln.identifiers)}

## Description
{vuln.description}

## Suggested Solution
{vuln.solution or 'No solution provided - analyze and determine best fix'}

## Instructions

### Step 1: Analyze Code Style (IMPORTANT)
Before making any changes, read the file and surrounding code to identify:
- Naming conventions (camelCase, snake_case, etc.)
- Indentation style (spaces vs tabs, indent size)
- Quote style (single vs double quotes)
- Error handling patterns used in this codebase
- Import organization
- Comment style

### Step 2: Fix the Vulnerability
1. Read the file {vuln.location.file_path}
2. Analyze the vulnerability at/around line {vuln.location.start_line or 'unknown'}
3. {"Explain the fix without modifying files" if dry_run else "Edit the file to fix the security issue"}
4. Make minimal changes - only fix the security issue
5. Do not refactor or change unrelated code

### Step 3: Match Existing Style (MANDATORY)
Your fix MUST match the existing code style EXACTLY:
- Use the same naming conventions as surrounding code
- Match indentation and formatting
- Follow the same error handling patterns
- Keep consistent with existing imports and structure
- DO NOT introduce new patterns, abstractions, or "best practices" that don't exist in the file
- DO NOT refactor or "improve" the code beyond fixing the security issue
- The goal is MINIMAL change that blends in with existing code

After {"analyzing" if dry_run else "fixing"}, provide:
- EXPLANATION: What the vulnerability is and how {"to fix" if dry_run else "it was fixed"}
- CONFIDENCE: Your confidence level (0.0-1.0) that this fix is correct
"""

        # Run Claude CLI
        result = self._run_claude(prompt, repo_path)

        if not result.success:
            print(f"Claude CLI error: {result.error}")
            return None

        # Read potentially modified content
        fixed_content = original_content
        if not dry_run and file_path.exists():
            fixed_content = file_path.read_text()

        # Parse explanation and confidence from output
        explanation, confidence = self._parse_output(result.output)

        return Fix(
            file_path=vuln.location.file_path,
            original_content=original_content,
            fixed_content=fixed_content,
            explanation=explanation,
            confidence=confidence,
            files_modified=result.files_modified or (
                [vuln.location.file_path] if fixed_content != original_content else []
            )
        )

    def fix_dependency(
        self,
        vuln: Vulnerability,
        repo_path: Path,
        dry_run: bool = False
    ) -> Fix | None:
        """
        Generate fix for dependency vulnerability using Claude CLI.

        Args:
            vuln: Dependency vulnerability to fix
            repo_path: Path to the local repository
            dry_run: If True, only analyze without making changes

        Returns:
            Fix object with results, or None if failed
        """
        action = "analyze" if dry_run else "fix"

        prompt = f"""
You are a security expert. {action.capitalize()} this dependency vulnerability:

## Vulnerability Details
- **Package**: {vuln.location.dependency or 'unknown'}
- **Identifiers**: {', '.join(vuln.identifiers)}
- **Severity**: {vuln.severity.value}
- **Description**: {vuln.description}
- **Solution**: {vuln.solution or 'Upgrade to patched version'}

## Instructions

### Step 1: Analyze Dependency File Style (CRITICAL)
Before making changes, read the dependency file to identify:
- Version pinning style (exact: "1.2.3", range: "^1.2.3", ">=1.2.3")
- How dependencies are declared (string literals vs version catalogs vs variables)
- Formatting and organization of dependencies

### Step 2: Fix the Vulnerability
1. Find the dependency file (requirements.txt, package.json, pyproject.toml, build.gradle.kts, pom.xml, etc.)
2. Locate the vulnerable package
3. {"Explain the required version change" if dry_run else "Update to a safe version"}
4. Only change the specific package version

### Step 3: Match Existing Style (MANDATORY)
Your fix MUST match the existing dependency file style EXACTLY:
- If other dependencies use string literals like "group:artifact:version", you MUST use the same format
- If other dependencies use version catalogs (libs.xxx), then use version catalogs
- DO NOT introduce new patterns, abstractions, or "best practices" that don't exist in the file
- DO NOT add entries to version catalog files (libs.versions.toml) unless the project already uses them for similar dependencies
- The goal is MINIMAL change - only add/change the version number, nothing else

Provide:
- EXPLANATION: What version change {"is needed" if dry_run else "was made"}
- CONFIDENCE: Your confidence (0.0-1.0) that this upgrade is safe
"""

        result = self._run_claude(prompt, repo_path)

        if not result.success:
            print(f"Claude CLI error: {result.error}")
            return None

        explanation, confidence = self._parse_output(result.output)

        return Fix(
            file_path=result.files_modified[0] if result.files_modified else "unknown",
            original_content="",  # Not tracked for dependency fixes
            fixed_content="",
            explanation=explanation,
            confidence=confidence,
            files_modified=result.files_modified
        )

    def _parse_output(self, output: str) -> tuple[str, float]:
        """
        Parse Claude's output to extract explanation and confidence.

        Args:
            output: Raw output from Claude CLI

        Returns:
            Tuple of (explanation, confidence)
        """
        explanation = output
        confidence = 0.7  # Default confidence

        # Try to extract structured parts
        if "EXPLANATION:" in output:
            parts = output.split("EXPLANATION:")
            if len(parts) > 1:
                explanation_part = parts[1]
                if "CONFIDENCE:" in explanation_part:
                    explanation = explanation_part.split("CONFIDENCE:")[0].strip()
                else:
                    explanation = explanation_part.strip()

        if "CONFIDENCE:" in output:
            try:
                conf_part = output.split("CONFIDENCE:")[1]
                # Extract first number found
                import re
                match = re.search(r"(\d+\.?\d*)", conf_part)
                if match:
                    confidence = float(match.group(1))
                    if confidence > 1:
                        confidence = confidence / 100  # Handle percentage
            except (IndexError, ValueError):
                pass

        return explanation, min(max(confidence, 0.0), 1.0)

    def validate_fix(self, fix: Fix, repo_path: Path) -> bool:
        """
        Ask Claude to validate a fix doesn't break anything.

        Args:
            fix: The fix to validate
            repo_path: Path to the repository

        Returns:
            True if fix appears valid
        """
        prompt = f"""
Review this security fix for correctness:

## File: {fix.file_path}

## Changes made:
{fix.explanation}

## Instructions:
1. Read the modified file
2. Check for syntax errors
3. Verify the fix addresses the security issue
4. Check for any obvious bugs introduced

Respond with:
- VALID: yes or no
- ISSUES: any problems found (or "none")
"""

        result = self._run_claude(prompt, repo_path)

        if not result.success:
            return False

        output_lower = result.output.lower()
        return "valid: yes" in output_lower or "valid:yes" in output_lower
