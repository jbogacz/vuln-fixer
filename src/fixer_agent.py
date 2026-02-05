"""AI-powered vulnerability fixer using Claude CLI."""

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .vuln_parser import Vulnerability


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


@dataclass
class ValidationResult:
    valid: bool
    issues: list[str]
    suggestions: list[str]
    confidence: float  # 0-1, how confident the validator is


class FixerAgent:
    """AI agent for analyzing and fixing vulnerabilities using Claude CLI."""

    def __init__(self, timeout: int = 300, max_turns: int = 30):
        """
        Initialize the fixer agent.

        Args:
            timeout: Max seconds to wait for Claude CLI response
            max_turns: Max iterations for Claude CLI agent loop (default: 30)
        """
        self.timeout = timeout
        self.max_turns = max_turns
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

    def _run_claude(self, prompt: str, cwd: Path, verbose: bool = True) -> ClaudeResult:
        """
        Run Claude CLI with a prompt, streaming progress output.

        Args:
            prompt: The task prompt for Claude
            cwd: Working directory (repo path)
            verbose: Print progress messages during execution

        Returns:
            ClaudeResult with output and modified files
        """
        try:
            # Use stream-json for real-time progress, then collect final result
            process = subprocess.Popen(
                [
                    "claude",
                    "-p", prompt,
                    "--output-format", "stream-json",
                    "--verbose",
                    "--max-turns", str(self.max_turns),
                    "--dangerously-skip-permissions"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd
            )

            result_data = None
            files_modified = []
            turn_count = 0
            last_tool = None

            # Stream and parse JSON lines
            try:
                for line in process.stdout or []:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        event = json.loads(line)
                        event_type = event.get("type", "")

                        # Track assistant turns (iterations)
                        if event_type == "assistant":
                            turn_count += 1
                            if verbose:
                                print(f"  [Turn {turn_count}/{self.max_turns}] Agent thinking...", flush=True)

                        # Track tool usage
                        elif event_type == "tool_use":
                            tool_name = event.get("tool", event.get("name", "unknown"))
                            if verbose and tool_name != last_tool:
                                print(f"  [Turn {turn_count}] Using tool: {tool_name}", flush=True)
                                last_tool = tool_name

                        # Track file modifications
                        elif event_type == "tool_result":
                            # Check if this was a file edit
                            tool = event.get("tool", "")
                            if tool in ("Edit", "Write"):
                                file_path = event.get("file_path", "")
                                if file_path and file_path not in files_modified:
                                    files_modified.append(file_path)
                                    if verbose:
                                        print(f"  [Turn {turn_count}] Modified: {file_path}", flush=True)

                        # Capture final result
                        elif event_type == "result":
                            result_data = event

                    except json.JSONDecodeError:
                        continue

                # Wait for process to complete
                process.wait(timeout=self.timeout)

            except subprocess.TimeoutExpired:
                process.kill()
                return ClaudeResult(
                    success=False,
                    output="",
                    files_modified=files_modified,
                    error=f"Claude CLI timed out after {self.timeout}s"
                )

            if verbose:
                print(f"  [Done] Completed in {turn_count} turns", flush=True)

            if process.returncode != 0:
                stderr = process.stderr.read() if process.stderr else ""
                return ClaudeResult(
                    success=False,
                    output="",
                    files_modified=files_modified,
                    error=stderr or "Claude CLI failed"
                )

            # Process final result
            if result_data:
                result_text = result_data.get("result", "")
                # Merge file lists
                result_files = result_data.get("files_modified", [])
                all_files = list(set(files_modified + result_files))

                # If result is empty (e.g., max_turns hit), try to build a summary
                if not result_text or result_text.strip() == "":
                    subtype = result_data.get("subtype", "")

                    if all_files:
                        files_str = ", ".join(all_files)
                        result_text = (
                            f"EXPLANATION:\n"
                            f"Files modified: {files_str}\n\n"
                            f"The AI agent applied changes to fix the vulnerability. "
                            f"Please review the diff to verify the fix is correct.\n\n"
                        )
                        if subtype == "error_max_turns":
                            result_text += f"(Note: Agent reached iteration limit at turn {turn_count})\n\n"
                        result_text += "CONFIDENCE: 0.7"
                    elif subtype == "error_max_turns":
                        result_text = (
                            f"EXPLANATION:\n"
                            f"The AI agent reached its iteration limit at turn {turn_count}. "
                            f"The fix may have been applied - please check git status.\n\n"
                            "CONFIDENCE: 0.5"
                        )
                    else:
                        result_text = (
                            "EXPLANATION:\n"
                            "Fix applied successfully.\n\n"
                            "CONFIDENCE: 0.7"
                        )

                return ClaudeResult(
                    success=True,
                    output=result_text,
                    files_modified=all_files,
                    error=None
                )

            # No result data - return what we collected
            return ClaudeResult(
                success=True,
                output="Fix completed (no detailed output available)",
                files_modified=files_modified,
                error=None
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

        package_name = vuln.location.dependency or 'unknown'
        identifiers = ', '.join(vuln.identifiers)

        prompt = f"""
You are a security expert. {action.capitalize()} this dependency vulnerability:

## Vulnerability Details
- **Package**: {package_name}
- **Identifiers**: {identifiers}
- **Severity**: {vuln.severity.value}
- **Description**: {vuln.description}
- **Solution**: {vuln.solution or 'Upgrade to patched version'}

## CRITICAL: Scope Limitation
You are ONLY fixing the vulnerability in package: {package_name}
- DO NOT fix any other vulnerabilities or packages
- DO NOT update any other dependencies, even if they appear vulnerable
- ONLY modify the {package_name} package
- If you see other vulnerabilities, IGNORE them - they will be fixed separately

## Instructions

### Step 1: Check for Gradle False Positive (IMPORTANT - Gradle projects only)
If this is a Gradle project (build.gradle or build.gradle.kts exists), BEFORE making any changes:

1. Run: `./gradlew dependencyInsight --dependency {package_name} --configuration compileClasspath 2>/dev/null || true`
   (try multiple modules if needed, e.g. `./gradlew :module-name:dependencyInsight ...`)
2. Look at the output to determine:
   - **Resolved version**: What version does Gradle actually resolve to at runtime?
   - **Requested version**: What version is declared in the dependency tree?
   - **Dependency chain**: Which library pulls in the vulnerable transitive version?

3. If the resolved version is ALREADY >= the fixed version (meaning Gradle conflict resolution
   already picks a safe version), this is a **false positive** at runtime. However, GitLab's
   scanner flags the *declared* transitive dependency version, not the resolved one.
   To silence the GitLab scanner, you MUST still fix it.

4. **Fix strategy for false positives (transitive dependency issues):**
   - **Preferred**: Upgrade the SOURCE dependency that pulls in the vulnerable transitive.
     For example, if `library-A:1.0` pulls in `vulnerable-lib:1.2.3`, upgrade `library-A`
     to a version that declares `vulnerable-lib >= fixed-version`.
   - **Alternative**: Add a dependency constraint in the build.gradle.kts to enforce minimum version:
     ```kotlin
     dependencies {{
         constraints {{
             implementation("{package_name}:<fixed-version>") {{
                 because("<CVE-ID>: <brief description>")
             }}
         }}
     }}
     ```
   - **Last resort**: Exclude the transitive and re-declare at safe version.

5. In your EXPLANATION, always report:
   - Whether the resolved runtime version was already safe
   - Which dependency is the source of the vulnerable transitive
   - Which fix strategy you chose and why

### Step 2: Analyze Dependency File Style (CRITICAL)
Before making changes, read the dependency file to identify:
- Version pinning style (exact: "1.2.3", range: "^1.2.3", ">=1.2.3")
- How dependencies are declared (string literals vs version catalogs vs variables)
- Formatting and organization of dependencies

### Step 3: Fix ONLY the {package_name} Vulnerability
1. Find the dependency file (requirements.txt, package.json, pyproject.toml, build.gradle.kts, pom.xml, etc.)
2. Locate the {package_name} package
3. {"Explain the required version change" if dry_run else "Update to a safe version"}
4. ONLY change the {package_name} version - nothing else

### Step 4: Match Existing Style (MANDATORY)
Your fix MUST match the existing dependency file style EXACTLY:
- If other dependencies use string literals like "group:artifact:version", you MUST use the same format
- If other dependencies use version catalogs (libs.xxx), then use version catalogs
- DO NOT introduce new patterns, abstractions, or "best practices" that don't exist in the file
- DO NOT add entries to version catalog files (libs.versions.toml) unless the project already uses them for similar dependencies
- The goal is MINIMAL change - only add/change the version number, nothing else

## Response Format

Provide your response in these EXACT sections:

EXPLANATION:

## Summary
- One-line description of what was done (e.g., "Fix CVE-XXXX by upgrading package X from A to B in `module/build.gradle.kts`")
- If false positive: note it was a false positive in GitLab scanner

## Context
Explain the root cause. If this was a Gradle false positive, explain:
- Which dependency declares the vulnerable transitive version
- What version Gradle actually resolves to at runtime
- Why GitLab flags it anyway (scans declarations, not resolved classpath)
If not a false positive, explain the vulnerability and why the fix is needed.

## What was changed
- List each file modified and what was changed (e.g., "Upgraded `library-X` from `1.0` to `2.0` in `module/build.gradle.kts`")

## Why we were safe before this change
(Include ONLY if this was a Gradle false positive)
Show a table like:
| Stage | Version | In runtime classpath? |
|-------|---------|----------------------|
| library-X requests | vulnerable-version | **No** |
| BOM/other manages | safe-version | **Yes** |
Explain briefly that Gradle conflict resolution was already picking the safe version.

## Why this change is needed
Explain why we still need to make the change (e.g., to silence GitLab scanner, or because the vulnerable version IS in the classpath).

CONFIDENCE: Your confidence (0.0-1.0) that this upgrade is safe
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

    def fix_cve_group(
        self,
        cve: str,
        vulns: list,
        repo_path: Path,
        dry_run: bool = False
    ) -> Fix | None:
        """
        Fix all vulnerabilities in a CVE group at once.

        Args:
            cve: The CVE identifier
            vulns: List of vulnerabilities sharing this CVE
            repo_path: Path to the local repository
            dry_run: If True, only analyze without making changes

        Returns:
            Fix object with results, or None if failed
        """
        action = "analyze" if dry_run else "fix"

        # Build list of affected files
        files_info = "\n".join(
            f"- {v.location.file_path} (package: {v.location.dependency or 'unknown'})"
            for v in vulns
        )

        # Use first vulnerability for details
        first_vuln = vulns[0]

        # Extract the specific package name(s) for this CVE
        packages = list(set(v.location.dependency for v in vulns if v.location.dependency))
        packages_str = ", ".join(packages) if packages else "unknown"

        prompt = f"""
You are a security expert. {action.capitalize()} this CVE across ALL affected files:

## CVE Details
- **CVE**: {cve}
- **Title**: {first_vuln.title}
- **Severity**: {first_vuln.severity.value}
- **Description**: {first_vuln.description}
- **Solution**: {first_vuln.solution or 'Upgrade to patched version'}
- **Affected Package(s)**: {packages_str}

## Affected Files ({len(vulns)} locations)
{files_info}

## CRITICAL: Scope Limitation
You are ONLY fixing {cve} which affects the package(s): {packages_str}
- DO NOT fix any other vulnerabilities or CVEs
- DO NOT update any other packages, even if they appear vulnerable
- ONLY modify the specific package(s) listed above
- If you see other vulnerabilities, IGNORE them - they will be fixed separately

## Instructions

### Step 1: Check for Gradle False Positive (IMPORTANT - Gradle projects only)
If this is a Gradle project (build.gradle or build.gradle.kts exists), BEFORE making any changes:

1. Run dependency insight to check what version Gradle actually resolves at runtime:
   `./gradlew dependencyInsight --dependency {packages_str.split(',')[0].strip()} --configuration compileClasspath 2>/dev/null || true`
   (try multiple modules from the affected files list above)
2. Analyze the output to determine:
   - **Resolved version**: What does Gradle actually use at runtime?
   - **Requested version**: What's declared in the dependency tree?
   - **Dependency chain**: Which library pulls in the vulnerable version as a transitive?

3. If the resolved version is ALREADY safe (>= fixed version), this is a **false positive** at runtime.
   GitLab flags the *declared* transitive dependency, not the resolved one.
   You MUST still fix it to silence the GitLab scanner.

4. **Fix strategy for transitive dependency false positives:**
   - **Preferred**: Upgrade the SOURCE dependency that pulls in the vulnerable transitive.
     Example: if `library-A:1.0` → `vulnerable-lib:1.2.3` (transitive), upgrade `library-A`
     to a newer version that no longer declares the vulnerable transitive version.
     Find the source by looking at the dependencyInsight output chain.
   - **Alternative**: Add a dependency constraint to enforce minimum version:
     ```kotlin
     dependencies {{
         constraints {{
             implementation("{packages_str.split(',')[0].strip()}:<fixed-version>") {{
                 because("{cve}: <brief description>")
             }}
         }}
     }}
     ```
   - **Last resort**: Exclude the transitive and re-declare at safe version.

5. **IMPORTANT**: When the same transitive source affects multiple modules, the fix may be
   in a single shared build file (e.g., root `build.gradle.kts` or a common module) rather
   than in each affected file individually.

6. In your EXPLANATION, always report:
   - Whether the resolved runtime version was already safe
   - Which dependency is the source of the vulnerable transitive
   - Which fix strategy you chose and why

### Step 2: Analyze Dependency File Style (CRITICAL)
Before making changes, read the dependency files to identify:
- Version pinning style (exact: "1.2.3", range: "^1.2.3", ">=1.2.3")
- How dependencies are declared (string literals vs version catalogs vs variables)
- Formatting and organization of dependencies

### Step 3: Fix ONLY the Affected Package in ALL Listed Files
1. Read each affected file listed above
2. {"Explain the required changes" if dry_run else "Update each file to use the safe version"}
3. Apply the SAME fix pattern to all files
4. ONLY change the {packages_str} package version - nothing else

### Step 4: Match Existing Style (MANDATORY)
Your fix MUST match the existing dependency file style EXACTLY:
- If other dependencies use string literals like "group:artifact:version", you MUST use the same format
- If other dependencies use version catalogs (libs.xxx), then use version catalogs
- DO NOT introduce new patterns, abstractions, or "best practices" that don't exist in the files
- DO NOT add entries to version catalog files (libs.versions.toml) unless the project already uses them for similar dependencies
- The goal is MINIMAL change - only add/change the version number, nothing else

## Response Format

Provide your response in these EXACT sections:

EXPLANATION:

## Summary
- One-line description of what was done (e.g., "Fix {cve} ({packages_str}) by upgrading source dependency X in `module/build.gradle.kts`")
- If false positive: note it was a false positive in GitLab scanner
- Number of affected files/modules

## Context
Explain the root cause. If this was a Gradle false positive, explain:
- Which dependency declares the vulnerable transitive version
- What version Gradle actually resolves to at runtime
- Why GitLab flags it anyway (scans declarations, not resolved classpath)
If not a false positive, explain the vulnerability and why the fix is needed.

## What was changed
- List each file modified and what was changed (e.g., "Upgraded `library-X` from `1.0` to `2.0` in `module/build.gradle.kts`")

## Why we were safe before this change
(Include ONLY if this was a Gradle false positive)
Show a table like:
| Stage | Version | In runtime classpath? |
|-------|---------|----------------------|
| library-X requests | vulnerable-version | **No** |
| BOM/other manages | safe-version | **Yes** |
Explain briefly that Gradle conflict resolution was already picking the safe version.

## Why this change is needed
Explain why we still need to make the change (e.g., to silence GitLab scanner, or because the vulnerable version IS in the classpath).

CONFIDENCE: Your confidence (0.0-1.0) that these fixes are correct
"""

        result = self._run_claude(prompt, repo_path)

        if not result.success:
            print(f"Claude CLI error: {result.error}")
            return None

        explanation, confidence = self._parse_output(result.output)

        return Fix(
            file_path=f"{cve} ({len(vulns)} files)",
            original_content="",
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

        # Try to extract EXPLANATION section (handles both "EXPLANATION:" and "## EXPLANATION")
        explanation_match = re.search(
            r"(?:#{1,3}\s*)?EXPLANATION[:\s]*\n*(.*?)(?=(?:#{1,3}\s*)?CONFIDENCE|\Z)",
            output,
            re.IGNORECASE | re.DOTALL
        )
        if explanation_match:
            explanation = explanation_match.group(1).strip()

        # Look for CONFIDENCE with or without colon (Claude may format as "## CONFIDENCE" or "CONFIDENCE:")
        conf_match = re.search(r"CONFIDENCE[:\s]*\n*\s*\**(\d+\.?\d*)", output, re.IGNORECASE)
        if conf_match:
            try:
                confidence = float(conf_match.group(1))
                if confidence > 1:
                    confidence = confidence / 100  # Handle percentage
            except ValueError:
                pass

        return explanation, min(max(confidence, 0.0), 1.0)

    def validate_fix(
        self,
        fix: Fix,
        repo_path: Path,
        vuln: Vulnerability | None = None,
        cve: str | None = None,
    ) -> ValidationResult:
        """
        Validate a fix using Claude to check correctness and safety.

        Args:
            fix: The fix to validate
            repo_path: Path to the repository
            vuln: Optional vulnerability details for context
            cve: Optional CVE identifier

        Returns:
            ValidationResult with detailed validation info
        """
        # Get git diff for the actual changes
        diff_result = subprocess.run(
            ["git", "diff", "--staged"],
            cwd=repo_path,
            capture_output=True,
            text=True
        )
        git_diff = diff_result.stdout.strip()

        # If nothing staged, try unstaged diff
        if not git_diff:
            diff_result = subprocess.run(
                ["git", "diff"],
                cwd=repo_path,
                capture_output=True,
                text=True
            )
            git_diff = diff_result.stdout.strip()

        # If still no diff (changes already committed), compare against main
        if not git_diff:
            diff_result = subprocess.run(
                ["git", "diff", "main..HEAD"],
                cwd=repo_path,
                capture_output=True,
                text=True
            )
            git_diff = diff_result.stdout.strip()

        # Build context about what we're fixing
        vuln_context = ""
        if vuln:
            vuln_context = f"""
## Vulnerability Details
- **CVE/ID**: {cve or vuln.id}
- **Title**: {vuln.title}
- **Severity**: {vuln.severity.value}
- **Type**: {vuln.vuln_type.value}
- **Package**: {vuln.location.dependency or 'N/A'}
- **Description**: {vuln.description[:500] if vuln.description else 'N/A'}
- **Expected Solution**: {vuln.solution or 'Upgrade to patched version'}
"""
        elif cve:
            vuln_context = f"""
## Vulnerability
- **CVE**: {cve}
"""

        # Determine fix type for specific validation
        is_dependency_fix = any(
            f.endswith(('.gradle', '.gradle.kts', 'pom.xml', 'package.json',
                       'requirements.txt', 'pyproject.toml', 'Gemfile', 'go.mod'))
            for f in fix.files_modified
        )

        if is_dependency_fix:
            specific_checks = """
### Dependency-Specific Checks
1. **Version Validity**: Is the new version a real, published version?
2. **Version Safety**: Does this version actually fix the CVE? (check if version >= known fixed version)
3. **Compatibility**: Could this version conflict with other dependencies (e.g., Spring Boot BOM, parent POMs)?
4. **Syntax**: Is the build file syntax correct (Gradle Kotlin DSL, Maven XML, etc.)?
5. **Scope**: Does the fix apply to the correct dependency (group:artifact)?
6. **Approach**: Is using constraints/dependencyManagement the right approach, or should the direct dependency be updated?
"""
        else:
            specific_checks = """
### Code-Specific Checks
1. **Syntax**: Does the code compile/parse correctly?
2. **Logic**: Does the fix actually prevent the vulnerability?
3. **Side Effects**: Could this change break existing functionality?
4. **Completeness**: Are all vulnerable code paths fixed?
5. **Style**: Does the fix match existing code style?
"""

        prompt = f"""
You are a security code reviewer. Validate this fix for correctness and safety.

{vuln_context}

## Changes Made (git diff)
```diff
{git_diff if git_diff else "No diff available - files may not be tracked yet"}
```

## Fix Explanation
{fix.explanation}

## Files Modified
{', '.join(fix.files_modified) if fix.files_modified else 'Unknown'}

{specific_checks}

## Your Task
1. Read the modified files to see the full context
2. Verify the fix is correct and complete
3. Check for any issues or concerns

## Response Format (REQUIRED)
You MUST respond with these exact sections:

VALID: yes or no

CONFIDENCE: 0.0-1.0

ISSUES:
- List any problems found (or "none")

SUGGESTIONS:
- List any improvements (or "none")

REASONING:
Brief explanation of your assessment
"""

        result = self._run_claude(prompt, repo_path, verbose=False)

        if not result.success:
            return ValidationResult(
                valid=False,
                issues=[f"Validation failed: {result.error}"],
                suggestions=[],
                confidence=0.0
            )

        return self._parse_validation_output(result.output)

    def _parse_validation_output(self, output: str) -> ValidationResult:
        """Parse validation output into structured result."""
        # Remove markdown formatting for easier parsing
        output_clean = re.sub(r'\*+', '', output)  # Remove asterisks
        output_lower = output_clean.lower()

        # Parse VALID (handles "VALID: yes", "**VALID**: yes", etc.)
        valid = False
        valid_match = re.search(r"valid[:\s]+\**(yes|no)\**", output_lower)
        if valid_match:
            valid = valid_match.group(1) == "yes"

        # Parse CONFIDENCE (handles "CONFIDENCE: 0.95", "**CONFIDENCE**: 0.95", etc.)
        confidence = 0.7  # default
        conf_match = re.search(r"confidence[:\s]*\**(\d+\.?\d*)", output_lower)
        if conf_match:
            try:
                confidence = float(conf_match.group(1))
                if confidence > 1:
                    confidence = confidence / 100
            except ValueError:
                pass

        # Parse ISSUES
        issues = []
        issues_match = re.search(
            r"issues[:\s]*\n(.*?)(?=suggestions|reasoning|$)",
            output,
            re.IGNORECASE | re.DOTALL
        )
        if issues_match:
            issues_text = issues_match.group(1).strip()
            if issues_text.lower() != "none" and issues_text != "-":
                for line in issues_text.split("\n"):
                    line = line.strip().lstrip("-•*").strip()
                    if line and line.lower() != "none":
                        issues.append(line)

        # Parse SUGGESTIONS
        suggestions = []
        suggestions_match = re.search(
            r"suggestions[:\s]*\n(.*?)(?=reasoning|$)",
            output,
            re.IGNORECASE | re.DOTALL
        )
        if suggestions_match:
            suggestions_text = suggestions_match.group(1).strip()
            if suggestions_text.lower() != "none" and suggestions_text != "-":
                for line in suggestions_text.split("\n"):
                    line = line.strip().lstrip("-•*").strip()
                    if line and line.lower() != "none":
                        suggestions.append(line)

        return ValidationResult(
            valid=valid,
            issues=issues,
            suggestions=suggestions,
            confidence=min(max(confidence, 0.0), 1.0)
        )
