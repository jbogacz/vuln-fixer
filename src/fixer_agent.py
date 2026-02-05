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
            last_event_type = None

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
                        # Only count as a new turn when the previous event was NOT
                        # an assistant event - stream-json emits multiple "assistant"
                        # events per turn (one per content block), so we deduplicate.
                        if event_type == "assistant":
                            if last_event_type != "assistant":
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

                        last_event_type = event_type

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
        dry_run: bool = False,
        retry_context: str | None = None,
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

After {"analyzing" if dry_run else "fixing"}, write your response as markdown that will be used directly
as the merge request description. Structure it as:

## Summary
- Brief description of the vulnerability and the fix applied

## What was changed
- List each file and what was modified

Then on the VERY LAST LINE of your response, output your confidence as an HTML comment:
<!--CONFIDENCE:0.95-->
(replace 0.95 with your actual confidence from 0.0 to 1.0)
"""

        if retry_context:
            prompt += retry_context

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
        dry_run: bool = False,
        retry_context: str | None = None,
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
- DO NOT fix any other vulnerabilities or CVEs
- DO NOT update unrelated dependencies, even if they appear vulnerable
- If you see other vulnerabilities, IGNORE them - they will be fixed separately
- **EXCEPTION**: You MUST also upgrade **sibling artifacts from the same group** to keep them
  in sync. For example, if fixing `ch.qos.logback:logback-core`, also upgrade
  `ch.qos.logback:logback-classic` to the same version. Mismatched versions within the same
  artifact group cause runtime errors.

## Instructions

### Step 1: Gradle Dependency Analysis (CRITICAL - Gradle projects only)
If this is a Gradle project (build.gradle or build.gradle.kts exists), BEFORE making any changes:

#### 1a. Find which configuration contains the vulnerable dependency
The dependency may NOT be in `compileClasspath`/`runtimeClasspath`. It could be in a build-tool
configuration like `ktlint`, `detekt`, `checkstyle`, `spotbugs`, `pmd`, etc.

Run dependency insight across MULTIPLE configurations to find where it actually lives:
```
./gradlew :module-name:dependencyInsight --dependency {package_name} --configuration compileClasspath 2>/dev/null || true
./gradlew :module-name:dependencyInsight --dependency {package_name} --configuration runtimeClasspath 2>/dev/null || true
./gradlew :module-name:dependencyInsight --dependency {package_name} --configuration ktlint 2>/dev/null || true
./gradlew :module-name:dependencyInsight --dependency {package_name} --configuration detekt 2>/dev/null || true
```
Also check: `./gradlew :module-name:dependencies 2>/dev/null | grep -i "{package_name.split(':')[-1] if ':' in package_name else package_name}"` to see ALL configurations.

#### 1b. Determine the context
From the dependency insight output, determine:
- **Which configuration(s)** contain the vulnerable dependency (e.g., `compileClasspath`, `ktlint`, `detekt`)
- **Is it a runtime dependency or build-tool-only?** If it's in `ktlint`, `detekt`, `checkstyle`,
  `spotbugs`, or similar — it is a BUILD-TOOL dependency with NO production runtime exposure.
- **Resolved version**: What version does Gradle actually resolve to?
- **Requested version**: What version is declared in the dependency tree?
- **Version branch**: What major.minor branch is the vulnerable version on? (e.g., 1.3.x vs 1.5.x)
  The fix version MUST be on the SAME branch. For example, logback-core 1.3.14 needs >= 1.3.15, NOT 1.5.21.
- **Dependency chain**: Which library pulls in the vulnerable transitive version?

#### 1c. Choose the correct fix strategy
**CRITICAL: Apply fixes to the CORRECT configuration. Do NOT add `implementation` constraints
for dependencies that only exist in build-tool configurations like `ktlint` or `detekt`.**

- **If build-tool-only dependency** (ktlint, detekt, etc.):
  - **Preferred**: Upgrade the build tool plugin/dependency to a version that uses the safe library version
  - **Alternative**: Add a resolution strategy to that SPECIFIC configuration:
    ```kotlin
    configurations.named("ktlint") {{
        resolutionStrategy {{
            force("{package_name}:<fixed-version-on-same-branch>")
        }}
    }}
    ```
  - Note in your analysis that this has NO production runtime exposure

- **If runtime dependency (compileClasspath/runtimeClasspath)**:
  - **Preferred**: Upgrade the SOURCE dependency that pulls in the vulnerable transitive
  - **Alternative**: Add a dependency constraint (to `implementation`, NOT to build-tool configs):
    ```kotlin
    dependencies {{
        constraints {{
            implementation("{package_name}:<fixed-version>") {{
                because("<CVE-ID>: <brief description>")
            }}
        }}
    }}
    ```
  - **Last resort**: Exclude the transitive and re-declare at safe version

- **If the resolved runtime version is already safe** (Gradle conflict resolution picks a safe version):
  This is a **false positive** at runtime. GitLab flags the *declared* transitive version, not
  the resolved one. You MUST still fix it to silence the GitLab scanner.

#### 1d. In your response, always report:
- Which Gradle configuration(s) contain the vulnerable dependency
- Whether it is a runtime or build-tool-only dependency
- Whether the resolved runtime version was already safe
- Which dependency is the source of the vulnerable transitive
- The version branch (e.g., "1.3.x line needs >= 1.3.15, not 1.5.x")
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

Your response will be used DIRECTLY as the merge request description (markdown).
Do NOT wrap it in any prefix like "EXPLANATION:" — just write the content.
Structure it with these sections:

## Summary
- One-line description of what was done
- Note if it was a false positive (build-tool only, or runtime already safe)

## Context
Explain the root cause:
- Which Gradle **configuration** contains the vulnerable dependency (e.g., `compileClasspath`, `ktlint`, `detekt`)
- Whether it's a **runtime** or **build-tool-only** dependency
- Which dependency declares the vulnerable transitive version
- What version branch the vulnerability is on (e.g., "1.3.x line, fix requires >= 1.3.15")
- What version Gradle actually resolves to (if applicable)
- Why GitLab flags it (scans declarations, not resolved classpath)

## What was changed
- List each file modified and what was changed
- Explain why the fix targets the correct configuration

## Why we were safe before this change
(Include if the runtime was already safe or dependency is build-tool-only)
If build-tool-only: explain that the dependency has no production runtime exposure.
If runtime false positive: show a version resolution table.

## Why this change is needed
Explain why we still need to make the change to silence the GitLab scanner.

On the VERY LAST LINE, output your confidence as an HTML comment:
<!--CONFIDENCE:0.95-->
(replace 0.95 with your actual confidence from 0.0 to 1.0)
"""

        if retry_context:
            prompt += retry_context

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
        dry_run: bool = False,
        retry_context: str | None = None,
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
- DO NOT update unrelated dependencies, even if they appear vulnerable
- If you see other vulnerabilities, IGNORE them - they will be fixed separately
- **EXCEPTION**: You MUST also upgrade **sibling artifacts from the same group** to keep them
  in sync. For example, if fixing `ch.qos.logback:logback-core`, also upgrade
  `ch.qos.logback:logback-classic` to the same version. Mismatched versions within the same
  artifact group cause runtime errors.

## Instructions

### Step 1: Gradle Dependency Analysis (CRITICAL - Gradle projects only)
If this is a Gradle project (build.gradle or build.gradle.kts exists), BEFORE making any changes:

#### 1a. Find which configuration contains the vulnerable dependency
The dependency may NOT be in `compileClasspath`/`runtimeClasspath`. It could be in a build-tool
configuration like `ktlint`, `detekt`, `checkstyle`, `spotbugs`, `pmd`, etc.

Run dependency insight across MULTIPLE configurations on affected modules:
```
./gradlew :module-name:dependencyInsight --dependency {packages_str.split(',')[0].strip()} --configuration compileClasspath 2>/dev/null || true
./gradlew :module-name:dependencyInsight --dependency {packages_str.split(',')[0].strip()} --configuration runtimeClasspath 2>/dev/null || true
./gradlew :module-name:dependencyInsight --dependency {packages_str.split(',')[0].strip()} --configuration ktlint 2>/dev/null || true
./gradlew :module-name:dependencyInsight --dependency {packages_str.split(',')[0].strip()} --configuration detekt 2>/dev/null || true
```
Also check: `./gradlew :module-name:dependencies 2>/dev/null | grep -i "{packages_str.split(',')[0].strip().split(':')[-1]}"` to see ALL configurations.

#### 1b. Determine the context
From the dependency insight output, determine:
- **Which configuration(s)** contain the vulnerable dependency (e.g., `compileClasspath`, `ktlint`, `detekt`)
- **Is it a runtime dependency or build-tool-only?** If it's in `ktlint`, `detekt`, `checkstyle`,
  `spotbugs`, or similar — it is a BUILD-TOOL dependency with NO production runtime exposure.
- **Resolved version**: What version does Gradle actually resolve to?
- **Requested version**: What version is declared in the dependency tree?
- **Version branch**: What major.minor branch is the vulnerable version on? (e.g., 1.3.x vs 1.5.x)
  The fix version MUST be on the SAME branch. For example, logback-core 1.3.14 needs >= 1.3.15, NOT 1.5.21.
- **Dependency chain**: Which library pulls in the vulnerable transitive version?

#### 1c. Choose the correct fix strategy
**CRITICAL: Apply fixes to the CORRECT configuration. Do NOT add `implementation` constraints
for dependencies that only exist in build-tool configurations like `ktlint` or `detekt`.**

- **If build-tool-only dependency** (ktlint, detekt, etc.):
  - **Preferred**: Upgrade the build tool plugin/dependency to a version that uses the safe library version
  - **Alternative**: Add a resolution strategy to that SPECIFIC configuration:
    ```kotlin
    configurations.named("ktlint") {{
        resolutionStrategy {{
            force("{packages_str.split(',')[0].strip()}:<fixed-version-on-same-branch>")
        }}
    }}
    ```
  - Note in your analysis that this has NO production runtime exposure

- **If runtime dependency (compileClasspath/runtimeClasspath)**:
  - **Preferred**: Upgrade the SOURCE dependency that pulls in the vulnerable transitive
  - **Alternative**: Add a dependency constraint (to `implementation`, NOT to build-tool configs):
    ```kotlin
    dependencies {{
        constraints {{
            implementation("{packages_str.split(',')[0].strip()}:<fixed-version>") {{
                because("{cve}: <brief description>")
            }}
        }}
    }}
    ```
  - **Last resort**: Exclude the transitive and re-declare at safe version

- **If the resolved runtime version is already safe** (Gradle conflict resolution picks a safe version):
  This is a **false positive** at runtime. GitLab flags the *declared* transitive version, not
  the resolved one. You MUST still fix it to silence the GitLab scanner.

#### 1d. Important considerations
- When the same transitive source affects multiple modules, the fix may be in a single shared
  build file (e.g., root `build.gradle.kts` or a common module) rather than each file individually.
- When adding constraints or resolution strategies, make sure they apply to ALL affected modules.

#### 1e. In your response, always report:
- Which Gradle configuration(s) contain the vulnerable dependency
- Whether it is a runtime or build-tool-only dependency
- Whether the resolved runtime version was already safe
- Which dependency is the source of the vulnerable transitive
- The version branch (e.g., "1.3.x line needs >= 1.3.15, not 1.5.x")
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

Your response will be used DIRECTLY as the merge request description (markdown).
Do NOT wrap it in any prefix like "EXPLANATION:" — just write the content.
Structure it with these sections:

## Summary
- One-line description of what was done
- Note if it was a false positive (build-tool only, or runtime already safe)
- Number of affected files/modules

## Context
Explain the root cause:
- Which Gradle **configuration** contains the vulnerable dependency (e.g., `compileClasspath`, `ktlint`, `detekt`)
- Whether it's a **runtime** or **build-tool-only** dependency
- Which dependency declares the vulnerable transitive version
- What version branch the vulnerability is on (e.g., "1.3.x line, fix requires >= 1.3.15")
- What version Gradle actually resolves to (if applicable)
- Why GitLab flags it (scans declarations, not resolved classpath)

## What was changed
- List each file modified and what was changed
- Explain why the fix targets the correct configuration

## Why we were safe before this change
(Include if the runtime was already safe or dependency is build-tool-only)
If build-tool-only: explain that the dependency has no production runtime exposure.
If runtime false positive: show a version resolution table.

## Why this change is needed
Explain why we still need to make the change to silence the GitLab scanner.

On the VERY LAST LINE, output your confidence as an HTML comment:
<!--CONFIDENCE:0.95-->
(replace 0.95 with your actual confidence from 0.0 to 1.0)
"""

        if retry_context:
            prompt += retry_context

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

        Confidence is extracted from an HTML comment tag: <!--CONFIDENCE:0.95-->
        Everything else is the explanation (used directly as MR description body).

        Args:
            output: Raw output from Claude CLI

        Returns:
            Tuple of (explanation, confidence)
        """
        confidence = 0.7  # Default confidence

        # Extract confidence from HTML comment: <!--CONFIDENCE:0.95-->
        conf_match = re.search(r"<!--CONFIDENCE:([\d.]+)-->", output)
        if conf_match:
            try:
                confidence = float(conf_match.group(1))
                if confidence > 1:
                    confidence = confidence / 100
            except ValueError:
                pass

        # Explanation = everything except the confidence tag
        explanation = re.sub(r"\s*<!--CONFIDENCE:[\d.]+-->\s*", "", output).strip()

        # Strip any preamble before the first markdown header (e.g., "Here is the merge request description:\n\n---")
        header_match = re.search(r"^## ", explanation, re.MULTILINE)
        if header_match and header_match.start() > 0:
            explanation = explanation[header_match.start():]

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

        is_gradle_fix = any(
            f.endswith(('.gradle', '.gradle.kts'))
            for f in fix.files_modified
        )

        if is_gradle_fix:
            package_name = vuln.location.dependency if vuln else "unknown"
            specific_checks = f"""
### Gradle-Specific Validation (CRITICAL)
You MUST run these checks — do NOT just review the diff. Execute commands in the repo.

#### 1. Configuration Check
Run `dependencyInsight` on the affected module(s) to verify the fix targets the **correct Gradle configuration**:
```
./gradlew :module:dependencyInsight --dependency {package_name} --configuration compileClasspath 2>/dev/null || true
./gradlew :module:dependencyInsight --dependency {package_name} --configuration runtimeClasspath 2>/dev/null || true
./gradlew :module:dependencyInsight --dependency {package_name} --configuration ktlint 2>/dev/null || true
./gradlew :module:dependencyInsight --dependency {package_name} --configuration detekt 2>/dev/null || true
```
- If the vulnerability is in a build-tool config (ktlint, detekt, checkstyle), an `implementation` constraint will NOT fix it.
- If the vulnerability is in runtimeClasspath, a `ktlint` resolution strategy will NOT fix it.
- FAIL if the fix targets the wrong configuration.

#### 2. Version Branch Check
- Determine the **version branch** of the vulnerable dependency (e.g., 1.3.x vs 1.5.x).
- Verify the fix version is on the **same branch**. For example, logback 1.3.14 must be fixed with 1.3.15+, NOT 1.5.21.
- FAIL if the fix crosses version branches without justification.

#### 3. Resolution Verification
After applying the fix, verify with `dependencyInsight` that the vulnerable version is actually resolved away:
- The resolved version in the flagged configuration must be >= the known fixed version.
- If the resolved version hasn't changed, the fix is ineffective.

#### 4. General Checks
1. **Version Validity**: Is the new version a real, published version?
2. **Syntax**: Is the Gradle Kotlin DSL / Groovy syntax correct?
3. **Scope**: Does the fix apply to the correct dependency (group:artifact)?
4. **Style**: Does the fix match existing dependency declaration style in the build file?
"""
        elif is_dependency_fix:
            specific_checks = """
### Dependency-Specific Checks
1. **Version Validity**: Is the new version a real, published version?
2. **Version Safety**: Does this version actually fix the CVE? (check if version >= known fixed version)
3. **Compatibility**: Could this version conflict with other dependencies (e.g., Spring Boot BOM, parent POMs)?
4. **Syntax**: Is the build file syntax correct (Maven XML, package.json, etc.)?
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

    @staticmethod
    def build_retry_context(validation: ValidationResult) -> str:
        """Build a retry context string from a failed validation result."""
        issues_str = "\n".join(f"- {issue}" for issue in validation.issues) if validation.issues else "- (none listed)"
        suggestions_str = "\n".join(f"- {s}" for s in validation.suggestions) if validation.suggestions else "- (none)"

        return f"""

## IMPORTANT: Previous Attempt Failed Validation

Your previous fix was rejected by the validator for these reasons:

Issues:
{issues_str}

Suggestions:
{suggestions_str}

You MUST address ALL of these issues in your new fix. Do NOT repeat the same mistake.
"""
