# Vuln-Fixer Architecture

## Problem Statement

Security vulnerability reports from GitLab (SAST, dependency scanning, etc.) generate lists of issues that need to be fixed. Manually triaging, analyzing, and fixing each vulnerability is time-consuming and error-prone.

**Goal:** Automate the process of reading vulnerability reports, analyzing affected code, generating fixes, and creating merge requests for review.

---

## Key Design Decisions

### 1. Zero Configuration

GitLab project is **auto-detected** from the local repository's git remote URL:

```
/path/to/repo/.git/config
    └─> git remote get-url origin
        └─> git@gitlab.com:group/subgroup/project.git
            └─> project: group/subgroup/project
            └─> hostname: gitlab.com
```

**No manual configuration required** - just point to a cloned repo.

### 2. CLI-Based Integration

Instead of implementing API clients and agent loops, we leverage existing CLI tools:

| Tool | Purpose | Why |
|------|---------|-----|
| **glab** | GitLab API | Already authenticated, familiar commands |
| **Claude CLI** | AI analysis & fixes | Built-in agent loop, file tools, auth handled |

This means:
- No API keys to manage
- No custom tool implementations
- Simpler, more maintainable code

---

## High-Level Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Local Git Repo │────▶│   Orchestrator   │────▶│  GitLab MR      │
│  (auto-detect)  │     │  (Python + CLI)  │     │  (with fixes)   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
        │                      │
        │ git remote URL       │ subprocess
        ▼                      ▼
┌─────────────────┐     ┌──────────────────┐
│  glab CLI       │     │   Claude CLI     │
│  (GitLab API)   │     │  (reads & edits) │
└─────────────────┘     └──────────────────┘
```

**Usage is simple:**
```bash
vuln-fixer -r /path/to/my-cloned-repo list
vuln-fixer -r /path/to/my-cloned-repo fix 12345
```

---

## Data Flow

```
1. DETECT         2. FETCH           3. INVOKE CLI      4. COMMIT         5. SUBMIT
   │                 │                  │                 │                 │
   ▼                 ▼                  ▼                 ▼                 ▼
┌─────────┐     ┌─────────┐       ┌─────────┐      ┌─────────┐      ┌─────────┐
│ Parse   │     │ glab    │       │ Claude  │      │ git     │      │ glab    │
│ git     │────▶│ api     │──────▶│ CLI     │─────▶│ commit  │─────▶│ mr      │
│ remote  │     │ vulns   │       │ fix     │      │ push    │      │ create  │
└─────────┘     └─────────┘       └─────────┘      └─────────┘      └─────────┘
     │               │                 │                │                │
   URL to        JSON from         Files edited      Branch with      MR for
   project       GitLab API        on disk           fix commit       review
```

---

## Component Overview

### 1. GitLab Client (`gitlab_client.py`)

**Auto-detects project** from repository and uses **glab CLI** for all operations:

```python
# Auto-detection from repo
client = GitLabClient.from_repo("/path/to/repo")
# Parses: git@gitlab.com:group/project.git
# Result: project="group/project", hostname=None (gitlab.com default)

# All operations use glab subprocess
client.get_vulnerability_report()  # glab api projects/:id/vulnerability_findings
client.create_merge_request(...)   # glab mr create
```

**Supported URL formats:**

| Format | Example |
|--------|---------|
| SSH | `git@gitlab.com:group/project.git` |
| HTTPS | `https://gitlab.com/group/project.git` |
| Nested | `git@gitlab.com:org/team/project.git` |
| Self-hosted | `git@gitlab.example.com:group/project.git` |

### 2. Vulnerability Parser (`vuln_parser.py`)

Normalizes GitLab vulnerability reports into a unified structure:

```python
@dataclass
class Vulnerability:
    id: str
    title: str
    description: str
    severity: Severity        # critical, high, medium, low
    vuln_type: VulnType       # dependency, sast, dast, secret, container
    location: Location        # file, line numbers, package
    identifiers: list[str]    # CVE-xxxx, CWE-xxx
    solution: str | None
```

**VulnType Mapping (from GitLab's `report_type` field):**

| GitLab report_type | VulnType | Description | Fix Strategy |
|-------------------|----------|-------------|--------------|
| `dependency_scanning` | DEPENDENCY | Package/library vulnerabilities | Upgrade version in manifest |
| `sast` | SAST | Static code analysis (SQLi, XSS, etc.) | Modify vulnerable code pattern |
| `dast` | DAST | Dynamic/runtime testing | Modify code/config |
| `secret_detection` | SECRET | Exposed credentials | Remove + use env vars/vaults |
| `container_scanning` | CONTAINER | Docker image vulnerabilities | Update base image/packages |

GitLab calls it "report_type" because vulnerabilities come from different CI scanner jobs, each producing a report artifact (e.g., `gl-dependency-scanning-report.json`).

### 3. Fixer Agent (`fixer_agent.py`)

Orchestrates **Claude CLI** to analyze and fix vulnerabilities:

```python
class FixerAgent:
    def analyze_and_fix(self, vuln, repo_path, dry_run=False):
        # Build prompt with vulnerability context
        prompt = f"Fix this {vuln.severity} vulnerability in {vuln.location.file_path}..."

        # Invoke Claude CLI - it handles file reading, analysis, and editing
        result = subprocess.run(
            ["claude", "-p", prompt, "--output-format", "json"],
            cwd=repo_path
        )

        # Parse results
        return Fix(explanation=..., confidence=..., files_modified=...)
```

**Claude CLI handles internally:**
- Reading affected files
- Analyzing the vulnerability
- Making minimal code edits
- Reporting what was changed

### 4. CLI (`main.py`)

Simple command interface:

```bash
vuln-fixer -r /path/to/repo info      # Show detected project
vuln-fixer -r /path/to/repo list      # List vulnerabilities
vuln-fixer -r /path/to/repo fix 123   # Fix specific vulnerability
vuln-fixer -r /path/to/repo fix-all   # Batch fix
```

---

## Workflow: Single Vulnerability Fix

```
┌──────────────────────────────────────────────────────────────────┐
│          USER RUNS: vuln-fixer -r /path/to/repo fix 12345        │
└──────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │  1. Check repo is clean │
                    │     (no uncommitted     │
                    │      changes)           │
                    └───────────┬─────────────┘
                                │ ABORT if dirty
                                ▼
                    ┌─────────────────────────┐
                    │  2. Auto-detect project │
                    │     from git remote     │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │  3. Fetch vuln details  │
                    │     via glab api        │
                    └───────────┬─────────────┘
                                │
                                ▼
┌───────────────────────────────────────────────────────────────────┐
│  4. CLAUDE CLI SUBPROCESS                                         │
│                                                                   │
│     subprocess.run(["claude", "-p", prompt, ...], cwd=repo_path)  │
│                                                                   │
│     Prompt includes SCOPE LIMITATION:                             │
│     - Only fix the specified CVE/package                          │
│     - Ignore other vulnerabilities                                │
│                                                                   │
│     Claude CLI autonomously:                                      │
│     ├─▶ Reads the affected file                                   │
│     ├─▶ Analyzes the vulnerability                                │
│     ├─▶ Determines the fix                                        │
│     ├─▶ Edits the file on disk                                    │
│     └─▶ Returns explanation + confidence                          │
└───────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │  5. Check confidence    │
                    │     threshold           │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │  6. Create branch       │
                    │     git checkout -b     │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │  7. Commit & push       │
                    │     git add/commit/push │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │  8. Create MR with      │
                    │     full analysis       │
                    │     (explanation, key   │
                    │     findings, changes,  │
                    │     confidence)         │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │  9. Return MR URL       │
                    │     for human review    │
                    └─────────────────────────┘
```

---

## Configuration

**Most users need no configuration.** Optional settings in `config/settings.yaml`:

```yaml
gitlab:
  target_branch: main       # MR target branch

agent:
  timeout: 300              # Claude CLI timeout (seconds)

options:
  min_confidence: 0.7       # Reject low-confidence fixes
  max_fixes_per_run: 10     # Batch limit
```

---

## Prerequisites

| Tool | Installation | Purpose |
|------|--------------|---------|
| Claude CLI | `npm install -g @anthropic-ai/claude-code` | AI analysis |
| glab | `brew install glab` | GitLab API |
| Python 3.11+ | - | Orchestration |

Both CLIs must be authenticated:
```bash
claude auth
glab auth login
```

---

## Safety Considerations

1. **Human Review Required** - All fixes create MRs for review
2. **Confidence Scores** - Low-confidence fixes prompt for confirmation
3. **Dry Run Mode** - `--dry-run` analyzes without making changes
4. **Minimal Changes** - Prompts instruct Claude to only fix the security issue
5. **No Auto-Merge** - MRs always require manual approval

---

## Error Handling

| Scenario | Handling |
|----------|----------|
| Not a git repo | Error with clear message |
| No git remote | Error with instructions |
| **Uncommitted changes** | **Abort with list of dirty files** |
| glab not installed | Error with install instructions |
| glab not authenticated | Error: "Run glab auth login" |
| Claude CLI timeout | Return error, continue to next vuln |
| Low confidence fix | Prompt user for confirmation |

---

## Supported Vulnerability Types

| Type | Source | Fix Strategy |
|------|--------|--------------|
| **Dependency CVE** | Dependency Scanning | Version bump in manifest |
| **SQL Injection** | SAST | Parameterized queries |
| **XSS** | SAST | Output encoding |
| **Path Traversal** | SAST | Input validation |
| **Hardcoded Secrets** | Secret Detection | Remove + env var |
| **Command Injection** | SAST | Safe API usage |

---

## Future Extensions

- **CI/CD Integration** - Run on new vulnerability reports
- **Fix Validation** - Run tests after applying fix
- **MCP Server** - Expose as MCP tools for Claude
- **Learning Loop** - Track fix approval rates
