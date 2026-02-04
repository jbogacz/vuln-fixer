# Vuln-Fixer: GitLab Security Vulnerability Auto-Remediation

## Overview

Automated tool to fetch security vulnerability reports from GitLab, analyze them, generate fixes using **Claude CLI**, and create Merge Requests.

**Key Design Decisions:**
- **Zero configuration** - GitLab project auto-detected from local repo's git remote URL
- **Claude CLI** as AI engine - built-in agent loop, file read/write, no custom tools needed
- **glab CLI** for GitLab - uses existing authentication, no API tokens to manage

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Point to any cloned GitLab repository - that's it!
python -m src.main -r /path/to/your/repo list
python -m src.main -r /path/to/your/repo fix VULN-123 --dry-run
python -m src.main -r /path/to/your/repo fix VULN-123
```

---

## Prerequisites

```bash
# Claude CLI (required for AI-powered fixes)
npm install -g @anthropic-ai/claude-code
claude --version
claude auth

# glab CLI (required for GitLab integration)
# macOS:
brew install glab
# Linux: see https://gitlab.com/gitlab-org/cli

glab --version
glab auth login
```

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│  YOU RUN: python -m src.main -r /path/to/repo list                  │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  1. Read git remote URL       │
              │     git@gitlab.com:group/proj │
              └───────────────┬───────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  2. Auto-detect GitLab project│
              │     project: group/proj       │
              │     hostname: gitlab.com      │
              └───────────────┬───────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  3. Fetch vulnerabilities     │
              │     via glab CLI              │
              └───────────────┬───────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  4. Display/Fix using         │
              │     Claude CLI                │
              └───────────────────────────────┘
```

---

## Commands

| Command | Description |
|---------|-------------|
| `info` | Show detected GitLab project from repo |
| `list` | List vulnerabilities (filtered by severity) |
| `fix <id> <jira>` | Fix a specific vulnerability |
| `list-groups` | List vulnerabilities grouped by CVE or package |
| `fix-group <cve> <jira>` | Fix all vulnerabilities for a CVE in one MR |
| `fix-all-groups <jira-prefix>` | Fix all CVE groups, one MR per CVE |

### Examples

```bash
# Show detected project info
vuln-fixer -r /path/to/repo info

# List high and critical vulnerabilities
vuln-fixer -r /path/to/repo list

# List all severities
vuln-fixer -r /path/to/repo list -s critical -s high -s medium -s low

# Analyze a vulnerability without making changes
vuln-fixer -r /path/to/repo fix 12345 SEC-789 --dry-run

# Fix and create MR
vuln-fixer -r /path/to/repo fix 12345 SEC-789

# Local only (don't push or create MR)
vuln-fixer -r /path/to/repo fix 12345 SEC-789 --local-only

# Force override existing branch/MR (if you own it)
vuln-fixer -r /path/to/repo fix 12345 SEC-789 --force
```

### Batch Processing (CVE Grouping)

```bash
# List vulnerabilities grouped by CVE
vuln-fixer -r /path/to/repo list-groups

# List grouped by package
vuln-fixer -r /path/to/repo list-groups --group-by package

# Fix all vulnerabilities for a specific CVE
vuln-fixer -r /path/to/repo fix-group CVE-2024-12798 SEC-800 --dry-run
vuln-fixer -r /path/to/repo fix-group CVE-2024-12798 SEC-800

# Fix ALL CVE groups at once (one MR per CVE)
vuln-fixer -r /path/to/repo fix-all-groups SEC-900 --dry-run
vuln-fixer -r /path/to/repo fix-all-groups SEC-900

# Limit to first N groups
vuln-fixer -r /path/to/repo fix-all-groups SEC-900 --max-groups 5
```

**Benefits:** Reduces MR count significantly (e.g., 20 vulnerabilities → 9 MRs when grouped by CVE).

**Note:** Batch processing ALWAYS groups by CVE - it will never create one MR per vulnerability.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                         CLI (main.py)                          │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌─────────────────┐  ┌─────────────────┐  ┌────────────────┐ │
│  │  gitlab_client  │  │   vuln_parser   │  │  fixer_agent   │ │
│  │                 │  │                 │  │                │ │
│  │ - auto-detect   │  │ - parse SAST    │  │ - run claude   │ │
│  │ - glab api      │  │ - parse deps    │  │ - parse output │ │
│  │ - create MR     │  │ - prioritize    │  │ - track files  │ │
│  └────────┬────────┘  └────────┬────────┘  └───────┬────────┘ │
│           │                    │                   │          │
│           ▼                    ▼                   ▼          │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │              Local Git Repository                       │  │
│  │  (project auto-detected from git remote URL)            │  │
│  └─────────────────────────────────────────────────────────┘  │
│           │                                        │          │
│           ▼                                        ▼          │
│  ┌─────────────────┐                   ┌────────────────────┐ │
│  │    glab CLI     │                   │    Claude CLI      │ │
│  │  (GitLab API)   │                   │   (AI analysis)    │ │
│  └─────────────────┘                   └────────────────────┘ │
└────────────────────────────────────────────────────────────────┘
```

---

## Supported Git Remote URL Formats

| Format | Example | Detected |
|--------|---------|----------|
| SSH | `git@gitlab.com:group/project.git` | project: `group/project` |
| HTTPS | `https://gitlab.com/group/project.git` | project: `group/project` |
| Nested groups | `git@gitlab.com:org/team/project.git` | project: `org/team/project` |
| Self-hosted | `git@gitlab.example.com:group/project.git` | hostname: `gitlab.example.com` |

---

## Configuration (Optional)

Most settings have sensible defaults. Create `config/settings.yaml` only if you need to customize:

```yaml
gitlab:
  target_branch: main  # Target branch for MRs (default: main)

agent:
  timeout: 300         # Claude CLI timeout in seconds

options:
  min_confidence: 0.7  # Reject fixes below this confidence
  max_fixes_per_run: 10
```

---

## Tech Stack

- **Language**: Python 3.11+
- **GitLab**: glab CLI (auto-authenticated)
- **AI**: Claude CLI (auto-authenticated)
- **Dependencies**: click, pyyaml (minimal)

**No API keys to configure!**

---

## Vulnerability Types Supported

| Type | Source | Fix Strategy |
|------|--------|--------------|
| Dependency CVE | Dependency Scanning | Version bump |
| SQL Injection | SAST | Parameterized queries |
| XSS | SAST | Output encoding |
| Hardcoded Secrets | Secret Detection | Remove + env var |
| Path Traversal | SAST | Input validation |

---

## Development Phases

### Phase 1: Foundation ✅
- [x] Auto-detect GitLab project from repo
- [x] Fetch vulnerabilities via glab
- [x] Parse vulnerability reports
- [x] Basic CLI commands

### Phase 2: AI Integration ✅
- [x] Claude CLI wrapper
- [x] Fix generation with confidence scores
- [x] Dry-run mode
- [x] Dependency fixes

### Phase 3: Code Style Consistency ✅
- [x] Prompt-based style matching (simplest approach)
- [x] Explicit "DO NOT introduce new patterns" instructions
- [ ] Post-fix linting/formatting (black, prettier, etc.)
- [ ] Review agent (gatekeeper for style validation)

### Phase 4: Batch Processing ✅
- [x] Group vulnerabilities by CVE
- [x] Group vulnerabilities by package
- [x] `list-groups` command
- [x] `fix-group` command for CVE-based batch fixes
- [x] `fix-all-groups` command for processing all CVEs at once
- [x] Smart transitive dependency detection
- [x] False positive detection (identifies already-patched dependencies)

### Phase 4.5: Safety & Quality ✅
- [x] Dirty repo check (abort if uncommitted changes exist)
- [x] Scope limitation in prompts (only fix requested CVE/package)
- [x] Full analysis in MR descriptions (explanation, key findings, changes, confidence)
- [x] Robust confidence parsing (handles markdown-formatted output)
- [x] Robust git status parsing (handles variable whitespace)
- [x] VulnType documentation (explains GitLab report_type mapping)

### Phase 5: Automation
- [ ] CI/CD integration
- [ ] Fix validation (run tests)
- [ ] Reporting and metrics

---

## Code Style Consistency

AI-generated fixes must match existing codebase patterns. We use a layered approach:

### Level 1: Prompt Instructions (Current)
The fixer agent prompt explicitly instructs Claude to:
1. Analyze surrounding code before making changes
2. Identify naming conventions, formatting, error handling patterns
3. Match these patterns exactly in the fix

### Level 2: Post-fix Formatting (Planned)
Run automated formatters after fix:
- Python: `black`, `isort`
- JavaScript/TypeScript: `prettier`, `eslint --fix`
- Go: `gofmt`

### Level 3: Review Agent (Planned)
A separate validation pass that:
1. Compares fix style against codebase patterns
2. Flags inconsistencies
3. Optionally auto-corrects or rejects

---

## Batch Processing (CVE Grouping)

Instead of creating one MR per vulnerability, group related vulnerabilities:

### Grouping Strategies

| Strategy | Use Case | Example |
|----------|----------|---------|
| **By CVE** | Same vulnerability across modules | CVE-2024-12798 affects 5 modules → 1 MR |
| **By Package** | Same package in multiple files | logback-core in 3 files → 1 MR |

### Smart Detection

The agent intelligently handles:
- **Transitive dependencies**: Finds the actual source, not just flagged files
- **Centralized fixes**: Uses root build.gradle.kts when appropriate
- **Consistent changes**: Applies same fix pattern across all affected files

---

## Safety Features

### Dirty Repo Check
Before starting any fix (except dry-run), the tool checks for uncommitted changes:
```
Error: Repository has uncommitted changes:
  - file1.txt
  - file2.kt

Please commit or stash your changes before running vuln-fixer.
```
This prevents accidental commits of unrelated changes.

### Scope Limitation
Every fix prompt includes strict scope constraints:
```
## CRITICAL: Scope Limitation
You are ONLY fixing CVE-2024-12798 which affects: ch.qos.logback/logback-core
- DO NOT fix any other vulnerabilities or CVEs
- DO NOT update any other packages
- If you see other vulnerabilities, IGNORE them
```

### Full Analysis in MR
MR descriptions now include Claude's complete analysis:
- **Key findings**: What was discovered during analysis
- **Changes made**: Specific modifications with file paths
- **Style compliance**: How the fix matches existing code patterns
- **Confidence reasoning**: Why the confidence score was assigned
