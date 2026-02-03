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
| `fix <id>` | Fix a specific vulnerability |
| `fix-all` | Batch fix vulnerabilities |

### Examples

```bash
# Show detected project info
python -m src.main -r /path/to/repo info

# List high and critical vulnerabilities
python -m src.main -r /path/to/repo list

# List all severities
python -m src.main -r /path/to/repo list -s critical -s high -s medium -s low

# Analyze a vulnerability without making changes
python -m src.main -r /path/to/repo fix 12345 --dry-run

# Fix and create MR
python -m src.main -r /path/to/repo fix 12345

# Batch fix up to 5 critical vulnerabilities
python -m src.main -r /path/to/repo fix-all -s critical -m 5
```

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

### Phase 3: Code Style Consistency
- [x] Prompt-based style matching (simplest approach)
- [ ] Post-fix linting/formatting (black, prettier, etc.)
- [ ] Review agent (gatekeeper for style validation)

### Phase 4: Automation
- [ ] Batch processing improvements
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
