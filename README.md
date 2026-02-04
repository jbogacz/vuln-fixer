# Vuln-Fixer

Automated security vulnerability remediation for GitLab repositories.

Fetches vulnerabilities from GitLab, uses AI (Claude CLI) to analyze and fix them, and creates merge requests for review.

## Features

- **Zero configuration** - GitLab project auto-detected from repo's git remote
- **AI-powered fixes** - Claude CLI analyzes code and generates minimal fixes
- **Dry-run mode** - Preview fixes before applying
- **Batch processing** - Fix multiple vulnerabilities at once
- **Confidence scoring** - AI reports confidence level for each fix

## Prerequisites

### 1. Claude CLI
```bash
npm install -g @anthropic-ai/claude-code
claude auth
```

### 2. glab CLI
```bash
# macOS
brew install glab

# Linux - see https://gitlab.com/gitlab-org/cli
glab auth login
```

### 3. Python 3.11+

## Installation

```bash
git clone <this-repo>
cd vuln-fixer

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in dev mode (recommended)
pip install -e .

# Or just install dependencies
pip install -r requirements.txt
```

After installing in dev mode, you can use `vuln-fixer` command directly.

## Usage

Point to any cloned GitLab repository - project is auto-detected from git remote URL.

### Show detected project
```bash
vuln-fixer -r /path/to/your/repo info
```

### List vulnerabilities
```bash
# High and critical (default)
vuln-fixer -r /path/to/your/repo list

# All severities
vuln-fixer -r /path/to/your/repo list -s critical -s high -s medium -s low
```

### Fix a vulnerability
```bash
# Dry run first (analyze without making changes)
vuln-fixer -r /path/to/your/repo fix 12345 SEC-789 --dry-run

# Apply fix and create MR
vuln-fixer -r /path/to/your/repo fix 12345 SEC-789
```

The Jira ticket is required and used for:
- **Branch name:** `security/SEC-789/vulnerability-description`
- **MR title:** `SEC-789: Fix vulnerability description`
- **Commit message:** `SEC-789: fix vulnerability description`

### Force override existing branch/MR
```bash
# Override existing branch and MR (only if you are the author)
vuln-fixer -r /path/to/your/repo fix 12345 SEC-789 --force
```

The `--force` flag will:
- Close an existing MR with the same source branch (only if you own it)
- Delete the remote branch
- Delete the local branch
- Create fresh branch and MR

**Safety:** Force only works if you are the author of the existing MR. If someone else owns it, the command will fail with an error showing the actual owner.

### Batch processing (group by CVE)

Instead of creating one MR per vulnerability, group them by CVE:

```bash
# List vulnerabilities grouped by CVE
vuln-fixer -r /path/to/your/repo list-groups

# List grouped by package instead
vuln-fixer -r /path/to/your/repo list-groups --group-by package

# Fix all vulnerabilities for a specific CVE in one MR
vuln-fixer -r /path/to/your/repo fix-group CVE-2024-12798 SEC-800 --dry-run
vuln-fixer -r /path/to/your/repo fix-group CVE-2024-12798 SEC-800

# Fix ALL CVE groups at once (one MR per CVE)
vuln-fixer -r /path/to/your/repo fix-all-groups SEC-900 --dry-run
vuln-fixer -r /path/to/your/repo fix-all-groups SEC-900

# Limit to first N groups
vuln-fixer -r /path/to/your/repo fix-all-groups SEC-900 --max-groups 5
```

This reduces the number of MRs significantly. For example:
- 20 vulnerabilities across 9 CVEs → 9 MRs instead of 20

**Note:** Batch processing ALWAYS groups by CVE - it will never create one MR per vulnerability.

### Local-only mode
```bash
# Create local branch only, don't push or create MR
vuln-fixer -r /path/to/your/repo fix 12345 SEC-789 --local-only
```

Useful for reviewing changes locally before pushing.

## How It Works

```
1. Point to local repo     →  Auto-detect GitLab project from git remote
2. Fetch vulnerabilities   →  glab api projects/:id/vulnerability_findings
3. Analyze & fix           →  Claude CLI reads files, analyzes, edits
4. Create branch & MR      →  git commit/push + glab mr create
```

## Example Session

```bash
$ vuln-fixer -r ~/projects/my-app info
Repository path: /Users/me/projects/my-app
GitLab project: my-company/my-app
GitLab host: gitlab.com

$ vuln-fixer -r ~/projects/my-app list
Fetching vulnerabilities via glab...

Found 3 vulnerabilities:

[!!] [12345] SQL Injection in user query
     Severity: critical | Type: sast
     Location: src/db/users.py:42
     IDs: CWE-89, CVE-2024-1234

[! ] [12346] Outdated lodash dependency
     Severity: high | Type: dependency
     Location: package.json
     Package: lodash
     IDs: CVE-2024-5678

$ vuln-fixer -r ~/projects/my-app fix 12345 SEC-456 --dry-run
Project: my-company/my-app
Looking for vulnerability 12345...
Found: SQL Injection in user query
File: src/db/users.py:42

Invoking Claude CLI to analyze...

Analysis complete (confidence: 92%)

Explanation:
The vulnerability is a SQL injection at line 42 where user input is
directly concatenated into the query. Fix: use parameterized query
with cursor.execute(query, (user_id,)) instead of string formatting.

[Dry run - no changes made]

$ vuln-fixer -r ~/projects/my-app fix 12345 SEC-456
...
Creating branch: security/SEC-456/sql-injection-in-user-query
Pushing branch...
Creating merge request...

MR created: https://gitlab.com/my-company/my-app/-/merge_requests/42
```

## Configuration (Optional)

Most settings have sensible defaults. Create `config/settings.yaml` only if needed:

```yaml
gitlab:
  target_branch: main      # MR target branch

agent:
  timeout: 300             # Claude CLI timeout (seconds)
  max_turns: 30            # Max iterations for AI agent (increase for complex fixes)

options:
  min_confidence: 0.7      # Reject fixes below this confidence
  max_fixes_per_run: 10    # Batch limit
```

## Supported Vulnerability Types

| Type | Source | Fix Strategy |
|------|--------|--------------|
| Dependency CVE | Dependency Scanning | Version bump |
| SQL Injection | SAST | Parameterized queries |
| XSS | SAST | Output encoding |
| Hardcoded Secrets | Secret Detection | Remove + env var |
| Path Traversal | SAST | Input validation |
| Command Injection | SAST | Safe API usage |

## Safety

- All fixes create MRs for human review
- No auto-merge - manual approval required
- Confidence scores help identify uncertain fixes
- Dry-run mode for safe previewing
- Prompts instruct AI to make minimal changes only
- **Dirty repo check** - Aborts if uncommitted changes exist (prevents accidental commits)
- **Scope limitation** - AI is strictly limited to fixing only the requested CVE/package
- **Full analysis in MR** - MR description includes Claude's complete analysis (key findings, changes made, style compliance, confidence reasoning)

## Project Structure

```
vuln-fixer/
├── config/
│   └── settings.yaml      # Optional configuration
├── docs/
│   ├── ARCHITECTURE.md    # Technical details
│   └── PLAN.md            # Project overview
├── src/
│   ├── fixer_agent.py     # Claude CLI integration
│   ├── gitlab_client.py   # glab CLI + auto-detection
│   ├── main.py            # CLI commands
│   └── vuln_parser.py     # Vulnerability parsing
└── requirements.txt
```

## Documentation

- [PLAN.md](docs/PLAN.md) - Project overview, commands, examples
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) - Technical deep dive

## License

MIT
