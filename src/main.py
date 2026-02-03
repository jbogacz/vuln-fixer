"""Main CLI for vuln-fixer."""

import os
import subprocess
from pathlib import Path

import click
import yaml

from .gitlab_client import create_client_from_repo
from .vuln_parser import VulnParser, Severity, VulnType
from .fixer_agent import FixerAgent


def load_config(config_path: str = "config/settings.yaml"):
    """Load configuration from YAML file."""
    config_file = Path(config_path)
    if not config_file.exists():
        return {}

    with open(config_path) as f:
        config = yaml.safe_load(f) or {}

    def substitute_env(obj):
        """Recursively substitute environment variables in config."""
        if obj is None:
            return obj
        if isinstance(obj, str):
            if obj.startswith("${") and obj.endswith("}"):
                env_var = obj[2:-1]
                return os.environ.get(env_var, obj)
            return obj
        if isinstance(obj, dict):
            return {k: substitute_env(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [substitute_env(v) for v in obj]
        return obj

    return substitute_env(config)


@click.group()
@click.option("--config", "-c", default="config/settings.yaml", help="Config file path")
@click.option("--repo", "-r", default=".", help="Path to local git repository (GitLab project auto-detected)")
@click.pass_context
def cli(ctx, config, repo):
    """Vuln-Fixer: Automated security vulnerability remediation.

    Uses Claude CLI for AI-powered fixes and glab CLI for GitLab integration.
    GitLab project is auto-detected from the repository's git remote URL.

    Example:
        vuln-fixer -r /path/to/my-project list
        vuln-fixer -r /path/to/my-project fix VULN-123
    """
    ctx.ensure_object(dict)
    ctx.obj["config"] = load_config(config)
    ctx.obj["repo_path"] = Path(repo).resolve()


@cli.command()
@click.pass_context
def info(ctx):
    """Show detected GitLab project information."""
    repo_path = ctx.obj["repo_path"]

    click.echo(f"Repository path: {repo_path}")

    try:
        client = create_client_from_repo(repo_path)
        info = client.get_project_info()
        click.echo(f"GitLab project: {info['project']}")
        click.echo(f"GitLab host: {info['hostname']}")
    except Exception as e:
        click.echo(f"Error: {e}")


@cli.command("list")
@click.option("--severity", "-s", multiple=True, default=["critical", "high"])
@click.pass_context
def list_vulns(ctx, severity):
    """List vulnerabilities from GitLab (project auto-detected from repo)."""
    repo_path = ctx.obj["repo_path"]

    # Auto-detect GitLab project from repository
    click.echo(f"Repository: {repo_path}")
    try:
        client = create_client_from_repo(repo_path)
        info = client.get_project_info()
        click.echo(f"Detected GitLab project: {info['project']} @ {info['hostname']}")
    except Exception as e:
        click.echo(f"Error detecting GitLab project: {e}")
        return

    # Fetch vulnerabilities
    click.echo("\nFetching vulnerabilities via glab...")
    raw_vulns = client.get_vulnerability_report()

    if not raw_vulns:
        click.echo("No vulnerabilities found (or unable to fetch).")
        return

    # Parse and filter
    parser = VulnParser()
    vulns = [parser.parse_gitlab_vulnerability(v) for v in raw_vulns]

    severity_filter = [Severity(s) for s in severity]
    vulns = parser.filter_by_severity(vulns, severity_filter)
    vulns = parser.prioritize(vulns)

    # Display
    click.echo(f"\nFound {len(vulns)} vulnerabilities:\n")
    for v in vulns:
        icon = {"critical": "!!", "high": "! ", "medium": "- ", "low": ". "}.get(
            v.severity.value, "  "
        )
        click.echo(f"[{icon}] [{v.id}] {v.title}")
        click.echo(f"     Severity: {v.severity.value} | Type: {v.vuln_type.value}")
        click.echo(f"     Location: {v.location.file_path}:{v.location.start_line or '?'}")
        if v.location.dependency:
            click.echo(f"     Package: {v.location.dependency}")
        click.echo(f"     IDs: {', '.join(v.identifiers[:3])}")
        click.echo()


def slugify(text: str, max_length: int = 50) -> str:
    """Convert text to a URL/branch-friendly slug."""
    import re
    # Lowercase and replace spaces/special chars with hyphens
    slug = re.sub(r'[^a-z0-9]+', '-', text.lower())
    # Remove leading/trailing hyphens
    slug = slug.strip('-')
    # Truncate to max length, avoiding cut in middle of word
    if len(slug) > max_length:
        slug = slug[:max_length].rsplit('-', 1)[0]
    return slug


def build_mr_details(vuln, jira_ticket: str, confidence: float | None = None) -> dict:
    """Build MR branch name, title, and description from vulnerability."""
    vuln_slug = slugify(vuln.title)
    branch_name = f"security/{jira_ticket}/{vuln_slug}"
    title = f"{jira_ticket}: Fix {vuln.title}"

    confidence_line = ""
    if confidence is not None:
        confidence_line = f"**Confidence:** {confidence:.0%}  \n"

    description = (
        f"## Security Fix\n"
        f"\n"
        f"**Vulnerability:** {vuln.title}  \n"
        f"**Severity:** {vuln.severity.value}  \n"
        f"{confidence_line}"
        f"\n"
        f"### Description\n"
        f"{vuln.description}\n"
        f"\n"
        f"### Solution\n"
        f"{vuln.solution or 'Upgrade to patched version'}\n"
        f"\n"
        f"---\n"
        f"*Generated by vuln-fixer using Claude CLI*"
    )
    return {
        "branch_name": branch_name,
        "title": title,
        "description": description,
    }


@cli.command()
@click.argument("vuln_id")
@click.argument("jira_ticket")
@click.option("--dry-run", is_flag=True, help="Analyze without making changes")
@click.option("--force", is_flag=True, help="Override existing branch and MR (only if you own them)")
@click.option("--local-only", is_flag=True, help="Create local branch only, don't push or create MR")
@click.pass_context
def fix(ctx, vuln_id, jira_ticket, dry_run, force, local_only):
    """Fix a specific vulnerability using Claude CLI.

    VULN_ID: The GitLab vulnerability ID to fix
    JIRA_TICKET: Jira ticket number (e.g., SEC-123, PROJ-456)
    """
    config = ctx.obj["config"]
    repo_path = ctx.obj["repo_path"]

    # Auto-detect GitLab project
    try:
        gl_client = create_client_from_repo(repo_path)
        info = gl_client.get_project_info()
        click.echo(f"Project: {info['project']}")
    except Exception as e:
        click.echo(f"Error: {e}")
        return

    parser = VulnParser()
    agent_config = config.get("agent", {})
    agent = FixerAgent(timeout=agent_config.get("timeout", 300))

    # Find the vulnerability
    click.echo(f"Looking for vulnerability {vuln_id}...")
    raw_vulns = gl_client.get_vulnerability_report()
    vulns = [parser.parse_gitlab_vulnerability(v) for v in raw_vulns]

    vuln = next((v for v in vulns if v.id == vuln_id), None)
    if not vuln:
        click.echo(f"Vulnerability {vuln_id} not found.")
        return

    click.echo(f"Found: {vuln.title}")
    click.echo(f"File: {vuln.location.file_path}:{vuln.location.start_line or '?'}")
    click.echo(f"\nInvoking Claude CLI to {'analyze' if dry_run else 'fix'}...")

    # Generate fix using Claude CLI
    if vuln.vuln_type == VulnType.DEPENDENCY:
        fix_result = agent.fix_dependency(vuln, repo_path, dry_run=dry_run)
    else:
        fix_result = agent.analyze_and_fix(vuln, repo_path, dry_run=dry_run)

    if not fix_result:
        click.echo("Could not generate fix.")
        return

    click.echo(f"\n{'Analysis' if dry_run else 'Fix'} complete (confidence: {fix_result.confidence:.0%})")
    click.echo(f"\nExplanation:\n{fix_result.explanation}")

    if dry_run:
        mr_details = build_mr_details(vuln, jira_ticket, confidence=fix_result.confidence)
        click.echo("\n--- MR Preview ---")
        click.echo(f"Branch: {mr_details['branch_name']}")
        click.echo(f"Title: {mr_details['title']}")
        click.echo(f"\nDescription:\n{mr_details['description']}")
        click.echo("\n[Dry run - no changes made]")
        return

    # Check for actual git modifications (more reliable than Claude's output)
    git_status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo_path,
        capture_output=True,
        text=True
    )
    modified_files = [
        line[3:].strip() for line in git_status.stdout.strip().split("\n")
        if line.strip() and len(line) > 3
    ]

    if not modified_files and not fix_result.files_modified:
        click.echo("\nNo files were modified.")
        return

    files_to_report = modified_files or fix_result.files_modified
    click.echo(f"\nFiles modified: {', '.join(files_to_report)}")

    # Check confidence threshold
    min_confidence = config.get("options", {}).get("min_confidence", 0.7)
    if fix_result.confidence < min_confidence:
        click.echo(f"\nWarning: Confidence ({fix_result.confidence:.0%}) below threshold ({min_confidence:.0%})")
        if not click.confirm("Proceed anyway?"):
            click.echo("Aborted.")
            return

    # Create branch and MR
    mr_details = build_mr_details(vuln, jira_ticket, confidence=fix_result.confidence)
    branch_name = mr_details["branch_name"]
    target_branch = config.get("gitlab", {}).get("target_branch", "main")

    original_branch = gl_client.get_current_branch()

    # Update target branch to ensure we're up-to-date
    click.echo(f"\nUpdating {target_branch} branch...")
    try:
        subprocess.run(["git", "fetch", "origin", target_branch], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(["git", "checkout", target_branch], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(["git", "pull", "origin", target_branch], cwd=repo_path, check=True, capture_output=True)
    except Exception as e:
        click.echo(f"Warning: Could not update {target_branch}: {e}")

    click.echo(f"Creating branch: {branch_name}")

    # Check if branch already exists
    local_exists = gl_client.branch_exists(branch_name)
    remote_exists = gl_client.remote_branch_exists(branch_name)

    if local_exists or remote_exists:
        if not force:
            click.echo(f"Branch '{branch_name}' already exists.")
            click.echo("Use --force to override (only if you own the existing MR).")
            return

        # Force mode: verify ownership before cleanup
        existing_mr = gl_client.find_mr_by_source_branch(branch_name)
        if existing_mr:
            mr_iid = existing_mr.get('iid')
            if not mr_iid:
                click.echo("Warning: Found MR but could not get its ID, skipping close")
            else:
                if not gl_client.is_mr_owned_by_current_user(existing_mr):
                    click.echo(f"Cannot force: MR !{mr_iid} exists but you are not the author.")
                    click.echo(f"Author: {existing_mr.get('author', {}).get('username', 'unknown')}")
                    return

                click.echo(f"Closing existing MR !{mr_iid} (owned by you)...")
                if not gl_client.close_merge_request(mr_iid):
                    click.echo("Failed to close existing MR")
                    return

        if remote_exists:
            click.echo(f"Deleting remote branch '{branch_name}'...")
            if not gl_client.delete_remote_branch(branch_name):
                click.echo("Failed to delete remote branch")
                return

        if local_exists:
            # Switch to original branch first if we're on the branch to delete
            current = gl_client.get_current_branch()
            if current == branch_name:
                gl_client.checkout_branch(original_branch)
            click.echo(f"Deleting local branch '{branch_name}'...")
            if not gl_client.delete_local_branch(branch_name, force=True):
                click.echo("Failed to delete local branch")
                return

    if not gl_client.checkout_branch(branch_name, create=True):
        click.echo("Failed to create branch")
        return

    # Commit changes (files already modified by Claude CLI)
    commit_msg = f"{jira_ticket}: fix {vuln.title}\n\nGenerated by vuln-fixer + Claude CLI"

    try:
        subprocess.run(["git", "add", "-A"], cwd=repo_path, check=True)
        subprocess.run(["git", "commit", "-m", commit_msg], cwd=repo_path, check=True)
    except Exception as e:
        click.echo(f"Failed to commit: {e}")
        gl_client.checkout_branch(original_branch)
        return

    if local_only:
        click.echo(f"\nLocal branch created: {branch_name}")
        click.echo("Use 'git diff main' to review changes")
        return

    # Push branch
    click.echo("Pushing branch...")
    if not gl_client.push_branch(branch_name):
        click.echo("Failed to push branch")
        gl_client.checkout_branch(original_branch)
        return

    click.echo("Creating merge request...")
    mr = gl_client.create_merge_request(
        source_branch=branch_name,
        target_branch=target_branch,
        title=mr_details["title"],
        description=mr_details["description"],
    )

    # Return to original branch
    gl_client.checkout_branch(original_branch)

    if mr:
        click.echo(f"\nMR created: {mr.get('web_url', 'success')}")
    else:
        click.echo("Failed to create MR (branch was pushed)")


# @cli.command("fix-all")
# @click.argument("jira_prefix")
# @click.option("--severity", "-s", multiple=True, default=["critical", "high"])
# @click.option("--dry-run", is_flag=True, help="Analyze without making changes")
# @click.option("--max-fixes", "-m", default=10, help="Max fixes to attempt")
# @click.option("--force", is_flag=True, help="Override existing branches and MRs (only if you own them)")
# @click.pass_context
# def fix_all(ctx, jira_prefix, severity, dry_run, max_fixes, force):
#     """Fix all vulnerabilities matching criteria.
#
#     JIRA_PREFIX: Base Jira ticket (e.g., SEC-123). Each fix gets numbered: SEC-123-1, SEC-123-2, etc.
#     """
#     config = ctx.obj["config"]
#     repo_path = ctx.obj["repo_path"]
#
#     click.echo(f"Batch fixing vulnerabilities (severity: {', '.join(severity)})")
#     click.echo(f"Max fixes: {max_fixes}, Dry run: {dry_run}")
#
#     # Auto-detect GitLab project
#     try:
#         gl_client = create_client_from_repo(repo_path)
#         info = gl_client.get_project_info()
#         click.echo(f"Project: {info['project']}")
#     except Exception as e:
#         click.echo(f"Error: {e}")
#         return
#
#     parser = VulnParser()
#
#     # Fetch and filter vulnerabilities
#     raw_vulns = gl_client.get_vulnerability_report()
#     vulns = [parser.parse_gitlab_vulnerability(v) for v in raw_vulns]
#
#     severity_filter = [Severity(s) for s in severity]
#     vulns = parser.filter_by_severity(vulns, severity_filter)
#     vulns = parser.prioritize(vulns)[:max_fixes]
#
#     click.echo(f"\nFound {len(vulns)} vulnerabilities to process\n")
#
#     results = {"success": 0, "failed": 0, "skipped": 0}
#
#     for i, vuln in enumerate(vulns, 1):
#         jira_ticket = f"{jira_prefix}-{i}"
#         click.echo(f"[{i}/{len(vulns)}] Processing: {vuln.title} ({jira_ticket})")
#
#         # Invoke fix command for each
#         try:
#             ctx.invoke(fix, vuln_id=vuln.id, jira_ticket=jira_ticket, dry_run=dry_run, force=force)
#             results["success"] += 1
#         except Exception as e:
#             click.echo(f"  Failed: {e}")
#             results["failed"] += 1
#
#         click.echo()
#
#     click.echo(f"\nSummary: {results['success']} success, {results['failed']} failed")


if __name__ == "__main__":
    cli()
