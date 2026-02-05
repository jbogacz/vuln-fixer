"""Main CLI for vuln-fixer."""

import os
import subprocess
from pathlib import Path

import click
import yaml

from .gitlab_client import create_client_from_repo
from .vuln_parser import VulnParser, Severity, VulnType
from .fixer_agent import FixerAgent, ValidationResult


def check_repo_is_clean(repo_path: Path) -> tuple[bool, list[str]]:
    """
    Check if the repository has uncommitted changes.

    Returns:
        Tuple of (is_clean, list_of_dirty_files)
    """
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo_path,
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        return False, ["(could not determine git status)"]

    dirty_files = []
    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        if line:
            # Parse git status porcelain format
            parts = line.split(None, 1)
            if len(parts) == 2:
                dirty_files.append(parts[1])

    return len(dirty_files) == 0, dirty_files


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


def display_validation_result(validation: ValidationResult) -> None:
    """Display validation result to user."""
    status = "PASSED" if validation.valid else "FAILED"
    color = "green" if validation.valid else "red"

    click.echo(f"\n--- Validation: {click.style(status, fg=color)} (confidence: {validation.confidence:.0%}) ---")

    if validation.issues:
        click.echo(click.style("Issues:", fg="yellow"))
        for issue in validation.issues:
            click.echo(f"  - {issue}")

    if validation.suggestions:
        click.echo(click.style("Suggestions:", fg="cyan"))
        for suggestion in validation.suggestions:
            click.echo(f"  - {suggestion}")


def build_mr_details(
    vuln,
    jira_ticket: str,
    confidence: float | None = None,
    explanation: str | None = None
) -> dict:
    """Build MR branch name, title, and description from vulnerability."""
    vuln_slug = slugify(vuln.title)
    branch_name = f"security/{jira_ticket}/{vuln_slug}"
    title = f"{jira_ticket}: Fix {vuln.title}"

    confidence_line = ""
    if confidence is not None:
        confidence_line = f"**Confidence:** {confidence:.0%}  \n"

    # If the agent produced a structured explanation (with ## Summary, ## Context, etc.),
    # use it as the primary MR body for richer context
    if explanation and "## Summary" in explanation and "## Context" in explanation:
        description = (
            f"{explanation}\n"
            f"\n"
            f"---\n"
            f"\n"
            f"**Vulnerability ID:** {vuln.id}  \n"
            f"**Severity:** {vuln.severity.value}  \n"
            f"**Type:** {vuln.vuln_type.value}  \n"
            f"{confidence_line}"
            f"\n"
            f"*This fix was automatically generated by an AI security agent and requires human review.*"
        )
    else:
        # Fallback: generic MR template
        analysis_section = ""
        if explanation:
            analysis_section = (
                f"### Analysis\n"
                f"{explanation}\n"
                f"\n"
            )

        if vuln.vuln_type.value == "dependency" and vuln.location.dependency:
            solution_text = (
                f"**Type:** Dependency vulnerability  \n"
                f"**Package:** `{vuln.location.dependency}`  \n"
                f"**Action:** {vuln.solution or 'Upgrade to patched version'}"
            )
        else:
            solution_text = vuln.solution or 'Apply security patch'

        description = (
            f"## Security Fix\n"
            f"\n"
            f"**Vulnerability:** {vuln.title}  \n"
            f"**Severity:** {vuln.severity.value}  \n"
            f"**Type:** {vuln.vuln_type.value}  \n"
            f"{confidence_line}"
            f"\n"
            f"### Description\n"
            f"{vuln.description}\n"
            f"\n"
            f"### Solution\n"
            f"{solution_text}\n"
            f"\n"
            f"{analysis_section}"
            f"---\n"
            f"*This fix was automatically generated by an AI security agent and requires human review.*"
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
@click.option("--skip-validation", is_flag=True, help="Skip AI validation of the fix")
@click.pass_context
def fix(ctx, vuln_id, jira_ticket, dry_run, force, local_only, skip_validation):
    """Fix a specific vulnerability using Claude CLI.

    VULN_ID: The GitLab vulnerability ID to fix
    JIRA_TICKET: Jira ticket number (e.g., SEC-123, PROJ-456)
    """
    config = ctx.obj["config"]
    repo_path = ctx.obj["repo_path"]

    # Check for uncommitted changes before starting (skip for dry-run)
    if not dry_run:
        is_clean, dirty_files = check_repo_is_clean(repo_path)
        if not is_clean:
            click.echo("Error: Repository has uncommitted changes:")
            for f in dirty_files[:10]:  # Show first 10 files
                click.echo(f"  - {f}")
            if len(dirty_files) > 10:
                click.echo(f"  ... and {len(dirty_files) - 10} more")
            click.echo("\nPlease commit or stash your changes before running vuln-fixer.")
            return

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
    agent = FixerAgent(
        timeout=agent_config.get("timeout", 300),
        max_turns=agent_config.get("max_turns", 30)
    )

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

    # For dry-run, we can run Claude on current branch (just analysis)
    if dry_run:
        click.echo("\nInvoking Claude CLI to analyze...")
        if vuln.vuln_type == VulnType.DEPENDENCY:
            fix_result = agent.fix_dependency(vuln, repo_path, dry_run=True)
        else:
            fix_result = agent.analyze_and_fix(vuln, repo_path, dry_run=True)

        if not fix_result:
            click.echo("Could not generate analysis.")
            return

        click.echo(f"\nAnalysis complete (confidence: {fix_result.confidence:.0%})")
        click.echo(f"\nExplanation:\n{fix_result.explanation}")

        mr_details = build_mr_details(
            vuln, jira_ticket,
            confidence=fix_result.confidence,
            explanation=fix_result.explanation
        )
        click.echo("\n--- MR Preview ---")
        click.echo(f"Branch: {mr_details['branch_name']}")
        click.echo(f"Title: {mr_details['title']}")
        click.echo(f"\nDescription:\n{mr_details['description']}")
        click.echo("\n[Dry run - no changes made]")
        return

    # === NON-DRY-RUN: Prepare branch FIRST, then run Claude ===

    # Build branch name early (needed for cleanup)
    vuln_slug = slugify(vuln.title)
    branch_name = f"security/{jira_ticket}/{vuln_slug}"
    target_branch = config.get("gitlab", {}).get("target_branch", "main")

    original_branch = gl_client.get_current_branch()

    # Step 1: Handle --force cleanup FIRST (before switching branches)
    local_exists = gl_client.branch_exists(branch_name)
    remote_exists = gl_client.remote_branch_exists(branch_name)

    if local_exists or remote_exists:
        if not force:
            click.echo(f"Branch '{branch_name}' already exists.")
            click.echo("Use --force to override (only if you own the existing MR).")
            return

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
            gl_client.delete_remote_branch(branch_name)

        if local_exists:
            current = gl_client.get_current_branch()
            if current == branch_name:
                subprocess.run(["git", "checkout", target_branch], cwd=repo_path, capture_output=True)
            click.echo(f"Deleting local branch '{branch_name}'...")
            gl_client.delete_local_branch(branch_name, force=True)

    # Step 2: Checkout target branch and hard reset to remote
    click.echo(f"\nUpdating {target_branch} branch...")
    try:
        subprocess.run(["git", "fetch", "origin", target_branch], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(["git", "checkout", target_branch], cwd=repo_path, check=True, capture_output=True)
        # Hard reset to ensure local matches remote exactly (not just merge)
        subprocess.run(["git", "reset", "--hard", f"origin/{target_branch}"], cwd=repo_path, check=True, capture_output=True)
        # Clean untracked files that might interfere
        subprocess.run(["git", "clean", "-fd"], cwd=repo_path, check=True, capture_output=True)
    except Exception as e:
        click.echo(f"Error: Could not update {target_branch}: {e}")
        return

    # Step 3: Create fresh fix branch from target
    click.echo(f"Creating branch: {branch_name}")
    if not gl_client.checkout_branch(branch_name, create=True):
        click.echo("Failed to create branch")
        return

    # Step 4: NOW run Claude on the clean branch
    click.echo("\nInvoking Claude CLI to fix...")
    if vuln.vuln_type == VulnType.DEPENDENCY:
        fix_result = agent.fix_dependency(vuln, repo_path, dry_run=False)
    else:
        fix_result = agent.analyze_and_fix(vuln, repo_path, dry_run=False)

    if not fix_result:
        click.echo("Could not generate fix.")
        gl_client.checkout_branch(target_branch)
        gl_client.delete_local_branch(branch_name, force=True)
        return

    click.echo(f"\nFix complete (confidence: {fix_result.confidence:.0%})")
    click.echo(f"\nExplanation:\n{fix_result.explanation}")

    # Step 5: Check for actual git modifications
    git_status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo_path,
        capture_output=True,
        text=True
    )
    modified_files = []
    for line in git_status.stdout.strip().split("\n"):
        line = line.strip()
        if line and len(line) > 2:
            parts = line.split(None, 1)
            if len(parts) == 2:
                modified_files.append(parts[1])

    if not modified_files and not fix_result.files_modified:
        click.echo("\nNo files were modified. The vulnerability may already be fixed.")
        gl_client.checkout_branch(target_branch)
        gl_client.delete_local_branch(branch_name, force=True)
        return

    files_to_report = modified_files or fix_result.files_modified
    click.echo(f"\nFiles modified: {', '.join(files_to_report)}")

    # Step 6: Validate the fix
    if not skip_validation:
        click.echo("\nValidating fix...")
        # Extract CVE from identifiers if available
        cve_id = next((i.split(":", 1)[1] for i in vuln.identifiers if i.startswith("CVE:")), None)
        validation = agent.validate_fix(
            fix=fix_result,
            repo_path=repo_path,
            vuln=vuln,
            cve=cve_id
        )
        display_validation_result(validation)

        if not validation.valid:
            click.echo(click.style("\nValidation failed!", fg="red"))
            if not click.confirm("Proceed anyway?"):
                click.echo("Aborted.")
                gl_client.checkout_branch(target_branch)
                gl_client.delete_local_branch(branch_name, force=True)
                return

    # Step 7: Check confidence threshold
    min_confidence = config.get("options", {}).get("min_confidence", 0.7)
    if fix_result.confidence < min_confidence:
        click.echo(f"\nWarning: Confidence ({fix_result.confidence:.0%}) below threshold ({min_confidence:.0%})")
        if not click.confirm("Proceed anyway?"):
            click.echo("Aborted.")
            gl_client.checkout_branch(target_branch)
            gl_client.delete_local_branch(branch_name, force=True)
            return

    # Step 8: Commit changes
    commit_msg = f"{jira_ticket}: fix {vuln.title}\n\nAutomated fix by AI security agent"

    try:
        subprocess.run(["git", "add", "-A"], cwd=repo_path, check=True)
        subprocess.run(["git", "commit", "-m", commit_msg], cwd=repo_path, check=True)
    except Exception as e:
        click.echo(f"Failed to commit: {e}")
        gl_client.checkout_branch(target_branch)
        gl_client.delete_local_branch(branch_name, force=True)
        return

    # Build MR details with explanation
    mr_details = build_mr_details(
        vuln, jira_ticket,
        confidence=fix_result.confidence,
        explanation=fix_result.explanation
    )

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


def build_group_mr_details(
    cve: str,
    vulns: list,
    jira_ticket: str,
    confidence: float | None = None,
    explanation: str | None = None
) -> dict:
    """Build MR branch name, title, and description for a CVE group."""
    # Use first vuln for naming
    first_vuln = vulns[0]
    vuln_slug = slugify(first_vuln.title)
    branch_name = f"security/{jira_ticket}/{cve.lower()}-{vuln_slug}"

    title = f"{jira_ticket}: Fix {cve} - {first_vuln.title[:50]}"

    confidence_line = ""
    if confidence is not None:
        confidence_line = f"**Confidence:** {confidence:.0%}  \n"

    # List all affected files
    files_list = "\n".join(f"- {v.location.file_path}" for v in vulns)

    # Get unique packages affected
    packages = list(set(v.location.dependency for v in vulns if v.location.dependency))

    # If the agent produced a structured explanation (with ## Summary, ## Context, etc.),
    # use it as the primary MR body for richer context
    if explanation and "## Summary" in explanation and "## Context" in explanation:
        description = (
            f"{explanation}\n"
            f"\n"
            f"---\n"
            f"\n"
            f"**CVE:** {cve}  \n"
            f"**Severity:** {first_vuln.severity.value}  \n"
            f"**Type:** {first_vuln.vuln_type.value}  \n"
            f"**Affected files:** {len(vulns)}  \n"
            f"{confidence_line}"
            f"\n"
            f"*This fix was automatically generated by an AI security agent and requires human review.*"
        )
    else:
        # Fallback: generic MR template
        analysis_section = ""
        if explanation:
            analysis_section = (
                f"### Analysis\n"
                f"{explanation}\n"
                f"\n"
            )

        if first_vuln.vuln_type.value == "dependency" and packages:
            packages_str = ", ".join(f"`{p}`" for p in packages)
            solution_text = (
                f"**Type:** Dependency vulnerability  \n"
                f"**Package(s):** {packages_str}  \n"
                f"**Action:** {first_vuln.solution or 'Upgrade to patched version'}"
            )
        else:
            solution_text = first_vuln.solution or 'Apply security patch'

        description = (
            f"## Security Fix\n"
            f"\n"
            f"**CVE:** {cve}  \n"
            f"**Vulnerability:** {first_vuln.title}  \n"
            f"**Severity:** {first_vuln.severity.value}  \n"
            f"**Type:** {first_vuln.vuln_type.value}  \n"
            f"**Affected files:** {len(vulns)}  \n"
            f"{confidence_line}"
            f"\n"
            f"### Affected Files\n"
            f"{files_list}\n"
            f"\n"
            f"### Description\n"
            f"{first_vuln.description}\n"
            f"\n"
            f"### Solution\n"
            f"{solution_text}\n"
            f"\n"
            f"{analysis_section}"
            f"---\n"
            f"*This fix was automatically generated by an AI security agent and requires human review.*"
        )

    return {
        "branch_name": branch_name,
        "title": title,
        "description": description,
    }


@cli.command("list-groups")
@click.option("--severity", "-s", multiple=True, default=["critical", "high"])
@click.option("--group-by", "-g", type=click.Choice(["cve", "package"]), default="cve", help="Grouping strategy")
@click.pass_context
def list_groups(ctx, severity, group_by):
    """List vulnerabilities grouped by CVE or package.

    Shows how vulnerabilities would be batched for fix-batch command.
    """
    repo_path = ctx.obj["repo_path"]

    try:
        gl_client = create_client_from_repo(repo_path)
        info = gl_client.get_project_info()
        click.echo(f"Project: {info['project']}")
    except Exception as e:
        click.echo(f"Error: {e}")
        return

    parser = VulnParser()

    # Fetch and filter
    raw_vulns = gl_client.get_vulnerability_report()
    vulns = [parser.parse_gitlab_vulnerability(v) for v in raw_vulns]

    severity_filter = [Severity(s) for s in severity]
    vulns = parser.filter_by_severity(vulns, severity_filter)

    # Group
    if group_by == "cve":
        groups = parser.group_by_cve(vulns)
    else:
        groups = parser.group_by_package(vulns)

    click.echo(f"\nFound {len(vulns)} vulnerabilities in {len(groups)} groups:\n")

    for i, (key, group) in enumerate(sorted(groups.items()), 1):
        click.echo(f"[{i}] {key} ({len(group)} vulnerabilities)")
        for v in group:
            click.echo(f"    - {v.location.file_path}: {v.title[:50]}...")
        click.echo()


@cli.command("fix-group")
@click.argument("cve")
@click.argument("jira_ticket")
@click.option("--severity", "-s", multiple=True, default=["critical", "high"])
@click.option("--dry-run", is_flag=True, help="Analyze without making changes")
@click.option("--force", is_flag=True, help="Override existing branch and MR (only if you own them)")
@click.option("--local-only", is_flag=True, help="Create local branch only, don't push or create MR")
@click.option("--skip-validation", is_flag=True, help="Skip AI validation of the fix")
@click.pass_context
def fix_group(ctx, cve, jira_ticket, severity, dry_run, force, local_only, skip_validation):
    """Fix all vulnerabilities for a specific CVE.

    CVE: The CVE identifier (e.g., CVE-2024-12798)
    JIRA_TICKET: Jira ticket number (e.g., SEC-123)
    """
    config = ctx.obj["config"]
    repo_path = ctx.obj["repo_path"]

    # Check for uncommitted changes before starting (skip for dry-run)
    if not dry_run:
        is_clean, dirty_files = check_repo_is_clean(repo_path)
        if not is_clean:
            click.echo("Error: Repository has uncommitted changes:")
            for f in dirty_files[:10]:  # Show first 10 files
                click.echo(f"  - {f}")
            if len(dirty_files) > 10:
                click.echo(f"  ... and {len(dirty_files) - 10} more")
            click.echo("\nPlease commit or stash your changes before running vuln-fixer.")
            return

    try:
        gl_client = create_client_from_repo(repo_path)
        info = gl_client.get_project_info()
        click.echo(f"Project: {info['project']}")
    except Exception as e:
        click.echo(f"Error: {e}")
        return

    parser = VulnParser()
    agent_config = config.get("agent", {})
    agent = FixerAgent(
        timeout=agent_config.get("timeout", 300),
        max_turns=agent_config.get("max_turns", 30)
    )

    # Fetch and filter vulnerabilities
    raw_vulns = gl_client.get_vulnerability_report()
    vulns = [parser.parse_gitlab_vulnerability(v) for v in raw_vulns]

    severity_filter = [Severity(s) for s in severity]
    vulns = parser.filter_by_severity(vulns, severity_filter)

    # Group by CVE and find the target group
    groups = parser.group_by_cve(vulns)

    if cve not in groups:
        click.echo(f"CVE {cve} not found. Available CVEs:")
        for key in sorted(groups.keys()):
            click.echo(f"  - {key}")
        return

    group = groups[cve]
    click.echo(f"\nFound {len(group)} vulnerabilities for {cve}:")
    for v in group:
        click.echo(f"  - {v.location.file_path}")

    # For dry-run, we can run Claude on current branch (just analysis)
    if dry_run:
        click.echo("\nInvoking Claude CLI to analyze...")
        fix_result = agent.fix_cve_group(cve, group, repo_path, dry_run=True)

        if not fix_result:
            click.echo("Could not generate analysis.")
            return

        click.echo(f"\nAnalysis complete (confidence: {fix_result.confidence:.0%})")
        click.echo(f"\nExplanation:\n{fix_result.explanation}")

        mr_details = build_group_mr_details(
            cve, group, jira_ticket,
            confidence=fix_result.confidence,
            explanation=fix_result.explanation
        )
        click.echo("\n--- MR Preview ---")
        click.echo(f"Branch: {mr_details['branch_name']}")
        click.echo(f"Title: {mr_details['title']}")
        click.echo(f"\nDescription:\n{mr_details['description']}")
        click.echo("\n[Dry run - no changes made]")
        return

    # === NON-DRY-RUN: Prepare branch FIRST, then run Claude ===

    # Build branch name early (needed for cleanup)
    first_vuln = group[0]
    vuln_slug = slugify(first_vuln.title)
    branch_name = f"security/{jira_ticket}/{cve.lower()}-{vuln_slug}"
    target_branch = config.get("gitlab", {}).get("target_branch", "main")

    original_branch = gl_client.get_current_branch()

    # Step 1: Handle --force cleanup FIRST (before switching branches)
    local_exists = gl_client.branch_exists(branch_name)
    remote_exists = gl_client.remote_branch_exists(branch_name)

    if local_exists or remote_exists:
        if not force:
            click.echo(f"Branch '{branch_name}' already exists.")
            click.echo("Use --force to override (only if you own the existing MR).")
            return

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
            gl_client.delete_remote_branch(branch_name)

        if local_exists:
            current = gl_client.get_current_branch()
            if current == branch_name:
                # Switch away before deleting
                subprocess.run(["git", "checkout", target_branch], cwd=repo_path, capture_output=True)
            click.echo(f"Deleting local branch '{branch_name}'...")
            gl_client.delete_local_branch(branch_name, force=True)

    # Step 2: Checkout target branch and hard reset to remote
    click.echo(f"\nUpdating {target_branch} branch...")
    try:
        subprocess.run(["git", "fetch", "origin", target_branch], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(["git", "checkout", target_branch], cwd=repo_path, check=True, capture_output=True)
        # Hard reset to ensure local matches remote exactly (not just merge)
        subprocess.run(["git", "reset", "--hard", f"origin/{target_branch}"], cwd=repo_path, check=True, capture_output=True)
        # Clean untracked files that might interfere
        subprocess.run(["git", "clean", "-fd"], cwd=repo_path, check=True, capture_output=True)
    except Exception as e:
        click.echo(f"Error: Could not update {target_branch}: {e}")
        return

    # Step 3: Create fresh fix branch from target
    click.echo(f"Creating branch: {branch_name}")
    if not gl_client.checkout_branch(branch_name, create=True):
        click.echo("Failed to create branch")
        return

    # Step 4: NOW run Claude on the clean branch
    click.echo("\nInvoking Claude CLI to fix...")
    fix_result = agent.fix_cve_group(cve, group, repo_path, dry_run=False)

    if not fix_result:
        click.echo("Could not generate fix.")
        gl_client.checkout_branch(target_branch)
        gl_client.delete_local_branch(branch_name, force=True)
        return

    click.echo(f"\nFix complete (confidence: {fix_result.confidence:.0%})")
    click.echo(f"\nExplanation:\n{fix_result.explanation}")

    # Step 5: Check for actual git modifications
    git_status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo_path,
        capture_output=True,
        text=True
    )
    modified_files = []
    for line in git_status.stdout.strip().split("\n"):
        line = line.strip()
        if line and len(line) > 2:
            parts = line.split(None, 1)
            if len(parts) == 2:
                modified_files.append(parts[1])

    if not modified_files and not fix_result.files_modified:
        click.echo("\nNo files were modified. The vulnerability may already be fixed.")
        gl_client.checkout_branch(target_branch)
        gl_client.delete_local_branch(branch_name, force=True)
        return

    files_to_report = modified_files or fix_result.files_modified
    click.echo(f"\nFiles modified: {', '.join(files_to_report)}")

    # Step 6: Validate the fix
    if not skip_validation:
        click.echo("\nValidating fix...")
        first_vuln = group[0]
        validation = agent.validate_fix(
            fix=fix_result,
            repo_path=repo_path,
            vuln=first_vuln,
            cve=cve
        )
        display_validation_result(validation)

        if not validation.valid:
            click.echo(click.style("\nValidation failed!", fg="red"))
            if not click.confirm("Proceed anyway?"):
                click.echo("Aborted.")
                gl_client.checkout_branch(target_branch)
                gl_client.delete_local_branch(branch_name, force=True)
                return

    # Step 7: Check confidence threshold
    min_confidence = config.get("options", {}).get("min_confidence", 0.7)
    if fix_result.confidence < min_confidence:
        click.echo(f"\nWarning: Confidence ({fix_result.confidence:.0%}) below threshold ({min_confidence:.0%})")
        if not click.confirm("Proceed anyway?"):
            click.echo("Aborted.")
            gl_client.checkout_branch(target_branch)
            gl_client.delete_local_branch(branch_name, force=True)
            return

    # Step 8: Commit changes
    commit_msg = f"{jira_ticket}: fix {cve} - {group[0].title}\n\nAutomated fix by AI security agent"

    try:
        subprocess.run(["git", "add", "-A"], cwd=repo_path, check=True)
        subprocess.run(["git", "commit", "-m", commit_msg], cwd=repo_path, check=True)
    except Exception as e:
        click.echo(f"Failed to commit: {e}")
        gl_client.checkout_branch(target_branch)
        gl_client.delete_local_branch(branch_name, force=True)
        return

    # Build MR details with explanation
    mr_details = build_group_mr_details(
        cve, group, jira_ticket,
        confidence=fix_result.confidence,
        explanation=fix_result.explanation
    )

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

    gl_client.checkout_branch(original_branch)

    if mr:
        click.echo(f"\nMR created: {mr.get('web_url', 'success')}")
    else:
        click.echo("Failed to create MR (branch was pushed)")


@cli.command("fix-all-groups")
@click.argument("jira_prefix")
@click.option("--severity", "-s", multiple=True, default=["critical", "high"])
@click.option("--dry-run", is_flag=True, help="Analyze without making changes")
@click.option("--force", is_flag=True, help="Override existing branches and MRs (only if you own them)")
@click.option("--local-only", is_flag=True, help="Create local branches only, don't push or create MRs")
@click.option("--max-groups", "-m", default=None, type=int, help="Max CVE groups to process")
@click.pass_context
def fix_all_groups(ctx, jira_prefix, severity, dry_run, force, local_only, max_groups):
    """Fix all CVE groups, creating one MR per CVE.

    JIRA_PREFIX: Base Jira ticket (e.g., SEC-800). Each CVE gets numbered: SEC-800-1, SEC-800-2, etc.

    This command ALWAYS groups by CVE - it will never create one MR per vulnerability.
    """
    config = ctx.obj["config"]
    repo_path = ctx.obj["repo_path"]

    try:
        gl_client = create_client_from_repo(repo_path)
        info = gl_client.get_project_info()
        click.echo(f"Project: {info['project']}")
    except Exception as e:
        click.echo(f"Error: {e}")
        return

    parser = VulnParser()

    # Fetch and filter vulnerabilities
    raw_vulns = gl_client.get_vulnerability_report()
    vulns = [parser.parse_gitlab_vulnerability(v) for v in raw_vulns]

    severity_filter = [Severity(s) for s in severity]
    vulns = parser.filter_by_severity(vulns, severity_filter)

    # Group by CVE - this is mandatory for batch processing
    groups = parser.group_by_cve(vulns)

    # Remove NO_CVE group if present (those need manual handling)
    if "NO_CVE" in groups:
        no_cve_count = len(groups.pop("NO_CVE"))
        click.echo(f"Skipping {no_cve_count} vulnerabilities without CVE (use 'fix' command for those)")

    # Sort and limit groups
    sorted_cves = sorted(groups.keys())
    if max_groups:
        sorted_cves = sorted_cves[:max_groups]

    total_vulns = sum(len(groups[cve]) for cve in sorted_cves)
    click.echo(f"\nFound {total_vulns} vulnerabilities in {len(sorted_cves)} CVE groups")
    click.echo(f"Mode: {'Dry run' if dry_run else 'Fix'}, Local only: {local_only}\n")

    results = {"success": 0, "failed": 0, "skipped": 0}

    for i, cve in enumerate(sorted_cves, 1):
        group = groups[cve]
        jira_ticket = f"{jira_prefix}-{i}"

        click.echo(f"\n{'='*60}")
        click.echo(f"[{i}/{len(sorted_cves)}] {cve} ({len(group)} vulnerabilities) → {jira_ticket}")
        click.echo(f"{'='*60}")

        for v in group:
            click.echo(f"  - {v.location.file_path}")

        try:
            # Invoke fix-group for this CVE
            ctx.invoke(
                fix_group,
                cve=cve,
                jira_ticket=jira_ticket,
                severity=severity,
                dry_run=dry_run,
                force=force,
                local_only=local_only
            )
            results["success"] += 1
        except Exception as e:
            click.echo(f"  Failed: {e}")
            results["failed"] += 1

        # Reset to main branch between fixes
        if not dry_run:
            try:
                target_branch = config.get("gitlab", {}).get("target_branch", "main")
                subprocess.run(["git", "checkout", target_branch], cwd=repo_path, capture_output=True)
                subprocess.run(["git", "checkout", "--", "."], cwd=repo_path, capture_output=True)
            except Exception:
                pass

    click.echo(f"\n{'='*60}")
    click.echo(f"Summary: {results['success']} CVE groups processed, {results['failed']} failed")
    click.echo(f"MRs created: {results['success']} (one per CVE group)")
    click.echo(f"{'='*60}")


if __name__ == "__main__":
    cli()
