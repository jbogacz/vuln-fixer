"""GitLab client using glab CLI for fetching vulnerabilities and creating MRs."""

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass
class GitLabConfig:
    project: str  # e.g., "group/project" or full path
    hostname: str | None = None  # e.g., "gitlab.example.com", None for gitlab.com


def detect_gitlab_from_repo(repo_path: Path) -> GitLabConfig:
    """
    Auto-detect GitLab project details from a local git repository.

    Parses the git remote URL to extract:
    - Project path (group/project)
    - Hostname (for self-hosted GitLab)

    Args:
        repo_path: Path to local git repository

    Returns:
        GitLabConfig with detected project and hostname

    Raises:
        RuntimeError: If not a git repo or no remote found
    """
    # Get the remote URL (try origin first, then any remote)
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            # Try to get any remote
            result = subprocess.run(
                ["git", "remote"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0 or not result.stdout.strip():
                raise RuntimeError("No git remote found")

            remote_name = result.stdout.strip().split("\n")[0]
            result = subprocess.run(
                ["git", "remote", "get-url", remote_name],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=10
            )

        remote_url = result.stdout.strip()
    except FileNotFoundError:
        raise RuntimeError("git command not found")

    if not remote_url:
        raise RuntimeError("Could not determine git remote URL")

    return parse_gitlab_url(remote_url)


def parse_gitlab_url(url: str) -> GitLabConfig:
    """
    Parse a GitLab URL (HTTPS or SSH) to extract project path and hostname.

    Supports:
    - https://gitlab.com/group/project.git
    - https://gitlab.example.com/group/subgroup/project.git
    - git@gitlab.com:group/project.git
    - git@gitlab.example.com:group/subgroup/project.git
    - ssh://git@gitlab.com/group/project.git

    Args:
        url: Git remote URL

    Returns:
        GitLabConfig with project and hostname
    """
    hostname = None
    project = None

    # Remove .git suffix
    url = url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]

    # SSH format: git@hostname:group/project
    ssh_match = re.match(r"git@([^:]+):(.+)", url)
    if ssh_match:
        hostname = ssh_match.group(1)
        project = ssh_match.group(2)
    else:
        # HTTPS or SSH with ssh:// prefix
        parsed = urlparse(url)
        if parsed.hostname:
            hostname = parsed.hostname
            # Remove leading slash from path
            project = parsed.path.lstrip("/")
            # Handle ssh://git@host/path format
            if "@" in (parsed.netloc or ""):
                hostname = parsed.hostname

    # Normalize hostname - None for gitlab.com (glab default)
    if hostname and hostname.lower() == "gitlab.com":
        hostname = None

    if not project:
        raise RuntimeError(f"Could not parse GitLab project from URL: {url}")

    return GitLabConfig(project=project, hostname=hostname)


class GitLabClient:
    """Client for interacting with GitLab using glab CLI."""

    def __init__(self, config: GitLabConfig | None = None, repo_path: Path | None = None):
        """
        Initialize GitLab client.

        Args:
            config: GitLab configuration. If None, auto-detected from repo_path.
            repo_path: Path to local git repo. Defaults to cwd.
        """
        self.repo_path = Path(repo_path) if repo_path else Path.cwd()

        if config:
            self.config = config
        else:
            # Auto-detect from repository
            self.config = detect_gitlab_from_repo(self.repo_path)

        self._verify_glab()

    @classmethod
    def from_repo(cls, repo_path: str | Path) -> "GitLabClient":
        """
        Create a GitLab client by auto-detecting project from a local repo.

        Args:
            repo_path: Path to local git repository

        Returns:
            Configured GitLabClient
        """
        repo_path = Path(repo_path).resolve()
        return cls(config=None, repo_path=repo_path)

    def _verify_glab(self) -> None:
        """Verify glab CLI is installed and authenticated."""
        try:
            result = subprocess.run(
                ["glab", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                raise RuntimeError("glab CLI not working properly")
        except FileNotFoundError:
            raise RuntimeError(
                "glab CLI not found. Install it from: https://gitlab.com/gitlab-org/cli"
            )

        # Check authentication
        result = subprocess.run(
            ["glab", "auth", "status"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            raise RuntimeError(
                "glab not authenticated. Run: glab auth login"
            )

    def _run_glab(
        self,
        args: list[str],
        check: bool = True
    ) -> subprocess.CompletedProcess:
        """
        Run a glab command.

        Args:
            args: Command arguments (without 'glab' prefix)
            check: Raise exception on non-zero exit

        Returns:
            CompletedProcess result
        """
        cmd = ["glab"] + args

        # Add repo flag if specified
        if self.config.project:
            cmd.extend(["--repo", self.config.project])

        # Add hostname if specified (for self-hosted GitLab)
        if self.config.hostname:
            cmd.extend(["--hostname", self.config.hostname])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=self.repo_path,
            timeout=60
        )

        if check and result.returncode != 0:
            raise RuntimeError(f"glab command failed: {result.stderr}")

        return result

    def _api(
        self,
        endpoint: str,
        method: str = "GET",
        fields: dict | None = None
    ) -> dict | list:
        """
        Make a GitLab API call via glab.

        Args:
            endpoint: API endpoint (e.g., "projects/:id/vulnerabilities")
            method: HTTP method
            fields: Request body fields

        Returns:
            Parsed JSON response
        """
        args = ["api", endpoint, "--method", method]

        if fields:
            for key, value in fields.items():
                args.extend(["--field", f"{key}={value}"])

        result = self._run_glab(args)

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"raw": result.stdout}

    def get_project_info(self) -> dict:
        """Get current project information."""
        return {
            "project": self.config.project,
            "hostname": self.config.hostname or "gitlab.com",
            "repo_path": str(self.repo_path),
        }

    def get_vulnerability_report(self) -> list[dict]:
        """
        Fetch vulnerability report from GitLab project.

        Returns:
            List of vulnerability dictionaries
        """
        all_vulns = []
        page = 1
        per_page = 100

        # Use the vulnerability findings API with pagination
        try:
            while True:
                endpoint = f"projects/:id/vulnerability_findings?per_page={per_page}&page={page}"
                result = self._api(endpoint, method="GET")

                if isinstance(result, list):
                    if not result:  # Empty page = no more results
                        break
                    all_vulns.extend(result)
                    if len(result) < per_page:  # Last page
                        break
                    page += 1
                else:
                    # Non-list response, try to extract vulnerabilities
                    vulns = result.get("vulnerabilities", [])
                    all_vulns.extend(vulns)
                    break

            return all_vulns
        except Exception as e:
            print(f"Warning: Could not fetch vulnerability_findings: {e}")
            # Fallback to vulnerabilities endpoint
            try:
                result = self._api(f"projects/:id/vulnerabilities?per_page={per_page}", method="GET")
                if isinstance(result, list):
                    return result
                return []
            except Exception as e2:
                print(f"Warning: Could not fetch vulnerabilities: {e2}")
                return []

    def get_pipeline_security_report(self, pipeline_id: int) -> dict | list:
        """
        Fetch security report from a specific pipeline.

        Args:
            pipeline_id: The pipeline ID

        Returns:
            Security report dictionary
        """
        return self._api(f"projects/:id/pipelines/{pipeline_id}/security_report_summary")

    def create_branch(self, branch_name: str, ref: str = "main") -> bool:
        """
        Create a new branch.

        Args:
            branch_name: Name for the new branch
            ref: Source branch/commit

        Returns:
            True if successful
        """
        try:
            self._api(
                "projects/:id/repository/branches",
                method="POST",
                fields={"branch": branch_name, "ref": ref}
            )
            return True
        except Exception as e:
            print(f"Failed to create branch: {e}")
            return False

    def commit_files(
        self,
        _branch: str,
        files: list[dict],  # [{"path": "...", "content": "..."}]
        commit_message: str
    ) -> bool:
        """
        Commit file changes to a branch.

        Args:
            _branch: Target branch (unused - commits to current branch)
            files: List of file changes
            commit_message: Commit message

        Returns:
            True if successful
        """
        try:
            # Use git directly since we have local repo
            for f in files:
                file_path = self.repo_path / f["path"]
                file_path.write_text(f["content"])

            subprocess.run(
                ["git", "add"] + [f["path"] for f in files],
                cwd=self.repo_path,
                check=True
            )
            subprocess.run(
                ["git", "commit", "-m", commit_message],
                cwd=self.repo_path,
                check=True
            )
            return True
        except Exception as e:
            print(f"Failed to commit: {e}")
            return False

    def push_branch(self, branch: str) -> bool:
        """
        Push a branch to remote.

        Args:
            branch: Branch name to push

        Returns:
            True if successful
        """
        try:
            subprocess.run(
                ["git", "push", "-u", "origin", branch],
                cwd=self.repo_path,
                check=True,
                capture_output=True
            )
            return True
        except Exception as e:
            print(f"Failed to push: {e}")
            return False

    def create_merge_request(
        self,
        source_branch: str,
        target_branch: str,
        title: str,
        description: str
    ) -> dict | None:
        """
        Create a merge request using glab mr create.

        Args:
            source_branch: Source branch with changes
            target_branch: Target branch to merge into
            title: MR title
            description: MR description

        Returns:
            MR info dict or None if failed
        """
        try:
            args = [
                "mr", "create",
                "--source-branch", source_branch,
                "--target-branch", target_branch,
                "--title", title,
                "--description", description,
                "--remove-source-branch",
                "--yes"  # Skip confirmation
            ]

            result = self._run_glab(args)

            # Parse MR URL from output
            output = result.stdout + result.stderr
            for line in output.split("\n"):
                if "merge_requests" in line or "/-/merge_requests/" in line:
                    return {"web_url": line.strip(), "success": True}

            return {"success": True, "output": output}

        except Exception as e:
            print(f"Failed to create MR: {e}")
            return None

    def checkout_branch(self, branch: str, create: bool = False) -> bool:
        """
        Checkout a git branch.

        Args:
            branch: Branch name
            create: Create branch if it doesn't exist

        Returns:
            True if successful
        """
        try:
            cmd = ["git", "checkout"]
            if create:
                cmd.append("-b")
            cmd.append(branch)

            subprocess.run(cmd, cwd=self.repo_path, check=True, capture_output=True)
            return True
        except Exception as e:
            print(f"Failed to checkout branch: {e}")
            return False

    def get_current_branch(self) -> str:
        """Get the current git branch name."""
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=self.repo_path,
            capture_output=True,
            text=True
        )
        return result.stdout.strip()

    def get_file_content(self, file_path: str, ref: str = "HEAD") -> str | None:
        """
        Get file content from git.

        Args:
            file_path: Path to file
            ref: Git ref (branch, commit, tag)

        Returns:
            File content or None
        """
        try:
            result = subprocess.run(
                ["git", "show", f"{ref}:{file_path}"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except Exception:
            return None

    def list_merge_requests(self, state: str = "opened") -> list[dict]:
        """
        List merge requests.

        Args:
            state: MR state filter (opened, closed, merged, all)

        Returns:
            List of MR dictionaries
        """
        try:
            result = self._run_glab(["mr", "list", "--state", state, "--output", "json"])
            return json.loads(result.stdout)
        except Exception:
            return []

    def get_current_user(self) -> dict | None:
        """
        Get the current authenticated GitLab user.

        Returns:
            User dict with 'username' and 'id', or None if failed
        """
        try:
            result = subprocess.run(
                ["glab", "api", "user"],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                return json.loads(result.stdout)
        except Exception:
            pass
        return None

    def branch_exists(self, branch: str) -> bool:
        """
        Check if a local branch exists.

        Args:
            branch: Branch name to check

        Returns:
            True if branch exists locally
        """
        result = subprocess.run(
            ["git", "branch", "--list", branch],
            cwd=self.repo_path,
            capture_output=True,
            text=True
        )
        return bool(result.stdout.strip())

    def remote_branch_exists(self, branch: str) -> bool:
        """
        Check if a remote branch exists.

        Args:
            branch: Branch name to check

        Returns:
            True if branch exists on remote
        """
        result = subprocess.run(
            ["git", "ls-remote", "--heads", "origin", branch],
            cwd=self.repo_path,
            capture_output=True,
            text=True
        )
        return bool(result.stdout.strip())

    def delete_local_branch(self, branch: str, force: bool = False) -> bool:
        """
        Delete a local branch.

        Args:
            branch: Branch name to delete
            force: Force delete even if not merged

        Returns:
            True if successful
        """
        try:
            flag = "-D" if force else "-d"
            subprocess.run(
                ["git", "branch", flag, branch],
                cwd=self.repo_path,
                check=True,
                capture_output=True
            )
            return True
        except Exception as e:
            print(f"Failed to delete branch: {e}")
            return False

    def delete_remote_branch(self, branch: str) -> bool:
        """
        Delete a remote branch.

        Args:
            branch: Branch name to delete

        Returns:
            True if successful
        """
        try:
            subprocess.run(
                ["git", "push", "origin", "--delete", branch],
                cwd=self.repo_path,
                check=True,
                capture_output=True
            )
            return True
        except Exception as e:
            print(f"Failed to delete remote branch: {e}")
            return False

    def find_mr_by_source_branch(self, source_branch: str, state: str = "opened") -> dict | None:
        """
        Find a merge request by source branch.

        Args:
            source_branch: Source branch name
            state: MR state filter

        Returns:
            MR dict if found, None otherwise
        """
        mrs = self.list_merge_requests(state=state)
        for mr in mrs:
            if mr.get("source_branch") == source_branch:
                return mr
        return None

    def is_mr_owned_by_current_user(self, mr: dict) -> bool:
        """
        Check if the current user is the author of an MR.

        Args:
            mr: MR dictionary

        Returns:
            True if current user is the author
        """
        current_user = self.get_current_user()
        if not current_user:
            return False

        author = mr.get("author", {})
        return (
            author.get("username") == current_user.get("username") or
            author.get("id") == current_user.get("id")
        )

    def close_merge_request(self, mr_iid: int) -> bool:
        """
        Close a merge request.

        Args:
            mr_iid: MR internal ID

        Returns:
            True if successful
        """
        try:
            self._run_glab(["mr", "close", str(mr_iid)])
            return True
        except Exception as e:
            print(f"Failed to close MR: {e}")
            return False


# Convenience function
def create_client_from_repo(repo_path: str | Path) -> GitLabClient:
    """
    Create a GitLab client by auto-detecting project from a local repo.

    Args:
        repo_path: Path to local git repository

    Returns:
        Configured GitLabClient
    """
    return GitLabClient.from_repo(repo_path)
