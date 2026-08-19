//! GloScope fork addition: hard gate in front of `apply_patch` that keeps the
//! AI fix flow off protected branches. Not upstream codex — this crate is a
//! hard fork with no upstream tracking, so this lives directly in
//! `core/src/tools` rather than behind the extension API (which has no hook
//! point inside `execute_verified_patch`).
//!
//! Policy (product decision, not a technical constraint):
//! - No git repository at all → reject. No repo means no rollback safety net.
//! - On the repository's protected branch (`main`/`master`/whatever the repo's
//!   default branch resolves to) → silently create and switch to a fresh
//!   `gloscope/fix-<timestamp>` branch, then let the patch proceed.
//! - Dirty working tree on a non-protected branch → allowed. Treated as
//!   normal agent state (e.g. an earlier patch in the same turn), not a
//!   condition to interrupt on.

use std::path::Path;
use std::process::Command;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use crate::function_tool::FunctionCallError;

/// Ensures `cwd` is a git repository and not checked out on its protected
/// branch before an `apply_patch` write is allowed to proceed. Creates and
/// switches to a new branch automatically when currently on the protected
/// branch; otherwise a no-op.
pub(crate) async fn ensure_safe_branch_for_patch(cwd: &Path) -> Result<(), FunctionCallError> {
    if codex_git_utils::get_git_repo_root(cwd).is_none() {
        return Err(FunctionCallError::RespondToModel(
            "apply_patch 被拒绝：目标目录不是 git 仓库，没有版本控制就没有回滚安全网。请先执行 git init 并提交一次快照。"
                .to_string(),
        ));
    }

    let Some(current_branch) = codex_git_utils::current_branch_name(cwd).await else {
        // Detached HEAD or an unborn branch (no commits yet): not the
        // protected-branch case this gate exists for, so let the patch
        // proceed rather than guessing at a policy for an edge case the
        // product decision didn't cover.
        return Ok(());
    };

    if !is_protected_branch(cwd, &current_branch).await {
        return Ok(());
    }

    let new_branch = format!("gloscope/fix-{}", unix_timestamp());
    checkout_new_branch(cwd, &new_branch).map_err(|err| {
        FunctionCallError::RespondToModel(format!(
            "apply_patch 被拒绝：当前在受保护分支 {current_branch} 上，尝试自动切换到 {new_branch} 失败: {err}"
        ))
    })
}

async fn is_protected_branch(cwd: &Path, branch: &str) -> bool {
    if branch == "main" || branch == "master" {
        return true;
    }
    match codex_git_utils::default_branch_name(cwd).await {
        Some(default_branch) => branch == default_branch,
        None => false,
    }
}

fn checkout_new_branch(cwd: &Path, branch: &str) -> std::io::Result<()> {
    let output = Command::new("git")
        .current_dir(cwd)
        .args(["checkout", "-b", branch])
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(std::io::Error::other(stderr));
    }
    Ok(())
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::path::Path;
    use tempfile::tempdir;

    fn run_git_in(repo_path: &Path, args: &[&str]) {
        let status = Command::new("git")
            .current_dir(repo_path)
            .args(args)
            .status()
            .expect("git command");
        assert!(status.success(), "git command failed: {args:?}");
    }

    fn init_test_repo(repo_path: &Path, initial_branch: &str) {
        run_git_in(
            repo_path,
            &["init", &format!("--initial-branch={initial_branch}")],
        );
        run_git_in(repo_path, &["config", "user.name", "Tester"]);
        run_git_in(repo_path, &["config", "user.email", "test@example.com"]);
        std::fs::write(repo_path.join("seed.txt"), "seed\n").expect("write seed file");
        run_git_in(repo_path, &["add", "seed.txt"]);
        run_git_in(repo_path, &["commit", "-m", "seed"]);
    }

    #[tokio::test]
    async fn rejects_non_git_directory() {
        let temp = tempdir().expect("tempdir");
        let result = ensure_safe_branch_for_patch(temp.path()).await;
        assert!(result.is_err(), "expected rejection for non-git dir");
    }

    #[tokio::test]
    async fn allows_feature_branch_without_switching() {
        let temp = tempdir().expect("tempdir");
        init_test_repo(temp.path(), "main");
        run_git_in(temp.path(), &["checkout", "-b", "feature/x"]);

        let result = ensure_safe_branch_for_patch(temp.path()).await;
        assert!(result.is_ok());
        let branch = codex_git_utils::current_branch_name(temp.path())
            .await
            .expect("branch");
        assert_eq!(branch, "feature/x");
    }

    #[tokio::test]
    async fn auto_branches_off_main() {
        let temp = tempdir().expect("tempdir");
        init_test_repo(temp.path(), "main");

        let result = ensure_safe_branch_for_patch(temp.path()).await;
        assert!(result.is_ok());
        let branch = codex_git_utils::current_branch_name(temp.path())
            .await
            .expect("branch");
        assert_ne!(branch, "main");
        assert!(branch.starts_with("gloscope/fix-"), "got branch {branch}");
    }

    #[tokio::test]
    async fn auto_branches_off_master() {
        let temp = tempdir().expect("tempdir");
        init_test_repo(temp.path(), "master");

        let result = ensure_safe_branch_for_patch(temp.path()).await;
        assert!(result.is_ok());
        let branch = codex_git_utils::current_branch_name(temp.path())
            .await
            .expect("branch");
        assert_ne!(branch, "master");
        assert!(branch.starts_with("gloscope/fix-"), "got branch {branch}");
    }

    #[tokio::test]
    async fn dirty_working_tree_on_feature_branch_does_not_block() {
        let temp = tempdir().expect("tempdir");
        init_test_repo(temp.path(), "main");
        run_git_in(temp.path(), &["checkout", "-b", "feature/y"]);
        std::fs::write(temp.path().join("dirty.txt"), "uncommitted\n").expect("write dirty file");

        let result = ensure_safe_branch_for_patch(temp.path()).await;
        assert!(result.is_ok());
        let branch = codex_git_utils::current_branch_name(temp.path())
            .await
            .expect("branch");
        assert_eq!(branch, "feature/y");
    }
}
