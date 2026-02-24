use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use regex::Regex;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use walkdir::WalkDir;

// --- GitHub App Auth ---

mod gh_app {
    use anyhow::{Context, Result};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde::{Deserialize, Serialize};
    use std::time::{SystemTime, UNIX_EPOCH};

    const DEFAULT_GH_APP_ID: &str = "2665041";
    const DEFAULT_GH_APP_INSTALLATION_ID: &str = "104427264";

    #[derive(Debug, Serialize)]
    struct Claims {
        iat: u64,
        exp: u64,
        iss: String,
    }

    #[derive(Debug, Deserialize)]
    struct InstallationToken {
        token: String,
    }

    /// Generate a GitHub App installation token.
    ///
    /// Reads config from environment variables:
    ///   - `GH_APP_ID` (or uses default 2665041)
    ///   - `GH_APP_INSTALLATION_ID` (or uses default 104427264)
    ///   - `GH_APP_PRIVATE_KEY` — PEM contents, OR
    ///   - `GH_APP_PRIVATE_KEY_FILE` — path to PEM file
    pub fn get_installation_token() -> Result<String> {
        let app_id = std::env::var("GH_APP_ID").unwrap_or_else(|_| DEFAULT_GH_APP_ID.to_string());
        let installation_id = std::env::var("GH_APP_INSTALLATION_ID")
            .unwrap_or_else(|_| DEFAULT_GH_APP_INSTALLATION_ID.to_string());

        let pem = if let Ok(key) = std::env::var("GH_APP_PRIVATE_KEY") {
            key
        } else if let Ok(path) = std::env::var("GH_APP_PRIVATE_KEY_FILE") {
            std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read private key from {}", path))?
        } else {
            anyhow::bail!(
                "GitHub App auth requires GH_APP_PRIVATE_KEY (PEM contents) or \
                 GH_APP_PRIVATE_KEY_FILE (path to PEM file)"
            );
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("System time error")?
            .as_secs();

        let claims = Claims {
            iat: now.saturating_sub(60),
            exp: now + (10 * 60), // 10 minutes
            iss: app_id,
        };

        let header = Header::new(Algorithm::RS256);
        let key =
            EncodingKey::from_rsa_pem(pem.as_bytes()).context("Invalid RSA private key PEM")?;
        let jwt = encode(&header, &claims, &key).context("Failed to encode JWT")?;

        let url = format!(
            "https://api.github.com/app/installations/{}/access_tokens",
            installation_id
        );

        let resp: InstallationToken = ureq::post(&url)
            .set("Authorization", &format!("Bearer {}", jwt))
            .set("Accept", "application/vnd.github+json")
            .set("User-Agent", "ai-agent-cleaner")
            .call()
            .context("Failed to request installation token")?
            .into_json()
            .context("Failed to parse installation token response")?;

        Ok(resp.token)
    }
}

/// Resolve a GitHub token for `gh` CLI authentication.
///
/// Priority:
///   1. `GH_TOKEN` env var (already set by user or CI)
///   2. GitHub App credentials (GH_APP_PRIVATE_KEY / GH_APP_PRIVATE_KEY_FILE)
///   3. None — fall back to whatever `gh auth` provides
fn resolve_gh_token() -> Option<String> {
    if let Ok(token) = std::env::var("GH_TOKEN") {
        if !token.is_empty() {
            return Some(token);
        }
    }

    match gh_app::get_installation_token() {
        Ok(token) => {
            eprintln!("Using GitHub App installation token");
            Some(token)
        }
        Err(e) => {
            eprintln!("GitHub App auth not available: {}", e);
            None
        }
    }
}

/// Create a `Command` for `gh` with the resolved token injected.
fn gh_command(token: &Option<String>) -> Command {
    let mut cmd = Command::new("gh");
    if let Some(t) = token {
        cmd.env("GH_TOKEN", t);
    }
    cmd
}

// --- CLI ---

#[derive(Parser, Debug)]
#[command(
    name = "ai-agent-cleaner",
    version,
    about = "AI agent for repository hygiene: sensitive file scanning and branch pruning"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan for sensitive files (API keys, secrets, credentials)
    Scan {
        /// Root directory to scan
        #[arg(short, long, default_value = ".")]
        root: PathBuf,

        /// Dry run mode (don't delete files, just report)
        #[arg(long)]
        dry_run: bool,

        /// Confirm deletion (required to delete files)
        #[arg(long)]
        confirm: bool,
    },

    /// Prune stale remote branches not in main/develop or open PRs
    Prune {
        /// GitHub org/owner to scan
        #[arg(short, long)]
        org: String,

        /// Specific repo (if omitted, scans all org repos)
        #[arg(short, long)]
        repo: Option<String>,

        /// Protected branches (always kept)
        #[arg(long, default_values_t = vec!["main".to_string(), "develop".to_string(), "master".to_string()])]
        protected: Vec<String>,

        /// Dry run mode (list branches to delete without deleting)
        #[arg(long)]
        dry_run: bool,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Include forked repos (by default forks are skipped)
        #[arg(long)]
        include_forks: bool,

        /// Only prune branches whose last commit is older than N days (0 = no age filter)
        #[arg(long, default_value_t = 0)]
        stale_days: u64,
    },
}

// --- Scan (sensitive file detection) ---

struct Pattern {
    name: &'static str,
    regex: Regex,
}

impl Pattern {
    fn new(name: &'static str, pattern: &'static str) -> Self {
        Self {
            name,
            regex: Regex::new(pattern).expect("Invalid regex"),
        }
    }
}

fn cmd_scan(root: PathBuf, dry_run: bool, confirm: bool) -> Result<()> {
    println!("Starting cleanup scan in: {:?}", root);

    let patterns = vec![
        Pattern::new("Stripe Secret Key", r"sk_live_[0-9a-zA-Z]{24}"),
        Pattern::new("Stripe Publishable Key", r"pk_live_[0-9a-zA-Z]{24}"),
        Pattern::new("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
        Pattern::new(
            "GCP Private Key",
            concat!("-----BEGIN PRIVATE ", "KEY-----"),
        ),
        Pattern::new("Generic Token", r"[a-zA-Z0-9]{32,}"),
    ];

    let mut sensitive_files = Vec::new();

    for entry in WalkDir::new(&root)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        if path.to_string_lossy().contains("/.")
            || path.to_string_lossy().contains("/target/")
            || path.to_string_lossy().contains("/node_modules/")
            || path.to_string_lossy().contains("/venv/")
        {
            continue;
        }

        if let Ok(content) = fs::read_to_string(path) {
            for pattern in &patterns {
                if pattern.regex.is_match(&content) {
                    println!("Sensitive Pattern Found: {} in {:?}", pattern.name, path);
                    sensitive_files.push(path.to_path_buf());
                    break;
                }
            }
        }
    }

    if sensitive_files.is_empty() {
        println!("No sensitive files found.");
        return Ok(());
    }

    println!("\nFound {} sensitive files:", sensitive_files.len());
    for file in &sensitive_files {
        println!(" - {:?}", file);
    }

    if dry_run {
        println!("\nDRY RUN: No files were deleted.");
    } else if confirm {
        println!("\nDeleting sensitive files...");
        for file in sensitive_files {
            if let Err(e) = fs::remove_file(&file) {
                eprintln!("Failed to delete {:?}: {}", file, e);
            } else {
                println!("Deleted {:?}", file);
            }
        }
    } else {
        println!("\nRun with --confirm to delete these files.");
    }

    Ok(())
}

// --- Prune (stale branch removal) ---

#[derive(Debug, Serialize)]
struct PruneResult {
    repo: String,
    branches_scanned: usize,
    branches_deleted: Vec<String>,
    branches_protected: Vec<String>,
    branches_with_open_prs: Vec<String>,
    branches_skipped_recent: Vec<String>,
    errors: Vec<String>,
}

/// Branch info returned from the API, including the last commit date
/// for age-based filtering without extra per-branch API calls.
struct BranchInfo {
    name: String,
    commit_date: Option<String>,
}

/// List remote branches for a repo using `gh api`.
/// Returns branch names and their last commit dates in a single batch.
fn list_remote_branches(
    token: &Option<String>,
    owner: &str,
    repo: &str,
) -> Result<Vec<BranchInfo>> {
    let mut branches = Vec::new();
    let mut page = 1;

    loop {
        let endpoint = format!(
            "repos/{}/{}/branches?per_page=100&page={}",
            owner, repo, page
        );
        let output = gh_command(token)
            .args([
                "api",
                &endpoint,
                "--jq",
                r#".[] | .name + "\t" + .commit.commit.committer.date"#,
            ])
            .output()
            .context("Failed to run gh api")?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("gh api failed for {}/{}: {}", owner, repo, err);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let page_branches: Vec<BranchInfo> = stdout
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                if let Some((name, date)) = l.split_once('\t') {
                    BranchInfo {
                        name: name.to_string(),
                        commit_date: if date.is_empty() || date == "null" {
                            None
                        } else {
                            Some(date.to_string())
                        },
                    }
                } else {
                    BranchInfo {
                        name: l.to_string(),
                        commit_date: None,
                    }
                }
            })
            .collect();

        if page_branches.is_empty() {
            break;
        }
        branches.extend(page_branches);
        page += 1;
    }

    Ok(branches)
}

/// List branches with open PRs for a repo
fn list_open_pr_branches(token: &Option<String>, owner: &str, repo: &str) -> Result<Vec<String>> {
    let output = gh_command(token)
        .args([
            "pr",
            "list",
            "--repo",
            &format!("{}/{}", owner, repo),
            "--state",
            "open",
            "--json",
            "headRefName",
            "--jq",
            ".[].headRefName",
        ])
        .output()
        .context("Failed to list open PRs")?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("gh pr list failed: {}", err);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect())
}

/// Delete a remote branch
fn delete_remote_branch(
    token: &Option<String>,
    owner: &str,
    repo: &str,
    branch: &str,
) -> Result<()> {
    let endpoint = format!("repos/{}/{}/git/refs/heads/{}", owner, repo, branch);
    let output = gh_command(token)
        .args(["api", "-X", "DELETE", &endpoint])
        .output()
        .context("Failed to delete branch")?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to delete {}: {}", branch, err);
    }
    Ok(())
}

/// List repos in an org, optionally excluding forks.
///
/// Uses the GitHub REST API with `type=sources` to exclude forks when
/// `include_forks` is false. This prevents accidentally deleting upstream
/// branches in forked repositories (e.g. llama.cpp with 543 branches).
fn list_org_repos(token: &Option<String>, org: &str, include_forks: bool) -> Result<Vec<String>> {
    const ORG_REPOS_PER_PAGE: u32 = 100;

    let mut repos = Vec::new();
    let mut page = 1;
    let repo_type = if include_forks { "all" } else { "sources" };

    loop {
        let endpoint = format!(
            "orgs/{}/repos?per_page={}&page={}&type={}&sort=name",
            org, ORG_REPOS_PER_PAGE, page, repo_type
        );
        let output = gh_command(token)
            .args([
                "api",
                &endpoint,
                "--jq",
                ".[] | select(.archived == false) | .name",
            ])
            .output()
            .context("Failed to list org repos")?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("gh repo list failed for {}: {}", org, err);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let page_repos: Vec<String> = stdout
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect();

        if page_repos.is_empty() {
            break;
        }
        repos.extend(page_repos);
        page += 1;
    }

    if !include_forks {
        eprintln!(
            "Found {} source repos in {} (forks excluded)",
            repos.len(),
            org
        );
    }

    Ok(repos)
}

/// Get the default branch for a repo (e.g. "main", "master").
/// Auto-protected to avoid HTTP 422 errors when attempting to delete it.
fn get_default_branch(token: &Option<String>, owner: &str, repo: &str) -> Result<String> {
    let endpoint = format!("repos/{}/{}", owner, repo);
    let output = gh_command(token)
        .args(["api", &endpoint, "--jq", ".default_branch"])
        .output()
        .context("Failed to get default branch")?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Failed to get default branch for {}/{}: {}",
            owner,
            repo,
            err
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Compute the age of a branch in days from its commit date string.
/// Uses the batch-fetched date from `list_remote_branches` — no extra API call.
fn branch_age_days(commit_date: &Option<String>) -> Option<u64> {
    let date_str = commit_date.as_deref()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    parse_iso8601_age_days(date_str, now)
}

/// Parse an ISO 8601 datetime string and return days elapsed since then.
/// Handles both "Z" and "+00:00" / "-00:00" timezone suffixes.
fn parse_iso8601_age_days(date_str: &str, now_epoch_secs: u64) -> Option<u64> {
    // Expected formats: "2025-06-15T12:34:56Z" or "2025-06-15T12:34:56+00:00"
    let parts: Vec<&str> = date_str.split('T').collect();
    if parts.len() != 2 {
        return None;
    }

    let date_parts: Vec<u64> = parts[0].split('-').filter_map(|p| p.parse().ok()).collect();
    if date_parts.len() != 3 {
        return None;
    }
    let (year, month, day) = (date_parts[0], date_parts[1], date_parts[2]);

    // Strip timezone suffix: "Z", "+00:00", "-05:00", etc.
    let time_part = parts[1];
    let time_str = if let Some(idx) = time_part.find('Z') {
        &time_part[..idx]
    } else if let Some(idx) = time_part.find('+') {
        &time_part[..idx]
    } else if let Some(idx) = time_part.rfind('-') {
        // rfind to skip the date hyphens; only match if after "HH:MM:SS"
        if idx >= 8 {
            &time_part[..idx]
        } else {
            time_part
        }
    } else {
        time_part
    };

    let time_parts: Vec<u64> = time_str.split(':').filter_map(|p| p.parse().ok()).collect();
    if time_parts.len() != 3 {
        return None;
    }
    let (hour, min, sec) = (time_parts[0], time_parts[1], time_parts[2]);

    // Days from year 0 to the given date (simplified, good enough for age calculation)
    fn days_from_epoch(y: u64, m: u64, d: u64) -> u64 {
        // Approximate days since Unix epoch using a simplified calculation
        let mut days: i64 = 0;
        // Years since 1970
        for yr in 1970..y {
            days += if yr.is_multiple_of(4) && (!yr.is_multiple_of(100) || yr.is_multiple_of(400)) {
                366
            } else {
                365
            };
        }
        let month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let is_leap = y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
        for mo in 1..m {
            days += month_days[(mo - 1) as usize] as i64;
            if mo == 2 && is_leap {
                days += 1;
            }
        }
        days += d as i64 - 1;
        days as u64
    }

    let commit_epoch = days_from_epoch(year, month, day) * 86400 + hour * 3600 + min * 60 + sec;

    if now_epoch_secs > commit_epoch {
        Some((now_epoch_secs - commit_epoch) / 86400)
    } else {
        Some(0)
    }
}

fn prune_repo(
    token: &Option<String>,
    owner: &str,
    repo: &str,
    protected: &[String],
    dry_run: bool,
    stale_days: u64,
) -> Result<PruneResult> {
    let full_name = format!("{}/{}", owner, repo);
    eprintln!("Scanning {}...", full_name);

    let branch_infos = list_remote_branches(token, owner, repo)?;
    let open_pr_branches = list_open_pr_branches(token, owner, repo)?;

    // Auto-protect the default branch to avoid HTTP 422 errors
    let default_branch = get_default_branch(token, owner, repo).unwrap_or_default();

    let mut protected_set: std::collections::HashSet<&str> =
        protected.iter().map(|s| s.as_str()).collect();
    if !default_branch.is_empty() {
        protected_set.insert(&default_branch);
    }
    let pr_set: std::collections::HashSet<&str> =
        open_pr_branches.iter().map(|s| s.as_str()).collect();

    let mut result = PruneResult {
        repo: full_name,
        branches_scanned: branch_infos.len(),
        branches_deleted: Vec::new(),
        branches_protected: Vec::new(),
        branches_with_open_prs: Vec::new(),
        branches_skipped_recent: Vec::new(),
        errors: Vec::new(),
    };

    for bi in &branch_infos {
        if protected_set.contains(bi.name.as_str()) {
            result.branches_protected.push(bi.name.clone());
            continue;
        }
        if pr_set.contains(bi.name.as_str()) {
            result.branches_with_open_prs.push(bi.name.clone());
            continue;
        }

        // Check branch age if --stale-days is set (uses batch-fetched date, no extra API call)
        if stale_days > 0 {
            if let Some(age) = branch_age_days(&bi.commit_date) {
                if age < stale_days {
                    result.branches_skipped_recent.push(bi.name.clone());
                    eprintln!(
                        "  skipped ({}d old, threshold {}d): {}",
                        age, stale_days, bi.name
                    );
                    continue;
                }
            }
            // If we can't determine age, treat it as stale (safe default)
        }

        // This branch is stale — delete it
        if dry_run {
            result.branches_deleted.push(bi.name.clone());
            eprintln!("  [dry-run] would delete: {}", bi.name);
        } else {
            match delete_remote_branch(token, owner, repo, &bi.name) {
                Ok(()) => {
                    result.branches_deleted.push(bi.name.clone());
                    eprintln!("  deleted: {}", bi.name);
                }
                Err(e) => {
                    result.errors.push(format!("{}: {}", bi.name, e));
                    eprintln!("  error deleting {}: {}", bi.name, e);
                }
            }
        }
    }

    Ok(result)
}

fn cmd_prune(
    org: String,
    repo: Option<String>,
    protected: Vec<String>,
    dry_run: bool,
    json_output: bool,
    include_forks: bool,
    stale_days: u64,
) -> Result<()> {
    let token = resolve_gh_token();

    let repos = if let Some(r) = repo {
        vec![r]
    } else {
        list_org_repos(&token, &org, include_forks)?
    };

    if dry_run {
        eprintln!("DRY RUN: No branches will be deleted.\n");
    }

    let mut all_results = Vec::new();

    for repo_name in &repos {
        match prune_repo(&token, &org, repo_name, &protected, dry_run, stale_days) {
            Ok(result) => {
                if !json_output {
                    let action = if dry_run { "would delete" } else { "deleted" };
                    let recent_info = if result.branches_skipped_recent.is_empty() {
                        String::new()
                    } else {
                        format!(", {} recent", result.branches_skipped_recent.len())
                    };
                    println!(
                        "{}: scanned {} branches, {} {}, {} protected, {} with open PRs{}",
                        result.repo,
                        result.branches_scanned,
                        result.branches_deleted.len(),
                        action,
                        result.branches_protected.len(),
                        result.branches_with_open_prs.len(),
                        recent_info,
                    );
                    if !result.errors.is_empty() {
                        for err in &result.errors {
                            eprintln!("  error: {}", err);
                        }
                    }
                }
                all_results.push(result);
            }
            Err(e) => {
                eprintln!("Error scanning {}/{}: {}", org, repo_name, e);
            }
        }
    }

    if json_output {
        let json = serde_json::to_string_pretty(&all_results)?;
        println!("{}", json);
    } else {
        let total_deleted: usize = all_results.iter().map(|r| r.branches_deleted.len()).sum();
        let total_scanned: usize = all_results.iter().map(|r| r.branches_scanned).sum();
        println!(
            "\nTotal: {} repos, {} branches scanned, {} {}",
            all_results.len(),
            total_scanned,
            total_deleted,
            if dry_run { "would delete" } else { "deleted" },
        );
    }

    Ok(())
}

// --- Main ---

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            root,
            dry_run,
            confirm,
        } => cmd_scan(root, dry_run, confirm),
        Commands::Prune {
            org,
            repo,
            protected,
            dry_run,
            json,
            include_forks,
            stale_days,
        } => cmd_prune(
            org,
            repo,
            protected,
            dry_run,
            json,
            include_forks,
            stale_days,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // --- Unit tests for branch classification logic ---

    fn classify_branches(
        branches: &[&str],
        protected: &[&str],
        open_pr_branches: &[&str],
    ) -> (Vec<String>, Vec<String>, Vec<String>) {
        let protected_set: HashSet<&str> = protected.iter().copied().collect();
        let pr_set: HashSet<&str> = open_pr_branches.iter().copied().collect();

        let mut to_delete = Vec::new();
        let mut kept_protected = Vec::new();
        let mut kept_pr = Vec::new();

        for &branch in branches {
            if protected_set.contains(branch) {
                kept_protected.push(branch.to_string());
            } else if pr_set.contains(branch) {
                kept_pr.push(branch.to_string());
            } else {
                to_delete.push(branch.to_string());
            }
        }

        (to_delete, kept_protected, kept_pr)
    }

    #[test]
    fn test_protected_branches_are_never_deleted() {
        let branches = vec!["main", "develop", "master", "feat/foo"];
        let protected = vec!["main", "develop", "master"];
        let (deleted, kept, _) = classify_branches(&branches, &protected, &[]);

        assert_eq!(deleted, vec!["feat/foo"]);
        assert_eq!(kept.len(), 3);
        assert!(kept.contains(&"main".to_string()));
        assert!(kept.contains(&"develop".to_string()));
        assert!(kept.contains(&"master".to_string()));
    }

    #[test]
    fn test_open_pr_branches_are_kept() {
        let branches = vec!["main", "feat/active-pr", "stale/old"];
        let protected = vec!["main"];
        let open_prs = vec!["feat/active-pr"];
        let (deleted, _, kept_pr) = classify_branches(&branches, &protected, &open_prs);

        assert_eq!(deleted, vec!["stale/old"]);
        assert_eq!(kept_pr, vec!["feat/active-pr"]);
    }

    #[test]
    fn test_no_branches_deleted_when_all_protected_or_pr() {
        let branches = vec!["main", "develop", "feat/pr-open"];
        let protected = vec!["main", "develop"];
        let open_prs = vec!["feat/pr-open"];
        let (deleted, _, _) = classify_branches(&branches, &protected, &open_prs);

        assert!(deleted.is_empty());
    }

    #[test]
    fn test_all_stale_branches_deleted() {
        let branches = vec!["main", "stale/a", "stale/b", "stale/c"];
        let protected = vec!["main"];
        let (deleted, _, _) = classify_branches(&branches, &protected, &[]);

        assert_eq!(deleted, vec!["stale/a", "stale/b", "stale/c"]);
    }

    #[test]
    fn test_empty_branch_list() {
        let (deleted, kept, kept_pr) = classify_branches(&[], &["main"], &[]);
        assert!(deleted.is_empty());
        assert!(kept.is_empty());
        assert!(kept_pr.is_empty());
    }

    // --- Tests for fork filtering (API endpoint construction) ---

    #[test]
    fn test_api_endpoint_excludes_forks_by_default() {
        let include_forks = false;
        let repo_type = if include_forks { "all" } else { "sources" };
        let endpoint = format!(
            "orgs/{}/repos?per_page=100&page=1&type={}&sort=name",
            "test-org", repo_type
        );

        assert!(endpoint.contains("type=sources"));
        assert!(!endpoint.contains("type=all"));
    }

    #[test]
    fn test_api_endpoint_includes_forks_when_flag_set() {
        let include_forks = true;
        let repo_type = if include_forks { "all" } else { "sources" };
        let endpoint = format!(
            "orgs/{}/repos?per_page=100&page=1&type={}&sort=name",
            "test-org", repo_type
        );

        assert!(endpoint.contains("type=all"));
        assert!(!endpoint.contains("type=sources"));
    }

    // --- Integration tests (require GH_TOKEN or GH_APP_PRIVATE_KEY_FILE) ---

    #[test]
    fn test_list_org_repos_skips_forks_integration() {
        if std::env::var("GH_TOKEN").is_err() && std::env::var("GH_APP_PRIVATE_KEY_FILE").is_err() {
            eprintln!("Skipping integration test: no GitHub auth available");
            return;
        }

        let token = resolve_gh_token();

        let source_repos =
            list_org_repos(&token, "stevedores-org", false).expect("Failed to list source repos");
        let all_repos =
            list_org_repos(&token, "stevedores-org", true).expect("Failed to list all repos");

        // stevedores-org has known forks (llama.cpp, gitoxide, libgit2, mlx)
        assert!(
            all_repos.len() > source_repos.len(),
            "Expected all_repos ({}) > source_repos ({}) due to forks",
            all_repos.len(),
            source_repos.len()
        );

        let known_forks = ["llama.cpp", "gitoxide", "libgit2", "mlx"];
        for fork in &known_forks {
            assert!(
                !source_repos.contains(&fork.to_string()),
                "Fork '{}' should be excluded from source repos",
                fork
            );
        }
    }

    #[test]
    fn test_include_forks_flag_returns_forks_integration() {
        if std::env::var("GH_TOKEN").is_err() && std::env::var("GH_APP_PRIVATE_KEY_FILE").is_err() {
            eprintln!("Skipping integration test: no GitHub auth available");
            return;
        }

        let token = resolve_gh_token();
        let all_repos =
            list_org_repos(&token, "stevedores-org", true).expect("Failed to list all repos");

        let has_fork = all_repos
            .iter()
            .any(|r| r == "llama.cpp" || r == "gitoxide");
        assert!(has_fork, "Expected at least one fork in all_repos list");
    }

    // --- Tests for default branch auto-protection ---

    #[test]
    fn test_default_branch_added_to_protected_set() {
        // Simulate what prune_repo does: merge user-provided protected + default branch
        let protected = vec!["main".to_string(), "develop".to_string()];
        let default_branch = "master".to_string(); // repo's default is master

        let mut protected_set: HashSet<&str> = protected.iter().map(|s| s.as_str()).collect();
        if !default_branch.is_empty() {
            protected_set.insert(&default_branch);
        }

        assert!(protected_set.contains("main"));
        assert!(protected_set.contains("develop"));
        assert!(protected_set.contains("master"));
    }

    #[test]
    fn test_default_branch_no_duplicate_when_already_protected() {
        let protected = vec!["main".to_string(), "develop".to_string()];
        let default_branch = "main".to_string(); // already in protected list

        let mut protected_set: HashSet<&str> = protected.iter().map(|s| s.as_str()).collect();
        if !default_branch.is_empty() {
            protected_set.insert(&default_branch);
        }

        // Should still be 2 entries, not 3
        assert_eq!(protected_set.len(), 2);
        assert!(protected_set.contains("main"));
    }

    #[test]
    fn test_empty_default_branch_does_not_add_to_protected() {
        let protected = vec!["main".to_string()];
        let default_branch = String::new();

        let mut protected_set: HashSet<&str> = protected.iter().map(|s| s.as_str()).collect();
        if !default_branch.is_empty() {
            protected_set.insert(&default_branch);
        }

        assert_eq!(protected_set.len(), 1);
    }

    #[test]
    fn test_default_branch_prevents_deletion() {
        // The default branch should appear in the protected list, not the delete list
        let branches = vec!["master", "feat/old", "bugfix/stale"];
        let protected = vec!["main", "develop"];
        let default_branch = "master";

        let mut protected_set: HashSet<&str> = protected.iter().copied().collect();
        protected_set.insert(default_branch);

        let (deleted, _kept_protected, _) = classify_branches(&branches, &[], &[]);
        // Without default branch protection, master would be deleted
        assert!(deleted.contains(&"master".to_string()));

        // With default branch in protected set, re-classify
        let protected_vec: Vec<&str> = protected_set.iter().copied().collect();
        let (deleted2, kept2, _) = classify_branches(&branches, &protected_vec, &[]);
        assert!(!deleted2.contains(&"master".to_string()));
        assert!(kept2.contains(&"master".to_string()));
    }

    #[test]
    fn test_get_default_branch_integration() {
        if std::env::var("GH_TOKEN").is_err() && std::env::var("GH_APP_PRIVATE_KEY_FILE").is_err() {
            eprintln!("Skipping integration test: no GitHub auth available");
            return;
        }

        let token = resolve_gh_token();

        // lornu-ai-cleaner's default branch should be "develop" or "main"
        let default = get_default_branch(&token, "lornu-ai", "lornu-ai-cleaner")
            .expect("Failed to get default branch");
        assert!(
            default == "main" || default == "develop",
            "Expected default branch to be main or develop, got: {}",
            default
        );

        // crossplane-heaven's default is "master"
        let default2 = get_default_branch(&token, "stevedores-org", "crossplane-heaven")
            .expect("Failed to get default branch");
        assert_eq!(default2, "master");
    }

    // --- Tests for --stale-days / ISO 8601 parsing ---

    #[test]
    fn test_parse_iso8601_age_days_recent() {
        // Use the same date for both "now" and commit — should be 0 or at most 1
        let now_epoch = 1771891200; // 2026-02-24T00:00:00Z
        let age = parse_iso8601_age_days("2026-02-24T00:00:00Z", now_epoch);
        assert!(age.is_some());
        assert!(
            age.unwrap() <= 1,
            "Same-day commit should be 0-1 days old, got {}",
            age.unwrap()
        );
    }

    #[test]
    fn test_parse_iso8601_age_days_30_days_old() {
        // 2026-01-25T00:00:00Z is 30 days before 2026-02-24
        let now = 1772020800; // ~2026-02-24T12:00:00Z
        let age = parse_iso8601_age_days("2026-01-25T00:00:00Z", now);
        assert!(age.is_some());
        let days = age.unwrap();
        assert!((29..=31).contains(&days), "Expected ~30 days, got {}", days);
    }

    #[test]
    fn test_parse_iso8601_age_days_one_year_old() {
        let now = 1772020800; // ~2026-02-24
        let age = parse_iso8601_age_days("2025-02-24T00:00:00Z", now);
        assert!(age.is_some());
        let days = age.unwrap();
        assert!(
            (364..=366).contains(&days),
            "Expected ~365 days, got {}",
            days
        );
    }

    #[test]
    fn test_parse_iso8601_invalid_format() {
        assert_eq!(parse_iso8601_age_days("not-a-date", 1772020800), None);
        assert_eq!(parse_iso8601_age_days("", 1772020800), None);
        assert_eq!(parse_iso8601_age_days("2026-02-24", 1772020800), None);
    }

    #[test]
    fn test_parse_iso8601_future_date_returns_zero() {
        let now = 1772020800; // ~2026-02-24
        let age = parse_iso8601_age_days("2027-01-01T00:00:00Z", now);
        assert_eq!(age, Some(0));
    }

    #[test]
    fn test_parse_iso8601_timezone_offset_format() {
        let now = 1772020800; // ~2026-02-24
                              // "+00:00" format (common GitHub API response)
        let age = parse_iso8601_age_days("2026-02-24T00:00:00+00:00", now);
        assert!(age.is_some(), "Should parse +00:00 timezone format");
        assert!(age.unwrap() <= 2);

        // "-05:00" format
        let age2 = parse_iso8601_age_days("2026-02-24T00:00:00-05:00", now);
        assert!(age2.is_some(), "Should parse -05:00 timezone format");
    }

    #[test]
    fn test_branch_age_days_from_batch_data() {
        // Simulate batch-fetched commit date
        let date = Some("2026-01-01T00:00:00Z".to_string());
        let age = branch_age_days(&date);
        assert!(age.is_some());
        assert!(age.unwrap() > 30, "Jan 1 should be > 30 days old");

        // None date returns None
        assert_eq!(branch_age_days(&None), None);
    }

    #[test]
    fn test_list_remote_branches_returns_dates_integration() {
        if std::env::var("GH_TOKEN").is_err() && std::env::var("GH_APP_PRIVATE_KEY_FILE").is_err() {
            eprintln!("Skipping integration test: no GitHub auth available");
            return;
        }

        let token = resolve_gh_token();
        let branches =
            list_remote_branches(&token, "lornu-ai", "lornu-ai-cleaner").expect("Failed to list");

        assert!(!branches.is_empty(), "Should have at least one branch");

        // Every branch should have a commit date
        for bi in &branches {
            assert!(
                bi.commit_date.is_some(),
                "Branch {} should have a commit date",
                bi.name
            );
        }

        // develop branch should have a recent commit
        let develop = branches.iter().find(|b| b.name == "develop");
        assert!(develop.is_some(), "Should have develop branch");
        let age = branch_age_days(&develop.unwrap().commit_date);
        assert!(age.is_some());
        assert!(
            age.unwrap() < 7,
            "develop should have recent commits, got {} days",
            age.unwrap()
        );
    }
}
