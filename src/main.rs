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
        let app_id = std::env::var("GH_APP_ID").unwrap_or_else(|_| "2665041".to_string());
        let installation_id = std::env::var("GH_APP_INSTALLATION_ID")
            .unwrap_or_else(|_| "104427264".to_string());

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
        Err(_) => None,
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
#[command(name = "ai-agent-cleaner", version, about = "AI agent for repository hygiene: sensitive file scanning and branch pruning")]
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
    errors: Vec<String>,
}

/// List remote branches for a repo using `gh api`
fn list_remote_branches(token: &Option<String>, owner: &str, repo: &str) -> Result<Vec<String>> {
    let mut branches = Vec::new();
    let mut page = 1;

    loop {
        let endpoint = format!(
            "repos/{}/{}/branches?per_page=100&page={}",
            owner, repo, page
        );
        let output = gh_command(token)
            .args(["api", &endpoint, "--jq", ".[].name"])
            .output()
            .context("Failed to run gh api")?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("gh api failed for {}/{}: {}", owner, repo, err);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let page_branches: Vec<String> = stdout
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
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
            "pr", "list",
            "--repo", &format!("{}/{}", owner, repo),
            "--state", "open",
            "--json", "headRefName",
            "--jq", ".[].headRefName",
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
fn delete_remote_branch(token: &Option<String>, owner: &str, repo: &str, branch: &str) -> Result<()> {
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

/// List repos in an org
fn list_org_repos(token: &Option<String>, org: &str) -> Result<Vec<String>> {
    let output = gh_command(token)
        .args([
            "repo", "list", org,
            "--no-archived",
            "--json", "name",
            "--jq", ".[].name",
            "--limit", "200",
        ])
        .output()
        .context("Failed to list org repos")?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("gh repo list failed: {}", err);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect())
}

fn prune_repo(
    token: &Option<String>,
    owner: &str,
    repo: &str,
    protected: &[String],
    dry_run: bool,
) -> Result<PruneResult> {
    let full_name = format!("{}/{}", owner, repo);
    eprintln!("Scanning {}...", full_name);

    let branches = list_remote_branches(token, owner, repo)?;
    let open_pr_branches = list_open_pr_branches(token, owner, repo)?;

    let protected_set: std::collections::HashSet<&str> =
        protected.iter().map(|s| s.as_str()).collect();
    let pr_set: std::collections::HashSet<&str> =
        open_pr_branches.iter().map(|s| s.as_str()).collect();

    let mut result = PruneResult {
        repo: full_name,
        branches_scanned: branches.len(),
        branches_deleted: Vec::new(),
        branches_protected: Vec::new(),
        branches_with_open_prs: Vec::new(),
        errors: Vec::new(),
    };

    for branch in &branches {
        if protected_set.contains(branch.as_str()) {
            result.branches_protected.push(branch.clone());
            continue;
        }
        if pr_set.contains(branch.as_str()) {
            result.branches_with_open_prs.push(branch.clone());
            continue;
        }

        // This branch is stale — delete it
        if dry_run {
            result.branches_deleted.push(branch.clone());
            eprintln!("  [dry-run] would delete: {}", branch);
        } else {
            match delete_remote_branch(token, owner, repo, branch) {
                Ok(()) => {
                    result.branches_deleted.push(branch.clone());
                    eprintln!("  deleted: {}", branch);
                }
                Err(e) => {
                    result.errors.push(format!("{}: {}", branch, e));
                    eprintln!("  error deleting {}: {}", branch, e);
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
) -> Result<()> {
    let token = resolve_gh_token();

    let repos = if let Some(r) = repo {
        vec![r]
    } else {
        list_org_repos(&token, &org)?
    };

    if dry_run {
        eprintln!("DRY RUN: No branches will be deleted.\n");
    }

    let mut all_results = Vec::new();

    for repo_name in &repos {
        match prune_repo(&token, &org, repo_name, &protected, dry_run) {
            Ok(result) => {
                if !json_output {
                    let action = if dry_run { "would delete" } else { "deleted" };
                    println!(
                        "{}: scanned {} branches, {} {}, {} protected, {} with open PRs",
                        result.repo,
                        result.branches_scanned,
                        result.branches_deleted.len(),
                        action,
                        result.branches_protected.len(),
                        result.branches_with_open_prs.len(),
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
        } => cmd_prune(org, repo, protected, dry_run, json),
    }
}
