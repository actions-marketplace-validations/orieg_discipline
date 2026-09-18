//! Git access. Every function here is three-state: a value, an empty value, or
//! an `Err` meaning "could not determine". Callers never turn the third state
//! into an empty diff — an unresolvable base ref in a shallow CI clone once
//! read as "no changes, PASS".

use anyhow::{anyhow, bail, Context, Result};
use git2::{Delta, DiffFindOptions, DiffOptions, Oid, Repository, Tree};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
    Renamed,
}

#[derive(Debug, Clone)]
pub struct ChangedFile {
    pub path: String,
    /// Path on the base side (differs from `path` for renames).
    pub old_path: String,
    pub kind: ChangeKind,
    /// 1-based line numbers added on the head side.
    pub added_lines: BTreeSet<usize>,
}

pub struct GitCtx {
    repo: Repository,
    /// Tree the change is measured against; `None` = empty tree (first commit).
    base: Option<Oid>,
    base_label: String,
    staged: bool,
}

impl GitCtx {
    /// `staged = true` inspects the index against `HEAD` (pre-commit hook).
    /// Otherwise the working tree is measured against the merge base of
    /// `base_ref` and `HEAD`.
    pub fn open(base_ref: &str, staged: bool) -> Result<Self> {
        let repo = Repository::discover(".").context(
            "not inside a git repository: discipline measures a change, so it needs git history",
        )?;
        if repo.is_bare() {
            bail!("bare repositories are not supported");
        }

        let head: Option<Oid> = repo
            .head()
            .ok()
            .and_then(|h| h.peel_to_commit().ok())
            .map(|c| c.id());
        let (base, base_label) = if staged {
            match head {
                Some(id) => (Some(id), "HEAD (staged changes)".to_string()),
                None => (None, "empty tree (first commit)".to_string()),
            }
        } else {
            let head = head.ok_or_else(|| {
                anyhow!("repository has no commits; use --staged for the first commit")
            })?;
            let base_commit = [base_ref.to_string(), format!("origin/{base_ref}")]
                .iter()
                .find_map(|name| Some(repo.revparse_single(name).ok()?.peel_to_commit().ok()?.id()))
                .ok_or_else(|| {
                    anyhow!(
                        "base ref `{base_ref}` does not resolve. In CI, check out with \
                         `fetch-depth: 0` or fetch the base branch first. Refusing to \
                         treat an unknown base as an empty diff."
                    )
                })?;
            let merge_base = repo.merge_base(base_commit, head).map_err(|e| {
                anyhow!(
                    "no merge base between `{base_ref}` and HEAD ({e}); the clone is \
                     probably shallow — fetch full history"
                )
            })?;
            (
                Some(merge_base),
                format!("{base_ref} (merge base {:.10})", merge_base.to_string()),
            )
        };

        Ok(Self {
            repo,
            base,
            base_label,
            staged,
        })
    }

    pub fn base_label(&self) -> &str {
        &self.base_label
    }

    fn base_tree(&self) -> Result<Option<Tree<'_>>> {
        match self.base {
            Some(oid) => Ok(Some(self.repo.find_commit(oid)?.tree()?)),
            None => Ok(None),
        }
    }

    pub fn changed_files(&self) -> Result<Vec<ChangedFile>> {
        let tree = self.base_tree()?;
        let mut opts = DiffOptions::new();
        opts.context_lines(0);
        let mut diff = if self.staged {
            self.repo
                .diff_tree_to_index(tree.as_ref(), None, Some(&mut opts))?
        } else {
            self.repo
                .diff_tree_to_workdir_with_index(tree.as_ref(), Some(&mut opts))?
        };
        // Without rename detection a moved test file reads as a deletion.
        diff.find_similar(Some(DiffFindOptions::new().renames(true)))?;

        let mut files: BTreeMap<String, ChangedFile> = BTreeMap::new();
        for delta in diff.deltas() {
            let kind = match delta.status() {
                Delta::Added | Delta::Untracked | Delta::Copied => ChangeKind::Added,
                Delta::Modified | Delta::Typechange => ChangeKind::Modified,
                Delta::Deleted => ChangeKind::Deleted,
                Delta::Renamed => ChangeKind::Renamed,
                _ => continue,
            };
            let path_of =
                |f: git2::DiffFile| f.path().map(|p| p.to_string_lossy().replace('\\', "/"));
            let new_path = path_of(delta.new_file());
            let old_path = path_of(delta.old_file());
            let path = match kind {
                ChangeKind::Deleted => old_path.clone(),
                _ => new_path.clone(),
            }
            .ok_or_else(|| anyhow!("diff delta without a path"))?;
            files.insert(
                path.clone(),
                ChangedFile {
                    old_path: old_path.unwrap_or_else(|| path.clone()),
                    path,
                    kind,
                    added_lines: BTreeSet::new(),
                },
            );
        }

        diff.foreach(
            &mut |_, _| true,
            None,
            None,
            Some(&mut |delta, _hunk, line| {
                if line.origin() == '+' {
                    if let (Some(p), Some(n)) = (delta.new_file().path(), line.new_lineno()) {
                        let key = p.to_string_lossy().replace('\\', "/");
                        if let Some(f) = files.get_mut(&key) {
                            f.added_lines.insert(n as usize);
                        }
                    }
                }
                true
            }),
        )?;

        Ok(files.into_values().collect())
    }

    /// Content of `path` on the base side; `None` when it did not exist there.
    pub fn base_content(&self, path: &str) -> Result<Option<String>> {
        let Some(tree) = self.base_tree()? else {
            return Ok(None);
        };
        match tree.get_path(std::path::Path::new(path)) {
            Ok(entry) => {
                let blob = self.repo.find_blob(entry.id())?;
                Ok(Some(String::from_utf8_lossy(blob.content()).into_owned()))
            }
            Err(e) if e.code() == git2::ErrorCode::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Content of `path` on the head side (index when staged, else worktree).
    /// `None` for binary content.
    pub fn head_content(&self, path: &str) -> Result<Option<String>> {
        let bytes = if self.staged {
            let index = self.repo.index()?;
            let entry = index
                .get_path(std::path::Path::new(path), 0)
                .ok_or_else(|| anyhow!("`{path}` is not in the index"))?;
            self.repo.find_blob(entry.id)?.content().to_vec()
        } else {
            let root = self
                .repo
                .workdir()
                .ok_or_else(|| anyhow!("repository has no working tree"))?;
            std::fs::read(root.join(path)).with_context(|| format!("failed to read `{path}`"))?
        };
        if bytes.contains(&0) {
            return Ok(None);
        }
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    }

    /// Tracked regular files. Symlinks are skipped so `CLAUDE.md -> AGENTS.md`
    /// is not scanned (and reported) twice.
    pub fn tracked_files(&self) -> Result<Vec<String>> {
        const MODE_SYMLINK: u32 = 0o120000;
        const MODE_GITLINK: u32 = 0o160000;
        let index = self.repo.index()?;
        let root = self.repo.workdir().map(|p| p.to_path_buf());
        let mut out = Vec::new();
        for entry in index.iter() {
            if entry.mode == MODE_SYMLINK || entry.mode == MODE_GITLINK {
                continue;
            }
            let path = String::from_utf8_lossy(&entry.path).replace('\\', "/");
            // Deleted in the worktree but not yet staged: nothing to scan.
            if !self.staged {
                if let Some(root) = &root {
                    if !root.join(&path).is_file() {
                        continue;
                    }
                }
            }
            out.push(path);
        }
        Ok(out)
    }

    /// Every tracked path including symlinks, for existence checks.
    pub fn is_tracked(&self, path: &str) -> Result<bool> {
        Ok(self
            .repo
            .index()?
            .get_path(std::path::Path::new(path), 0)
            .is_some())
    }

    pub fn is_symlink(&self, path: &str) -> Result<bool> {
        Ok(self
            .repo
            .index()?
            .get_path(std::path::Path::new(path), 0)
            .map(|e| e.mode == 0o120000)
            .unwrap_or(false))
    }

    /// Messages of the commits between the base and `HEAD` (empty when staged).
    pub fn commit_messages(&self) -> Result<Vec<String>> {
        let (Some(base), false) = (self.base, self.staged) else {
            return Ok(Vec::new());
        };
        let mut walk = self.repo.revwalk()?;
        walk.push_head()?;
        walk.hide(base)?;
        let mut out = Vec::new();
        for oid in walk {
            let commit = self.repo.find_commit(oid?)?;
            out.push(String::from_utf8_lossy(commit.message_bytes()).into_owned());
        }
        Ok(out)
    }
}
