use crate::extractor::Extractor;
use crate::fireworks::FireworksClient;
use crate::heuristics::Scorer;
use crate::htaccess;
use crate::model::{AIMode, ScanResult};
use crate::signature;
use crate::webshell::{self, Policy};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub type ProgressFn = Box<dyn Fn(usize, usize) + Send + Sync>;

pub struct Scanner {
    pub ai_mode: AIMode,
    pub threshold: i32,
    pub max_bytes: u64,
    pub workers: usize,
    pub exclude_patterns: Vec<String>,
    pub extra_extensions: Vec<String>,
    pub extractor: Extractor,
    pub scorer: Scorer,
    pub ai_client: FireworksClient,
    pub policy: Policy,
}

impl Scanner {
    pub fn new(
        ai_mode: AIMode,
        threshold: i32,
        max_bytes: u64,
        workers: usize,
        excludes: Vec<String>,
        extra_exts: Vec<String>,
        api_key: String,
    ) -> Self {
        let workers = if workers == 0 { 4 } else { workers };
        Self {
            ai_mode,
            threshold,
            max_bytes,
            workers,
            exclude_patterns: excludes,
            extra_extensions: extra_exts.clone(),
            extractor: Extractor::new(max_bytes),
            scorer: Scorer::new(threshold, ai_mode),
            ai_client: FireworksClient::new(api_key),
            policy: Policy::new(&[]).with_extra_extensions(&extra_exts),
        }
    }

    fn is_excluded(&self, path: &Path) -> bool {
        let base = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let path_str = path.to_string_lossy();
        self.exclude_patterns
            .iter()
            .any(|pat| glob_match(pat, base) || glob_match(pat, &path_str))
    }

    fn walk_files(&self, target: &Path, recursive: bool) -> anyhow::Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        if target.is_file() {
            if !self.is_excluded(target) {
                files.push(target.canonicalize().unwrap_or_else(|_| target.to_path_buf()));
            }
            return Ok(files);
        }

        if recursive {
            for entry in walkdir::WalkDir::new(target)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_dir() {
                    continue;
                }
                let path = entry.path();
                if self.is_excluded(path) {
                    continue;
                }
                if path.to_string_lossy().contains("/.malscan/") {
                    continue;
                }
                files.push(path.canonicalize().unwrap_or_else(|_| path.to_path_buf()));
            }
        } else if let Ok(entries) = fs::read_dir(target) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && !self.is_excluded(&path) {
                    files.push(path.canonicalize().unwrap_or_else(|_| path));
                }
            }
        }
        Ok(files)
    }

    fn build_policy(&self, all_files: &[PathBuf]) -> Policy {
        let mut configs = Vec::new();
        for path in all_files {
            if htaccess::is_htaccess_file(path) {
                if let Ok(data) = fs::read_to_string(path) {
                    configs.push(htaccess::parse(&data));
                }
            }
        }
        Policy::new(&configs).with_extra_extensions(&self.extra_extensions)
    }

    fn filter_targets(&self, all_files: &[PathBuf], policy: &Policy) -> Vec<PathBuf> {
        all_files
            .iter()
            .filter(|path| {
                if htaccess::is_htaccess_file(path) {
                    return true;
                }
                match fs::read(path) {
                    Ok(mut data) => {
                        if data.len() as u64 > self.max_bytes {
                            data.truncate(self.max_bytes as usize);
                        }
                        policy.should_scan(path, &data)
                    }
                    Err(_) => htaccess::is_htaccess_file(path),
                }
            })
            .cloned()
            .collect()
    }

    fn file_sha256(&self, path: &Path) -> String {
        match fs::read(path) {
            Ok(mut data) => {
                if data.len() as u64 > self.max_bytes {
                    data.truncate(self.max_bytes as usize);
                }
                format!("{:x}", Sha256::digest(&data))
            }
            Err(_) => format!("err:{}", path.display()),
        }
    }

    fn scan_file(&self, path: &Path, policy: &Policy) -> ScanResult {
        let raw = match fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                return ScanResult {
                    features: crate::model::FileFeatures {
                        path: path.to_string_lossy().to_string(),
                        errors: vec![format!("read failed: {e}")],
                        ..Default::default()
                    },
                    heuristic: Default::default(),
                    ai_verdict: None,
                };
            }
        };

        let mut data = raw.clone();
        if data.len() as u64 > self.max_bytes {
            data.truncate(self.max_bytes as usize);
        }

        let mut features = self.extractor.extract(path);
        self.apply_webshell_context(&mut features, path, &data, policy);
        features.signature_hits = signature::scan_webshell(&features, &data);
        let heuristic = self.scorer.score(&features);

        let ai_verdict = if heuristic.escalate_to_ai && self.ai_mode != AIMode::Off {
            Some(self.ai_client.analyze(&features))
        } else {
            None
        };

        ScanResult {
            features,
            heuristic,
            ai_verdict,
        }
    }

    fn apply_webshell_context(
        &self,
        features: &mut crate::model::FileFeatures,
        path: &Path,
        raw: &[u8],
        policy: &Policy,
    ) {
        if htaccess::is_htaccess_file(path) {
            features.file_type = "htaccess".into();
            features.mime_hint = "application/apache-htaccess".into();
            return;
        }

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        let base = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        if let Some(handler) = policy.disguised_ext.get(&ext) {
            features.file_type = "webshell".into();
            features.mime_hint = format!("disguised/{ext} (handler: {handler})");
            features.disguised_ext = ext;
            features.handler_name = handler.clone();
            return;
        }

        if policy.allowed_files.contains(&base) {
            features.allowed_by_htaccess = true;
        }

        if features.file_type == "php" || webshell::looks_like_php(raw) {
            features.file_type = "webshell".into();
        }
    }

    pub fn scan(
        &mut self,
        target: &Path,
        recursive: bool,
        progress: Option<ProgressFn>,
    ) -> anyhow::Result<Vec<ScanResult>> {
        let all_files = self.walk_files(target, recursive)?;
        if all_files.is_empty() {
            return Ok(vec![]);
        }

        self.policy = self.build_policy(&all_files);
        let targets = self.filter_targets(&all_files, &self.policy);
        if targets.is_empty() {
            return Ok(vec![]);
        }

        let mut path_hash: HashMap<String, String> = HashMap::new();
        let mut sha_to_paths: HashMap<String, Vec<PathBuf>> = HashMap::new();
        let mut sha_order: Vec<String> = Vec::new();

        for path in &targets {
            let hash = self.file_sha256(path);
            path_hash.insert(path.to_string_lossy().to_string(), hash.clone());
            if !sha_to_paths.contains_key(&hash) {
                sha_order.push(hash.clone());
            }
            sha_to_paths.entry(hash).or_default().push(path.clone());
        }

        let representatives: Vec<PathBuf> = sha_order
            .iter()
            .map(|h| sha_to_paths[h][0].clone())
            .collect();

        let total = representatives.len();
        let mut hash_results: Vec<ScanResult> = Vec::with_capacity(total);
        for (idx, path) in representatives.iter().enumerate() {
            let result = self.scan_file(path, &self.policy);
            if let Some(ref cb) = progress {
                cb(idx + 1, total);
            }
            hash_results.push(result);
        }

        let mut result_by_hash: HashMap<String, ScanResult> = HashMap::new();
        for (i, hash) in sha_order.iter().enumerate() {
            result_by_hash.insert(hash.clone(), hash_results[i].clone());
        }

        let total_targets = targets.len();
        let mut results = Vec::with_capacity(total_targets);

        for path in &targets {
            let hash = &path_hash[path.to_string_lossy().as_ref()];
            let rep = result_by_hash.get(hash).unwrap().clone();
            let path_str = path.to_string_lossy().to_string();
            let result = if rep.features.path == path_str {
                rep
            } else {
                rep.clone_with_path(path_str)
            };
            results.push(result);
        }

        Ok(results)
    }
}

pub fn sort_results(results: &mut [ScanResult]) {
    results.sort_by(|a, b| a.features.path.cmp(&b.features.path));
}

fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.is_empty() {
            return true;
        }
        let mut pos = 0;
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }
            if i == 0 && !text.starts_with(part) {
                return false;
            }
            if let Some(idx) = text[pos..].find(part) {
                pos += idx + part.len();
            } else {
                return false;
            }
        }
        true
    } else {
        pattern == text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AIMode;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn dedup_identical_sha256() {
        let dir = tempfile_dir();
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("tests")
            .join("samples")
            .join("webshell.php");
        let data = fs::read(&src).expect("read sample");
        let a = dir.join("a.php");
        let b = dir.join("b.php");
        fs::write(&a, &data).unwrap();
        fs::write(&b, &data).unwrap();

        let mut s = Scanner::new(AIMode::Off, 40, 0, 1, vec![], vec![], String::new());
        let results = s.scan(&dir, false, None).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].features.sha256, results[1].features.sha256);
        assert_eq!(results[0].heuristic.score, results[1].heuristic.score);
    }

    fn tempfile_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("malscan-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
