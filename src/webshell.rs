use crate::htaccess::{self, Config, DEFAULT_EXTENSIONS};
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Policy {
    pub extensions: HashSet<String>,
    pub disguised_ext: HashMap<String, String>,
    pub allowed_files: HashSet<String>,
    pub htaccess_hits: Vec<String>,
}

impl Policy {
    pub fn new(configs: &[Config]) -> Self {
        let mut p = Policy {
            extensions: HashSet::new(),
            disguised_ext: HashMap::new(),
            allowed_files: HashSet::new(),
            htaccess_hits: Vec::new(),
        };
        for ext in DEFAULT_EXTENSIONS {
            p.extensions.insert(ext.to_string());
        }
        for cfg in configs {
            p.merge(cfg);
        }
        p
    }

    pub fn with_extra_extensions(mut self, exts: &[String]) -> Self {
        for ext in exts {
            let ext = ext.trim().trim_start_matches('.').to_lowercase();
            if !ext.is_empty() {
                self.extensions.insert(ext);
            }
        }
        self
    }

    fn merge(&mut self, cfg: &Config) {
        for ext in &cfg.regex_extensions {
            self.extensions.insert(ext.clone());
        }
        for (ext, handler) in &cfg.handler_extensions {
            self.extensions.insert(ext.clone());
            self.disguised_ext.insert(ext.clone(), handler.clone());
        }
        for name in &cfg.allowed_files {
            self.allowed_files.insert(name.to_lowercase());
        }
        for hit in &cfg.hits {
            if !self.htaccess_hits.iter().any(|h| h == hit) {
                self.htaccess_hits.push(hit.clone());
            }
        }
    }

    pub fn should_scan(&self, path: &Path, content: &[u8]) -> bool {
        let base = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        if htaccess::is_htaccess_file(path) {
            return true;
        }

        if self.allowed_files.contains(&base) {
            return true;
        }

        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let ext = ext.to_lowercase();
            if self.extensions.contains(&ext) || self.disguised_ext.contains_key(&ext) {
                return true;
            }
        }

        looks_like_php(content)
    }
}

pub fn looks_like_php(content: &[u8]) -> bool {
    if content.len() < 5 {
        return false;
    }
    let n = content.len().min(4096);
    let prefix = String::from_utf8_lossy(&content[..n]).to_lowercase();
    prefix.contains("<?php")
        || prefix.contains("<?=")
        || prefix.contains("<? ")
        || prefix.contains("<%")
}
