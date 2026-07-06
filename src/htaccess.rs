use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub const DEFAULT_EXTENSIONS: &[&str] = &[
    "shtml", "php", "phar", "phtml", "pht", "php3", "php4", "php5", "php7", "phtm", "inc",
];

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub handler_extensions: HashMap<String, String>,
    pub regex_extensions: Vec<String>,
    pub allowed_files: Vec<String>,
    pub hits: Vec<String>,
}

pub fn is_htaccess_file(path: &Path) -> bool {
    let base = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    base == ".htaccess" || base.ends_with(".htaccess")
}

pub fn parse(content: &str) -> Config {
    let add_handler = Regex::new(r"(?i)AddHandler\s+(\S+)\s+\.([A-Za-z0-9]+)").unwrap();
    let files_match = Regex::new(r#"(?i)<FilesMatch\s+"([^"]+)""#).unwrap();
    let files_direct = Regex::new(r"(?i)<Files\s+([^>\s]+)").unwrap();
    let php_handler = Regex::new(r"(?i)(?:php|lsphp|server-parsed)").unwrap();
    let group_re = Regex::new(r"\(([a-z0-9|]+)\)").unwrap();

    let mut cfg = Config::default();
    let mut ext_seen: HashSet<String> = HashSet::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(caps) = add_handler.captures(line) {
            let handler = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let ext = caps.get(2).map(|m| m.as_str().to_lowercase()).unwrap_or_default();
            if php_handler.is_match(handler) {
                cfg.handler_extensions.insert(ext.clone(), handler.to_string());
                append_unique(&mut cfg.hits, format!("htaccess:php_handler_disguise(.{ext})"));
            }
            if handler.to_lowercase().contains("server-parsed") {
                cfg.handler_extensions.insert(ext.clone(), handler.to_string());
                append_unique(&mut cfg.hits, format!("htaccess:ssi_handler_disguise(.{ext})"));
            }
        }

        if let Some(caps) = files_match.captures(line) {
            let pattern = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            for ext in extract_extensions_from_pattern(pattern, &group_re) {
                if ext_seen.insert(ext.clone()) {
                    cfg.regex_extensions.push(ext);
                }
            }
        }

        if let Some(caps) = files_direct.captures(line) {
            let name = caps
                .get(1)
                .map(|m| m.as_str().trim_matches('"').trim_matches('\''))
                .unwrap_or("")
                .to_string();
            cfg.allowed_files.push(name.clone());
            let lower = name.to_lowercase();
            if lower.contains(".php") || lower.ends_with(".phtml") {
                append_unique(&mut cfg.hits, format!("htaccess:allowed_php_file({name})"));
            }
        }
    }

    cfg
}

fn extract_extensions_from_pattern(pattern: &str, group_re: &Regex) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for caps in group_re.captures_iter(&pattern.to_lowercase()) {
        if let Some(group) = caps.get(1) {
            for part in group.as_str().split('|') {
                let part = part.trim();
                if !part.is_empty() && part.len() <= 10 && seen.insert(part.to_string()) {
                    out.push(part.to_string());
                }
            }
        }
    }
    out
}

fn append_unique(slice: &mut Vec<String>, val: String) {
    if !slice.iter().any(|s| s == &val) {
        slice.push(val);
    }
}
