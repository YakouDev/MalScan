use crate::model::FileFeatures;
use md5::{Digest as Md5Digest, Md5};
use regex::Regex;
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

const MAX_STRINGS: usize = 500;
const DEFAULT_MAX_BYTES: u64 = 50 * 1024 * 1024;

pub struct Extractor {
    pub max_bytes: u64,
}

impl Extractor {
    pub fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes: if max_bytes == 0 {
                DEFAULT_MAX_BYTES
            } else {
                max_bytes
            },
        }
    }

    pub fn extract(&self, path: &Path) -> FileFeatures {
        let abs = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let abs_str = abs.to_string_lossy().to_string();

        let meta = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                return FileFeatures {
                    path: abs_str,
                    errors: vec![format!("stat failed: {e}")],
                    ..Default::default()
                };
            }
        };

        let mut data = match fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                return FileFeatures {
                    path: abs_str,
                    size: meta.len(),
                    errors: vec![format!("read failed: {e}")],
                    ..Default::default()
                };
            }
        };

        if data.len() as u64 > self.max_bytes {
            data.truncate(self.max_bytes as usize);
        }

        let md5_hash = format!("{:x}", Md5::digest(&data));
        let sha256_hash = format!("{:x}", Sha256::digest(&data));
        let (file_type, mime_hint) = detect_file_type(&data, path);
        let entropy = shannon_entropy(&data);
        let strings = extract_printable_strings(&data);
        let combined = if data.len() < 1024 * 1024 {
            format!("{}\n{}", strings.join("\n"), String::from_utf8_lossy(&data))
        } else {
            strings.join("\n")
        };
        let iocs = extract_iocs(&combined);

        FileFeatures {
            path: abs_str,
            size: meta.len(),
            md5: md5_hash,
            sha256: sha256_hash,
            file_type,
            mime_hint,
            entropy: (entropy * 10000.0).round() / 10000.0,
            strings,
            iocs,
            ..Default::default()
        }
    }
}

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn detect_file_type(data: &[u8], path: &Path) -> (String, String) {
    if data.len() >= 2 && data[0] == b'M' && data[1] == b'Z' {
        return ("pe".into(), "application/x-dos-executable".into());
    }
    if data.len() >= 4 && &data[..4] == b"\x7fELF" {
        return ("elf".into(), "application/x-elf".into());
    }
    let prefix_len = data.len().min(512);
    let prefix = String::from_utf8_lossy(&data[..prefix_len]).to_lowercase();
    if prefix.starts_with("<?php") || prefix.starts_with("<?=") {
        return ("php".into(), "application/x-php".into());
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    if ext == "php" || ext == "phtml" {
        return ("php".into(), "application/x-php".into());
    }
    if data.len() >= 2 && data[0] == b'#' && data[1] == b'!' {
        return ("script".into(), "text/x-shellscript".into());
    }
    ("text".into(), "text/plain".into())
}

fn extract_printable_strings(data: &[u8]) -> Vec<String> {
    let re = Regex::new(r"[\x20-\x7e]{6,}").unwrap();
    let text = String::from_utf8_lossy(data);
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for m in re.find_iter(&text) {
        let s = m.as_str().to_string();
        if seen.insert(s.clone()) {
            out.push(s);
            if out.len() >= MAX_STRINGS {
                break;
            }
        }
    }
    out
}

fn extract_iocs(text: &str) -> HashMap<String, Vec<String>> {
    let url_re = Regex::new(r#"(?i)https?://[^\s<>"'{}|\\^`\[\]]+"#).unwrap();
    let ip_re = Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b",
    )
    .unwrap();

    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    let mut add = |key: &str, vals: Vec<String>| {
        if !vals.is_empty() {
            out.insert(key.to_string(), vals);
        }
    };

    add("urls", url_re.find_iter(text).map(|m| m.as_str().to_string()).collect());
    add(
        "ips",
        ip_re
            .find_iter(text)
            .map(|m| m.as_str().to_string())
            .filter(|ip| ip != "127.0.0.1" && !ip.starts_with("0."))
            .collect(),
    );
    out
}
