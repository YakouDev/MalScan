use crate::htaccess;
use crate::model::FileFeatures;
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

struct PhpPattern {
    name: &'static str,
    re: Regex,
}

fn patterns() -> Vec<PhpPattern> {
    vec![
        PhpPattern { name: "eval_sink", re: Regex::new(r"(?i)\beval\s*\(").unwrap() },
        PhpPattern { name: "assert_sink", re: Regex::new(r"(?i)\bassert\s*\(").unwrap() },
        PhpPattern { name: "system_sink", re: Regex::new(r"(?i)\bsystem\s*\(").unwrap() },
        PhpPattern { name: "exec_sink", re: Regex::new(r"(?i)\bexec\s*\(").unwrap() },
        PhpPattern { name: "shell_exec_sink", re: Regex::new(r"(?i)\bshell_exec\s*\(").unwrap() },
        PhpPattern { name: "passthru_sink", re: Regex::new(r"(?i)\bpassthru\s*\(").unwrap() },
        PhpPattern { name: "base64_decode", re: Regex::new(r"(?i)\bbase64_decode\s*\(").unwrap() },
        PhpPattern { name: "gzinflate", re: Regex::new(r"(?i)\bgzinflate\s*\(").unwrap() },
        PhpPattern { name: "obfuscated_eval", re: Regex::new(r"(?i)\beval\s*\(\s*(?:gzinflate|gzuncompress|str_rot13|base64_decode|convert_uudecode)\s*\(").unwrap() },
        PhpPattern { name: "known_china_chopper", re: Regex::new(r"(?i)@eval\s*\(\s*\$_(?:POST|REQUEST)").unwrap() },
        PhpPattern { name: "create_function_sink", re: Regex::new(r"(?i)\bcreate_function\s*\(").unwrap() },
        PhpPattern { name: "preg_replace_e_modifier", re: Regex::new(r#"(?i)preg_replace\s*\(\s*['"][^'"]*\/[a-z]*e[a-z]*['"]"#).unwrap() },
        PhpPattern { name: "call_user_func_sink", re: Regex::new(r"(?i)\bcall_user_func(_array)?\s*\(").unwrap() },
        PhpPattern { name: "extract_superglobal", re: Regex::new(r"(?i)\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)").unwrap() },
        PhpPattern { name: "phpinfo_disclosure", re: Regex::new(r"(?i)\bphpinfo\s*\(").unwrap() },
    ]
}

static INPUT_TO_SINK: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?is)\$_(?:GET|POST|REQUEST|COOKIE).{0,200}?\beval\s*\(").unwrap(),
        Regex::new(r"(?is)\$_(?:GET|POST|REQUEST|COOKIE).{0,200}?\b(system|exec|shell_exec|passthru|popen|proc_open|assert)\s*\(").unwrap(),
        Regex::new(r"(?is)@eval\s*\(\s*\$_(?:POST|REQUEST|GET)").unwrap(),
    ]
});

static OBF_EVAL_CHAINS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?is)eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|convert_uudecode|hex2bin|strrev)\s*\(").unwrap(),
        Regex::new(r"(?is)(?:base64_decode|gzinflate|gzuncompress|str_rot13|convert_uudecode|hex2bin)\s*\([^;]{0,200}eval\s*\(").unwrap(),
        Regex::new(r"(?is)assert\s*\(\s*\$\w+\s*\(").unwrap(),
    ]
});

static INPUT_SOURCES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*(?:\[[^\]]+\])?").unwrap());

pub fn scan_webshell(features: &FileFeatures, raw: &[u8]) -> Vec<String> {
    let combined = if features.strings.is_empty() && !raw.is_empty() {
        String::from_utf8_lossy(raw).to_string()
    } else {
        features.strings.join("\n")
    };

    if htaccess::is_htaccess_file(std::path::Path::new(&features.path)) {
        return htaccess::parse(&combined).hits;
    }

    if features.file_type == "php"
        || features.file_type == "webshell"
        || is_php_content(raw)
        || has_webshell_indicators(&combined)
    {
        return scan_php(raw, &combined);
    }

    vec![]
}

fn has_webshell_indicators(text: &str) -> bool {
    let lower = text.to_lowercase();
    [
        "eval(",
        "shell_exec(",
        "system(",
        "base64_decode(",
        "$_post",
        "$_get",
        "$_request",
        "create_function(",
        "extract($_",
        "call_user_func(",
    ]
    .iter()
    .any(|ind| lower.contains(ind))
}

fn is_php_content(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }
    let n = data.len().min(512);
    let prefix = String::from_utf8_lossy(&data[..n]).to_lowercase();
    prefix.starts_with("<?php") || prefix.starts_with("<?=") || prefix.contains("<?php")
}

pub fn scan_php(raw: &[u8], combined: &str) -> Vec<String> {
    let content = if combined.is_empty() {
        String::from_utf8_lossy(raw).to_string()
    } else {
        combined.to_string()
    };

    let mut hits = Vec::new();
    let mut seen = HashSet::new();
    let mut add = |name: &str| {
        let key = format!("php:{name}");
        if seen.insert(key.clone()) {
            hits.push(key);
        }
    };

    for p in patterns() {
        if p.re.is_match(&content) {
            add(p.name);
        }
    }

    if INPUT_SOURCES.is_match(&content) {
        add("superglobal_input");
    }

    for re in INPUT_TO_SINK.iter() {
        if re.is_match(&content) {
            add("eval_input");
            break;
        }
    }

    for (i, re) in OBF_EVAL_CHAINS.iter().enumerate() {
        if re.is_match(&content) {
            add(&format!("obf_eval_chain_{i}"));
        }
    }

    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obf_eval_chain_detected() {
        let content = r#"<?php eval(base64_decode("ZXZhbCgkX1BPU1RbJ3gnXSk7")); ?>"#;
        let hits = scan_php(content.as_bytes(), content);
        assert!(hits.iter().any(|h| h == "php:obf_eval_chain_0"));
    }
}
