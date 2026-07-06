use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    #[default]
    Clean,
    Suspicious,
    Malicious,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Clean => "clean",
            Verdict::Suspicious => "suspicious",
            Verdict::Malicious => "malicious",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AIMode {
    Auto,
    Always,
    Off,
}

impl AIMode {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "always" => AIMode::Always,
            "off" => AIMode::Off,
            _ => AIMode::Auto,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct FileFeatures {
    pub path: String,
    pub size: u64,
    pub md5: String,
    pub sha256: String,
    pub file_type: String,
    pub mime_hint: String,
    pub entropy: f64,
    pub strings: Vec<String>,
    pub iocs: HashMap<String, Vec<String>>,
    pub signature_hits: Vec<String>,
    pub disguised_ext: String,
    pub handler_name: String,
    pub allowed_by_htaccess: bool,
    pub errors: Vec<String>,
}

impl FileFeatures {
    pub fn summary_dict(&self, max_strings: usize, max_iocs: usize) -> serde_json::Value {
        let mut iocs = serde_json::Map::new();
        for (k, v) in &self.iocs {
            if v.is_empty() {
                continue;
            }
            let limit = v.len().min(max_iocs);
            iocs.insert(k.clone(), serde_json::json!(v[..limit]));
        }
        let str_limit = self.strings.len().min(max_strings);
        serde_json::json!({
            "path": self.path,
            "size": self.size,
            "md5": self.md5,
            "sha256": self.sha256,
            "file_type": self.file_type,
            "mime_hint": self.mime_hint,
            "entropy": (self.entropy * 10000.0).round() / 10000.0,
            "strings_sample": &self.strings[..str_limit],
            "iocs": iocs,
            "signature_hits": self.signature_hits,
            "errors": self.errors,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct HeuristicResult {
    pub score: i32,
    pub reasons: Vec<String>,
    pub escalate_to_ai: bool,
}

impl HeuristicResult {
    pub fn verdict(&self) -> Verdict {
        if self.score >= 70 {
            Verdict::Malicious
        } else if self.score >= 40 {
            Verdict::Suspicious
        } else {
            Verdict::Clean
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AIVerdict {
    pub verdict: Verdict,
    pub confidence: f64,
    pub threat_type: String,
    pub indicators: Vec<String>,
    pub reasoning: String,
    pub error: String,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub features: FileFeatures,
    pub heuristic: HeuristicResult,
    pub ai_verdict: Option<AIVerdict>,
}

impl ScanResult {
    pub fn final_verdict(&self) -> Verdict {
        if let Some(ai) = &self.ai_verdict {
            if ai.error.is_empty() {
                return ai.verdict;
            }
        }
        self.heuristic.verdict()
    }

    pub fn final_confidence(&self) -> f64 {
        if let Some(ai) = &self.ai_verdict {
            if ai.error.is_empty() {
                return ai.confidence;
            }
        }
        self.heuristic.score as f64 / 100.0
    }

    pub fn clone_with_path(&self, path: String) -> Self {
        let mut clone = self.clone();
        clone.features.path = path;
        clone
    }
}
