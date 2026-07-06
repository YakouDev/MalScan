use crate::model::{ScanResult, Verdict};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const MALSCAN_DIR: &str = ".malscan";

pub struct Reporter {
    pub format: String,
}

impl Reporter {
    pub fn new(format: &str) -> Self {
        Self {
            format: format.to_string(),
        }
    }

    pub fn render_non_clean(&self, results: &[ScanResult], target: &str) -> anyhow::Result<String> {
        let filtered: Vec<_> = results
            .iter()
            .filter(|r| r.final_verdict() != Verdict::Clean)
            .cloned()
            .collect();
        match self.format.as_str() {
            "json" => Ok(render_json(&filtered, results, target)),
            "sarif" => Ok(render_sarif(&filtered)),
            _ => Ok(render_text(&filtered, results, target)),
        }
    }
}

pub fn output_dir(target: &str) -> PathBuf {
    let p = Path::new(target);
    let base = if p.is_file() {
        p.parent().unwrap_or(p)
    } else {
        p
    };
    base.canonicalize()
        .unwrap_or_else(|_| base.to_path_buf())
        .join(MALSCAN_DIR)
}

pub fn write_by_verdict(results: &[ScanResult], target: &str) -> anyhow::Result<(PathBuf, Vec<PathBuf>)> {
    let dir = output_dir(target);
    fs::create_dir_all(&dir)?;

    let mut buckets: HashMap<Verdict, Vec<&ScanResult>> = HashMap::new();
    for r in results {
        buckets.entry(r.final_verdict()).or_default().push(r);
    }

    let mut written = Vec::new();
    for level in [Verdict::Suspicious, Verdict::Malicious] {
        let bucket: Vec<ScanResult> = buckets
            .get(&level)
            .map(|v| v.iter().map(|r| (*r).clone()).collect())
            .unwrap_or_default();

        let json_path = dir.join(format!("{}.json", level.as_str()));
        fs::write(&json_path, render_json(&bucket, results, target))?;
        written.push(json_path);

        let txt_path = dir.join(format!("{}.txt", level.as_str()));
        fs::write(&txt_path, render_text(&bucket, results, target))?;
        written.push(txt_path);
    }

    let summary = serde_json::json!({
        "scanner": "malscan",
        "target": target,
        "timestamp": chrono_now(),
        "summary": summary_counts(results),
        "output_dir": dir.to_string_lossy(),
        "files": {
            "suspicious": dir.join("suspicious.json").to_string_lossy(),
            "malicious": dir.join("malicious.json").to_string_lossy(),
        }
    });
    let summary_path = dir.join("summary.json");
    fs::write(&summary_path, serde_json::to_string_pretty(&summary)?)?;
    written.push(summary_path);

    Ok((dir, written))
}

fn summary_counts(results: &[ScanResult]) -> HashMap<String, usize> {
    let mut s = HashMap::from([
        ("total".to_string(), results.len()),
        ("clean".to_string(), 0),
        ("suspicious".to_string(), 0),
        ("malicious".to_string(), 0),
    ]);
    for r in results {
        *s.entry(r.final_verdict().as_str().to_string()).or_insert(0) += 1;
    }
    s
}

fn render_json(filtered: &[ScanResult], all: &[ScanResult], target: &str) -> String {
    let items: Vec<_> = filtered
        .iter()
        .map(|r| result_dict(r))
        .collect();
    let payload = serde_json::json!({
        "scanner": "malscan",
        "target": target,
        "timestamp": chrono_now(),
        "summary": summary_counts(all),
        "results": items,
    });
    serde_json::to_string_pretty(&payload).unwrap_or_default()
}

fn render_text(filtered: &[ScanResult], all: &[ScanResult], target: &str) -> String {
    let sum = summary_counts(all);
    let mut out = format!(
        "\nMalScan Report — {target}\nScanned: {} file(s)\nSummary: {} clean, {} suspicious, {} malicious\n\n",
        all.len(),
        sum.get("clean").unwrap_or(&0),
        sum.get("suspicious").unwrap_or(&0),
        sum.get("malicious").unwrap_or(&0),
    );
    for r in filtered {
        out.push_str(&format!(
            "[{}] {}\n  Score: {}/100 | SHA256: {}...\n",
            r.final_verdict().as_str().to_uppercase(),
            r.features.path,
            r.heuristic.score,
            &r.features.sha256[..16.min(r.features.sha256.len())]
        ));
        for reason in r.heuristic.reasons.iter().take(5) {
            out.push_str(&format!("  • {reason}\n"));
        }
        if let Some(ai) = &r.ai_verdict {
            if !ai.error.is_empty() {
                out.push_str(&format!("  AI error: {}\n", ai.error));
            } else {
                out.push_str(&format!(
                    "  AI ({}, conf={:.2}): {}\n",
                    ai.threat_type,
                    ai.confidence,
                    truncate(&ai.reasoning, 200)
                ));
            }
        }
        out.push('\n');
    }
    out
}

fn render_sarif(filtered: &[ScanResult]) -> String {
    let results: Vec<_> = filtered
        .iter()
        .map(|scan| {
            serde_json::json!({
                "ruleId": format!("malscan/{}", scan.final_verdict().as_str()),
                "level": if scan.final_verdict() == Verdict::Malicious { "error" } else { "warning" },
                "message": {"text": scan.heuristic.reasons.join("; ")},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": scan.features.path}}}],
            })
        })
        .collect();

    serde_json::to_string_pretty(&serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "MalScan"}}, "results": results}]
    }))
    .unwrap_or_default()
}

fn result_dict(r: &ScanResult) -> serde_json::Value {
    let mut out = serde_json::json!({
        "path": r.features.path,
        "size": r.features.size,
        "md5": r.features.md5,
        "sha256": r.features.sha256,
        "file_type": r.features.file_type,
        "heuristic_score": r.heuristic.score,
        "heuristic_verdict": r.heuristic.verdict().as_str(),
        "heuristic_reasons": r.heuristic.reasons,
        "final_verdict": r.final_verdict().as_str(),
        "final_confidence": (r.final_confidence() * 10000.0).round() / 10000.0,
        "signature_hits": r.features.signature_hits,
    });
    if let Some(ai) = &r.ai_verdict {
        out["ai_verdict"] = serde_json::json!({
            "verdict": ai.verdict.as_str(),
            "confidence": ai.confidence,
            "threat_type": ai.threat_type,
            "indicators": ai.indicators,
            "reasoning": ai.reasoning,
            "error": ai.error,
        });
    }
    out
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        s[..n].to_string()
    }
}

fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", dur.as_secs())
}
