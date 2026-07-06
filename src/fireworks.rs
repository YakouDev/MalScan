use crate::model::{AIVerdict, FileFeatures, Verdict};
use anyhow::{anyhow, Context, Result};
use reqwest::blocking::Client;
use std::thread;
use std::time::Duration;

const BASE_URL: &str = "https://token-plan-sgp.xiaomimimo.com/v1";
const MODEL: &str = "mimo-v2.5";
const MAX_RETRIES: u32 = 5;

const SYSTEM_PROMPT: &str = r#"You are an expert web application security analyst specializing in PHP webshell detection.
Analyze the provided static feature summary from a webshell scanner.
Base your assessment ONLY on the provided static indicators — do not speculate beyond the evidence.

Respond with a single JSON object (no markdown, no code fences) matching this exact schema:
{
  "verdict": "clean" | "suspicious" | "malicious",
  "confidence": <float 0.0-1.0>,
  "threat_type": "<short category e.g. webshell, backdoor, htaccess_bypass, obfuscated_php, benign, unknown>",
  "indicators": ["<list of key malicious or suspicious indicators found>"],
  "reasoning": "<concise technical explanation, max 500 chars>"
}

Guidelines:
- "malicious": clear webshell/backdoor (eval+superglobal, shell_exec, China Chopper, obfuscated eval chains)
- "suspicious": anomalous PHP in disguised extensions, htaccess PHP handler bypass, inconclusive obfuscation
- "clean": no significant webshell indicators, likely benign web file
- htaccess AddHandler mapping PHP to .js/.html/etc is a strong suspicious/malicious signal
- Pay special attention to: obf_eval_chain, preg_replace /e modifier, extract($_POST/GET), create_function callbacks
"#;

pub struct FireworksClient {
    api_key: String,
    http: Client,
}

impl FireworksClient {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            http: Client::builder()
                .timeout(Duration::from_secs(120))
                .build()
                .unwrap_or_default(),
        }
    }

    pub fn configured(&self) -> bool {
        !self.api_key.is_empty()
    }

    pub fn analyze(&self, features: &FileFeatures) -> AIVerdict {
        if !self.configured() {
            return error_verdict("FIREWORKS_API_KEY not configured");
        }

        let summary = features.summary_dict(40, 15);
        let user_prompt = format!(
            "Analyze the following static feature summary and return your JSON verdict:\n\n{}",
            serde_json::to_string_pretty(&summary).unwrap_or_default()
        );

        let body = serde_json::json!({
            "model": MODEL,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": 4096,
            "temperature": 0.1,
            "top_k": 40,
            "presence_penalty": 0,
            "frequency_penalty": 0,
            "reasoning_effort": "low",
            "response_format": {"type": "json_object"},
            "thinking": {"type": "disabled"},
        });

        let url = format!("{BASE_URL}/chat/completions");
        let mut last_err = "unknown error".to_string();

        for attempt in 0..MAX_RETRIES {
            match self.http.post(&url)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", self.api_key))
                .json(&body)
                .send()
            {
                Ok(resp) => {
                    let status = resp.status();
                    let text = resp.text().unwrap_or_default();
                    if status.as_u16() == 429 || (500..600).contains(&status.as_u16()) {
                        last_err = format!("HTTP {status}: {}", truncate(&text, 200));
                        sleep_backoff(attempt);
                        continue;
                    }
                    if !status.is_success() {
                        return error_verdict(&format!("API error HTTP {status}: {}", truncate(&text, 300)));
                    }
                    return parse_response(&text).unwrap_or_else(|e| error_verdict(&e.to_string()));
                }
                Err(e) => {
                    last_err = e.to_string();
                    if attempt + 1 < MAX_RETRIES {
                        sleep_backoff(attempt);
                        continue;
                    }
                    return error_verdict(&format!("request failed: {last_err}"));
                }
            }
        }

        error_verdict(&format!("max retries exceeded: {last_err}"))
    }
}

fn parse_response(text: &str) -> Result<AIVerdict> {
    let root: serde_json::Value = serde_json::from_str(text).context("parse API response")?;
    let content = root["choices"][0]["message"]["content"]
        .as_str()
        .ok_or_else(|| anyhow!("empty content"))?
        .trim()
        .to_string();

    let mut json_str = content;
    if json_str.starts_with("```") {
        let lines: Vec<&str> = json_str.lines().collect();
        if lines.len() >= 2 {
            let end = if lines.last().map(|l| l.trim()) == Some("```") {
                lines.len() - 1
            } else {
                lines.len()
            };
            json_str = lines[1..end].join("\n");
        }
    }

    let data: serde_json::Value = serde_json::from_str(&json_str).context("parse AI JSON")?;
    for field in ["verdict", "confidence", "threat_type", "indicators", "reasoning"] {
        if data.get(field).is_none() {
            return Err(anyhow!("missing field: {field}"));
        }
    }

    let verdict = match data["verdict"].as_str().unwrap_or("").to_lowercase().as_str() {
        "clean" => Verdict::Clean,
        "malicious" => Verdict::Malicious,
        _ => Verdict::Suspicious,
    };

    let mut confidence = data["confidence"].as_f64().unwrap_or(0.5);
    confidence = confidence.clamp(0.0, 1.0);

    let indicators = match &data["indicators"] {
        serde_json::Value::Array(arr) => arr
            .iter()
            .map(|v| v.as_str().unwrap_or("").to_string())
            .collect(),
        other => vec![other.to_string()],
    };

    Ok(AIVerdict {
        verdict,
        confidence,
        threat_type: data["threat_type"].as_str().unwrap_or("").to_string(),
        indicators,
        reasoning: data["reasoning"].as_str().unwrap_or("").to_string(),
        error: String::new(),
    })
}

fn error_verdict(msg: &str) -> AIVerdict {
    AIVerdict {
        verdict: Verdict::Suspicious,
        confidence: 0.0,
        threat_type: "analysis_error".into(),
        reasoning: msg.to_string(),
        error: msg.to_string(),
        ..Default::default()
    }
}

fn sleep_backoff(attempt: u32) {
    let secs = 1u64 << attempt;
    thread::sleep(Duration::from_secs(secs));
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        s[..n].to_string()
    }
}
