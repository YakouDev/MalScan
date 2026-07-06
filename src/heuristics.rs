use crate::model::{AIMode, FileFeatures, HeuristicResult};
use std::collections::HashMap;

pub struct Scorer {
    pub threshold: i32,
    pub ai_mode: AIMode,
}

impl Scorer {
    pub fn new(threshold: i32, ai_mode: AIMode) -> Self {
        Self {
            threshold: if threshold <= 0 { 40 } else { threshold },
            ai_mode,
        }
    }

    fn weight_for_hit(&self, hit: &str) -> i32 {
        let weights: HashMap<&str, i32> = HashMap::from([
            ("htaccess:php_handler_disguise", 50),
            ("htaccess:allowed_php_file", 55),
            ("php:eval_input", 45),
            ("php:known_china_chopper", 60),
            ("php:known_wso", 55),
            ("php:obfuscated_eval", 50),
            ("php:obf_eval_chain", 50),
            ("php:eval_sink", 35),
            ("php:system_sink", 40),
            ("php:shell_exec_sink", 40),
            ("php:preg_replace_e_modifier", 45),
            ("php:create_function_sink", 40),
            ("php:extract_superglobal", 35),
            ("php:superglobal_input", 15),
            ("php:base64_decode", 20),
        ]);

        for (prefix, weight) in weights {
            if hit == prefix || hit.starts_with(prefix) {
                return weight;
            }
        }
        if hit.starts_with("php:") {
            return 20;
        }
        5
    }

    pub fn score(&self, features: &FileFeatures) -> HeuristicResult {
        let mut reasons = Vec::new();
        let mut total = 0;

        for hit in &features.signature_hits {
            let w = self.weight_for_hit(hit);
            total += w;
            reasons.push(format!("[+{w}] {hit}"));
        }

        if features.allowed_by_htaccess {
            total += 25;
            reasons.push("[+25] htaccess_whitelisted_file".into());
        }

        if !features.disguised_ext.is_empty() {
            total += 30;
            reasons.push(format!(
                "[+30] disguised_extension(.{})",
                features.disguised_ext
            ));
        }

        if features.file_type == "webshell" && has_php_input_sink(&features.signature_hits) {
            total += 15;
            reasons.push("[+15] webshell_input_to_sink".into());
        }

        if total > 100 {
            total = 100;
        }

        let escalate = match self.ai_mode {
            AIMode::Always => true,
            AIMode::Off => false,
            AIMode::Auto => total >= self.threshold || total >= 70,
        };

        HeuristicResult {
            score: total,
            reasons,
            escalate_to_ai: escalate,
        }
    }
}

fn has_php_input_sink(hits: &[String]) -> bool {
    let has_input = hits.iter().any(|h| h.contains("eval_input") || h.contains("superglobal_input"));
    let has_sink = hits.iter().any(|h| {
        h.contains("eval_sink")
            || h.contains("system_sink")
            || h.contains("shell_exec_sink")
            || h.contains("exec_sink")
    });
    has_input && has_sink
}
