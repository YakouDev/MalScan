use std::env;

pub fn resolve() -> String {
    env::var("OPENROUTER_API_KEY").unwrap_or_default()
}
