use std::env;

pub fn resolve() -> String {
    env::var("FIREWORKS_API_KEY").unwrap_or_default()
}
