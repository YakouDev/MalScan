use clap::{Parser, Subcommand};

const BANNER: &str = "\
\x1b[38;5;46m╔══════════════════════════════════════════════════════════════════════════╗
\x1b[38;5;46m║\x1b[38;5;82m  ██████╗ ██████╗ ███████╗██╗     ██╗██╗  ██╗ ██╗██████╗ ██████╗ ███████╗\x1b[38;5;46m ║
\x1b[38;5;46m║\x1b[38;5;83m ██╔═══██╗██╔══██╗██╔════╝██║     ██║╚██╗██╔╝███║╚════██╗╚════██╗╚════██║\x1b[38;5;46m ║
\x1b[38;5;46m║\x1b[38;5;84m ██║   ██║██████╔╝█████╗  ██║     ██║ ╚███╔╝ ╚██║ █████╔╝ █████╔╝    ██╔╝\x1b[38;5;46m ║
\x1b[38;5;46m║\x1b[38;5;85m ██║   ██║██╔══██╗██╔══╝  ██║     ██║ ██╔██╗  ██║ ╚═══██╗ ╚═══██╗   ██╔╝ \x1b[38;5;46m ║
\x1b[38;5;46m║\x1b[38;5;86m ╚██████╔╝██████╔╝███████╗███████╗██║██╔╝ ██╗ ██║██████╔╝██████╔╝   ██║  \x1b[38;5;46m ║
\x1b[38;5;46m║\x1b[38;5;87m  ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝╚═╝  ╚═╝ ╚═╝╚═════╝ ╚═════╝    ╚═╝  \x1b[38;5;46m ║
\x1b[38;5;46m║\x1b[38;5;118m    Awesome Malware Scanner - Powered by Obelix1337 💀\x1b[38;5;46m                    ║
\x1b[38;5;46m╚══════════════════════════════════════════════════════════════════════════╝\x1b[0m
";

#[derive(Parser)]
#[command(name = "malscan", version = "0.4.0", about = "Webshell scanner (PHP + htaccess bypass)", before_help = BANNER, arg_required_else_help = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Scan(ScanArgs),
    Version,
}

#[derive(Parser)]
pub struct ScanArgs {
    pub path: String,
    #[arg(long, default_value_t = true)]
    pub recursive: bool,
    #[arg(long)]
    pub no_recursive: bool,
    #[arg(long, default_value = "auto")]
    pub ai_mode: String,
    #[arg(short, long, default_value = "text")]
    pub format: String,
    #[arg(short, long, default_value_t = 40)]
    pub threshold: i32,
    #[arg(long, default_value = "52428800")]
    pub max_bytes: u64,
    #[arg(short, long, default_value_t = 4)]
    pub workers: usize,
    #[arg(short, long)]
    pub output: Option<String>,
    #[arg(short, long)]
    pub quiet: bool,
    #[arg(long)]
    pub exclude: Option<String>,
    #[arg(long)]
    pub ext: Option<String>,
    #[arg(long)]
    pub api_key: Option<String>,
}
