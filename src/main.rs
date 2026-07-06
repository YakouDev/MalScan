mod banner;
mod cli;
mod extractor;
mod fireworks;
mod heuristics;
mod htaccess;
mod key;
mod model;
mod reporter;
mod scanner;
mod signature;
mod webshell;

use cli::{Cli, Commands, ScanArgs};
use clap::Parser;
use model::{AIMode, Verdict};
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    match Cli::parse().command {
        Commands::Version => {
            println!("malscan 0.4.0");
            ExitCode::SUCCESS
        }
        Commands::Scan(args) => run_scan(args),
    }
}

fn run_scan(args: ScanArgs) -> ExitCode {
    let path = Path::new(&args.path);
    if !path.exists() {
        eprintln!("Error: path not found: {}", args.path);
        return ExitCode::from(1);
    }

    let ai_mode = AIMode::parse(&args.ai_mode);
    let mut api_key = args.api_key.unwrap_or_default();
    if api_key.is_empty() {
        api_key = key::resolve();
    }
    if ai_mode != AIMode::Off && api_key.is_empty() {
        eprintln!("Warning: API key not configured. AI analysis disabled.");
    }

    let excludes: Vec<String> = args
        .exclude
        .map(|e| e.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();

    let extra_exts: Vec<String> = args
        .ext
        .map(|e| e.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();

    let effective_ai_mode = if ai_mode != AIMode::Off && api_key.is_empty() {
        AIMode::Off
    } else {
        ai_mode
    };

    let recursive = args.recursive && !args.no_recursive;
    let mut s = scanner::Scanner::new(
        effective_ai_mode,
        args.threshold,
        args.max_bytes,
        args.workers,
        excludes,
        extra_exts,
        api_key,
    );

    let quiet = args.quiet;
    if !quiet {
        banner::print();
    }

    let progress = if quiet {
        None
    } else {
        Some(Box::new(move |cur: usize, total: usize| {
            let pct = if total == 0 { 0.0 } else { (cur as f64 / total as f64) * 100.0 };
            eprint!("\rMalScan scanning {cur}/{total} ({pct:.0}%)...");
        }) as scanner::ProgressFn)
    };

    let results = match s.scan(path, recursive, progress) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Scan error: {e}");
            return ExitCode::from(1);
        }
    };

    if !quiet {
        eprintln!();
    }

    if results.is_empty() {
        eprintln!("No webshell-target files found at: {}", args.path);
        return ExitCode::from(1);
    }

    let mut results = results;
    scanner::sort_results(&mut results);

    match reporter::write_by_verdict(&results, &args.path) {
        Ok((dir, written)) => {
            if !quiet {
                eprintln!("Reports written to {}", dir.display());
                for f in written {
                    eprintln!("  {}", f.display());
                }
            }
        }
        Err(e) => {
            eprintln!("Output error: {e}");
            return ExitCode::from(1);
        }
    }

    let rep = reporter::Reporter::new(&args.format);
    match rep.render_non_clean(&results, &args.path) {
        Ok(content) => {
            if let Some(out) = &args.output {
                if let Err(e) = std::fs::write(out, &content) {
                    eprintln!("Write error: {e}");
                    return ExitCode::from(1);
                }
            } else if !quiet {
                print!("{content}");
            }
        }
        Err(e) => {
            eprintln!("Report error: {e}");
            return ExitCode::from(1);
        }
    }

    let mut malicious = 0;
    let mut suspicious = 0;
    for r in &results {
        match r.final_verdict() {
            Verdict::Malicious => malicious += 1,
            Verdict::Suspicious => suspicious += 1,
            _ => {}
        }
    }

    if malicious > 0 {
        ExitCode::from(2)
    } else if suspicious > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
