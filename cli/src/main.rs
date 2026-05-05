use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(name = "chat4n6", version, about = "Forensic chat extraction tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run full pipeline: extract + report
    Run(commands::run::RunArgs),
    /// Regenerate HTML report from an existing carve-results.json
    Report(commands::report::ReportArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    }
    match cli.command {
        Commands::Run(args) => commands::run::run(args),
        Commands::Report(args) => commands::report::report(args),
    }
}
