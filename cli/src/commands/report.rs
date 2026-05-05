use anyhow::{Context, Result};
use chat4n6_report::ReportGenerator;
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct ReportArgs {
    /// Path to an existing carve-results.json produced by a previous run
    #[arg(long)]
    pub from: PathBuf,
    /// Output directory for report files
    #[arg(short, long)]
    pub output: PathBuf,
    /// Case name for the report
    #[arg(long, default_value = "Unnamed Case")]
    pub case_name: String,
    /// Messages per HTML page [default: 500]
    #[arg(long, default_value_t = 500)]
    pub page_size: usize,
}

pub fn report(args: ReportArgs) -> Result<()> {
    let json = std::fs::read_to_string(&args.from)
        .with_context(|| format!("cannot read {}", args.from.display()))?;
    let result: chat4n6_plugin_api::ExtractionResult = serde_json::from_str(&json)
        .with_context(|| format!("invalid carve-results.json at {}", args.from.display()))?;

    let generator = ReportGenerator::new()
        .context("failed to load report templates")?
        .with_page_size(args.page_size);
    generator
        .render(&args.case_name, &result, &args.output)
        .context("report generation failed")?;

    println!("Report written to: {}", args.output.display());
    println!("  index.html");
    Ok(())
}
