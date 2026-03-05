use anyhow::{Context, Result};
use chat4n6_fs::{DarFs, IosBackupFs, PlaintextDirFs};
use chat4n6_plugin_api::ForensicPlugin;
use chat4n6_report::ReportGenerator;
use chat4n6_whatsapp::WhatsAppPlugin;
use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct RunArgs {
    /// Input: extracted Android filesystem directory, iOS backup directory, or .dar archive file
    #[arg(short, long)]
    pub input: PathBuf,
    /// Output directory for report files
    #[arg(short, long)]
    pub output: PathBuf,
    /// Case name for the report
    #[arg(long, default_value = "Unnamed Case")]
    pub case_name: String,
    /// Timezone offset string (e.g. "+08:00" or "Asia/Manila")
    #[arg(long)]
    pub timezone: Option<String>,
    /// Skip unallocated space carving (faster)
    #[arg(long)]
    pub no_unalloc: bool,
}

pub fn run(args: RunArgs) -> Result<()> {
    let fs = open_fs(&args.input)?;
    let plugins: Vec<Box<dyn ForensicPlugin>> = vec![Box::new(WhatsAppPlugin)];

    let bar = ProgressBar::new(plugins.len() as u64);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner} [{bar:40}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("=> "),
    );

    let tz_offset = resolve_tz_arg(args.timezone.as_deref())?;
    let mut combined = chat4n6_plugin_api::ExtractionResult::default();

    for plugin in &plugins {
        bar.set_message(plugin.name().to_string());
        if plugin.detect(&*fs) {
            let result = plugin
                .extract(&*fs, tz_offset)
                .with_context(|| format!("plugin '{}' extraction failed", plugin.name()))?;
            merge_results(&mut combined, result);
        }
        bar.inc(1);
    }
    bar.finish_with_message("extraction complete");

    if combined.chats.is_empty() && combined.calls.is_empty() {
        eprintln!("Warning: no artifacts found in {:?}", args.input);
    }

    let generator = ReportGenerator::new().context("failed to load report templates")?;
    generator
        .render(&args.case_name, &combined, &args.output)
        .context("report generation failed")?;

    println!("Report written to: {}", args.output.display());
    println!("  index.html");
    println!("  carve-results.json");
    Ok(())
}

/// Open the correct filesystem abstraction for `input`.
///
/// Detection order:
/// 1. File with `.dar` extension → DarFs (slice number stripped from basename)
/// 2. Directory containing `Manifest.db` → IosBackupFs
/// 3. Directory → PlaintextDirFs
fn open_fs(input: &Path) -> Result<Box<dyn chat4n6_plugin_api::ForensicFs>> {
    if input.is_file() {
        let ext = input.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "dar" {
            // Strip trailing slice number: "userdata.1" → "userdata"
            let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let base_name = stem.rsplit_once('.').map(|(b, _)| b).unwrap_or(stem);
            let basename = input
                .parent()
                .unwrap_or(Path::new("."))
                .join(base_name);
            return Ok(Box::new(
                DarFs::open_slices(&basename)
                    .with_context(|| format!("cannot open DAR archive: {}", input.display()))?,
            ));
        }
        anyhow::bail!(
            "{} is a file, not a directory. \
             --input must be a .dar archive, an iOS backup directory, \
             or an extracted Android filesystem tree.",
            input.display()
        );
    }
    if input.join("Manifest.db").exists() {
        return Ok(Box::new(
            IosBackupFs::open(input)
                .with_context(|| format!("cannot open iOS backup: {}", input.display()))?,
        ));
    }
    Ok(Box::new(
        PlaintextDirFs::new(input)
            .with_context(|| format!("cannot open input: {}", input.display()))?,
    ))
}

fn resolve_tz_arg(tz: Option<&str>) -> Result<Option<i32>> {
    match tz {
        None => Ok(None),
        Some(s) => chat4n6_whatsapp::timezone::resolve_timezone_offset(s)
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("unrecognised timezone: '{s}'")),
    }
}

fn merge_results(
    dst: &mut chat4n6_plugin_api::ExtractionResult,
    src: chat4n6_plugin_api::ExtractionResult,
) {
    dst.chats.extend(src.chats);
    dst.contacts.extend(src.contacts);
    dst.calls.extend(src.calls);
    dst.wal_deltas.extend(src.wal_deltas);
    if dst.timezone_offset_seconds.is_none() {
        dst.timezone_offset_seconds = src.timezone_offset_seconds;
    }
}
