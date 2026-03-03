use anyhow::{Context, Result};
use chat4n6_core::PlaintextDirFs;
use chat4n6_plugin_api::ForensicPlugin;
use chat4n6_report::ReportGenerator;
use chat4n6_whatsapp::WhatsAppPlugin;
use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;

#[derive(Args)]
pub struct RunArgs {
    /// Input directory (plaintext Android filesystem tree)
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
    // Give a clear error if the user passes a .dar file directly.
    // DAR archives are not yet natively supported; extract first with:
    //   dar -x <basename> -R <output_dir>
    if args.input.is_file() {
        let ext = args
            .input
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        if ext == "dar" {
            anyhow::bail!(
                "{} is a DAR archive. Native DAR reading is not yet supported.\n\
                 Extract it first with:\n\
                 \n  dar -x \"{}\" -R /path/to/output\n\
                 \nThen re-run with --input pointing to the extracted directory.",
                args.input.display(),
                args.input
                    .file_stem()
                    .and_then(|s| s.to_str())
                    // strip trailing slice number: "userdata.1" → "userdata"
                    .and_then(|s| s.rsplit_once('.').map(|(base, _)| base).or(Some(s)))
                    .unwrap_or("archive")
            );
        }
        anyhow::bail!(
            "{} is a file, not a directory. --input must be an extracted Android filesystem tree.",
            args.input.display()
        );
    }

    // --- Filesystem ---
    let fs = PlaintextDirFs::new(&args.input)
        .with_context(|| format!("cannot open input: {}", args.input.display()))?;

    let plugins: Vec<Box<dyn ForensicPlugin>> = vec![Box::new(WhatsAppPlugin)];

    // --- Detect and extract ---
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
        if plugin.detect(&fs) {
            let result = plugin
                .extract(&fs, tz_offset)
                .with_context(|| format!("plugin '{}' extraction failed", plugin.name()))?;
            merge_results(&mut combined, result);
        }
        bar.inc(1);
    }
    bar.finish_with_message("extraction complete");

    if combined.chats.is_empty() && combined.calls.is_empty() {
        eprintln!("Warning: no artifacts found in {:?}", args.input);
    }

    // --- Report ---
    let generator = ReportGenerator::new().context("failed to load report templates")?;
    generator
        .render(&args.case_name, &combined, &args.output)
        .context("report generation failed")?;

    println!("Report written to: {}", args.output.display());
    println!("  index.html");
    println!("  carve-results.json");
    Ok(())
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

