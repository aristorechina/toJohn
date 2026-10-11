use std::io::Write;
use std::path::Path;

use clap::Parser;

/// tojohn — unified hash extractor: pulls crackable password hashes out of
/// 100+ file formats and renders them as crackable hash-line strings
/// (project "toJohn" by Aristore).
#[derive(Parser)]
#[command(name = "tojohn", version, about)]
struct Cli {
    /// Input file(s); with --recursive, directories to scan.
    files: Vec<String>,

    /// Force a specific format (see --list-formats).
    #[arg(short = 'f', long = "format")]
    format: Option<String>,

    /// List supported formats and exit.
    #[arg(long)]
    list_formats: bool,

    /// Show details (accepts/description) for each format and exit.
    #[arg(long)]
    list_details: bool,

    /// Inline text input for string-based formats (use with -f).
    #[arg(long, conflicts_with = "files")]
    text: Option<String>,

    /// Recurse into directories.
    #[arg(short = 'r', long)]
    recursive: bool,

    /// Write output to a file instead of stdout.
    #[arg(short = 'o', long)]
    output: Option<String>,

    /// Keyfile for formats that take one (keepass).
    #[arg(short = 'k', long = "keyfile")]
    keyfile: Option<String>,

    /// Keep going after per-file errors (default in batch mode).
    #[arg(long)]
    keep_going: bool,

    /// Suppress the per-file summary on stderr.
    #[arg(long)]
    quiet: bool,
}

fn main() {
    let cli = Cli::parse();

    if cli.list_formats || cli.list_details {
        for extractor in tojohn::registry::all() {
            if cli.list_details {
                println!(
                    "{:<18} accepts={:<5} {}",
                    extractor.name(),
                    if extractor.accepts(&tojohn::Input::from_bytes("", Vec::new())) {
                        "maybe"
                    } else {
                        "explicit"
                    },
                    extractor.description()
                );
            } else {
                println!("{}", extractor.name());
            }
        }
        return;
    }

    run(&cli);
}

fn collect_files(paths: &[String], recursive: bool) -> Vec<String> {
    let mut out = Vec::new();
    for p in paths {
        let path = Path::new(p);
        if path.is_dir() {
            if recursive {
                let mut stack = vec![path.to_path_buf()];
                while let Some(dir) = stack.pop() {
                    if let Ok(entries) = std::fs::read_dir(&dir) {
                        for entry in entries.flatten() {
                            let ep = entry.path();
                            if ep.is_dir() {
                                stack.push(ep);
                            } else {
                                out.push(ep.display().to_string());
                            }
                        }
                    }
                }
                out.sort();
            } else {
                eprintln!("error: {p} is a directory (use -r to recurse)");
                std::process::exit(2);
            }
        } else {
            out.push(p.to_string());
        }
    }
    out
}

fn run(cli: &Cli) {
    let registry = tojohn::registry::all();
    let files = collect_files(&cli.files, cli.recursive);
    if cli.text.is_none() && files.is_empty() {
        eprintln!("error: no input files given");
        std::process::exit(2);
    }

    // forced format: single extractor
    let forced = cli.format.as_deref().and_then(tojohn::registry::by_name);
    if cli.format.is_some() && forced.is_none() {
        eprintln!(
            "error: unknown format {:?} (see --list-formats)",
            cli.format.as_deref().unwrap_or("")
        );
        std::process::exit(2);
    }

    // output sink
    let stdout = std::io::stdout();
    let mut file_out = cli
        .output
        .as_ref()
        .and_then(|p| std::fs::File::create(p).ok());
    if cli.output.is_some() && file_out.is_none() {
        eprintln!(
            "error: cannot create output file {:?}",
            cli.output.as_deref().unwrap_or("")
        );
        std::process::exit(2);
    }
    let mut write = |s: &str| {
        if let Some(f) = file_out.as_mut() {
            let _ = f.write_all(s.as_bytes());
        } else {
            let _ = stdout.lock().write_all(s.as_bytes());
        }
    };

    let mut ok_count = 0usize;
    let mut err_count = 0usize;

    // inline text mode
    if let Some(text) = &cli.text {
        let Some(ext) = forced.as_ref() else {
            eprintln!("error: --text requires -f/--format");
            std::process::exit(2);
        };
        let mut input = tojohn::Input::from_text(text.clone());
        attach_keyfile(&mut input, cli.keyfile.as_deref());
        match ext.extract(&input) {
            Ok(hashes) => {
                for h in hashes {
                    write(&h.line);
                    write("\n");
                }
                ok_count += 1;
            }
            Err(e) => {
                eprintln!("error: {e}");
                err_count += 1;
            }
        }
    }

    for file in &files {
        let mut input = match tojohn::Input::from_path(file) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("error: {file}: {e}");
                err_count += 1;
                continue;
            }
        };
        attach_keyfile(&mut input, cli.keyfile.as_deref());
        let ext: &dyn tojohn::Extractor = if let Some(f) = forced.as_ref() {
            f.as_ref()
        } else {
            match detect(&registry, &input) {
                Some(e) => e,
                None => {
                    if !cli.quiet {
                        eprintln!("note: {file}: no matching format detected, skipped");
                    }
                    err_count += 1;
                    continue;
                }
            }
        };
        match ext.extract(&input) {
            Ok(hashes) if !hashes.is_empty() => {
                for h in hashes {
                    write(&h.line);
                    write("\n");
                }
                ok_count += 1;
            }
            Ok(_) => {
                if !cli.quiet {
                    eprintln!("note: {file}: format {} produced no hashes", ext.name());
                }
                err_count += 1;
            }
            Err(e) => {
                eprintln!("error: {file}: {e}");
                err_count += 1;
            }
        }
    }

    if !cli.quiet {
        eprintln!();
        eprintln!("{ok_count} file(s) processed, {err_count} failed/skipped");
    }
    std::process::exit(if err_count > 0 { 1 } else { 0 });
}

/// Automatic format detection: first extractor whose `accepts` matches.
fn detect<'a>(
    registry: &'a [Box<dyn tojohn::Extractor>],
    input: &tojohn::Input,
) -> Option<&'a dyn tojohn::Extractor> {
    registry
        .iter()
        .find(|e| e.accepts(input))
        .map(|e| e.as_ref())
}

/// Attach the `--keyfile` file to the input as an extra file (used by keepass).
fn attach_keyfile(input: &mut tojohn::Input, keyfile: Option<&str>) {
    let Some(path) = keyfile else {
        return;
    };
    match std::fs::read(path) {
        Ok(data) => input.extra_files.push(tojohn::input::ExtraFile {
            label: path.to_string(),
            data,
        }),
        Err(e) => {
            eprintln!("error: cannot read keyfile {path}: {e}");
            std::process::exit(2);
        }
    }
}
