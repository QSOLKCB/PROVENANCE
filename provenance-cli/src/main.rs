use std::env;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const BACKEND_COMMANDS: &[&str] = &[
    "record",
    "inspect",
    "verify",
    "finalize",
    "export",
    "package",
    "sign-package",
    "anchor-payload",
    "anchor-git",
    "verify-assurance",
    "redact-disclosure",
    "verify-disclosure",
    "transfer-create",
    "transfer-receive",
    "verify-transfer",
    "verify-receipt",
];

const TUI_COMMANDS: &[&str] = &["record", "inspect", "verify", "finalize", "export", "package"];

fn print_help() {
    println!("PROVENANCE CLI");
    println!();
    println!("Usage:");
    println!("  provenance <store-command> --store <path> --custody <path> [options]");
    println!("  provenance <standalone-command> [options]");
    println!("  provenance tui --store <path> --custody <path>");
    println!();
    println!("Commands:");
    println!("  record    Record operator-supplied content as DECLARED evidence");
    println!("  inspect   Inspect current working/finalized evidence");
    println!("  verify    Independently verify current bundle + custody");
    println!("  finalize  Finalize the current working evidence set");
    println!("  export    Copy and independently verify the current snapshot");
    println!("  package          Create a portable Phase 11 forensic package");
    println!("  sign-package     Create a detached Ed25519 SSHSIG record");
    println!("  anchor-payload   Write canonical bytes to commit as a Git anchor");
    println!("  anchor-git       Bind a package identity to an existing Git commit");
    println!("  verify-assurance Verify integrity/signature/anchor dimensions");
    println!("  redact-disclosure Create a redacted DERIVED disclosure");
    println!("  verify-disclosure Verify disclosure lineage and optional source");
    println!("  transfer-create   Create a signed offline transfer bundle");
    println!("  transfer-receive  Accept a transfer and create signed receipt");
    println!("  verify-transfer   Verify sender offer/package handoff");
    println!("  verify-receipt    Verify receiver acknowledgement/custody");
    println!("  tui               Keyboard-first store/custody command palette");
    println!();
    println!("Type 'provenance <command> --help' for backend command options.");
}

fn palette_matches(prefix: &str) -> Vec<&'static str> {
    TUI_COMMANDS
        .iter()
        .copied()
        .filter(|command| command.starts_with(prefix))
        .collect()
}

fn find_project_root() -> Result<PathBuf, String> {
    if let Ok(value) = env::var("PROVENANCE_ROOT") {
        let root = PathBuf::from(value);
        if root.join("provenance_cli").join("backend.py").is_file() {
            return Ok(root);
        }
        return Err("PROVENANCE_ROOT does not contain provenance_cli/backend.py".into());
    }

    if let Ok(cwd) = env::current_dir() {
        for candidate in cwd.ancestors() {
            if candidate.join("provenance_cli").join("backend.py").is_file() {
                return Ok(candidate.to_path_buf());
            }
        }
    }

    if let Ok(exe) = env::current_exe() {
        for candidate in exe.ancestors() {
            if candidate.join("provenance_cli").join("backend.py").is_file() {
                return Ok(candidate.to_path_buf());
            }
        }
    }

    Err(
        "cannot locate PROVENANCE checkout; run inside the repository or set PROVENANCE_ROOT"
            .into(),
    )
}

fn pythonpath_with_root(root: &Path) -> String {
    let existing = env::var("PYTHONPATH").unwrap_or_default();
    if existing.is_empty() {
        root.display().to_string()
    } else {
        format!("{}:{}", root.display(), existing)
    }
}

fn run_backend(args: &[String]) -> Result<i32, String> {
    let root = find_project_root()?;
    let python = env::var("PROVENANCE_PYTHON").unwrap_or_else(|_| "python3".to_string());

    let status = Command::new(python)
        .arg("-m")
        .arg("provenance_cli.backend")
        .args(args)
        .env("PYTHONPATH", pythonpath_with_root(&root))
        .status()
        .map_err(|error| format!("failed to start provenance CLI backend: {error}"))?;

    Ok(status.code().unwrap_or(1))
}

fn parse_tui_common(args: &[String]) -> Result<(String, String), String> {
    let mut store: Option<String> = None;
    let mut custody: Option<String> = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--store" => {
                index += 1;
                store = args.get(index).cloned();
                if store.is_none() {
                    return Err("--store requires a value".into());
                }
            }
            "--custody" => {
                index += 1;
                custody = args.get(index).cloned();
                if custody.is_none() {
                    return Err("--custody requires a value".into());
                }
            }
            "--help" | "-h" => {
                return Err("help".into());
            }
            other => {
                return Err(format!("unsupported tui argument: {other}"));
            }
        }
        index += 1;
    }

    Ok((
        store.ok_or_else(|| "tui requires --store <path>".to_string())?,
        custody.ok_or_else(|| "tui requires --custody <path>".to_string())?,
    ))
}

fn show_palette(prefix: &str) {
    let matches = palette_matches(prefix);
    if matches.is_empty() {
        println!("  no commands match /{prefix}");
        return;
    }
    for command in matches {
        println!("  /{command}");
    }
}

fn run_tui(args: &[String]) -> Result<i32, String> {
    let (store, custody) = match parse_tui_common(args) {
        Ok(values) => values,
        Err(value) if value == "help" => {
            println!("Usage: provenance tui --store <path> --custody <path>");
            println!("Type / to open the command palette; /quit exits.");
            return Ok(0);
        }
        Err(error) => return Err(error),
    };

    let interactive = io::stdin().is_terminal() && io::stdout().is_terminal();
    println!("PROVENANCE Phase 8 terminal");
    println!("store   = {store}");
    println!("custody = {custody}");
    println!("Type / for commands, /help for usage, /quit to exit.");

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    let mut session_status = 0;

    loop {
        if interactive {
            print!("provenance> ");
            io::stdout()
                .flush()
                .map_err(|error| format!("failed to flush prompt: {error}"))?;
        }

        let line = match lines.next() {
            Some(Ok(value)) => value,
            Some(Err(error)) => return Err(format!("stdin read failed: {error}")),
            None => return Ok(session_status),
        };
        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "/" {
            show_palette("");
            continue;
        }
        if trimmed == "/help" {
            println!("Slash commands:");
            show_palette("");
            println!("  /quit");
            println!();
            println!("Examples:");
            println!("  /verify");
            println!("  /inspect");
            println!("  /finalize --scope closed");
            println!("  /record --file evidence.bin --actor operator:alice --operation file.capture");
            println!("  /export --destination ./exported-bundle");
            continue;
        }
        if trimmed == "/quit" || trimmed == "/q" {
            return Ok(session_status);
        }
        if !trimmed.starts_with('/') {
            println!("commands begin with '/'; type / for the palette");
            continue;
        }

        let body = &trimmed[1..];
        let mut parts = body.split_whitespace();
        let Some(command) = parts.next() else {
            show_palette("");
            continue;
        };

        if !TUI_COMMANDS.contains(&command) {
            show_palette(command);
            continue;
        }

        let mut backend_args = vec![
            command.to_string(),
            "--store".to_string(),
            store.clone(),
            "--custody".to_string(),
            custody.clone(),
        ];
        backend_args.extend(parts.map(str::to_string));

        let code = run_backend(&backend_args)?;
        if code != 0 {
            if session_status == 0 {
                session_status = code.clamp(1, 255);
            }
            println!("command exited with status {code}");
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print_help();
        return ExitCode::SUCCESS;
    }

    let result = if args[0] == "tui" {
        run_tui(&args[1..])
    } else if BACKEND_COMMANDS.contains(&args[0].as_str()) {
        run_backend(&args)
    } else {
        Err(format!("unknown command: {}", args[0]))
    };

    match result {
        Ok(0) => ExitCode::SUCCESS,
        Ok(code) => ExitCode::from(code.clamp(1, 255) as u8),
        Err(error) => {
            eprintln!("provenance: {error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn palette_filters_prefixes() {
        assert_eq!(palette_matches("v"), vec!["verify"]);
        assert_eq!(palette_matches(""), TUI_COMMANDS.to_vec());
        assert!(palette_matches("zzz").is_empty());
    }

    #[test]
    fn backend_commands_are_stable() {
        assert_eq!(
            BACKEND_COMMANDS,
            [
                "record",
                "inspect",
                "verify",
                "finalize",
                "export",
                "package",
                "sign-package",
                "anchor-payload",
                "anchor-git",
                "verify-assurance",
                "redact-disclosure",
                "verify-disclosure",
                "transfer-create",
                "transfer-receive",
                "verify-transfer",
                "verify-receipt",
            ]
        );
    }
}
