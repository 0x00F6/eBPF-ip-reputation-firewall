use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::process::Command;

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Build helper tasks for the eBPF IP reputation firewall", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build the eBPF kernel program targeting bpfel-unknown-none
    BuildEbpf {
        /// Build in release mode with optimizations
        #[arg(long)]
        release: bool,
    },
    /// Build both eBPF and user space binaries
    Build {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
    /// Run the userspace firewall daemon
    Run {
        /// Build in release mode
        #[arg(long)]
        release: bool,
        /// Arguments to pass through to the firewall binary
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        run_args: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::BuildEbpf { release } => {
            build_ebpf(release)?;
        }
        Commands::Build { release } => {
            build_ebpf(release)?;
            build_userspace(release)?;
        }
        Commands::Run { release, run_args } => {
            build_ebpf(release)?;
            run_userspace(release, run_args)?;
        }
    }

    Ok(())
}

fn build_ebpf(release: bool) -> Result<()> {
    println!(">>> Building eBPF kernel program (target: bpfel-unknown-none)...");

    let mut cmd = Command::new("cargo");
    cmd.arg("+nightly")
        .arg("build")
        .arg("--manifest-path=firewall-ebpf/Cargo.toml")
        .arg("--target=bpfel-unknown-none")
        .arg("-Z")
        .arg("build-std=core")
        .arg("--target-dir=target");

    if release {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .context("Failed to execute cargo build for eBPF")?;
    if !status.success() {
        bail!("eBPF build failed with exit code: {:?}", status.code());
    }

    // Ensure the output binary exists
    let profile = if release { "release" } else { "debug" };
    let artifact = format!("target/bpfel-unknown-none/{profile}/firewall-ebpf");
    println!(">>> eBPF program successfully built: {artifact}");
    Ok(())
}

fn build_userspace(release: bool) -> Result<()> {
    println!(">>> Building user space firewall daemon...");

    let mut cmd = Command::new("cargo");
    cmd.arg("build").arg("--package=firewall");

    if release {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .context("Failed to execute cargo build for user space")?;
    if !status.success() {
        bail!(
            "User space build failed with exit code: {:?}",
            status.code()
        );
    }

    println!(">>> User space firewall daemon built successfully.");
    Ok(())
}

fn run_userspace(release: bool, run_args: Vec<String>) -> Result<()> {
    println!(">>> Running user space firewall daemon...");

    let mut cmd = Command::new("cargo");
    cmd.arg("run").arg("--package=firewall");

    if release {
        cmd.arg("--release");
    }

    if !run_args.is_empty() {
        cmd.arg("--").args(run_args);
    }

    let status = cmd.status().context("Failed to execute cargo run")?;
    if !status.success() {
        bail!("Firewall exited with error: {:?}", status.code());
    }

    Ok(())
}
