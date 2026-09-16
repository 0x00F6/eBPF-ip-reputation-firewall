use crate::{
    config::XdpModeChoice,
    console::*,
    error::{FirewallError, Result},
};
use aya::{
    programs::{Xdp, XdpMode},
    Ebpf, EbpfLoader,
};
use firewall_common::{
    MAX_IPV4_HASH_ENTRIES, MAX_IPV4_LPM_ENTRIES, MAX_IPV6_HASH_ENTRIES, MAX_IPV6_LPM_ENTRIES,
};
use std::{
    fs,
    path::{Path, PathBuf},
};
use tracing::{info, warn};

/// Manages the lifecycle and interface attachment of the XDP firewall eBPF program.
pub struct XdpFirewall {
    pub ebpf: Ebpf,
    #[allow(dead_code)]
    pub iface: String,
}

impl XdpFirewall {
    /// Load eBPF bytecode without attaching the hook to the network interface.
    /// This enables populating and validating eBPF maps before exposing the firewall to live traffic.
    pub fn load(custom_bpf_path: Option<&PathBuf>) -> Result<Self> {
        let bpf_path = match custom_bpf_path {
            Some(p) => {
                if !p.is_file() {
                    return Err(FirewallError::Config(format!(
                        "Specified eBPF binary path {:?} does not exist or is a directory.",
                        p
                    )));
                }
                p.clone()
            }
            None => locate_ebpf_binary()?,
        };

        info!(
            "📦 Loading eBPF firewall bytecode from: {}",
            bold(format!("{:?}", bpf_path))
        );
        let bytecode = fs::read(&bpf_path).map_err(|e| {
            FirewallError::Config(format!(
                "Failed to read eBPF binary at {:?}: {}. Run 'cargo xtask build-ebpf' or 'make build-ebpf' first.",
                bpf_path, e
            ))
        })?;

        // Bump memlock rlimit so eBPF maps and programs can be allocated in kernel
        bump_memlock_rlimit();

        let mut ebpf = EbpfLoader::new()
            .map_max_entries("IPV4_EXACT_MAP", MAX_IPV4_HASH_ENTRIES)
            .map_max_entries("IPV6_EXACT_MAP", MAX_IPV6_HASH_ENTRIES)
            .map_max_entries("IPV4_LPM_MAP", MAX_IPV4_LPM_ENTRIES)
            .map_max_entries("IPV6_LPM_MAP", MAX_IPV6_LPM_ENTRIES)
            .load(&bytecode)?;

        let program: &mut Xdp = ebpf
            .program_mut("firewall")
            .ok_or_else(|| FirewallError::Config("XDP program 'firewall' not found in ELF".into()))?
            .try_into()?;

        program.load()?;

        Ok(Self {
            ebpf,
            iface: String::new(),
        })
    }

    /// Attach the loaded XDP program to `iface` with the requested attachment mode.
    pub fn attach(&mut self, iface: &str, mode_choice: XdpModeChoice) -> Result<()> {
        let program: &mut Xdp = self
            .ebpf
            .program_mut("firewall")
            .ok_or_else(|| FirewallError::Config("XDP program 'firewall' not found in ELF".into()))?
            .try_into()?;

        match mode_choice {
            XdpModeChoice::Driver => {
                info!(
                    "⚡ Attaching XDP program to '{}' in Driver (native) mode... 🏎️",
                    bold(iface)
                );
                program.attach(iface, XdpMode::Driver)?;
            }
            XdpModeChoice::Generic => {
                info!(
                    "🌐 Attaching XDP program to '{}' in Generic (SKB) mode... 🛡️",
                    bold(iface)
                );
                program.attach(iface, XdpMode::Skb)?;
            }
            XdpModeChoice::Hardware => {
                info!(
                    "💎 Attaching XDP program to '{}' in Hardware offload mode... 🚀",
                    bold(iface)
                );
                program.attach(iface, XdpMode::Hardware)?;
            }
            XdpModeChoice::Auto => {
                info!("🔍 Attempting Native Driver mode for '{}'...", bold(iface));
                match program.attach(iface, XdpMode::Driver) {
                    Ok(_) => {
                        info!(
                            "{}",
                            green_bold(format!(
                                "✅ Successfully attached XDP in Native Driver mode to '{}' 🏎️",
                                bold(iface)
                            ))
                        );
                    }
                    Err(err) => {
                        warn!(
                            "{}",
                            yellow_bold(format!(
                                "⚠️  Driver mode failed ({}), falling back to Generic (SKB) mode for '{}'...",
                                err,
                                bold(iface)
                            ))
                        );
                        program.attach(iface, XdpMode::Skb)?;
                        info!(
                            "{}",
                            green_bold(format!(
                                "✅ Successfully attached XDP in Generic (SKB) mode to '{}' 🌐",
                                bold(iface)
                            ))
                        );
                    }
                }
            }
        }

        self.iface = iface.to_string();
        Ok(())
    }

    /// Load eBPF bytecode and attach the firewall XDP hook to `iface`.
    pub fn load_and_attach(
        iface: &str,
        mode_choice: XdpModeChoice,
        custom_bpf_path: Option<&PathBuf>,
    ) -> Result<Self> {
        let mut fw = Self::load(custom_bpf_path)?;
        fw.attach(iface, mode_choice)?;
        Ok(fw)
    }

    #[allow(dead_code)]
    pub fn iface(&self) -> &str {
        &self.iface
    }
}

/// Attempts to locate the compiled eBPF ELF binary across known candidate paths.
fn locate_ebpf_binary() -> Result<PathBuf> {
    if let Ok(env_path) = std::env::var("FIREWALL_EBPF_PATH") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            return Ok(p);
        }
    }

    let candidate_paths = [
        "target/bpfel-unknown-none/release/firewall-ebpf",
        "target/bpfel-unknown-none/debug/firewall-ebpf",
        "/app/firewall-ebpf",
        "firewall-ebpf/target/bpfel-unknown-none/release/firewall-ebpf",
        "firewall-ebpf/target/bpfel-unknown-none/debug/firewall-ebpf",
        "../target/bpfel-unknown-none/release/firewall-ebpf",
        "../target/bpfel-unknown-none/debug/firewall-ebpf",
        "../firewall-ebpf/target/bpfel-unknown-none/release/firewall-ebpf",
        "../firewall-ebpf/target/bpfel-unknown-none/debug/firewall-ebpf",
        "./firewall-ebpf",
    ];

    for candidate in &candidate_paths {
        let p = Path::new(candidate);
        if p.is_file() {
            return Ok(p.to_path_buf());
        }
    }

    // Check relative to current executable location if possible
    if let Ok(mut exe_dir) = std::env::current_exe() {
        if exe_dir.pop() {
            let sibling_candidates = [
                exe_dir.join("../bpfel-unknown-none/release/firewall-ebpf"),
                exe_dir.join("../bpfel-unknown-none/debug/firewall-ebpf"),
                exe_dir.join("../../firewall-ebpf/target/bpfel-unknown-none/release/firewall-ebpf"),
                exe_dir.join("../../firewall-ebpf/target/bpfel-unknown-none/debug/firewall-ebpf"),
            ];
            for p in &sibling_candidates {
                if p.is_file() {
                    return Ok(p.clone());
                }
            }
        }
    }

    Err(FirewallError::Config(
        "Could not find compiled eBPF binary. Please build it first with 'cargo xtask build-ebpf' or 'make build-ebpf'.".into()
    ))
}

/// Raises the `RLIMIT_MEMLOCK` resource limit to infinity so eBPF maps can be allocated.
fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("⚠️ Failed to set RLIMIT_MEMLOCK to infinity. eBPF map allocation might fail on older kernels.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locate_ebpf_binary_candidates() {
        // In unit test environment, the binary may not exist yet, but candidate logic should execute cleanly.
        let res = locate_ebpf_binary();
        if let Ok(p) = res {
            assert!(p.is_file());
        }
    }

    #[test]
    fn test_locate_ebpf_binary_with_env() {
        use tempfile::NamedTempFile;
        let tmp = NamedTempFile::new().expect("create temp file");
        let path_str = tmp.path().to_str().unwrap();
        std::env::set_var("FIREWALL_EBPF_PATH", path_str);

        let res = locate_ebpf_binary();
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), tmp.path());

        std::env::remove_var("FIREWALL_EBPF_PATH");
    }

    #[test]
    fn test_bump_memlock_rlimit() {
        bump_memlock_rlimit();
    }

    #[test]
    fn test_xdp_firewall_load_nonexistent_path() {
        let non_existent = PathBuf::from("/non/existent/path/firewall-ebpf");
        let res = XdpFirewall::load(Some(&non_existent));
        match res {
            Err(e) => assert!(e.to_string().contains("does not exist")),
            Ok(_) => panic!("expected error"),
        }

        let res2 = XdpFirewall::load_and_attach(
            "dummy_eth",
            XdpModeChoice::Generic,
            Some(&non_existent),
        );
        assert!(res2.is_err());
    }
}
