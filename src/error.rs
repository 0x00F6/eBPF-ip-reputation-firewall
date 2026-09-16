use std::fmt;

/// High-level firewall error representing all failure modes in userspace and eBPF subsystems.
#[derive(Debug)]
pub enum FirewallError {
    Ebpf(aya::EbpfError),
    Map(aya::maps::MapError),
    Program(aya::programs::ProgramError),
    Io(std::io::Error),
    ParseError { line: usize, reason: String },
    Interface(String),
    RingBuf(String),
    Config(String),
    Cache(String),
}

impl std::error::Error for FirewallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FirewallError::Ebpf(e) => Some(e),
            FirewallError::Map(e) => Some(e),
            FirewallError::Program(e) => Some(e),
            FirewallError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<aya::EbpfError> for FirewallError {
    fn from(e: aya::EbpfError) -> Self {
        Self::Ebpf(e)
    }
}

impl From<aya::maps::MapError> for FirewallError {
    fn from(e: aya::maps::MapError) -> Self {
        Self::Map(e)
    }
}

impl From<aya::programs::ProgramError> for FirewallError {
    fn from(e: aya::programs::ProgramError) -> Self {
        Self::Program(e)
    }
}

impl From<std::io::Error> for FirewallError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl fmt::Display for FirewallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base_msg = match self {
            FirewallError::Ebpf(e) => format!("eBPF subsystem error: {e}"),
            FirewallError::Map(e) => format!("eBPF map error: {e}"),
            FirewallError::Program(e) => format!("eBPF program error: {e}"),
            FirewallError::Io(e) => format!("IO error: {e}"),
            FirewallError::ParseError { line, reason } => {
                format!("Rule parse error on line {line}: {reason}")
            }
            FirewallError::Interface(msg) => format!("Network interface error: {msg}"),
            FirewallError::RingBuf(msg) => format!("Ring buffer error: {msg}"),
            FirewallError::Config(msg) => format!("Configuration error: {msg}"),
            FirewallError::Cache(msg) => format!("Cache (RocksDB) error: {msg}"),
        };

        // Traverse the error source chain to unwrap underlying causes (e.g. OS errors)
        let mut messages = vec![base_msg];
        let mut current = std::error::Error::source(self);
        let mut is_permission_denied = false;

        while let Some(e) = current {
            let msg = e.to_string();
            // Avoid repeating identical or redundant messages in the output
            if !messages.iter().any(|m| m.contains(&msg) || msg.contains(m)) {
                messages.push(msg);
            }

            if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                if io_err.kind() == std::io::ErrorKind::PermissionDenied
                    || io_err.raw_os_error() == Some(libc::EPERM)
                    || io_err.raw_os_error() == Some(libc::EACCES)
                {
                    is_permission_denied = true;
                }
            }

            current = e.source();
        }

        let combined = messages.join(": ");
        if is_permission_denied
            || combined.contains("Operation not permitted")
            || combined.contains("Permission denied")
        {
            if !combined.contains("sudo") && !combined.contains("privilege") {
                write!(
                    f,
                    "{combined}. Elevated root privileges required (try running with 'sudo' or check CAP_BPF/CAP_NET_ADMIN capabilities)"
                )
            } else {
                write!(f, "{combined}")
            }
        } else {
            write!(f, "{combined}")
        }
    }
}

pub type Result<T> = std::result::Result<T, FirewallError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[derive(Debug)]
    struct DeepCause;
    impl fmt::Display for DeepCause {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "deep root cause")
        }
    }
    impl Error for DeepCause {}

    #[derive(Debug)]
    struct WrapError(DeepCause);
    impl fmt::Display for WrapError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "wrapper context")
        }
    }
    impl Error for WrapError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn test_permission_denied_formatting() {
        let io_err = std::io::Error::from_raw_os_error(libc::EPERM);
        let err = FirewallError::Io(io_err);
        let display_str = err.to_string();

        assert!(display_str.contains("Operation not permitted"));
        assert!(display_str.contains("Elevated root privileges required"));
        assert!(!display_str.contains("Os {"));

        let eacces = std::io::Error::from_raw_os_error(libc::EACCES);
        let err_eacces = FirewallError::Io(eacces);
        assert!(err_eacces.to_string().contains("Elevated root privileges required"));

        let custom_perm = FirewallError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "already mention sudo privileges",
        ));
        assert!(!custom_perm.to_string().ends_with("(try running with 'sudo' or check CAP_BPF/CAP_NET_ADMIN capabilities)"));
    }

    #[test]
    fn test_custom_error_formatting() {
        let err = FirewallError::Config("Invalid test value".into());
        assert_eq!(err.to_string(), "Configuration error: Invalid test value");
        assert!(err.source().is_none());

        let err = FirewallError::Interface("eth999".into());
        assert_eq!(err.to_string(), "Network interface error: eth999");
        assert!(err.source().is_none());

        let err = FirewallError::RingBuf("Buffer full".into());
        assert_eq!(err.to_string(), "Ring buffer error: Buffer full");
        assert!(err.source().is_none());

        let err = FirewallError::Cache("Corrupted record".into());
        assert_eq!(err.to_string(), "Cache (RocksDB) error: Corrupted record");
        assert!(err.source().is_none());

        let err = FirewallError::ParseError {
            line: 42,
            reason: "Bad IP".into(),
        };
        assert_eq!(err.to_string(), "Rule parse error on line 42: Bad IP");
        assert!(err.source().is_none());
    }

    #[test]
    fn test_aya_error_conversions_and_display() {
        let ebpf_err: FirewallError = aya::EbpfError::NoBTF.into();
        assert_eq!(
            ebpf_err.to_string(),
            "eBPF subsystem error: no BTF parsed for object"
        );
        assert!(ebpf_err.source().is_some());

        let map_err: FirewallError = aya::maps::MapError::KeyNotFound.into();
        assert_eq!(map_err.to_string(), "eBPF map error: key not found");
        assert!(map_err.source().is_some());
    }

    #[test]
    fn test_error_chain_pushes_unique_source_messages() {
        // io::Error wrapping a custom payload: the io layer re-displays "wrapper context",
        // while its own source carries the distinct "deep root cause" message.
        let io_err = std::io::Error::other(WrapError(DeepCause));
        let err = FirewallError::Io(io_err);
        let display_str = err.to_string();

        assert!(display_str.contains("IO error: wrapper context"));
        assert!(display_str.contains("deep root cause"));
        assert!(!display_str.contains("Elevated root privileges required"));
    }

    #[test]
    fn test_from_conversions_and_sources() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let firewall_io: FirewallError = io_err.into();
        assert!(matches!(firewall_io, FirewallError::Io(_)));
        assert!(firewall_io.source().is_some());
    }
}
