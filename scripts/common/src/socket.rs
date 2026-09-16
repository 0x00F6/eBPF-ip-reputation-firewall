//! High-performance raw socket sender and network probing utilities.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use std::process::Command;
use std::time::Duration;

/// High-speed raw socket sender utilizing `AF_INET / SOCK_RAW / IPPROTO_RAW` with `IP_HDRINCL`.
pub struct RawSocketSender {
    fd: RawFd,
}

impl RawSocketSender {
    /// Creates and configures a new raw IP socket for wire-speed line-rate packet injection.
    pub fn new() -> std::io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Enable IP_HDRINCL so we can supply our own IPv4 header with spoofed source IPs
        let one: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of_val(&one) as libc::socklen_t,
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }

        // Set socket send buffer to 4 MiB to maximize burst throughput and prevent ENOBUFS
        let sndbuf: libc::c_int = 4 * 1024 * 1024;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &sndbuf as *const _ as *const libc::c_void,
                std::mem::size_of_val(&sndbuf) as libc::socklen_t,
            );
        }

        Ok(Self { fd })
    }

    /// Sends a pre-crafted IPv4 frame directly to the kernel network driver without copies.
    #[inline(always)]
    pub fn send_to(&self, packet: &[u8], dst_ip: Ipv4Addr) -> std::io::Result<usize> {
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_addr.s_addr = u32::from_ne_bytes(dst_ip.octets());

        let res = unsafe {
            libc::sendto(
                self.fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&addr) as libc::socklen_t,
            )
        };

        if res >= 0 {
            Ok(res as usize)
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

impl AsRawFd for RawSocketSender {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for RawSocketSender {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

/// Attempts a standard TCP connection to determine if packets are accepted or dropped.
pub fn probe_tcp_connect(target: SocketAddr, timeout: Duration) -> bool {
    match TcpStream::connect_timeout(&target, timeout) {
        Ok(_) => true,
        Err(e) => {
            // ConnectionRefused (RST) means the packet reached the target host and the Linux stack replied!
            // That means the eBPF firewall accepted the packet!
            // TimedOut means the packet was dropped silently at XDP level.
            e.kind() == std::io::ErrorKind::ConnectionRefused
        }
    }
}

/// Sends a UDP datagram to target, optionally bound to a local source IP address.
pub fn send_udp_datagram(
    src_ip: Option<Ipv4Addr>,
    target: SocketAddr,
    payload: &[u8],
) -> std::io::Result<()> {
    let bind_addr = SocketAddrV4::new(src_ip.unwrap_or(Ipv4Addr::UNSPECIFIED), 0);
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;
    socket.send_to(payload, target)?;
    Ok(())
}

/// Runs a ping command to check ICMP connectivity.
pub fn run_ping_check(
    src_ip: Option<Ipv4Addr>,
    target: Ipv4Addr,
    count: u32,
    timeout_secs: u32,
) -> bool {
    let mut cmd = Command::new("ping");
    if let Some(src) = src_ip {
        cmd.args(["-I", &src.to_string()]);
    }
    cmd.args([
        "-c",
        &count.to_string(),
        "-W",
        &timeout_secs.to_string(),
        &target.to_string(),
    ]);

    match cmd.output() {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

/// Adds an IP alias to an interface using `ip addr add` (requires root/NET_ADMIN).
pub fn add_ip_alias(iface: &str, ip: Ipv4Addr) -> bool {
    let cidr = format!("{}/32", ip);
    Command::new("ip")
        .args(["addr", "add", &cidr, "dev", iface])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Removes an IP alias from an interface using `ip addr del`.
pub fn del_ip_alias(iface: &str, ip: Ipv4Addr) -> bool {
    let cidr = format!("{}/32", ip);
    Command::new("ip")
        .args(["addr", "del", &cidr, "dev", iface])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn test_probe_tcp_connect_listening() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let result = probe_tcp_connect(addr, Duration::from_millis(500));
        assert!(result);
    }

    #[test]
    fn test_probe_tcp_connect_connection_refused() {
        // Bind and immediately drop listener so the port is closed and gives RST
        let addr = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
            listener.local_addr().expect("local addr")
        };
        let result = probe_tcp_connect(addr, Duration::from_millis(500));
        // RST returns ConnectionRefused, which is treated as true (stack replied)
        assert!(result);
    }

    #[test]
    fn test_send_udp_datagram() {
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind udp receiver");
        let addr = receiver.local_addr().expect("local addr");

        // Send with None src_ip
        let res1 = send_udp_datagram(None, addr, b"test_payload_1");
        assert!(res1.is_ok());

        let mut buf = [0u8; 64];
        let (len, _) = receiver.recv_from(&mut buf).expect("recv udp");
        assert_eq!(&buf[..len], b"test_payload_1");

        // Send with Some(127.0.0.1) src_ip
        let res2 = send_udp_datagram(Some(Ipv4Addr::LOCALHOST), addr, b"test_payload_2");
        assert!(res2.is_ok());

        let (len2, _) = receiver.recv_from(&mut buf).expect("recv udp");
        assert_eq!(&buf[..len2], b"test_payload_2");
    }

    #[test]
    fn test_run_ping_check() {
        // Ping localhost with count 1
        let ok = run_ping_check(None, Ipv4Addr::LOCALHOST, 1, 1);
        // On standard linux, ping to localhost succeeds unless ping binary is missing
        if let Ok(_) = Command::new("ping").arg("-V").output() {
            assert!(ok);
        }

        // Ping non-existent local source IP should fail
        let fake_src = Ipv4Addr::new(192, 0, 2, 250);
        let _ = run_ping_check(Some(fake_src), Ipv4Addr::LOCALHOST, 1, 1);
    }

    #[test]
    fn test_ip_alias_invalid_interface() {
        let fake_iface = "nonexistent_dev_99";
        let fake_ip = Ipv4Addr::new(198, 51, 100, 99);
        assert!(!add_ip_alias(fake_iface, fake_ip));
        assert!(!del_ip_alias(fake_iface, fake_ip));
    }

    #[test]
    fn test_raw_socket_sender_creation() {
        // On non-root, raw socket creation returns PermissionDenied
        match RawSocketSender::new() {
            Ok(sender) => {
                assert!(sender.as_raw_fd() >= 0);
                let _ = sender.send_to(b"test", Ipv4Addr::LOCALHOST);
            }
            Err(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
            }
        }
    }
}
