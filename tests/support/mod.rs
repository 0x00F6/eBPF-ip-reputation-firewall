//! Shared fixtures for the opt-in, isolated Linux kernel integration suite.
#![allow(dead_code)]
use aya::{
    programs::{TestRun, TestRunOptions, Xdp},
    Ebpf, EbpfLoader,
};
use firewall_common::RuleValue;
use firewall_lib::{loader::ParsedRuleSet, maps::MapManager};
use std::{
    net::Ipv6Addr,
    path::{Path, PathBuf},
};

pub fn bpf_path() -> PathBuf {
    std::env::var_os("FIREWALL_EBPF_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target/bpfel-unknown-none/release/firewall-ebpf")
        })
}

pub fn load(capacity: u32) -> Ebpf {
    let mut bpf = EbpfLoader::new()
        .map_max_entries("IPV4_EXACT_MAP", capacity)
        .map_max_entries("IPV6_EXACT_MAP", capacity)
        .map_max_entries("IPV4_LPM_MAP", capacity)
        .map_max_entries("IPV6_LPM_MAP", capacity)
        .load_file(bpf_path())
        .expect("load kernel maps; run via scripts/run_kernel_test.sh");
    let program: &mut Xdp = bpf.program_mut("firewall").unwrap().try_into().unwrap();
    program.load().expect("XDP verifier acceptance");
    bpf
}

pub fn run_packet(bpf: &Ebpf, packet: &[u8]) -> u32 {
    let program: &Xdp = bpf.program("firewall").unwrap().try_into().unwrap();
    program
        .test_run(TestRunOptions {
            data_in: Some(packet),
            ..Default::default()
        })
        .expect("BPF_PROG_TEST_RUN")
        .return_value
}

pub fn v6(n: u8) -> [u8; 16] {
    Ipv6Addr::new(0x2001, 0xdb8, n as u16, 0, 0, 0, 0, 1).octets()
}

pub fn packet_v4(src: [u8; 4], protocol: u8, sport: u16, dport: u16) -> Vec<u8> {
    let mut packet = vec![0; 64];
    packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    packet[14] = 0x45;
    packet[16..18].copy_from_slice(&50u16.to_be_bytes());
    packet[22] = 64;
    packet[23] = protocol;
    packet[26..30].copy_from_slice(&src);
    packet[30..34].copy_from_slice(&[203, 0, 113, 1]);
    packet[34..36].copy_from_slice(&sport.to_be_bytes());
    packet[36..38].copy_from_slice(&dport.to_be_bytes());
    packet
}

pub fn packet_v6(src: [u8; 16], protocol: u8) -> Vec<u8> {
    let mut packet = vec![0; 74];
    packet[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    packet[14] = 0x60;
    packet[18..20].copy_from_slice(&20u16.to_be_bytes());
    packet[20] = protocol;
    packet[21] = 64;
    packet[22..38].copy_from_slice(&src);
    packet[38..54].copy_from_slice(&v6(99));
    packet[54..56].copy_from_slice(&12345u16.to_be_bytes());
    packet[56..58].copy_from_slice(&443u16.to_be_bytes());
    packet
}

pub fn rules(n: u8, id: u32) -> ParsedRuleSet {
    let mut rules = ParsedRuleSet::new();
    rules.exact_v4.insert([192, 0, 2, n], RuleValue::drop(id));
    rules.exact_v6.insert(v6(n), RuleValue::drop(id + 1));
    rules
        .lpm_v4
        .push((24, [198, 51, n, 0], RuleValue::drop(id + 2)));
    let mut net = v6(n + 10);
    net[15] = 0;
    rules.lpm_v6.push((64, net, RuleValue::drop(id + 3)));
    rules.total_rules = 4;
    rules
}

pub fn counts(maps: &MapManager) -> [usize; 4] {
    [
        maps.total_exact_v4(),
        maps.total_exact_v6(),
        maps.total_lpm_v4(),
        maps.total_lpm_v6(),
    ]
}

pub fn commit(repo: &git2::Repository, contents: &str) -> String {
    std::fs::write(repo.workdir().unwrap().join("feed.netset"), contents).unwrap();
    let mut index = repo.index().unwrap();
    index.add_path(Path::new("feed.netset")).unwrap();
    index.write().unwrap();
    let tree = repo.find_tree(index.write_tree().unwrap()).unwrap();
    let parent = repo.head().ok().map(|h| h.peel_to_commit().unwrap());
    let signature = git2::Signature::new(
        "Test",
        "test@example.invalid",
        &git2::Time::new(1_700_000_000, 0),
    )
    .unwrap();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "Feed update",
        &tree,
        &parent.iter().collect::<Vec<_>>(),
    )
    .unwrap()
    .to_string()
}
