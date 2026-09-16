use criterion::{black_box, criterion_group, criterion_main, Criterion};
use firewall_ebpf::{
    check_bounds, classify_packet, extract_transport_ports, parse_ethernet, parse_ipv4,
    parse_ipv6, simulate_exact_match, ETH_HDR_LEN, ETH_P_IP, ETH_P_IPV6, PROTO_TCP, PROTO_UDP,
};

fn build_raw_ipv4_tcp_packet(src_ip: [u8; 4], dst_ip: [u8; 4], sport: u16, dport: u16) -> [u8; 54] {
    let mut buf = [0u8; 54];
    buf[0..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    buf[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    buf[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());

    buf[14] = 0x45;
    buf[15] = 0x00;
    buf[16..18].copy_from_slice(&40u16.to_be_bytes());
    buf[23] = PROTO_TCP;
    buf[26..30].copy_from_slice(&src_ip);
    buf[30..34].copy_from_slice(&dst_ip);

    buf[34..36].copy_from_slice(&sport.to_be_bytes());
    buf[36..38].copy_from_slice(&dport.to_be_bytes());
    buf[46] = 0x50;
    buf[47] = 0x02;

    buf
}

fn build_raw_ipv4_udp_packet(src_ip: [u8; 4], dst_ip: [u8; 4], sport: u16, dport: u16) -> [u8; 42] {
    let mut buf = [0u8; 42];
    buf[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
    buf[14] = 0x45;
    buf[23] = PROTO_UDP;
    buf[26..30].copy_from_slice(&src_ip);
    buf[30..34].copy_from_slice(&dst_ip);
    buf[34..36].copy_from_slice(&sport.to_be_bytes());
    buf[36..38].copy_from_slice(&dport.to_be_bytes());
    buf
}

fn build_raw_vlan_packet() -> [u8; 58] {
    let mut buf = [0u8; 58];
    buf[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    buf[6..12].copy_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    buf[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
    buf[14..16].copy_from_slice(&100u16.to_be_bytes());
    buf[16..18].copy_from_slice(&ETH_P_IP.to_be_bytes());

    buf[18] = 0x45;
    buf[27] = PROTO_UDP;
    buf[30..34].copy_from_slice(&[192, 168, 1, 50]);
    buf[34..38].copy_from_slice(&[10, 0, 0, 1]);
    buf[38..40].copy_from_slice(&5353u16.to_be_bytes());
    buf[40..42].copy_from_slice(&53u16.to_be_bytes());
    buf
}

fn build_raw_ipv6_tcp_packet() -> [u8; 74] {
    let mut buf = [0u8; 74];
    buf[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
    buf[14..18].copy_from_slice(&0x60000000u32.to_be_bytes());
    buf[18..20].copy_from_slice(&20u16.to_be_bytes());
    buf[20] = PROTO_TCP;
    buf[21] = 64;
    buf[22..38].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    buf[38..54].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    buf[54..56].copy_from_slice(&8080u16.to_be_bytes());
    buf[56..58].copy_from_slice(&80u16.to_be_bytes());
    buf
}

fn bench_parsing_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("ebpf_packet_parsing");

    group.bench_function("check_bounds_safe", |b| {
        b.iter(|| {
            let ok = check_bounds(black_box(1500), black_box(14), black_box(20));
            black_box(ok);
        })
    });

    let tcp_packet = build_raw_ipv4_tcp_packet([192, 168, 1, 100], [10, 0, 0, 1], 54321, 80);
    let vlan_packet = build_raw_vlan_packet();
    let udp_packet = build_raw_ipv4_udp_packet([10, 0, 0, 42], [10, 0, 0, 1], 5353, 53);
    let ipv6_packet = build_raw_ipv6_tcp_packet();

    group.bench_function("parse_ethernet_standard", |b| {
        b.iter(|| {
            let res = parse_ethernet(black_box(&tcp_packet));
            let _ = black_box(res);
        })
    });

    group.bench_function("parse_ethernet_8021q_vlan", |b| {
        b.iter(|| {
            let res = parse_ethernet(black_box(&vlan_packet));
            let _ = black_box(res);
        })
    });

    group.bench_function("parse_ipv4_header_and_ports", |b| {
        b.iter(|| {
            let (ip_hdr, l4_offset) = parse_ipv4(black_box(&tcp_packet), ETH_HDR_LEN).unwrap();
            let ports = extract_transport_ports(black_box(&tcp_packet), l4_offset, ip_hdr.protocol);
            black_box((ip_hdr, ports));
        })
    });

    group.bench_function("parse_ipv4_udp_header_and_ports", |b| {
        b.iter(|| {
            let (ip_hdr, l4_offset) = parse_ipv4(black_box(&udp_packet), ETH_HDR_LEN).unwrap();
            let ports = extract_transport_ports(black_box(&udp_packet), l4_offset, ip_hdr.protocol);
            black_box((ip_hdr, ports));
        })
    });

    group.bench_function("parse_ipv6_header_and_ports", |b| {
        b.iter(|| {
            let (ip_hdr, l4_offset) = parse_ipv6(black_box(&ipv6_packet), ETH_HDR_LEN).unwrap();
            let ports = extract_transport_ports(black_box(&ipv6_packet), l4_offset, ip_hdr.next_header);
            black_box((ip_hdr, ports));
        })
    });

    group.bench_function("classify_packet_full_ipv4_tcp", |b| {
        b.iter(|| {
            let parsed = classify_packet(black_box(&tcp_packet));
            let _ = black_box(parsed);
        })
    });

    group.bench_function("classify_packet_full_ipv6_tcp", |b| {
        b.iter(|| {
            let parsed = classify_packet(black_box(&ipv6_packet));
            let _ = black_box(parsed);
        })
    });

    group.bench_function("classify_and_exact_match_simulation", |b| {
        let exact_v4 = [[198, 51, 100, 14], [10, 0, 0, 99], [192, 168, 1, 100]];
        b.iter(|| {
            let parsed = classify_packet(black_box(&tcp_packet)).unwrap();
            let decision = simulate_exact_match(&parsed, black_box(&exact_v4), &[]);
            black_box(decision);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_parsing_pipeline);
criterion_main!(benches);
