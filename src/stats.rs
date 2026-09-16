use crate::console::*;
use crate::{maps::MapManager, metrics::PrometheusMetrics};
use firewall_common::FirewallStats;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{watch, Mutex};
use tracing::{debug, info};

/// Periodically queries the eBPF kernel counters and logs live metrics.
pub struct StatsReporter {
    map_manager: Arc<Mutex<MapManager>>,
    interval: Duration,
    metrics: Option<Arc<PrometheusMetrics>>,
}

impl StatsReporter {
    pub fn new(map_manager: Arc<Mutex<MapManager>>, interval_secs: u64) -> Self {
        Self {
            map_manager,
            interval: Duration::from_secs(interval_secs),
            metrics: None,
        }
    }

    /// Attach Prometheus metrics collector.
    pub fn with_metrics(mut self, metrics: Arc<PrometheusMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Background monitoring loop.
    pub async fn run(self, mut shutdown_rx: watch::Receiver<bool>) {
        info!(
            "{}",
            green_bold(format!(
                "📊 Starting firewall metrics reporter (interval: {}s)... ⏱️",
                bold_num(self.interval.as_secs())
            ))
        );

        // Sync to Prometheus at least every 1 second (or faster if interval is smaller)
        let sync_interval = if self.interval.is_zero() {
            Duration::from_secs(1)
        } else {
            self.interval.min(Duration::from_secs(1))
        };
        let mut ticker = tokio::time::interval(sync_interval);

        let mut last_log_time = Instant::now();
        let mut last_stats = FirewallStats::default();

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    info!("{}", yellow_bold("🛑 Stats reporter stopping."));
                    break;
                }
                _ = ticker.tick() => {
                    let stats = {
                        let mgr = self.map_manager.lock().await;
                        mgr.get_stats().unwrap_or_default()
                    };

                    // Synchronize to Prometheus metrics on every fast tick
                    if let Some(m) = &self.metrics {
                        m.update_from_ebpf_stats(&stats);
                    }

                    // Console logging is paced at self.interval
                    let current_time = Instant::now();
                    let elapsed = current_time.duration_since(last_log_time).as_secs_f64();
                    if !self.interval.is_zero() && elapsed >= self.interval.as_secs_f64() {
                        let delta_rx_pkts = stats.rx_packets.saturating_sub(last_stats.rx_packets);
                        let delta_rx_bytes = stats.rx_bytes.saturating_sub(last_stats.rx_bytes);
                        let delta_drop_pkts = stats.dropped_packets.saturating_sub(last_stats.dropped_packets);
                        let delta_drop_bytes = stats.dropped_bytes.saturating_sub(last_stats.dropped_bytes);
                        let delta_ringbuf = stats.ringbuf_events.saturating_sub(last_stats.ringbuf_events);

                        let rx_pps = (delta_rx_pkts as f64) / elapsed;
                        let rx_mbps = ((delta_rx_bytes as f64) * 8.0) / (elapsed * 1_000_000.0);
                        let drop_pps = (delta_drop_pkts as f64) / elapsed;
                        let drop_mbps = ((delta_drop_bytes as f64) * 8.0) / (elapsed * 1_000_000.0);

                        let drop_pct = if delta_rx_pkts > 0 {
                            ((delta_drop_pkts as f64) / (delta_rx_pkts as f64)) * 100.0
                        } else {
                            0.0
                        };

                        debug!(
                            "📊 [FIREWALL STATS] 📥 Ingress: {} pps ({} Mbps) | {} | {} | 📡 RingBuf: +{} events",
                            bold(format_float_with_spaces(rx_pps, 0)),
                            format_float_with_spaces(rx_mbps, 2),
                            red_bold(format!(
                                "🚫 Dropped: {} pps ({} Mbps, {:.1}%)",
                                format_float_with_spaces(drop_pps, 0),
                                format_float_with_spaces(drop_mbps, 2),
                                drop_pct
                            )),
                            green_bold(format!("✅ Accepted: {} pkts", bold_num(stats.accepted_packets))),
                            bold_num(delta_ringbuf)
                        );

                        last_log_time = current_time;
                        last_stats = stats;
                    }
                }
            }
        }
    }
}
