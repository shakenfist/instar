//! VMM statistics tracking for performance monitoring and resource limiting.
//!
//! This module provides internal counters for tracking VM behavior, including:
//! - Exit counts by type (I/O, MMIO, HLT, etc.)
//! - Runtime tracking with wall-clock time
//! - Throughput calculation
//! - Resource limit checking
//!
//! These statistics are useful for:
//! - Performance tuning (comparing sector sizes, I/O patterns)
//! - Security (detecting DoS attempts via excessive exits or runtime)
//! - Debugging (understanding VM behavior)

use std::time::Instant;

/// Statistics tracked by the VMM during guest execution.
#[derive(Debug)]
pub struct VmmStats {
    /// When execution started
    start_time: Instant,

    /// Total number of VM exits
    pub total_exits: u64,

    /// Port I/O exits (serial communication)
    pub io_in_exits: u64,
    pub io_out_exits: u64,

    /// Memory-mapped I/O exits (virtio devices)
    pub mmio_read_exits: u64,
    pub mmio_write_exits: u64,

    /// HLT instruction exits
    pub hlt_exits: u64,

    /// Shutdown/triple fault exits
    pub shutdown_exits: u64,

    /// Failed VM entry
    pub fail_entry_exits: u64,

    /// Unhandled exit types
    pub unknown_exits: u64,

    /// Bytes read from input device
    pub bytes_read: u64,

    /// Bytes written to output device
    pub bytes_written: u64,

    /// Number of sectors processed
    pub sectors_read: u64,
    pub sectors_written: u64,
}

impl VmmStats {
    /// Create a new statistics tracker.
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            total_exits: 0,
            io_in_exits: 0,
            io_out_exits: 0,
            mmio_read_exits: 0,
            mmio_write_exits: 0,
            hlt_exits: 0,
            shutdown_exits: 0,
            fail_entry_exits: 0,
            unknown_exits: 0,
            bytes_read: 0,
            bytes_written: 0,
            sectors_read: 0,
            sectors_written: 0,
        }
    }

    /// Get elapsed time since start in seconds.
    pub fn elapsed_secs(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }

    /// Get elapsed time since start in nanoseconds.
    #[allow(dead_code)]
    pub fn elapsed_nanos(&self) -> u128 {
        self.start_time.elapsed().as_nanos()
    }

    /// Record an I/O input exit.
    pub fn record_io_in(&mut self) {
        self.total_exits += 1;
        self.io_in_exits += 1;
    }

    /// Record an I/O output exit.
    pub fn record_io_out(&mut self) {
        self.total_exits += 1;
        self.io_out_exits += 1;
    }

    /// Record an MMIO read exit.
    pub fn record_mmio_read(&mut self) {
        self.total_exits += 1;
        self.mmio_read_exits += 1;
    }

    /// Record an MMIO write exit.
    pub fn record_mmio_write(&mut self) {
        self.total_exits += 1;
        self.mmio_write_exits += 1;
    }

    /// Record an HLT exit.
    pub fn record_hlt(&mut self) {
        self.total_exits += 1;
        self.hlt_exits += 1;
    }

    /// Record a shutdown exit.
    pub fn record_shutdown(&mut self) {
        self.total_exits += 1;
        self.shutdown_exits += 1;
    }

    /// Record a failed VM entry.
    pub fn record_fail_entry(&mut self) {
        self.total_exits += 1;
        self.fail_entry_exits += 1;
    }

    /// Record an unknown/unhandled exit.
    pub fn record_unknown(&mut self) {
        self.total_exits += 1;
        self.unknown_exits += 1;
    }

    /// Record bytes read from the input device.
    pub fn record_read(&mut self, bytes: u64, sectors: u64) {
        self.bytes_read += bytes;
        self.sectors_read += sectors;
    }

    /// Record bytes written to the output device.
    pub fn record_write(&mut self, bytes: u64, sectors: u64) {
        self.bytes_written += bytes;
        self.sectors_written += sectors;
    }

    /// Total I/O exits (in + out).
    #[allow(dead_code)]
    pub fn io_exits(&self) -> u64 {
        self.io_in_exits + self.io_out_exits
    }

    /// Total MMIO exits (read + write).
    pub fn mmio_exits(&self) -> u64 {
        self.mmio_read_exits + self.mmio_write_exits
    }

    /// Calculate read throughput in bytes per second.
    pub fn read_throughput(&self) -> f64 {
        let elapsed = self.elapsed_secs();
        if elapsed > 0.0 {
            self.bytes_read as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Calculate write throughput in bytes per second.
    pub fn write_throughput(&self) -> f64 {
        let elapsed = self.elapsed_secs();
        if elapsed > 0.0 {
            self.bytes_written as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Calculate exit rate (exits per second).
    pub fn exit_rate(&self) -> f64 {
        let elapsed = self.elapsed_secs();
        if elapsed > 0.0 {
            self.total_exits as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Calculate MMIO exits per sector (for efficiency analysis).
    pub fn mmio_exits_per_sector(&self) -> f64 {
        let total_sectors = self.sectors_read + self.sectors_written;
        if total_sectors > 0 {
            self.mmio_exits() as f64 / total_sectors as f64
        } else {
            0.0
        }
    }

    /// Calculate bytes transferred per exit (for efficiency analysis).
    pub fn bytes_per_exit(&self) -> f64 {
        if self.total_exits > 0 {
            (self.bytes_read + self.bytes_written) as f64 / self.total_exits as f64
        } else {
            0.0
        }
    }

    /// Format a byte count as a human-readable string.
    fn format_bytes(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = 1024 * KB;
        const GB: u64 = 1024 * MB;

        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{bytes} B")
        }
    }

    /// Format a throughput value as a human-readable string.
    fn format_throughput(bytes_per_sec: f64) -> String {
        const KB: f64 = 1024.0;
        const MB: f64 = 1024.0 * KB;
        const GB: f64 = 1024.0 * MB;

        if bytes_per_sec >= GB {
            format!("{:.2} GB/s", bytes_per_sec / GB)
        } else if bytes_per_sec >= MB {
            format!("{:.2} MB/s", bytes_per_sec / MB)
        } else if bytes_per_sec >= KB {
            format!("{:.2} KB/s", bytes_per_sec / KB)
        } else {
            format!("{bytes_per_sec:.2} B/s")
        }
    }

    /// Format a count with percentage of total.
    fn format_count_percent(&self, count: u64) -> String {
        if self.total_exits > 0 {
            let percent = (count as f64 / self.total_exits as f64) * 100.0;
            format!("{} ({:.1}%)", Self::format_number(count), percent)
        } else {
            Self::format_number(count)
        }
    }

    /// Format a number with thousands separators.
    fn format_number(n: u64) -> String {
        let s = n.to_string();
        let mut result = String::new();
        for (i, c) in s.chars().rev().enumerate() {
            if i > 0 && i % 3 == 0 {
                result.push(',');
            }
            result.push(c);
        }
        result.chars().rev().collect()
    }

    /// Display statistics summary to stdout.
    pub fn display(&self) {
        let elapsed = self.elapsed_secs();

        println!();
        println!("=== VMM Statistics ===");
        println!();

        // Runtime
        println!("Runtime:        {elapsed:.3} seconds");
        println!();

        // Exit counts
        println!("Total exits:    {}", Self::format_number(self.total_exits));
        println!(
            "  IO in:        {}",
            self.format_count_percent(self.io_in_exits)
        );
        println!(
            "  IO out:       {}",
            self.format_count_percent(self.io_out_exits)
        );
        println!(
            "  MMIO read:    {}",
            self.format_count_percent(self.mmio_read_exits)
        );
        println!(
            "  MMIO write:   {}",
            self.format_count_percent(self.mmio_write_exits)
        );
        println!(
            "  HLT:          {}",
            self.format_count_percent(self.hlt_exits)
        );
        if self.shutdown_exits > 0 {
            println!(
                "  Shutdown:     {}",
                self.format_count_percent(self.shutdown_exits)
            );
        }
        if self.fail_entry_exits > 0 {
            println!(
                "  Fail entry:   {}",
                self.format_count_percent(self.fail_entry_exits)
            );
        }
        if self.unknown_exits > 0 {
            println!(
                "  Unknown:      {}",
                self.format_count_percent(self.unknown_exits)
            );
        }
        println!();

        // Throughput
        println!("Data transfer:");
        println!(
            "  Bytes read:   {} ({} sectors)",
            Self::format_bytes(self.bytes_read),
            Self::format_number(self.sectors_read)
        );
        println!(
            "  Bytes written: {} ({} sectors)",
            Self::format_bytes(self.bytes_written),
            Self::format_number(self.sectors_written)
        );
        println!(
            "  Read rate:    {}",
            Self::format_throughput(self.read_throughput())
        );
        println!(
            "  Write rate:   {}",
            Self::format_throughput(self.write_throughput())
        );
        println!();

        // Efficiency metrics
        println!("Efficiency:");
        println!("  Exit rate:    {:.0} exits/sec", self.exit_rate());
        println!(
            "  MMIO/sector:  {:.1} exits/sector",
            self.mmio_exits_per_sector()
        );
        println!("  Bytes/exit:   {:.1}", self.bytes_per_exit());
    }
}

impl Default for VmmStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_number() {
        assert_eq!(VmmStats::format_number(0), "0");
        assert_eq!(VmmStats::format_number(123), "123");
        assert_eq!(VmmStats::format_number(1234), "1,234");
        assert_eq!(VmmStats::format_number(1234567), "1,234,567");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(VmmStats::format_bytes(500), "500 B");
        assert_eq!(VmmStats::format_bytes(1024), "1.00 KB");
        assert_eq!(VmmStats::format_bytes(1536), "1.50 KB");
        assert_eq!(VmmStats::format_bytes(1048576), "1.00 MB");
        assert_eq!(VmmStats::format_bytes(1073741824), "1.00 GB");
    }

    #[test]
    fn test_counters() {
        let mut stats = VmmStats::new();

        stats.record_io_in();
        stats.record_io_out();
        stats.record_mmio_read();
        stats.record_mmio_write();
        stats.record_hlt();

        assert_eq!(stats.total_exits, 5);
        assert_eq!(stats.io_exits(), 2);
        assert_eq!(stats.mmio_exits(), 2);
        assert_eq!(stats.hlt_exits, 1);
    }

    #[test]
    fn test_data_tracking() {
        let mut stats = VmmStats::new();

        stats.record_read(4096, 1);
        stats.record_write(4096, 1);

        assert_eq!(stats.bytes_read, 4096);
        assert_eq!(stats.bytes_written, 4096);
        assert_eq!(stats.sectors_read, 1);
        assert_eq!(stats.sectors_written, 1);
    }
}
