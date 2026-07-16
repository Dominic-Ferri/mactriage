use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 2;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    /// Displayed as "Fatal error": the machine itself died (kernel panic,
    /// watchdog/thermal/PMU forced shutdown). JSON keeps "critical" for schema
    /// stability; `--min-severity fatal` is accepted as an alias
    #[value(alias("fatal"))]
    Critical,
}

impl Severity {
    pub fn exit_code(self) -> i32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 10,
            Severity::Medium => 20,
            Severity::High => 30,
            Severity::Critical => 40,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Fatal error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverallCondition {
    Unknown,
    Healthy,
    Minor,
    Degraded,
    Serious,
    Critical,
}

impl OverallCondition {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN",
            Self::Healthy => "HEALTHY",
            Self::Minor => "MINOR",
            Self::Degraded => "DEGRADED",
            Self::Serious => "SERIOUS",
            Self::Critical => "CRITICAL",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Unknown => {
                "The scan is incomplete, so the Mac's overall condition cannot be trusted."
            }
            Self::Healthy => "No actionable findings were found in a complete scan.",
            Self::Minor => {
                "Only low-severity problems were found; monitor and repair them when practical."
            }
            Self::Degraded => {
                "Meaningful problems were found; schedule remediation and watch for escalation."
            }
            Self::Serious => "High-severity problems were found; prompt remediation is warranted.",
            Self::Critical => {
                "Fatal-level system events were found; immediate attention is warranted."
            }
        }
    }
}

/// Scan categories selectable with --only / --skip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, clap::ValueEnum)]
#[clap(rename_all = "lowercase")]
pub enum Category {
    Crashes,
    Panics,
    Hangs,
    Memory,
    Thermal,
    Disk,
    Power,
    Gpu,
    Services,
    /// cpu_resource / wakeups_resource diag files (runaway CPU, excessive wakeups)
    ResourceAbuse,
    Io,
    Spotlight,
    Snapshot,
    // v0.2.0 additions
    LaunchItems,
    Battery,
    Posture,
    Network,
    Bluetooth,
    Backups,
    Updates,
    Boot,
    Security,
    Kexts,
    /// Live hardware checks: SSD wear, battery/charger, built-in keyboard/trackpad
    Hardware,
}

impl Category {
    pub const ALL: &'static [Category] = &[
        Category::Crashes,
        Category::Panics,
        Category::Hangs,
        Category::Memory,
        Category::Thermal,
        Category::Disk,
        Category::Power,
        Category::Gpu,
        Category::Services,
        Category::ResourceAbuse,
        Category::Io,
        Category::Spotlight,
        Category::Snapshot,
        Category::LaunchItems,
        Category::Battery,
        Category::Posture,
        Category::Network,
        Category::Bluetooth,
        Category::Backups,
        Category::Updates,
        Category::Boot,
        Category::Security,
        Category::Kexts,
        Category::Hardware,
    ];
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub source: String,
    pub excerpt: String,
}

/// One unified-log line that matched a rule, kept so the JSON report carries
/// the raw evidence behind each log finding for deeper post-scan review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub timestamp: Option<DateTime<Utc>>,
    pub rule_id: String,
    pub process: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    /// snake_case category string kept for schema stability (e.g. "crash_loop").
    pub category: String,
    pub timestamp: Option<DateTime<Utc>>,
    pub first_seen: Option<DateTime<Utc>>,
    pub process: Option<String>,
    pub summary: String,
    pub detail: String,
    pub next_step: Option<String>,
    pub count: u32,
    pub evidence: Vec<Evidence>,
}

impl Finding {
    pub fn new(rule_id: &str, severity: Severity, category: &str, summary: &str) -> Self {
        Finding {
            rule_id: rule_id.into(),
            severity,
            category: category.into(),
            timestamp: None,
            first_seen: None,
            process: None,
            summary: summary.into(),
            detail: String::new(),
            next_step: None,
            count: 1,
            evidence: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vital {
    pub label: String,
    pub value: String,
    pub flag: Option<Severity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub model: String,
    pub chip: String,
    pub memory_gb: u64,
    pub macos_version: String,
    pub macos_build: String,
    pub arch: String,
    pub uptime: String,
    pub root: bool,
    /// Marketing name, e.g. "MacBook Air" (empty in reports from < 0.11).
    #[serde(default)]
    pub model_name: String,
    /// Boot drive, e.g. "APPLE SSD AP0512Z · 500.3 GB" (empty in reports from < 0.11).
    #[serde(default)]
    pub storage: String,
}

impl HostInfo {
    /// "MacBook Air (Mac17,3)", or just the model identifier when the
    /// marketing name is unknown.
    pub fn machine(&self) -> String {
        if self.model_name.is_empty() {
            self.model.clone()
        } else {
            format!("{} ({})", self.model_name, self.model)
        }
    }

    /// " · APPLE SSD AP0512Z · 500.3 GB", or empty when unknown.
    pub fn storage_suffix(&self) -> String {
        if self.storage.is_empty() {
            String::new()
        } else {
            format!(" · {}", self.storage)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skipped {
    pub what: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Stats {
    pub files_scanned: u32,
    pub files_unparsed: u32,
    pub log_lines: u64,
    pub log_rules_run: u32,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRecommendation {
    NoEraseNeeded,
    RepairSoftwareFirst,
    ReinstallMacosInPlace,
    FirmwareOrHardwareFirst,
    CollectMoreEvidence,
}

impl RecoveryRecommendation {
    pub fn label(self) -> &'static str {
        match self {
            Self::NoEraseNeeded => "NO ERASE NEEDED",
            Self::RepairSoftwareFirst => "REPAIR SOFTWARE FIRST",
            Self::ReinstallMacosInPlace => "REINSTALL macOS IN PLACE",
            Self::FirmwareOrHardwareFirst => "DFU REVIVE / HARDWARE FIRST",
            Self::CollectMoreEvidence => "COLLECT MORE EVIDENCE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanInstallStatus {
    NotIndicated,
    NotYetJustified,
    Blocked,
}

impl CleanInstallStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::NotIndicated => "NOT INDICATED",
            Self::NotYetJustified => "NOT YET JUSTIFIED",
            Self::Blocked => "BLOCKED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// A conservative recovery disposition. It recommends the next recovery tier;
/// it never performs or authorizes an erase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryAssessment {
    pub recommendation: RecoveryRecommendation,
    pub clean_install: CleanInstallStatus,
    pub confidence: Confidence,
    pub reasons: Vec<String>,
    pub blockers: Vec<String>,
    pub next_steps: Vec<String>,
    pub required_before_clean_install: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    /// Tool name + version, so a saved JSON report is self-describing.
    pub tool: String,
    pub tool_version: String,
    pub generated_at: DateTime<Utc>,
    pub scan_window: String,
    /// Machine-readable bounds of what was scanned (None for snapshot mode).
    pub window_since: Option<DateTime<Utc>>,
    pub window_until: Option<DateTime<Utc>>,
    /// False when any source failed, timed out, or was denied — a consumer must
    /// not treat an incomplete scan with zero findings as a clean bill of health.
    pub complete: bool,
    pub host: HostInfo,
    pub vitals: Vec<Vital>,
    pub findings: Vec<Finding>,
    pub skipped: Vec<Skipped>,
    pub notes: Vec<String>,
    /// Present on full scans. Snapshot/watch reports omit it because they do not
    /// collect enough historical evidence for a recovery decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryAssessment>,
    pub stats: Stats,
    /// Every unified-log line that matched a rule, chronological. JSON-only
    /// (terminal/HTML reports keep the 3-excerpt evidence); empty when the
    /// unified-log pass did not run (snapshot, watch, --no-log).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub log_events: Vec<LogEvent>,
}

pub const TOOL_NAME: &str = "mactriage";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

impl Report {
    pub fn worst(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    pub fn actionable_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity != Severity::Info)
            .count()
    }

    pub fn overall_condition(&self) -> OverallCondition {
        match self.worst() {
            Some(Severity::Critical) => OverallCondition::Critical,
            Some(Severity::High) => OverallCondition::Serious,
            Some(Severity::Medium) => OverallCondition::Degraded,
            Some(Severity::Low) => OverallCondition::Minor,
            None | Some(Severity::Info) if self.complete => OverallCondition::Healthy,
            None | Some(Severity::Info) => OverallCondition::Unknown,
        }
    }

    pub fn exit_code(&self) -> i32 {
        self.worst().map(|s| s.exit_code()).unwrap_or(0)
    }

    /// Sort by severity desc, then most recent first; cap per category unless --full.
    pub fn finalize(&mut self, cap_per_category: Option<usize>) {
        self.findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(b.timestamp.cmp(&a.timestamp))
        });
        if let Some(cap) = cap_per_category {
            let mut seen: std::collections::HashMap<String, usize> = Default::default();
            let mut dropped: std::collections::HashMap<String, usize> = Default::default();
            self.findings.retain(|f| {
                let n = seen.entry(f.category.clone()).or_insert(0);
                *n += 1;
                if *n > cap {
                    *dropped.entry(f.category.clone()).or_insert(0) += 1;
                    false
                } else {
                    true
                }
            });
            for (cat, n) in dropped {
                self.notes.push(format!(
                    "{n} more {cat} findings hidden — use --full to see all"
                ));
            }
        }
    }
}
