//! Terminal report renderer — format matches v0.1.0 output.

use crate::report::{CleanInstallStatus, OverallCondition, Report, Severity};
use crate::util::wrap;
use chrono::Local;

const WIDTH: usize = 100;

pub struct Style {
    color: bool,
}

impl Style {
    pub fn new(no_color_flag: bool) -> Self {
        use std::io::IsTerminal;
        let color = !no_color_flag
            && std::env::var_os("NO_COLOR").is_none()
            && std::io::stdout().is_terminal();
        Style { color }
    }
    fn paint(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn sev_color(&self, sev: Severity, s: &str) -> String {
        let code = match sev {
            Severity::Critical => "1;31",
            Severity::High => "31",
            Severity::Medium => "33",
            Severity::Low => "36",
            Severity::Info => "2",
        };
        self.paint(code, s)
    }
}

pub fn render(report: &Report, style: &Style, verbose: u8, quiet: bool) -> String {
    let mut out = String::new();

    if !quiet {
        header(report, style, &mut out);
        recovery(report, style, &mut out);
        vitals(report, style, &mut out);
    } else {
        // Quiet still needs the verdict line so exit codes aren't the only signal.
        verdict_line(report, style, &mut out, false);
    }

    findings(report, style, verbose, &mut out);

    if !quiet {
        footer(report, style, &mut out);
    }
    out
}

fn header(report: &Report, style: &Style, out: &mut String) {
    let title = format!("mactriage {}", env!("CARGO_PKG_VERSION"));
    let now = Local::now().format("%Y-%m-%d %H:%M").to_string();
    let pad = WIDTH.saturating_sub(title.len() + now.len());
    out.push_str(&format!(
        "{}{}{}\n",
        style.paint("1", &title),
        " ".repeat(pad),
        now
    ));
    let h = &report.host;
    out.push_str(&format!(
        "{} · {} · {} GB{} · macOS {} ({}) · up {}\n",
        h.machine(),
        h.chip,
        h.memory_gb,
        h.storage_suffix(),
        h.macos_version,
        h.macos_build,
        h.uptime
    ));
    out.push_str(&format!(
        "window {} · {}\n\n",
        report.scan_window,
        if h.root {
            "running as root — full coverage".to_string()
        } else {
            "unprivileged — sudo adds coverage".to_string()
        }
    ));
    verdict_line(report, style, out, true);
    out.push('\n');
}

fn verdict_line(report: &Report, style: &Style, out: &mut String, detailed: bool) {
    let mut counts: std::collections::BTreeMap<Severity, usize> = Default::default();
    for f in &report.findings {
        *counts.entry(f.severity).or_insert(0) += 1;
    }
    let actionable = report.actionable_count();
    let condition = report.overall_condition();
    let banner = match condition {
        OverallCondition::Critical => style.paint("1;97;41", condition.label()),
        OverallCondition::Serious => style.paint("1;31", condition.label()),
        OverallCondition::Degraded => style.paint("1;33", condition.label()),
        OverallCondition::Minor => style.paint("1;36", condition.label()),
        OverallCondition::Healthy => style.paint("1;32", condition.label()),
        OverallCondition::Unknown => style.paint("1;33", condition.label()),
    };
    let summary = if actionable == 0 {
        if report.findings.is_empty() {
            "no findings".to_string()
        } else {
            format!("{} informational item(s) only", report.findings.len())
        }
    } else {
        let breakdown = counts
            .iter()
            .rev()
            .filter(|(severity, _)| **severity > Severity::Info)
            .map(|(severity, count)| format!("{count} {}", severity.label().to_lowercase()))
            .collect::<Vec<_>>()
            .join(" · ");
        let info = report.findings.len() - actionable;
        let info_note = if info > 0 {
            format!(" (+{info} info)")
        } else {
            String::new()
        };
        format!("{actionable} actionable — {breakdown}{info_note}")
    };
    out.push_str(&format!("  Overall condition  {banner} · {summary}\n"));
    if detailed {
        out.push_str(&format!("  {}\n", condition.description()));
        if !report.complete && condition != OverallCondition::Unknown {
            out.push_str("  Coverage is incomplete; additional problems may be missing.\n");
        }
    }
}

fn vitals(report: &Report, style: &Style, out: &mut String) {
    if report.vitals.is_empty() {
        return;
    }
    out.push_str("Vitals\n");
    let width = report
        .vitals
        .iter()
        .map(|v| v.label.len())
        .max()
        .unwrap_or(7);
    for v in &report.vitals {
        let dot = match v.flag {
            Some(s) => style.sev_color(s, "●"),
            None => style.paint("2", "●"),
        };
        out.push_str(&format!(
            "  {dot} {:<width$}  {}\n",
            v.label,
            v.value,
            width = width
        ));
    }
    out.push('\n');
}

fn recovery(report: &Report, style: &Style, out: &mut String) {
    let Some(recovery) = &report.recovery else {
        return;
    };
    let clean_install = match recovery.clean_install {
        CleanInstallStatus::NotIndicated => style.paint("1;32", recovery.clean_install.label()),
        CleanInstallStatus::NotYetJustified => style.paint("1;33", recovery.clean_install.label()),
        CleanInstallStatus::Blocked => style.paint("1;31", recovery.clean_install.label()),
    };
    out.push_str("Recovery decision\n");
    out.push_str(&format!(
        "  Recommendation  {}\n",
        style.paint("1", recovery.recommendation.label())
    ));
    out.push_str(&format!("  Clean install   {clean_install}\n"));
    out.push_str(&format!(
        "  Confidence      {}\n",
        recovery.confidence.label()
    ));
    for reason in &recovery.reasons {
        out.push_str(&format!(
            "  Why             {}\n",
            wrap(reason, WIDTH - 18, "                  ")
        ));
    }
    for blocker in &recovery.blockers {
        out.push_str(&format!(
            "  Blocker         {}\n",
            wrap(blocker, WIDTH - 18, "                  ")
        ));
    }
    for step in &recovery.next_steps {
        out.push_str(&format!(
            "  Next            {}\n",
            wrap(step, WIDTH - 18, "                  ")
        ));
    }
    if !recovery.required_before_clean_install.is_empty() {
        out.push_str("  Before erase\n");
        for gate in &recovery.required_before_clean_install {
            out.push_str(&format!("    □ {}\n", wrap(gate, WIDTH - 6, "      ")));
        }
    }
    out.push('\n');
}

fn findings(report: &Report, style: &Style, verbose: u8, out: &mut String) {
    let severities = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
    let mut last_detail = String::new();
    let mut last_step = String::new();
    for sev in severities {
        let group: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == sev)
            .collect();
        if group.is_empty() {
            continue;
        }
        let title = format!("{} ({}) ", sev.label(), group.len());
        let rule = "─".repeat(WIDTH.saturating_sub(title.len()));
        out.push_str(&format!(
            "{}{}\n",
            style.sev_color(sev, &title),
            style.paint("2", &rule)
        ));

        for f in group {
            // Right-aligned time / count column.
            let when = match (f.first_seen, f.timestamp) {
                (Some(a), Some(b)) if f.count > 1 => format!(
                    "×{} · {} → {}",
                    f.count,
                    a.with_timezone(&Local).format("%b %e %H:%M"),
                    b.with_timezone(&Local).format("%b %e %H:%M")
                ),
                (_, Some(b)) => b.with_timezone(&Local).format("%b %e %H:%M").to_string(),
                _ => String::new(),
            };
            let bullet = format!("  ▪ {}", f.summary);
            let pad = WIDTH
                .saturating_sub(bullet.chars().count() + when.len())
                .max(2);
            out.push_str(&format!(
                "{}{}{}\n",
                style.paint("1", &bullet),
                " ".repeat(pad),
                style.paint("2", &when)
            ));

            if !f.detail.is_empty() {
                if f.detail == last_detail {
                    out.push_str("      (same as above)\n");
                } else {
                    out.push_str(&format!("      {}\n", wrap(&f.detail, WIDTH - 6, "      ")));
                    last_detail = f.detail.clone();
                }
            }
            if let Some(step) = &f.next_step {
                if step == &last_step {
                    out.push_str(&format!(
                        "      → same fix as above{}\n",
                        f.process
                            .as_ref()
                            .map(|p| format!(", with {p}"))
                            .unwrap_or_default()
                    ));
                } else {
                    out.push_str(&format!("      → {}\n", wrap(step, WIDTH - 8, "        ")));
                    last_step = step.clone();
                }
            }
            if verbose >= 1 {
                for e in &f.evidence {
                    let line = if e.excerpt.is_empty() {
                        e.source.clone()
                    } else {
                        format!("{} — {}", e.source, e.excerpt)
                    };
                    out.push_str(&format!(
                        "      {}\n",
                        style.paint("2", &wrap(&line, WIDTH - 6, "        "))
                    ));
                }
            }
            out.push('\n');
        }
    }
}

fn footer(report: &Report, style: &Style, out: &mut String) {
    for note in &report.notes {
        out.push_str(&format!("  {}\n", style.paint("2", note)));
    }
    if !report.skipped.is_empty() {
        out.push_str(&format!("{}\n", style.paint("2", "Skipped")));
        for s in &report.skipped {
            out.push_str(&format!(
                "  {}\n",
                style.paint("2", &format!("· {} — {}", s.what, s.reason))
            ));
        }
    }
    out.push_str(&format!(
        "{}\n",
        style.paint(
            "2",
            &format!(
                "{} files · {} log lines · {} ms",
                report.stats.files_scanned, report.stats.log_lines, report.stats.duration_ms
            )
        )
    ));
}
