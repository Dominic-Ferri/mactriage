//! --html: self-contained report for tickets / hand-off.

use crate::report::{OverallCondition, Report, Severity};

pub fn render(report: &Report) -> String {
    let mut rows = String::new();
    for f in &report.findings {
        let (badge_bg, badge_fg) = badge_colors(f.severity);
        let when = f
            .timestamp
            .map(|t| {
                t.with_timezone(&chrono::Local)
                    .format("%b %e %H:%M")
                    .to_string()
            })
            .unwrap_or_default();
        let count = if f.count > 1 {
            format!("×{}", f.count)
        } else {
            String::new()
        };
        let evidence = f
            .evidence
            .iter()
            .map(|e| {
                format!(
                    "<div class=\"ev\"><code>{}</code>{}</div>",
                    esc(&e.source),
                    if e.excerpt.is_empty() {
                        String::new()
                    } else {
                        format!(" — {}", esc(&e.excerpt))
                    }
                )
            })
            .collect::<String>();
        rows.push_str(&format!(
            r#"<div class="finding">
  <div class="fhead">
    <span class="badge" style="background:{badge_bg};color:{badge_fg}">{}</span>
    <span class="fsummary">{}</span>
    <span class="fwhen">{count} {when}</span>
  </div>
  <p class="fdetail">{}</p>
  {}
  {}
</div>
"#,
            esc(f.severity.label()),
            esc(&f.summary),
            esc(&f.detail),
            f.next_step
                .as_ref()
                .map(|s| format!("<p class=\"fstep\">→ {}</p>", esc(s)))
                .unwrap_or_default(),
            if evidence.is_empty() {
                String::new()
            } else {
                format!("<details><summary>evidence</summary>{evidence}</details>")
            }
        ));
    }

    let vitals = report
        .vitals
        .iter()
        .map(|v| {
            let dot = match v.flag {
                Some(Severity::High) | Some(Severity::Critical) => "#d33",
                Some(Severity::Medium) => "#d90",
                Some(_) => "#08a",
                None => "#999",
            };
            format!(
                "<div class=\"vital\"><span class=\"dot\" style=\"background:{dot}\"></span><b>{}</b> {}</div>",
                esc(&v.label),
                esc(&v.value)
            )
        })
        .collect::<String>();

    let recovery = report
        .recovery
        .as_ref()
        .map(|r| {
            format!(
                r#"<h2>Recovery decision</h2>
<div class="recovery">
  <p><b>Recommendation:</b> {recommendation}</p>
  <p><b>Clean install:</b> {clean_install} · <b>Confidence:</b> {confidence}</p>
  {reasons}
  {blockers}
  {next_steps}
  {gates}
</div>"#,
                recommendation = esc(r.recommendation.label()),
                clean_install = esc(r.clean_install.label()),
                confidence = esc(r.confidence.label()),
                reasons = list_block("Why", &r.reasons),
                blockers = list_block("Blockers", &r.blockers),
                next_steps = list_block("Next steps", &r.next_steps),
                gates = list_block(
                    "Required before any clean install",
                    &r.required_before_clean_install
                ),
            )
        })
        .unwrap_or_default();

    let skipped = if report.skipped.is_empty() {
        String::new()
    } else {
        format!(
            "<h2>Skipped</h2><ul>{}</ul>",
            report
                .skipped
                .iter()
                .map(|s| format!("<li><b>{}</b> — {}</li>", esc(&s.what), esc(&s.reason)))
                .collect::<String>()
        )
    };

    // Notes carry scan-completeness warnings (timeout, log failure, truncation).
    // Without them an incomplete HTML report can still read as a clean bill of health.
    let notes = if report.notes.is_empty() {
        String::new()
    } else {
        let banner = if report.complete {
            String::new()
        } else {
            "<p class=\"incomplete\">⚠ This scan was incomplete — findings below may be missing.</p>"
                .to_string()
        };
        format!(
            "<h2>Notes</h2>{banner}<ul>{}</ul>",
            report
                .notes
                .iter()
                .map(|n| format!("<li>{}</li>", esc(n)))
                .collect::<String>()
        )
    };

    let h = &report.host;
    let condition = report.overall_condition();
    let condition_color = match condition {
        OverallCondition::Critical => "#d11",
        OverallCondition::Serious => "#d33",
        OverallCondition::Degraded | OverallCondition::Unknown => "#d90",
        OverallCondition::Minor => "#08a",
        OverallCondition::Healthy => "#2a2",
    };
    let worst = report
        .worst()
        .filter(|severity| *severity != Severity::Info)
        .map(Severity::label)
        .unwrap_or("none");

    format!(
        r#"<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mactriage report — {host}</title>
<style>
  body {{ font: 15px/1.5 -apple-system, system-ui, sans-serif; margin: 2rem auto; max-width: 60rem; padding: 0 1rem; color: #222; }}
  @media (prefers-color-scheme: dark) {{ body {{ background:#1b1b1f; color:#ddd; }} .finding, .condition {{ background:#26262b !important; }} code {{ background:#333 !important; }} }}
  h1 {{ font-size: 1.4rem; }} h2 {{ font-size: 1.1rem; margin-top: 2rem; }}
  .meta {{ color: #888; margin: .2rem 0; }}
  .verdict {{ display:inline-block; font-weight:700; color:#fff; background:{vcolor}; padding:.2rem .6rem; border-radius:4px; }}
  .condition {{ background:#f6f6f8; border-left:6px solid {vcolor}; border-radius:8px; padding:.8rem 1rem; margin:1rem 0; }}
  .condition p {{ margin:.2rem 0; }} .condition strong {{ font-size:1.1rem; }}
  .vital {{ margin:.2rem 0; }} .dot {{ display:inline-block; width:.6rem; height:.6rem; border-radius:50%; margin-right:.5rem; }}
  .finding {{ background:#f6f6f8; border-radius:8px; padding: .8rem 1rem; margin: .8rem 0; }}
  .recovery {{ border:2px solid #8885; border-radius:8px; padding:.8rem 1rem; margin:.8rem 0; }}
  .recovery p {{ margin:.25rem 0; }} .recovery ul {{ margin:.25rem 0 .7rem; }}
  .fhead {{ display:flex; gap:.6rem; align-items:baseline; }}
  .badge {{ font-size:.75rem; font-weight:700; padding:.1rem .45rem; border-radius:4px; white-space:nowrap; }}
  .fsummary {{ font-weight:600; flex:1; }}
  .fwhen {{ color:#888; font-size:.85rem; white-space:nowrap; }}
  .fdetail {{ margin:.4rem 0 .2rem; }}
  .fstep {{ margin:.2rem 0; color:#0a6; font-weight:500; }}
  .ev {{ color:#777; font-size:.85rem; margin:.15rem 0; overflow-x:auto; }}
  code {{ background:#eceef0; padding:.05rem .3rem; border-radius:3px; font-size:.85em; }}
  details summary {{ cursor:pointer; color:#888; font-size:.85rem; }}
  .incomplete {{ color:#d33; font-weight:600; }}
</style></head><body>
<h1>mactriage {version} <span class="verdict">{vlabel}</span></h1>
<p class="meta">{machine} · {chip} · {mem} GB{storage} · macOS {ver} ({build}) · up {uptime}</p>
<p class="meta">generated {gen} · window {window} · {privilege}</p>
<div class="condition">
  <p><strong>Overall condition: {vlabel}</strong></p>
  <p>{condition_description}</p>
  <p class="meta">{actionable} actionable · worst {worst} · coverage {coverage}</p>
</div>
<h2>Vitals</h2>
{vitals}
{recovery}
<h2>Findings ({nfind})</h2>
{rows}
{notes}
{skipped}
<p class="meta">{files} files · {loglines} log lines · {ms} ms</p>
</body></html>
"#,
        host = esc(&h.model),
        machine = esc(&h.machine()),
        storage = esc(&h.storage_suffix()),
        vcolor = condition_color,
        vlabel = condition.label(),
        condition_description = esc(condition.description()),
        actionable = report.actionable_count(),
        worst = esc(worst),
        coverage = if report.complete {
            "complete"
        } else {
            "INCOMPLETE"
        },
        version = env!("CARGO_PKG_VERSION"),
        chip = esc(&h.chip),
        mem = h.memory_gb,
        ver = esc(&h.macos_version),
        build = esc(&h.macos_build),
        uptime = esc(&h.uptime),
        gen = report
            .generated_at
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M"),
        window = esc(&report.scan_window),
        privilege = if h.root {
            "root — full coverage"
        } else {
            "unprivileged"
        },
        vitals = vitals,
        recovery = recovery,
        nfind = report.findings.len(),
        rows = rows,
        notes = notes,
        skipped = skipped,
        files = report.stats.files_scanned,
        loglines = report.stats.log_lines,
        ms = report.stats.duration_ms,
    )
}

fn badge_colors(sev: Severity) -> (&'static str, &'static str) {
    match sev {
        Severity::Critical => ("#d11", "#fff"),
        Severity::High => ("#d33", "#fff"),
        Severity::Medium => ("#d90", "#fff"),
        Severity::Low => ("#08a", "#fff"),
        Severity::Info => ("#8886", "#555"),
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn list_block(title: &str, items: &[String]) -> String {
    if items.is_empty() {
        return String::new();
    }
    format!(
        "<p><b>{}</b></p><ul>{}</ul>",
        esc(title),
        items
            .iter()
            .map(|item| format!("<li>{}</li>", esc(item)))
            .collect::<String>()
    )
}
