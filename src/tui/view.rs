use super::app::{App, ResultTab, Screen};
use crate::report::{CleanInstallStatus, OverallCondition, Report, Severity};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, Gauge, Paragraph, Tabs, Wrap};
use ratatui::Frame;

const ACCENT: Color = Color::Cyan;
const MUTED: Color = Color::DarkGray;

pub fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();
    if area.width < 72 || area.height < 20 {
        let message = Paragraph::new(vec![
            Line::from(Span::styled(
                "MacTriage needs a larger Terminal window",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(format!(
                "Current: {}×{} · Minimum: 72×20",
                area.width, area.height
            )),
        ])
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).title(" MacTriage "));
        frame.render_widget(message, area);
        return;
    }

    match app.screen {
        Screen::Home => render_home(frame, area, app),
        Screen::Running => render_running(frame, area, app),
        Screen::Results => render_results(frame, area, app),
        Screen::Rules => render_rules(frame, area, app),
    }
    if app.show_help {
        render_help(frame, area);
    }
}

fn shell(area: Rect) -> [Rect; 3] {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);
    [chunks[0], chunks[1], chunks[2]]
}

fn render_header(frame: &mut Frame, area: Rect, app: &App, title: &str) {
    let coverage = if app.privileged {
        Span::styled("FULL COVERAGE", Style::default().fg(Color::Green))
    } else {
        Span::styled("REDUCED COVERAGE", Style::default().fg(Color::Yellow))
    };
    let lines = vec![
        Line::from(vec![
            Span::styled(
                format!("MacTriage {}", env!("CARGO_PKG_VERSION")),
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("  ·  {title}  ·  ")),
            // On the title line so a long host line can't push it off-screen.
            coverage,
        ]),
        Line::from(vec![Span::raw(format!(
            "{} · {} · {} GB{} · macOS {} ({})",
            app.host.machine(),
            app.host.chip,
            app.host.memory_gb,
            app.host.storage_suffix(),
            app.host.macos_version,
            app.host.macos_build
        ))]),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn render_footer(frame: &mut Frame, area: Rect, app: &App, keys: &str) {
    let line = Line::from(vec![
        Span::styled(keys, Style::default().fg(ACCENT)),
        Span::raw("  ·  "),
        Span::styled(&app.status, Style::default().fg(MUTED)),
    ]);
    frame.render_widget(
        Paragraph::new(line).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn render_home(frame: &mut Frame, area: Rect, app: &App) {
    let [header, body, footer] = shell(area);
    render_header(frame, header, app, "Choose a scan profile");

    let mut lines = vec![
        Line::from(Span::styled(
            "Scan profiles",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    for (index, profile) in super::app::Profile::ALL.iter().enumerate() {
        let selected = index == app.profile_index;
        let marker = if selected { "▶" } else { " " };
        let style = if selected {
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(
            format!(" {marker} {:<16}  {} ", profile.label(), profile.detail()),
            style,
        )));
        lines.push(Line::from(""));
    }
    lines.extend([
        Line::from(""),
        Line::from(Span::styled(
            "Safety boundary",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("MacTriage collects and explains evidence. It never repairs, erases, restarts,"),
        Line::from("or changes this Mac. Incomplete scans are always labeled and fail closed."),
    ]);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" Dashboard ")),
        body,
    );
    render_footer(
        frame,
        footer,
        app,
        "↑/↓ select  Enter start  l rules  ? help  q quit",
    );
}

fn render_running(frame: &mut Frame, area: Rect, app: &App) {
    let [header, body, footer] = shell(area);
    render_header(frame, header, app, app.selected_profile().label());
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Min(4),
        ])
        .split(body);
    let percent = (app.progress * 100.0).round() as u16;
    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Scan progress "),
        )
        .gauge_style(Style::default().fg(if app.cancelling {
            Color::Yellow
        } else {
            ACCENT
        }))
        .percent(percent.min(100))
        .label(format!("{}%", percent.min(100)));
    frame.render_widget(gauge, chunks[0]);

    let elapsed = app.elapsed();
    let detail = vec![
        Line::from(vec![
            Span::styled("Phase    ", Style::default().fg(MUTED)),
            Span::raw(&app.progress_label),
        ]),
        Line::from(vec![
            Span::styled("Elapsed  ", Style::default().fg(MUTED)),
            Span::raw(format!(
                "{}m {:02}s",
                elapsed.as_secs() / 60,
                elapsed.as_secs() % 60
            )),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(detail).block(Block::default().borders(Borders::ALL)),
        chunks[1],
    );
    let note = if app.cancelling {
        "Cancellation requested. MacTriage is stopping and reaping the active scanner safely."
    } else {
        "The interface stays responsive while the bundled worker scans. Press Esc to cancel safely."
    };
    frame.render_widget(
        Paragraph::new(note)
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Center),
        chunks[2],
    );
    render_footer(frame, footer, app, "Esc cancel  q cancel and quit  ? help");
}

fn render_results(frame: &mut Frame, area: Rect, app: &App) {
    let [header, body, footer] = shell(area);
    render_header(frame, header, app, "Results");
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(6)])
        .split(body);
    let selected = ResultTab::ALL
        .iter()
        .position(|tab| *tab == app.result_tab)
        .unwrap_or(0);
    let tabs = Tabs::new(
        ResultTab::ALL
            .iter()
            .map(|tab| Line::from(tab.label()))
            .collect::<Vec<_>>(),
    )
    .select(selected)
    .highlight_style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD))
    .divider(" │ ")
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(tabs, chunks[0]);

    if let Some(report) = app.report.as_ref() {
        match app.result_tab {
            ResultTab::Summary => render_summary(frame, chunks[1], report, app.result_scroll),
            ResultTab::Findings => render_findings(
                frame,
                chunks[1],
                report,
                app.selected_finding,
                app.result_scroll,
            ),
            ResultTab::Recovery => render_recovery(frame, chunks[1], report, app.result_scroll),
            ResultTab::Vitals => render_vitals(frame, chunks[1], report, app.result_scroll),
            ResultTab::Coverage => render_coverage(frame, chunks[1], report, app.result_scroll),
        }
    }
    render_footer(
        frame,
        footer,
        app,
        "Tab/←/→ section  j/k findings  PgUp/PgDn scroll  e e export  r rerun  Esc home  q quit",
    );
}

fn render_summary(frame: &mut Frame, area: Rect, report: &Report, scroll: u16) {
    let condition = report.overall_condition();
    let color = match condition {
        OverallCondition::Critical | OverallCondition::Serious => Color::Red,
        OverallCondition::Degraded | OverallCondition::Unknown => Color::Yellow,
        OverallCondition::Minor => Color::Cyan,
        OverallCondition::Healthy => Color::Green,
    };
    let mut lines = vec![
        Line::from(Span::styled(
            format!(" OVERALL: {} ", condition.label()),
            Style::default()
                .fg(Color::Black)
                .bg(color)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(condition.description()),
        Line::from(format!(
            "{} actionable · worst {} · coverage {}",
            report.actionable_count(),
            report
                .worst()
                .filter(|severity| *severity != Severity::Info)
                .map(Severity::label)
                .unwrap_or("none"),
            if report.complete {
                "complete"
            } else {
                "INCOMPLETE"
            }
        )),
        Line::from(""),
    ];
    let attention_count = report.actionable_count();
    if attention_count > 0 {
        lines.push(Line::from(Span::styled(
            format!("Needs attention ({attention_count})"),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )));
        for finding in report
            .findings
            .iter()
            .filter(|finding| finding.severity != Severity::Info)
        {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  {:<11} ", finding.severity.label()),
                    severity_style(finding.severity).add_modifier(Modifier::BOLD),
                ),
                Span::raw(&finding.summary),
            ]));
            if let Some(next_step) = &finding.next_step {
                lines.push(Line::from(vec![
                    Span::styled("    Next: ", Style::default().fg(MUTED)),
                    Span::raw(next_step),
                ]));
            }
        }
        lines.push(Line::from(""));
    }
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let count = report
            .findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .count();
        lines.push(Line::from(format!("  {:<14} {count}", severity.label())));
    }
    lines.extend([
        Line::from(""),
        Line::from(format!("  Window          {}", report.scan_window)),
        Line::from(format!(
            "  Coverage        {}",
            if report.complete {
                "complete"
            } else {
                "INCOMPLETE"
            }
        )),
        Line::from(format!("  Files scanned   {}", report.stats.files_scanned)),
        Line::from(format!("  Log lines       {}", report.stats.log_lines)),
        Line::from(format!("  Duration        {} ms", report.stats.duration_ms)),
    ]);
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((scroll, 0))
            .block(Block::default().borders(Borders::ALL).title(" Verdict "))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_findings(frame: &mut Frame, area: Rect, report: &Report, selected: usize, scroll: u16) {
    if report.findings.is_empty() {
        frame.render_widget(
            Paragraph::new("No findings in the selected scan.")
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL).title(" Findings ")),
            area,
        );
        return;
    }
    let chunks = if area.width >= 100 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(44), Constraint::Percentage(56)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
            .split(area)
    };
    let visible = chunks[0].height.saturating_sub(2) as usize;
    let start = selected.saturating_sub(visible.saturating_sub(1) / 2);
    let end = (start + visible).min(report.findings.len());
    let list = report.findings[start..end]
        .iter()
        .enumerate()
        .map(|(offset, finding)| {
            let index = start + offset;
            let style = if index == selected {
                Style::default().fg(Color::Black).bg(ACCENT)
            } else {
                severity_style(finding.severity)
            };
            Line::from(Span::styled(
                format!(
                    "{} {:<11} {}",
                    if index == selected { "▶" } else { " " },
                    finding.severity.label(),
                    finding.summary
                ),
                style,
            ))
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(list).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Findings ({}) ", report.findings.len())),
        ),
        chunks[0],
    );

    let finding = &report.findings[selected.min(report.findings.len() - 1)];
    let mut detail = vec![
        Line::from(Span::styled(
            &finding.summary,
            severity_style(finding.severity).add_modifier(Modifier::BOLD),
        )),
        Line::from(format!(
            "Rule: {} · Category: {}",
            finding.rule_id, finding.category
        )),
        Line::from(""),
        Line::from(finding.detail.as_str()),
    ];
    if let Some(step) = &finding.next_step {
        detail.extend([
            Line::from(""),
            Line::from(Span::styled(
                "Next step",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(step.as_str()),
        ]);
    }
    if !finding.evidence.is_empty() {
        detail.extend([
            Line::from(""),
            Line::from(Span::styled(
                "Evidence",
                Style::default().add_modifier(Modifier::BOLD),
            )),
        ]);
        for evidence in &finding.evidence {
            detail.push(Line::from(format!(
                "• {}{}",
                evidence.source,
                if evidence.excerpt.is_empty() {
                    String::new()
                } else {
                    format!(" — {}", evidence.excerpt)
                }
            )));
        }
    }
    frame.render_widget(
        Paragraph::new(detail)
            .scroll((scroll, 0))
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title(" Detail ")),
        chunks[1],
    );
}

fn render_recovery(frame: &mut Frame, area: Rect, report: &Report, scroll: u16) {
    let lines = match &report.recovery {
        Some(recovery) => {
            let clean_style = match recovery.clean_install {
                CleanInstallStatus::NotIndicated => Style::default().fg(Color::Green),
                CleanInstallStatus::NotYetJustified => Style::default().fg(Color::Yellow),
                CleanInstallStatus::Blocked => Style::default().fg(Color::Red),
            };
            let mut lines = vec![
                Line::from(vec![
                    Span::styled("Recommendation  ", Style::default().fg(MUTED)),
                    Span::styled(
                        recovery.recommendation.label(),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Clean install   ", Style::default().fg(MUTED)),
                    Span::styled(recovery.clean_install.label(), clean_style),
                ]),
                Line::from(format!("Confidence      {}", recovery.confidence.label())),
                Line::from(""),
            ];
            append_section(&mut lines, "Why", &recovery.reasons);
            append_section(&mut lines, "Blockers", &recovery.blockers);
            append_section(&mut lines, "Next steps", &recovery.next_steps);
            append_section(
                &mut lines,
                "Required before any erase",
                &recovery.required_before_clean_install,
            );
            lines
        }
        None => vec![Line::from(
            "Recovery assessment is available only after a full historical scan.",
        )],
    };
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((scroll, 0))
            .wrap(Wrap { trim: true })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Advisory recovery decision "),
            ),
        area,
    );
}

fn append_section<'a>(lines: &mut Vec<Line<'a>>, title: &'a str, items: &'a [String]) {
    if items.is_empty() {
        return;
    }
    lines.push(Line::from(Span::styled(
        title,
        Style::default().add_modifier(Modifier::BOLD),
    )));
    for item in items {
        lines.push(Line::from(format!("  • {item}")));
    }
    lines.push(Line::from(""));
}

fn render_vitals(frame: &mut Frame, area: Rect, report: &Report, scroll: u16) {
    let lines = if report.vitals.is_empty() {
        vec![Line::from("No live vitals were collected.")]
    } else {
        report
            .vitals
            .iter()
            .map(|vital| {
                Line::from(vec![
                    Span::styled(
                        format!("{:<18}", vital.label),
                        vital.flag.map(severity_style).unwrap_or_default(),
                    ),
                    Span::raw(&vital.value),
                ])
            })
            .collect()
    };
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((scroll, 0))
            .wrap(Wrap { trim: true })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Live vitals "),
            ),
        area,
    );
}

fn render_coverage(frame: &mut Frame, area: Rect, report: &Report, scroll: u16) {
    let mut lines = vec![Line::from(vec![
        Span::styled("Status  ", Style::default().fg(MUTED)),
        Span::styled(
            if report.complete {
                "COMPLETE"
            } else {
                "INCOMPLETE"
            },
            Style::default()
                .fg(if report.complete {
                    Color::Green
                } else {
                    Color::Yellow
                })
                .add_modifier(Modifier::BOLD),
        ),
    ])];
    if !report.notes.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Notes",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        for note in &report.notes {
            lines.push(Line::from(format!("  • {note}")));
        }
    }
    if !report.skipped.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Skipped sources",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        for skipped in &report.skipped {
            lines.push(Line::from(format!(
                "  • {} — {}",
                skipped.what, skipped.reason
            )));
        }
    }
    lines.extend([
        Line::from(""),
        Line::from(format!(
            "Files {} · Unparsed {} · Log lines {} · Rules {} · {} ms",
            report.stats.files_scanned,
            report.stats.files_unparsed,
            report.stats.log_lines,
            report.stats.log_rules_run,
            report.stats.duration_ms
        )),
    ]);
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((scroll, 0))
            .wrap(Wrap { trim: true })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Coverage and trust "),
            ),
        area,
    );
}

fn render_rules(frame: &mut Frame, area: Rect, app: &App) {
    let [header, body, footer] = shell(area);
    render_header(frame, header, app, "Detection rules");
    frame.render_widget(
        Paragraph::new(crate::rules::table())
            .scroll((app.rules_scroll, 0))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Rule catalog "),
            ),
        body,
    );
    render_footer(
        frame,
        footer,
        app,
        "j/k scroll  PgUp/PgDn  Esc home  q quit",
    );
}

fn render_help(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(74, 72, area);
    frame.render_widget(Clear, popup);
    let help = Text::from(vec![
        Line::from(Span::styled(
            "MacTriage keyboard help",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("Home       ↑/↓ or j/k select · Enter start · l rules"),
        Line::from("Running    Esc cancels · q cancels then quits"),
        Line::from("Results    Tab or ←/→ sections · j/k findings"),
        Line::from("           PgUp/PgDn scrolls the current section or detail"),
        Line::from("            e twice exports · r reruns · Esc home"),
        Line::from("Everywhere ? toggles help · q quits when no scan is active"),
        Line::from(""),
        Line::from(Span::styled(
            "Coverage",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("Full coverage uses the app launcher's sudo preflight."),
        Line::from("Reduced scans clearly mark privileged sources as skipped."),
        Line::from(""),
        Line::from(Span::styled(
            "Press Esc, ?, or q to close this help window.",
            Style::default().fg(MUTED),
        )),
    ]);
    frame.render_widget(
        Paragraph::new(help)
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title(" Help ")),
        popup,
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn severity_style(severity: Severity) -> Style {
    Style::default().fg(match severity {
        Severity::Critical | Severity::High => Color::Red,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Cyan,
        Severity::Info => MUTED,
    })
}

#[cfg(test)]
mod tests {
    use super::render;
    use crate::report::{
        Finding, Report, Severity, Stats, SCHEMA_VERSION, TOOL_NAME, TOOL_VERSION,
    };
    use crate::tui::app::{App, Screen};
    use chrono::Utc;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn home_renders_at_minimum_supported_size() {
        let backend = TestBackend::new(72, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        let app = App::new(false);
        terminal.draw(|frame| render(frame, &app)).unwrap();
        let visible = terminal.backend().to_string();
        assert!(visible.contains("MacTriage"));
        assert!(visible.contains("Full scan"));
        assert!(visible.contains("REDUCED COVERAGE"));
    }

    #[test]
    fn tiny_terminal_shows_resize_message() {
        let backend = TestBackend::new(50, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        let app = App::new(false);
        terminal.draw(|frame| render(frame, &app)).unwrap();
        assert!(terminal
            .backend()
            .to_string()
            .contains("needs a larger Terminal window"));
    }

    #[test]
    fn summary_displays_every_actionable_finding_and_next_step() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = App::new(false);
        let mut high = Finding::new("test.high", Severity::High, "test", "High risk item");
        high.next_step = Some("Replace the failing cable".into());
        app.report = Some(Report {
            schema_version: SCHEMA_VERSION,
            tool: TOOL_NAME.into(),
            tool_version: TOOL_VERSION.into(),
            generated_at: Utc::now(),
            scan_window: "test window".into(),
            window_since: None,
            window_until: None,
            complete: true,
            host: app.host.clone(),
            vitals: Vec::new(),
            findings: vec![
                Finding::new(
                    "test.critical",
                    Severity::Critical,
                    "test",
                    "Critical risk item",
                ),
                high,
                Finding::new("test.medium", Severity::Medium, "test", "Medium risk item"),
                Finding::new("test.low", Severity::Low, "test", "Low risk item"),
                Finding::new("test.info", Severity::Info, "test", "Informational item"),
            ],
            skipped: Vec::new(),
            notes: Vec::new(),
            recovery: None,
            stats: Stats::default(),
            log_events: vec![],
        });
        app.screen = Screen::Results;

        terminal.draw(|frame| render(frame, &app)).unwrap();
        let visible = terminal.backend().to_string();
        assert!(visible.contains("OVERALL: CRITICAL"));
        assert!(visible.contains("Fatal-level system events were found"));
        assert!(visible.contains("Needs attention (4)"));
        assert!(visible.contains("Critical risk item"));
        assert!(visible.contains("High risk item"));
        assert!(visible.contains("Medium risk item"));
        assert!(visible.contains("Low risk item"));
        assert!(visible.contains("Next: Replace the failing cable"));
        assert!(!visible.contains("Informational item"));
    }
}
