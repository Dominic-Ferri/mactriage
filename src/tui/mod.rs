mod app;
mod trace;
mod view;

use clap::Args;
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use std::io::IsTerminal;
use std::time::{Duration, Instant};

#[derive(Args, Clone, Debug, Default)]
pub struct UiOpts {
    /// Use the sudo credential preflight performed by MacTriage.app
    #[arg(long, hide = true)]
    pub privileged: bool,
    /// Start the selected full scan immediately after the dashboard opens
    #[arg(long, hide = true)]
    pub autorun: bool,
}

pub fn run(opts: UiOpts) -> std::io::Result<i32> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(std::io::Error::other(
            "the interactive UI needs a real terminal; use the regular CLI for pipes",
        ));
    }
    let mut app = app::App::new(opts.privileged);
    app.trace = trace::Trace::open();
    app.trace.line(format!(
        "mactriage {} ui · macOS {} ({}) · {} · {} · privileged={} · pid {} · TERM_PROGRAM={} TERM={}",
        env!("CARGO_PKG_VERSION"),
        app.host.macos_version,
        app.host.macos_build,
        app.host.model,
        app.host.chip,
        opts.privileged,
        std::process::id(),
        std::env::var("TERM_PROGRAM").unwrap_or_default(),
        std::env::var("TERM").unwrap_or_default(),
    ));
    trace::spawn_watchdog(app.trace.clone(), app.hb.clone());
    if opts.autorun {
        app.start_selected();
    }

    let result = ratatui::run(|terminal| -> std::io::Result<i32> {
        let mut dirty = true;
        let mut last_draw = Instant::now() - Duration::from_secs(1);
        loop {
            app.hb.beat(trace::Stage::Poll);
            dirty |= app.poll_background();
            if app.screen == app::Screen::Running && last_draw.elapsed() >= Duration::from_secs(1) {
                dirty = true;
            }
            if dirty {
                app.hb.beat(trace::Stage::Draw);
                terminal.draw(|frame| view::render(frame, &app))?;
                dirty = false;
                last_draw = Instant::now();
            }
            if app.should_quit() {
                return Ok(app.exit_code());
            }
            app.hb.beat(trace::Stage::Input);
            if event::poll(Duration::from_millis(100))? {
                match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        app.hb.beat(trace::Stage::Key);
                        app.trace
                            .line(format!("key {:?} on {:?}", key.code, app.screen));
                        app.handle_key(key);
                        dirty = true;
                    }
                    Event::Resize(_, _) => dirty = true,
                    _ => {}
                }
            }
        }
    });
    match &result {
        Ok(code) => app.trace.line(format!("dashboard closed, exit {code}")),
        Err(e) => app.trace.line(format!("dashboard error: {e}")),
    }
    if result.is_err() {
        app.cancel_and_reap_worker();
    }
    result
}
