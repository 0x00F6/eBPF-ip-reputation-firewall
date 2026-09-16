//! Console styling and terminal output helpers for traffic tools using `pretty-console`.
//!
//! Provides support for bold relevant text and colored output for important messages,
//! with runtime color disabling via the `--no-color` CLI flag or `NO_COLOR` environment variable.

use clap::builder::styling::{AnsiColor, Effects, Styles};

/// Custom Clap CLI styles featuring bold colored headers, cyan flags, and yellow placeholders.
pub const CLAP_STYLING: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .error(AnsiColor::Red.on_default().effects(Effects::BOLD))
    .valid(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .invalid(AnsiColor::Yellow.on_default().effects(Effects::BOLD));

use pretty_console::Console;
use std::sync::atomic::{AtomicBool, Ordering};

static NO_COLOR: AtomicBool = AtomicBool::new(false);

/// Initialize the color subsystem with an explicit CLI flag and standard environment variables.
pub fn init_color(cli_no_color: bool) {
    let env_no_color = is_env_no_color();
    NO_COLOR.store(cli_no_color || env_no_color, Ordering::Relaxed);
}

fn is_env_no_color() -> bool {
    let check = |var: &str| match std::env::var(var) {
        Ok(v) => !v.is_empty() && v != "0" && v.to_lowercase() != "false",
        Err(_) => false,
    };
    check("NO_COLOR") || check("BENCHMARK_NO_COLOR") || check("TEST_TRAFFIC_NO_COLOR")
}

/// Manually enable or disable colors at runtime.
pub fn set_no_color(no_color: bool) {
    NO_COLOR.store(no_color, Ordering::Relaxed);
}

/// Check whether colors and ANSI formatting are currently disabled.
pub fn is_no_color() -> bool {
    NO_COLOR.load(Ordering::Relaxed)
}

/// Render pertinent text in bold (unstyled if colors/styles are disabled).
pub fn bold<T: ToString>(text: T) -> Console {
    let c = Console::new(text.to_string());
    if is_no_color() {
        c
    } else {
        c.bold()
    }
}

/// Render text in green.
pub fn green<T: ToString>(text: T) -> Console {
    let c = Console::new(text.to_string());
    if is_no_color() {
        c
    } else {
        c.green()
    }
}

/// Render text in green and bold.
pub fn green_bold<T: ToString>(text: T) -> Console {
    let c = Console::new(text.to_string());
    if is_no_color() {
        c
    } else {
        c.green().bold()
    }
}

/// Render text in red.
pub fn red<T: ToString>(text: T) -> Console {
    let c = Console::new(text.to_string());
    if is_no_color() {
        c
    } else {
        c.red()
    }
}

/// Render text in red and bold.
pub fn red_bold<T: ToString>(text: T) -> Console {
    let c = Console::new(text.to_string());
    if is_no_color() {
        c
    } else {
        c.red().bold()
    }
}

/// Render text in yellow.
pub fn yellow<T: ToString>(text: T) -> Console {
    let c = Console::new(text.to_string());
    if is_no_color() {
        c
    } else {
        c.yellow()
    }
}

/// Render text in yellow and bold.
pub fn yellow_bold<T: ToString>(text: T) -> Console {
    let c = Console::new(text.to_string());
    if is_no_color() {
        c
    } else {
        c.yellow().bold()
    }
}

/// Render text in cyan.
pub fn cyan<T: ToString>(text: T) -> Console {
    let c = Console::new(text.to_string());
    if is_no_color() {
        c
    } else {
        c.cyan()
    }
}

/// Render text in cyan and bold.
pub fn cyan_bold<T: ToString>(text: T) -> Console {
    let c = Console::new(text.to_string());
    if is_no_color() {
        c
    } else {
        c.cyan().bold()
    }
}

/// Render text in blue.
pub fn blue<T: ToString>(text: T) -> Console {
    let c = Console::new(text.to_string());
    if is_no_color() {
        c
    } else {
        c.blue()
    }
}

/// Render text in blue and bold.
pub fn blue_bold<T: ToString>(text: T) -> Console {
    let c = Console::new(text.to_string());
    if is_no_color() {
        c
    } else {
        c.blue().bold()
    }
}

/// Render text in magenta.
pub fn magenta<T: ToString>(text: T) -> Console {
    let c = Console::new(text.to_string());
    if is_no_color() {
        c
    } else {
        c.magenta()
    }
}

/// Render text in magenta and bold.
pub fn magenta_bold<T: ToString>(text: T) -> Console {
    let c = Console::new(text.to_string());
    if is_no_color() {
        c
    } else {
        c.magenta().bold()
    }
}

/// Render text in bright white and bold.
pub fn white_bold<T: ToString>(text: T) -> Console {
    let c = Console::new(text.to_string());
    if is_no_color() {
        c
    } else {
        c.bright_white().bold()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `NO_COLOR` is a process-global; serialize the tests that mutate it so they
    /// don't clobber each other when the harness runs them concurrently.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_traffic_tools_console_styling() {
        let _guard = TEST_LOCK.lock().unwrap();
        set_no_color(false);
        let b = bold("bold_val").to_string();
        assert!(b.contains("bold_val"));
        assert!(b.contains("\x1b["));

        let gb = green_bold("ok").to_string();
        assert!(gb.contains("ok"));
        assert!(gb.contains("\x1b["));

        let g = green("g").to_string();
        assert!(g.contains("g"));
        let r = red("r").to_string();
        assert!(r.contains("r"));
        let rb = red_bold("rb").to_string();
        assert!(rb.contains("rb"));
        let y = yellow("y").to_string();
        assert!(y.contains("y"));
        let yb = yellow_bold("yb").to_string();
        assert!(yb.contains("yb"));
        let c = cyan("c").to_string();
        assert!(c.contains("c"));
        let cb = cyan_bold("cb").to_string();
        assert!(cb.contains("cb"));
        let bl = blue("bl").to_string();
        assert!(bl.contains("bl"));
        let blb = blue_bold("blb").to_string();
        assert!(blb.contains("blb"));
        let m = magenta("m").to_string();
        assert!(m.contains("m"));
        let mb = magenta_bold("mb").to_string();
        assert!(mb.contains("mb"));
        let wb = white_bold("wb").to_string();
        assert!(wb.contains("wb"));

        set_no_color(true);
        let b_plain = bold("bold_val").to_string();
        assert_eq!(b_plain, "bold_val");
        assert!(!b_plain.contains("\x1b"));

        let gb_plain = green_bold("ok").to_string();
        assert_eq!(gb_plain, "ok");
        assert!(!gb_plain.contains("\x1b"));

        assert_eq!(green("g").to_string(), "g");
        assert_eq!(red("r").to_string(), "r");
        assert_eq!(red_bold("rb").to_string(), "rb");
        assert_eq!(yellow("y").to_string(), "y");
        assert_eq!(yellow_bold("yb").to_string(), "yb");
        assert_eq!(cyan("c").to_string(), "c");
        assert_eq!(cyan_bold("cb").to_string(), "cb");
        assert_eq!(blue("bl").to_string(), "bl");
        assert_eq!(blue_bold("blb").to_string(), "blb");
        assert_eq!(magenta("m").to_string(), "m");
        assert_eq!(magenta_bold("mb").to_string(), "mb");
        assert_eq!(white_bold("wb").to_string(), "wb");

        set_no_color(false);
    }

    #[test]
    fn test_traffic_tools_env_vars() {
        let _guard = TEST_LOCK.lock().unwrap();
        init_color(true);
        assert!(is_no_color());

        init_color(false);
        set_no_color(false);
        assert!(!is_no_color());

        std::env::set_var("BENCHMARK_NO_COLOR", "1");
        init_color(false);
        assert!(is_no_color());
        std::env::remove_var("BENCHMARK_NO_COLOR");

        std::env::set_var("TEST_TRAFFIC_NO_COLOR", "true");
        init_color(false);
        assert!(is_no_color());
        std::env::remove_var("TEST_TRAFFIC_NO_COLOR");

        set_no_color(false);
    }
}
