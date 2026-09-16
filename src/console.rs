//! Console styling and terminal output helpers using `pretty-console`.
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
///
/// Disables color if:
/// - `cli_no_color` is true (via `--no-color` argument)
/// - `NO_COLOR` env var is set and not empty, "0", or "false"
/// - `FIREWALL_NO_COLOR` env var is set and not empty, "0", or "false"
pub fn init_color(cli_no_color: bool) {
    let env_no_color = is_env_no_color();
    NO_COLOR.store(cli_no_color || env_no_color, Ordering::Relaxed);
}

fn is_env_no_color() -> bool {
    let check = |var: &str| match std::env::var(var) {
        Ok(v) => !v.is_empty() && v != "0" && v.to_lowercase() != "false",
        Err(_) => false,
    };
    check("NO_COLOR") || check("FIREWALL_NO_COLOR")
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

/// Formats an unsigned integer with space thousand separators (e.g. 3556586 -> "3 556 586", 193490 -> "193 490").
pub fn format_int_with_spaces(mut n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut parts = Vec::new();
    while n > 0 {
        let rem = n % 1000;
        n /= 1000;
        if n > 0 {
            parts.push(format!("{:03}", rem));
        } else {
            parts.push(format!("{}", rem));
        }
    }
    parts.reverse();
    parts.join(" ")
}

/// Formats a signed integer with space thousand separators (e.g. -1234567 -> "-1 234 567").
pub fn format_signed_with_spaces(n: i64) -> String {
    if n < 0 {
        format!("-{}", format_int_with_spaces(n.unsigned_abs()))
    } else {
        format_int_with_spaces(n as u64)
    }
}

/// Formats a floating-point number with space thousand separators on the integer part.
/// e.g. 1310100.06 with decimals=2 -> "1 310 100.06"
pub fn format_float_with_spaces(val: f64, decimals: usize) -> String {
    if val.is_nan() || val.is_infinite() {
        return format!("{val}");
    }
    let sign = if val < 0.0 { "-" } else { "" };
    let abs_val = val.abs();
    let int_part = abs_val.trunc() as u64;
    let formatted_int = format_int_with_spaces(int_part);
    if decimals == 0 {
        format!("{sign}{formatted_int}")
    } else {
        let pow = 10f64.powi(decimals as i32);
        let frac_part = ((abs_val.fract() * pow).round() as u64) % (pow as u64);
        format!(
            "{sign}{formatted_int}.{frac_part:0width$}",
            width = decimals
        )
    }
}

/// Trait for types that can be formatted as numbers with space thousand separators.
pub trait SpacedNumber {
    fn format_spaced(&self) -> String;
}

impl SpacedNumber for usize {
    fn format_spaced(&self) -> String {
        format_int_with_spaces(*self as u64)
    }
}

impl SpacedNumber for u64 {
    fn format_spaced(&self) -> String {
        format_int_with_spaces(*self)
    }
}

impl SpacedNumber for u32 {
    fn format_spaced(&self) -> String {
        format_int_with_spaces(*self as u64)
    }
}

impl SpacedNumber for u16 {
    fn format_spaced(&self) -> String {
        format_int_with_spaces(*self as u64)
    }
}

impl SpacedNumber for u8 {
    fn format_spaced(&self) -> String {
        format_int_with_spaces(*self as u64)
    }
}

impl SpacedNumber for i64 {
    fn format_spaced(&self) -> String {
        format_signed_with_spaces(*self)
    }
}

impl SpacedNumber for i32 {
    fn format_spaced(&self) -> String {
        format_signed_with_spaces(*self as i64)
    }
}

impl SpacedNumber for f64 {
    fn format_spaced(&self) -> String {
        format_float_with_spaces(*self, 2)
    }
}

/// Render a formatted number with space thousand separators in bold.
pub fn bold_num<T: SpacedNumber>(n: T) -> Console {
    bold(n.format_spaced())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_console_styling_enabled_and_disabled() {
        set_no_color(false);
        let b = bold("pertinent_text").to_string();
        assert!(b.contains("\x1b[1m") || b.contains("\x1b["));
        assert!(b.contains("pertinent_text"));

        let gb = green_bold("important_green").to_string();
        assert!(gb.contains("important_green"));
        assert!(gb.contains("\x1b["));

        let rb = red_bold("important_red").to_string();
        assert!(rb.contains("important_red"));
        assert!(rb.contains("\x1b["));

        let g = green("g").to_string();
        assert!(g.contains("g"));
        let r = red("r").to_string();
        assert!(r.contains("r"));
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
        let b_plain = bold("pertinent_text").to_string();
        assert_eq!(b_plain, "pertinent_text");
        assert!(!b_plain.contains("\x1b"));

        let gb_plain = green_bold("important_green").to_string();
        assert_eq!(gb_plain, "important_green");
        assert!(!gb_plain.contains("\x1b"));

        let rb_plain = red_bold("important_red").to_string();
        assert_eq!(rb_plain, "important_red");
        assert!(!rb_plain.contains("\x1b"));

        assert_eq!(green("g").to_string(), "g");
        assert_eq!(red("r").to_string(), "r");
        assert_eq!(yellow("y").to_string(), "y");
        assert_eq!(yellow_bold("yb").to_string(), "yb");
        assert_eq!(cyan("c").to_string(), "c");
        assert_eq!(cyan_bold("cb").to_string(), "cb");
        assert_eq!(blue("bl").to_string(), "bl");
        assert_eq!(blue_bold("blb").to_string(), "blb");
        assert_eq!(magenta("m").to_string(), "m");
        assert_eq!(magenta_bold("mb").to_string(), "mb");
        assert_eq!(white_bold("wb").to_string(), "wb");

        // Reset
        set_no_color(false);
    }

    #[test]
    fn test_format_int_with_spaces() {
        assert_eq!(format_int_with_spaces(0), "0");
        assert_eq!(format_int_with_spaces(5), "5");
        assert_eq!(format_int_with_spaces(999), "999");
        assert_eq!(format_int_with_spaces(1000), "1 000");
        assert_eq!(format_int_with_spaces(193490), "193 490");
        assert_eq!(format_int_with_spaces(3556586), "3 556 586");
        assert_eq!(format_int_with_spaces(4102771), "4 102 771");
    }

    #[test]
    fn test_format_signed_with_spaces() {
        assert_eq!(format_signed_with_spaces(0), "0");
        assert_eq!(format_signed_with_spaces(1234), "1 234");
        assert_eq!(format_signed_with_spaces(-1234567), "-1 234 567");
    }

    #[test]
    fn test_format_float_with_spaces() {
        assert_eq!(format_float_with_spaces(0.0, 2), "0.00");
        assert_eq!(format_float_with_spaces(1234.56, 2), "1 234.56");
        assert_eq!(format_float_with_spaces(-1234.56, 2), "-1 234.56");
        assert_eq!(format_float_with_spaces(3556586.12, 1), "3 556 586.1");
        assert_eq!(format_float_with_spaces(1234.56, 0), "1 234");
        assert_eq!(format_float_with_spaces(f64::NAN, 2), "NaN");
        assert_eq!(format_float_with_spaces(f64::INFINITY, 2), "inf");
    }

    #[test]
    fn test_spaced_number_trait_impls() {
        assert_eq!(1234u64.format_spaced(), "1 234");
        assert_eq!(1234u32.format_spaced(), "1 234");
        assert_eq!(1234u16.format_spaced(), "1 234");
        assert_eq!(250u8.format_spaced(), "250");
        assert_eq!(123456i32.format_spaced(), "123 456");
        assert_eq!((-123456i32).format_spaced(), "-123 456");
        assert_eq!(1234.56f64.format_spaced(), "1 234.56");
    }

    #[test]
    fn test_bold_num() {
        let s = bold_num(3556586usize).to_string();
        assert!(s.contains("3 556 586"));
        assert_eq!(3556586usize.format_spaced(), "3 556 586");
        assert_eq!((-1234567i64).format_spaced(), "-1 234 567");
    }

    #[test]
    fn test_init_color_flag_and_env() {
        init_color(true);
        assert!(is_no_color());

        init_color(false);
        set_no_color(false);
        assert!(!is_no_color());

        std::env::set_var("NO_COLOR", "1");
        init_color(false);
        assert!(is_no_color());
        std::env::remove_var("NO_COLOR");

        std::env::set_var("FIREWALL_NO_COLOR", "true");
        init_color(false);
        assert!(is_no_color());
        std::env::remove_var("FIREWALL_NO_COLOR");

        set_no_color(false);
    }
}
