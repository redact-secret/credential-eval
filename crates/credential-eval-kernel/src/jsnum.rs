//! JavaScript number semantics the protocol depends on.
//!
//! Legacy accounting rounds every published point and bound with
//! `Number(value.toFixed(precision))` (`accounting/shared/primitives.ts:25`).
//! `toFixed` picks the integer `n` minimising `|n / 10^p - x|` over the
//! **exact** binary value of `x`, taking the larger `n` on a tie (ECMA-262
//! `Number.prototype.toFixed`, step 10.a). That is round-half-up on the
//! magnitude, which differs from Rust's `{:.p}` formatting (round-half-even)
//! on exact ties such as `0.0078125` at six places. This module reproduces the
//! JavaScript rule bit for bit.

/// Digits of the exact decimal expansion requested from the formatter. Every
/// finite `f64` has at most 1074 fractional digits, so this is exact.
const EXACT_DIGITS: usize = 1100;

/// `Number(value.toFixed(precision))` (`accounting/shared/primitives.ts:25`).
///
/// Non-finite values and magnitudes `>= 1e21` are returned unchanged, as
/// `toFixed` falls back to `ToString` for them and `Number` parses that back.
pub fn round_to_fixed(value: f64, precision: u32) -> f64 {
    if !value.is_finite() || value.abs() >= 1e21 {
        return value;
    }
    let precision = precision as usize;
    let negative = value < 0.0;
    let exact = format!("{:.*}", EXACT_DIGITS, value.abs());
    let (int_part, frac_part) = exact.split_once('.').unwrap_or((exact.as_str(), ""));
    let mut digits: Vec<u8> = int_part
        .bytes()
        .chain(frac_part.bytes().take(precision))
        .collect();
    let round_up = frac_part
        .as_bytes()
        .get(precision)
        .is_some_and(|d| *d >= b'5');
    if round_up {
        let mut i = digits.len();
        loop {
            if i == 0 {
                digits.insert(0, b'1');
                break;
            }
            i -= 1;
            if digits[i] == b'9' {
                digits[i] = b'0';
            } else {
                digits[i] += 1;
                break;
            }
        }
    }
    let split = digits.len() - precision;
    let mut text = String::with_capacity(digits.len() + 2);
    if negative {
        text.push('-');
    }
    text.push_str(std::str::from_utf8(&digits[..split]).expect("ascii digits"));
    if precision > 0 {
        text.push('.');
        text.push_str(std::str::from_utf8(&digits[split..]).expect("ascii digits"));
    }
    text.parse().expect("decimal literal parses")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ties_round_up_like_javascript() {
        // Exact binary ties: Rust's `{:.6}` would round these to even.
        assert_eq!(round_to_fixed(1.0 / 128.0, 6), 0.007813);
        assert_eq!(round_to_fixed(0.125, 2), 0.13);
        assert_eq!(round_to_fixed(2.5, 0), 3.0);
        assert_eq!(round_to_fixed(-2.5, 0), -3.0);
        // Not a tie in binary: 1.005 is 1.00499999999999989... so it rounds down.
        assert_eq!(round_to_fixed(1.005, 2), 1.0);
        assert_eq!(round_to_fixed(0.9999995, 6), 1.0);
        assert_eq!(round_to_fixed(1.0 / 3.0, 6), 0.333333);
        assert_eq!(round_to_fixed(2.0 / 3.0, 6), 0.666667);
        assert_eq!(round_to_fixed(0.0, 6), 0.0);
        assert_eq!(round_to_fixed(99.99999999, 3), 100.0);
    }

    #[test]
    fn passthrough() {
        assert!(round_to_fixed(f64::NAN, 3).is_nan());
        assert_eq!(round_to_fixed(1e21, 2), 1e21);
    }
}
