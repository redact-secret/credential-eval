//! Timing summaries and the direction rule.

use credential_eval_contracts::performance::{Direction, TimingSummary};

/// Smallest noise band ever applied (5%). Process-spawn timings on a shared
/// host do not resolve smaller differences: the beta.13 perf cards saw 5-20%
/// run-to-run spread on identical code. A band below this is not credible, so
/// a quiet A/A control cannot talk the rule into a direction.
pub const NOISE_FLOOR: f64 = 0.05;

/// Summarize `samples` (nanoseconds). An empty set summarizes to zeros.
pub fn summarize(samples: Vec<u64>) -> TimingSummary {
    let mut sorted = samples.clone();
    sorted.sort_unstable();
    let min_ns = sorted.first().copied().unwrap_or(0);
    let median_ns = match sorted.len() {
        0 => 0,
        n if n % 2 == 1 => sorted[n / 2],
        n => {
            let (low, high) = (sorted[n / 2 - 1], sorted[n / 2]);
            low + (high - low) / 2
        }
    };
    TimingSummary {
        min_ns,
        median_ns,
        samples_ns: samples,
    }
}

/// The comparison of a candidate against a baseline and its A/A control.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Verdict {
    /// `candidate.median / baseline.median`.
    pub median_ratio: f64,
    /// `candidate.min / baseline.min`.
    pub min_ratio: f64,
    /// Half-width of the noise band.
    pub noise_band: f64,
    /// Reported direction.
    pub direction: Direction,
}

fn ratio(numerator: u64, denominator: u64) -> Option<f64> {
    (denominator > 0).then(|| numerator as f64 / denominator as f64)
}

/// Share of rounds, as `numerator / denominator`, in which the candidate must
/// beat its own round's baseline for a direction to be reported (80%). A
/// transient load spike moves a few rounds, not most of them.
const CONSISTENCY: (usize, usize) = (4, 5);

fn consistent(candidate: &[u64], baseline: &[u64], won: impl Fn(u64, u64) -> bool) -> bool {
    let rounds = candidate.len().min(baseline.len());
    let wins = candidate
        .iter()
        .zip(baseline)
        .filter(|(c, b)| won(**c, **b))
        .count();
    rounds > 0 && wins * CONSISTENCY.1 >= rounds * CONSISTENCY.0
}

/// Apply the direction rule.
///
/// The noise band is the larger of the A/A control's median and minimum
/// deviations from the baseline and [`NOISE_FLOOR`]. The candidate is
/// `faster` (or `slower`) only when its median *and* its minimum both clear
/// the band in that direction **and** it beat its own round's baseline in at
/// least 80% of the rounds (samples are kept in round order, and the rotation
/// of arm positions makes each round a fair pair). Anything else, and any run
/// with failed invocations or a zero baseline, is `indistinguishable`.
pub fn verdict(
    baseline: &TimingSummary,
    candidate: &TimingSummary,
    control: &TimingSummary,
    failed_invocations: u32,
) -> Verdict {
    let ratios = (
        ratio(candidate.median_ns, baseline.median_ns),
        ratio(candidate.min_ns, baseline.min_ns),
        ratio(control.median_ns, baseline.median_ns),
        ratio(control.min_ns, baseline.min_ns),
    );
    let (Some(median_ratio), Some(min_ratio), Some(control_median), Some(control_min)) = ratios
    else {
        return Verdict {
            median_ratio: 1.0,
            min_ratio: 1.0,
            noise_band: NOISE_FLOOR,
            direction: Direction::Indistinguishable,
        };
    };
    let noise_band = (control_median - 1.0)
        .abs()
        .max((control_min - 1.0).abs())
        .max(NOISE_FLOOR);
    let direction = if failed_invocations > 0 {
        Direction::Indistinguishable
    } else if median_ratio < 1.0 - noise_band
        && min_ratio < 1.0 - noise_band
        && consistent(&candidate.samples_ns, &baseline.samples_ns, |c, b| c < b)
    {
        Direction::Faster
    } else if median_ratio > 1.0 + noise_band
        && min_ratio > 1.0 + noise_band
        && consistent(&candidate.samples_ns, &baseline.samples_ns, |c, b| c > b)
    {
        Direction::Slower
    } else {
        Direction::Indistinguishable
    };
    Verdict {
        median_ratio,
        min_ratio,
        noise_band,
        direction,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(samples: &[u64]) -> TimingSummary {
        summarize(samples.to_vec())
    }

    #[test]
    fn minimum_and_median() {
        let s = summary(&[5, 1, 9]);
        assert_eq!((s.min_ns, s.median_ns), (1, 5));
        assert_eq!(s.samples_ns, [5, 1, 9], "samples keep round order");
        assert_eq!(summary(&[4, 2, 8, 6]).median_ns, 5);
        assert_eq!(summary(&[]).median_ns, 0);
        assert_eq!(summary(&[u64::MAX, u64::MAX]).median_ns, u64::MAX);
    }

    #[test]
    fn a_clear_gain_beyond_noise_is_faster() {
        let a = summary(&[1000, 1010, 990]);
        let b = summary(&[500, 510, 495]);
        let c = summary(&[1005, 995, 1000]);
        let v = verdict(&a, &b, &c, 0);
        assert_eq!(v.direction, Direction::Faster);
        assert!(v.median_ratio < 0.6 && v.noise_band >= NOISE_FLOOR);
    }

    #[test]
    fn a_clear_loss_beyond_noise_is_slower() {
        let a = summary(&[1000, 1010, 990]);
        let b = summary(&[2000, 2100, 1990]);
        let c = summary(&[1005, 995, 1000]);
        assert_eq!(verdict(&a, &b, &c, 0).direction, Direction::Slower);
    }

    #[test]
    fn a_difference_inside_the_aa_band_is_not_a_direction() {
        // The control itself differs from the baseline by 10%: a 5% gain is noise.
        let a = summary(&[1000, 1000, 1000]);
        let c = summary(&[1100, 1100, 1100]);
        let b = summary(&[950, 950, 950]);
        let v = verdict(&a, &b, &c, 0);
        assert!(v.noise_band >= 0.1 - 1e-9);
        assert_eq!(v.direction, Direction::Indistinguishable);
    }

    #[test]
    fn median_and_minimum_must_agree() {
        let c = summary(&[1000, 1000, 1000]);
        let a = summary(&[1000, 1000, 1000]);
        // The median is 20% slower but the fastest candidate sample is faster.
        let b = summary(&[700, 1200, 1200]);
        let v = verdict(&a, &b, &c, 0);
        assert!(v.median_ratio > 1.1 && v.min_ratio < 0.9);
        assert_eq!(v.direction, Direction::Indistinguishable);
    }

    #[test]
    fn a_direction_needs_most_rounds_to_agree() {
        let c = summary(&[1000; 5]);
        let a = summary(&[1000; 5]);
        // Median and minimum are both 30% faster, but only 3 of 5 rounds
        // (60%) beat their baseline: a transient, not a direction.
        let b = summary(&[700, 700, 700, 1500, 1500]);
        let v = verdict(&a, &b, &c, 0);
        assert!(v.median_ratio < 0.8 && v.min_ratio < 0.8);
        assert_eq!(v.direction, Direction::Indistinguishable);
        // 4 of 5 rounds (80%) is enough.
        let b = summary(&[700, 700, 700, 700, 1500]);
        assert_eq!(verdict(&a, &b, &c, 0).direction, Direction::Faster);
        let b = summary(&[1500, 1500, 1500, 1500, 1100]);
        assert_eq!(verdict(&a, &b, &c, 0).direction, Direction::Slower);
    }

    #[test]
    fn failures_and_zero_baselines_report_no_direction() {
        let a = summary(&[1000; 3]);
        let b = summary(&[100; 3]);
        assert_eq!(
            verdict(&a, &b, &a, 1).direction,
            Direction::Indistinguishable
        );
        let zero = summary(&[0; 3]);
        assert_eq!(
            verdict(&zero, &b, &zero, 0).direction,
            Direction::Indistinguishable
        );
    }
}
