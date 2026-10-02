//! Counting-semantics tests. `harness = false`: libtest would allocate on its
//! own threads while a region is open, and the counters are process-wide.

use redact_secret_alloc::counted;
use redact_secret_alloc::report::rfc3339;

fn main() {
    requests_are_counted_exactly();
    realloc_growth_is_counted_apart();
    repeated_measurements_are_deterministic();
    nothing_outside_the_region_is_counted();
    timestamps_format();
    println!("counting: ok");
}

fn requests_are_counted_exactly() {
    let (boxes, activity) = counted(|| (0..10).map(|i| Box::new(i as u64)).collect::<Vec<_>>());
    // Ten boxes plus the vector's buffer: the vector grows by `collect`'s size hint,
    // so it is one allocation of exactly ten slots.
    assert_eq!(boxes.len(), 10);
    assert_eq!(activity.alloc_requests, 11, "{activity:?}");
    assert_eq!(activity.realloc_requests, 0, "{activity:?}");
    assert_eq!(activity.allocated_bytes, 10 * 8 + 10 * 8, "{activity:?}");
}

fn realloc_growth_is_counted_apart() {
    let (v, activity) = counted(|| {
        let mut v: Vec<u8> = Vec::with_capacity(8);
        v.extend_from_slice(&[0; 64]);
        v
    });
    assert!(v.len() == 64);
    assert_eq!(activity.alloc_requests, 1, "{activity:?}");
    assert_eq!(activity.realloc_requests, 1, "{activity:?}");
    // `allocated_bytes` includes the growth of a realloc (8 + 56).
    assert_eq!(activity.allocated_bytes, 64, "{activity:?}");
    assert_eq!(activity.realloc_net_bytes, 56, "{activity:?}");
}

fn repeated_measurements_are_deterministic() {
    let work = || {
        let mut s = String::new();
        for i in 0..100 {
            s.push_str(&format!("line {i}\n"));
        }
        s.len()
    };
    let (_, first) = counted(work);
    let (_, second) = counted(work);
    assert_eq!(first, second);
    assert!(first.alloc_requests > 100);
}

fn nothing_outside_the_region_is_counted() {
    let before = vec![0_u8; 1 << 16];
    let (_, activity) = counted(|| 1 + 1);
    drop(before);
    assert_eq!(activity.alloc_requests, 0);
    assert_eq!(activity.realloc_requests, 0);
    assert_eq!(activity.allocated_bytes, 0);
}

fn timestamps_format() {
    assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
    assert_eq!(rfc3339(1_000_000_000), "2001-09-09T01:46:40Z");
}
