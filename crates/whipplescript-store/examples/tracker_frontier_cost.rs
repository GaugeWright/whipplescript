//! What a content-addressed frontier would cost the tracker projection.
//!
//! The open question from G4 in `spec/output-attribution-research-note.md`:
//! `project_tracker_issues` runs on EVERY rule pass and projects each ready
//! item as a `tracker.issue.ready` fact carrying no version identity. Giving a
//! reader the frontier it observed means a `state_token` per item, and that is
//! an event fold per item (`issue_conflicts` → `load_issue_events` +
//! `analyze_issue_dag`) rather than a column read.
//!
//! So this measures the real path at several shapes rather than reasoning about
//! it: the projection's current read (`list_items`) against the same read plus
//! one `issue_conflicts` per returned item.
//!
//! Usage: cargo run -p whipplescript-store --features native \
//!          --example tracker_frontier_cost
//!
//! File-backed with WAL, because that is what production runs; an in-memory
//! store would flatter the fold by removing the page cache from the question.

use std::time::Instant;

use serde_json::json;
use whipplescript_store::items::WorkItemStore;

/// Median of a small sample, which is what a per-pass cost wants: one run
/// competing with a background job is not the number an operator lives with.
fn median(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(|a, b| a.partial_cmp(b).expect("no NaN timings"));
    samples[samples.len() / 2]
}

fn build(items: usize, events_per_item: usize) -> (tempdir::Guard, WorkItemStore) {
    let guard = tempdir::Guard::new();
    let mut store = WorkItemStore::open(guard.path().join("items.sqlite")).expect("open");
    for index in 0..items {
        let filed = store
            .file_item(
                "q",
                &format!("item {index}"),
                "",
                &[],
                &json!({}),
                Some("filer"),
            )
            .expect("file");
        // `issue.created` is one event; the rest accumulate as field sets, the
        // shape an issue actually grows by.
        for event in 1..events_per_item {
            store
                .set_field(&filed.id, "note", &format!("v{event}"))
                .expect("set field");
        }
    }
    (guard, store)
}

fn measure(items: usize, events_per_item: usize, rounds: usize) {
    let (_guard, store) = build(items, events_per_item);

    let mut baseline = Vec::with_capacity(rounds);
    let mut with_frontier = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let start = Instant::now();
        let listed = store.list_items(Some("q"), None).expect("list");
        baseline.push(start.elapsed().as_secs_f64() * 1000.0);
        assert_eq!(listed.len(), items);

        let start = Instant::now();
        let listed = store.list_items(Some("q"), None).expect("list");
        let mut tokens = 0usize;
        for item in &listed {
            if store
                .issue_conflicts(&item.id)
                .expect("conflicts")
                .is_some()
            {
                tokens += 1;
            }
        }
        with_frontier.push(start.elapsed().as_secs_f64() * 1000.0);
        assert_eq!(tokens, items);
    }

    let base = median(baseline);
    let full = median(with_frontier);
    println!(
        "{items:>5} items x {events_per_item:>4} events   \
         list {base:>8.3} ms   list+frontier {full:>9.3} ms   \
         added {:>9.3} ms   x{:>6.1}   per-item {:>7.4} ms",
        full - base,
        if base > 0.0 { full / base } else { f64::NAN },
        (full - base) / items as f64,
    );
}

fn main() {
    println!("tracker projection: cost of a content-addressed frontier per pass");
    println!("(median of 5 rounds; file-backed WAL store)\n");
    for &(items, events) in &[
        (10usize, 5usize),
        (10, 20),
        (10, 100),
        (50, 5),
        (50, 20),
        (50, 100),
        (200, 5),
        (200, 20),
    ] {
        measure(items, events, 5);
    }

    // The shape above is dominated by ONE variable, so isolate it: a single
    // issue, growing. If the fold were linear in its event count this doubles;
    // what it actually does decides whether the projection question is the
    // interesting one.
    println!("\nscaling of one issue's frontier by its event count:");
    let mut previous: Option<(usize, f64)> = None;
    for &events in &[25usize, 50, 100, 200, 400] {
        let (_guard, store) = build(1, events);
        let id = store.list_items(Some("q"), None).expect("list")[0]
            .id
            .clone();
        let samples = (0..5)
            .map(|_| {
                let start = Instant::now();
                store.issue_conflicts(&id).expect("conflicts");
                start.elapsed().as_secs_f64() * 1000.0
            })
            .collect::<Vec<_>>();
        let cost = median(samples);
        let growth = match previous {
            Some((prior_events, prior_cost)) if prior_cost > 0.0 => {
                let event_ratio = (events as f64 / prior_events as f64).ln();
                format!(
                    "  x{:>6.2} cost for x{:.0} events  -> exponent {:>4.2}",
                    cost / prior_cost,
                    events as f64 / prior_events as f64,
                    (cost / prior_cost).ln() / event_ratio,
                )
            }
            _ => String::new(),
        };
        println!("{events:>5} events   {cost:>9.3} ms{growth}");
        previous = Some((events, cost));
    }
}

/// A temp directory that removes itself, so the measurement leaves nothing
/// behind. Deliberately hand-rolled: a dev-dependency would not be available to
/// an example built with `--features native` alone.
mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct Guard {
        path: PathBuf,
    }

    impl Guard {
        pub fn new() -> Self {
            let base = std::env::temp_dir().join(format!(
                "whip-tracker-frontier-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&base).expect("temp dir");
            Self { path: base }
        }

        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
}
