//! Reservations over regions (norm-plane §7, slice R1): what a path selector
//! covers, when two claims overlap, and the conflicts a merged ledger carries.
//!
//! Regions include future members. `dir/**` covers the subtree whether or not
//! a file under it exists yet, a plain path covers itself, and `**` covers
//! everything. A pattern this module cannot resolve covers everything too:
//! an unsupported overlap decision widens conservatively rather than letting
//! two exclusive claims look disjoint.

use serde::{Deserialize, Serialize};

/// What one selector denotes.
enum Region<'a> {
    Everything,
    Subtree(&'a str),
    Path(&'a str),
}

fn region(selector: &str) -> Region<'_> {
    if selector == "**" {
        return Region::Everything;
    }
    if let Some(root) = selector.strip_suffix("/**") {
        if !root.contains('*') {
            return Region::Subtree(root);
        }
    }
    if selector.contains('*') {
        return Region::Everything;
    }
    Region::Path(selector)
}

fn within(path: &str, root: &str) -> bool {
    path == root || path.starts_with(&format!("{root}/"))
}

/// Whether a selector covers a path, existing or not.
pub fn selector_covers(selector: &str, path: &str) -> bool {
    match region(selector) {
        Region::Everything => true,
        Region::Subtree(root) => within(path, root),
        Region::Path(own) => own == path,
    }
}

/// Whether two selectors can name a common path, now or later.
pub fn selectors_overlap(a: &str, b: &str) -> bool {
    match (region(a), region(b)) {
        (Region::Everything, _) | (_, Region::Everything) => true,
        (Region::Subtree(x), Region::Subtree(y)) => within(x, y) || within(y, x),
        (Region::Subtree(root), Region::Path(path))
        | (Region::Path(path), Region::Subtree(root)) => within(path, root),
        (Region::Path(x), Region::Path(y)) => x == y,
    }
}

/// Whether any selector of one claim overlaps any selector of another.
pub fn claims_overlap(a: &[String], b: &[String]) -> bool {
    a.iter()
        .any(|left| b.iter().any(|right| selectors_overlap(left, right)))
}

/// A time as the ledger and hosts write it — `unix:<seconds>` or RFC 3339
/// with a `Z` or numeric offset — as seconds since the epoch. `None` for
/// anything else, which every caller treats conservatively: an unreadable
/// expiry never lets a claim lapse.
pub fn instant(text: &str) -> Option<i64> {
    if let Some(seconds) = text.strip_prefix("unix:") {
        return seconds.parse().ok();
    }
    let bytes = text.as_bytes();
    let number = |from: usize, to: usize| -> Option<i64> {
        text.get(from..to)
            .filter(|digits| digits.bytes().all(|b| b.is_ascii_digit()))?
            .parse()
            .ok()
    };
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    // Skip a fractional second, then read the offset.
    let mut rest = &text[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        rest = &fraction[digits..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            if rest.len() != 6 || rest.as_bytes()[3] != b':' {
                return None;
            }
            sign * (number(20, 22)? * 3600 + number(23, 25)? * 60)
        }
    };
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

/// Whether a claim expiring at `expires` has lapsed at `now`. An unreadable
/// time on either side has not lapsed.
pub fn lapsed(expires: &str, now: &str) -> bool {
    matches!((instant(expires), instant(now)), (Some(expires), Some(now)) if expires <= now)
}

/// What a snapshot shows of a ledger's reservations: every conflict among
/// live claims.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReservationsView {
    pub conflicts: Vec<ReservationConflict>,
}

/// Two live claims whose regions overlap, at least one of them exclusive:
/// both survive, and the conflict names both holders (norm-plane §7).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReservationConflict {
    pub claims: [String; 2],
    pub holders: [String; 2],
    pub statuses: [String; 2],
    pub selectors: [Vec<String>; 2],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instants_read_both_clock_forms_and_nothing_else() {
        assert_eq!(instant("unix:0"), Some(0));
        assert_eq!(instant("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(instant("2026-09-27T12:00:00Z"), Some(1_790_510_400));
        assert_eq!(instant("2026-09-27T14:00:00+02:00"), Some(1_790_510_400));
        assert_eq!(instant("2026-09-27T12:00:00.250Z"), Some(1_790_510_400));
        assert_eq!(instant("2000-02-29T00:00:00Z"), Some(951_782_400));
        for unreadable in [
            "",
            "yesterday",
            "unix:",
            "2026-13-01T00:00:00Z",
            "2026-09-27 12:00:00Z",
            "2026-09-27T12:00:00",
            "2026-09-27T12:00:00.Z",
        ] {
            assert_eq!(instant(unreadable), None, "{unreadable}");
        }
        assert!(lapsed("2026-09-27T12:00:00Z", "unix:1790510400"));
        assert!(!lapsed("2026-09-27T12:00:01Z", "unix:1790510400"));
        assert!(!lapsed("whenever", "unix:1790510400"));
    }

    #[test]
    fn selectors_cover_and_overlap_future_members_and_widen_what_they_cannot_resolve() {
        assert!(selector_covers("src/**", "src/new.py"));
        assert!(selector_covers("src/**", "src"));
        assert!(!selector_covers("src/**", "srcs/a.py"));
        assert!(selector_covers("src/auth.py", "src/auth.py"));
        assert!(!selector_covers("src/auth.py", "src/parser.py"));
        assert!(selector_covers("**", "README.md"));
        assert!(selector_covers("src/*.py", "checks/q0.json"));
        assert!(selectors_overlap("src/**", "src/new.py"));
        assert!(selectors_overlap("src/new.py", "src/**"));
        assert!(selectors_overlap("src/**", "src/deep/**"));
        assert!(!selectors_overlap("src/**", "docs/**"));
        assert!(!selectors_overlap("src/a.py", "src/b.py"));
        assert!(selectors_overlap("src/new.py", "src/new.py"));
        assert!(selectors_overlap("src/*.py", "docs/**"));
        assert!(claims_overlap(
            &["docs/**".into(), "src/new.py".into()],
            &["src/**".into()]
        ));
        assert!(!claims_overlap(&["docs/**".into()], &["src/**".into()]));
    }
}
