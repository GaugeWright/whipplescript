//! A view of admitted evaluations, not a replay of enclosing event sequences.
use super::Journal;

impl Journal {
    /// Select already recorded evaluations through an inclusive frontier.
    /// The enclosing commit may have been published after that frontier.
    /// Facts and effects must be reconstructed separately from the same prefix.
    /// This view cannot establish that a previously unadmitted root existed.
    pub fn at_evaluation(&self, frontier: i64) -> Self {
        let mut selected = self.clone();
        selected.roots.retain(|_, root| root.frontier <= frontier);
        selected.frames.retain(|_, calls| {
            calls.retain(|_, call| call.frontier <= frontier);
            !calls.is_empty()
        });
        selected.regions.retain(|_, regions| {
            regions.retain(|_, history| {
                history.retain_through(frontier);
                history.latest().is_some()
            });
            !regions.is_empty()
        });
        selected
    }
}

#[cfg(test)]
mod tests;
