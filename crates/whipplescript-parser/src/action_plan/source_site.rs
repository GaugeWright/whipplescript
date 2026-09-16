//! Ephemeral compiler join keys. Diagnostic offsets and generated text never
//! identify a checked source statement. These are not durable operation IDs.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Owner {
    Action(String),
    Rule(String),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct SourceSite {
    owner: Owner,
    path: Vec<usize>,
}
impl SourceSite {
    pub fn action(name: &str) -> Self {
        Self {
            owner: Owner::Action(name.into()),
            path: Vec::new(),
        }
    }
    pub fn rule(name: &str) -> Self {
        Self {
            owner: Owner::Rule(name.into()),
            path: Vec::new(),
        }
    }
    /// Alternating statement and child-block indexes. `then` retains its
    /// statement site; entering a callee resets to that definition's root.
    pub fn child(&self, index: usize) -> Self {
        let mut site = self.clone();
        site.path.push(index);
        site
    }
}
