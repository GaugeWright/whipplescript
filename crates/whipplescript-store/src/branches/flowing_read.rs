//! Shared retained ref facts. Validation belongs to each owning algorithm.
use super::flowing_fence::FlowingFenceState;
use super::flowing_sources::{
    ContributionBasis, ContributionDeclaration, FlowingSources, HandoffReceipt, PrivateCutPin,
};
use super::{BranchRow, Branches, CutRow};
use crate::StoreResult;

pub(crate) trait Reader {
    fn branch(&self, id: &str) -> StoreResult<Option<BranchRow>>;
    fn cut(&self, id: &str) -> StoreResult<Option<CutRow>>;
    fn fence(&self, id: &str) -> StoreResult<Option<FlowingFenceState>>;
    fn unit(&self, id: &str) -> StoreResult<Option<(ContributionDeclaration, ContributionBasis)>>;
    fn pin(&self, id: &str) -> StoreResult<Option<PrivateCutPin>>;
    fn handoff(&self, id: &str) -> StoreResult<Option<HandoffReceipt>>;
}

pub(crate) struct StoreReader<'a, B>(pub(crate) &'a B);
impl<B: Branches + FlowingSources> Reader for StoreReader<'_, B> {
    fn branch(&self, id: &str) -> StoreResult<Option<BranchRow>> {
        self.0.get_branch(id)
    }
    fn cut(&self, id: &str) -> StoreResult<Option<CutRow>> {
        self.0.get_cut(id)
    }
    fn fence(&self, id: &str) -> StoreResult<Option<FlowingFenceState>> {
        self.0.flowing_source(id)
    }
    fn unit(&self, id: &str) -> StoreResult<Option<(ContributionDeclaration, ContributionBasis)>> {
        Ok(self
            .0
            .contribution_declaration(id)?
            .zip(self.0.contribution_basis(id)?))
    }
    fn pin(&self, id: &str) -> StoreResult<Option<PrivateCutPin>> {
        self.0.private_cut_pin(id)
    }
    fn handoff(&self, id: &str) -> StoreResult<Option<HandoffReceipt>> {
        self.0.contribution_handoff(id)
    }
}

#[cfg(feature = "native")]
pub(crate) struct NativeReader<'a>(pub(crate) &'a rusqlite::Connection);
#[cfg(feature = "native")]
impl Reader for NativeReader<'_> {
    fn branch(&self, id: &str) -> StoreResult<Option<BranchRow>> {
        super::BranchStore::row_by_id(self.0, id)
    }
    fn cut(&self, id: &str) -> StoreResult<Option<CutRow>> {
        super::BranchStore::cut_by_id(self.0, id)
    }
    fn fence(&self, id: &str) -> StoreResult<Option<FlowingFenceState>> {
        super::flowing_fence::native::read_state(self.0, id)
    }
    fn unit(&self, id: &str) -> StoreResult<Option<(ContributionDeclaration, ContributionBasis)>> {
        super::flowing_sources::native::lineage_unit(self.0, id)
    }
    fn pin(&self, id: &str) -> StoreResult<Option<PrivateCutPin>> {
        super::flowing_sources::native::holder_pin(self.0, id)
    }
    fn handoff(&self, id: &str) -> StoreResult<Option<HandoffReceipt>> {
        super::flowing_sources::native::holder_handoff(self.0, id)
    }
}
