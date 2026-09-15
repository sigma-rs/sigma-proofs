//! Composition of relation builders, with validation deferred to compilation.

use alloc::vec::Vec;
use group::prime::PrimeGroup;

use super::{ComposedInstance, InstanceNode};
use crate::codec::{GroupCodec, ScalarCodec};
use crate::errors::InvalidInstance;
use crate::{LinearRelation, MultiScalarMul};

/// A builder for AND/OR compositions of [`LinearRelation`] values.
///
/// Use `&` and `|` to compose owned linear or composed relation builders,
/// then call [`compile`][Self::compile] to validate all leaves:
///
/// ```
/// # use curve25519_dalek::RistrettoPoint as G;
/// # use sigma_proofs::LinearRelation;
/// # let a = LinearRelation::<G>::new();
/// # let b = LinearRelation::<G>::new();
/// # let c = LinearRelation::<G>::new();
/// let statement = ((a & b) | c).compile()?;
/// # Ok::<(), sigma_proofs::errors::InvalidInstance>(())
/// ```
///
/// Each operator creates a two-branch node, preserving operand order and
/// nesting. `&` binds more tightly than `|`; repeated operators associate
/// to the left. The [`ComposedWitness`][super::ComposedWitness] must mirror
/// the resulting tree. Variables in separate leaves are independent; use
/// one `LinearRelation` for equations that must share a witness scalar.
#[derive(Clone, Debug)]
pub struct ComposedRelation<G: PrimeGroup>(RelationNode<G>);

#[derive(Clone, Debug)]
enum RelationNode<G: PrimeGroup> {
    Simple(LinearRelation<G>),
    And(Vec<ComposedRelation<G>>),
    Or(Vec<ComposedRelation<G>>),
}

impl<G: PrimeGroup> ComposedRelation<G> {
    /// The AND of the given builders. An empty AND is trivially true.
    pub fn and<T: Into<Self>>(relations: impl IntoIterator<Item = T>) -> Self {
        Self(RelationNode::And(
            relations.into_iter().map(Into::into).collect(),
        ))
    }

    /// The OR of the given builders. An empty OR is trivially false.
    pub fn or<T: Into<Self>>(relations: impl IntoIterator<Item = T>) -> Self {
        Self(RelationNode::Or(
            relations.into_iter().map(Into::into).collect(),
        ))
    }

    /// Compile every leaf into a validated instance, preserving the tree.
    ///
    /// Returns [`InvalidInstance`] if any leaf fails to compile, including
    /// an invalid leaf in an OR whose other branch could be satisfied.
    pub fn compile(&self) -> Result<ComposedInstance<G>, InvalidInstance>
    where
        G: MultiScalarMul + GroupCodec,
        G::Scalar: ScalarCodec,
    {
        let node = match &self.0 {
            RelationNode::Simple(relation) => InstanceNode::Simple(relation.compile()?),
            RelationNode::And(branches) => InstanceNode::And(
                branches
                    .iter()
                    .map(Self::compile)
                    .collect::<Result<_, _>>()?,
            ),
            RelationNode::Or(branches) => InstanceNode::Or(
                branches
                    .iter()
                    .map(Self::compile)
                    .collect::<Result<_, _>>()?,
            ),
        };
        Ok(ComposedInstance(node))
    }
}

impl<G: PrimeGroup> From<LinearRelation<G>> for ComposedRelation<G> {
    fn from(relation: LinearRelation<G>) -> Self {
        Self(RelationNode::Simple(relation))
    }
}
