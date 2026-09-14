//! Binary composition preserves both operand order and tree structure.

use alloc::vec;
use core::ops::{BitAnd, BitOr};
use group::prime::PrimeGroup;

use super::{ComposedInstance, ComposedRelation, ComposedWitness, InstanceNode};
use crate::codec::{GroupCodec, ScalarCodec};
use crate::linear_relation::{Instance, LinearRelation};
use crate::MultiScalarMul;

macro_rules! impl_instance_ops {
    ($($operand:ty),+ $(,)?) => {
        $(
        impl<G: PrimeGroup, Rhs: Into<ComposedInstance<G>>> BitAnd<Rhs> for $operand {
            type Output = ComposedInstance<G>;

            fn bitand(self, rhs: Rhs) -> Self::Output {
                ComposedInstance(InstanceNode::And(vec![self.into(), rhs.into()]))
            }
        }

        impl<G: PrimeGroup, Rhs: Into<ComposedInstance<G>>> BitOr<Rhs> for $operand {
            type Output = ComposedInstance<G>;

            fn bitor(self, rhs: Rhs) -> Self::Output {
                ComposedInstance(InstanceNode::Or(vec![self.into(), rhs.into()]))
            }
        }
        )+
    };
}

impl_instance_ops!(Instance<G>, ComposedInstance<G>);

macro_rules! impl_relation_ops {
    ($($operand:ty),+ $(,)?) => {
        $(
        impl<G: PrimeGroup, Rhs: Into<ComposedRelation<G>>> BitAnd<Rhs> for $operand {
            type Output = ComposedRelation<G>;

            fn bitand(self, rhs: Rhs) -> Self::Output {
                ComposedRelation::and([ComposedRelation::from(self), rhs.into()])
            }
        }

        impl<G: PrimeGroup, Rhs: Into<ComposedRelation<G>>> BitOr<Rhs> for $operand {
            type Output = ComposedRelation<G>;

            fn bitor(self, rhs: Rhs) -> Self::Output {
                ComposedRelation::or([ComposedRelation::from(self), rhs.into()])
            }
        }
        )+
    };
}

impl_relation_ops!(LinearRelation<G>, ComposedRelation<G>);

impl<G, Rhs> BitAnd<Rhs> for ComposedWitness<G>
where
    G: PrimeGroup + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec,
    Rhs: Into<Self>,
{
    type Output = Self;

    fn bitand(self, rhs: Rhs) -> Self::Output {
        Self::And(vec![self, rhs.into()])
    }
}

impl<G, Rhs> BitOr<Rhs> for ComposedWitness<G>
where
    G: PrimeGroup + MultiScalarMul + GroupCodec,
    G::Scalar: ScalarCodec,
    Rhs: Into<Self>,
{
    type Output = Self;

    fn bitor(self, rhs: Rhs) -> Self::Output {
        Self::Or(vec![self, rhs.into()])
    }
}
