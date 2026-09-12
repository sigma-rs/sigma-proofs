use alloc::vec;
use alloc::vec::Vec;
use ff::Field;
use group::Group;

use super::{GroupVar, ScalarTerm, ScalarVar, Sum, Term, Weighted};

impl<G> From<ScalarVar<G>> for ScalarTerm<G> {
    fn from(value: ScalarVar<G>) -> Self {
        Self::Var(value)
    }
}

impl<G: Group> From<ScalarVar<G>> for Weighted<ScalarTerm<G>, G::Scalar> {
    fn from(value: ScalarVar<G>) -> Self {
        ScalarTerm::from(value).into()
    }
}

impl<G: Group> From<Weighted<ScalarVar<G>, G::Scalar>> for Weighted<ScalarTerm<G>, G::Scalar> {
    fn from(value: Weighted<ScalarVar<G>, G::Scalar>) -> Self {
        Self {
            term: value.term.into(),
            weight: value.weight,
        }
    }
}

// NOTE: Rust does not accept an impl over From<G::Scalar>
impl<T: Field + Into<G::Scalar>, G: Group> From<T> for Weighted<ScalarTerm<G>, G::Scalar> {
    fn from(value: T) -> Self {
        Self {
            term: ScalarTerm::Unit,
            weight: value.into(),
        }
    }
}

impl<G> From<(ScalarVar<G>, GroupVar<G>)> for Term<G> {
    fn from((scalar, elem): (ScalarVar<G>, GroupVar<G>)) -> Self {
        Self {
            scalar: scalar.into(),
            elem,
        }
    }
}

impl<G> From<(ScalarTerm<G>, GroupVar<G>)> for Term<G> {
    fn from((scalar, elem): (ScalarTerm<G>, GroupVar<G>)) -> Self {
        Self { scalar, elem }
    }
}

impl<G> From<GroupVar<G>> for Term<G> {
    fn from(value: GroupVar<G>) -> Self {
        Term {
            scalar: ScalarTerm::Unit,
            elem: value,
        }
    }
}

impl<G: Group> From<(ScalarVar<G>, GroupVar<G>)> for Weighted<Term<G>, G::Scalar> {
    fn from(pair: (ScalarVar<G>, GroupVar<G>)) -> Self {
        Term::from(pair).into()
    }
}

impl<G: Group> From<(ScalarTerm<G>, GroupVar<G>)> for Weighted<Term<G>, G::Scalar> {
    fn from(pair: (ScalarTerm<G>, GroupVar<G>)) -> Self {
        Term::from(pair).into()
    }
}

impl<G: Group> From<GroupVar<G>> for Weighted<Term<G>, G::Scalar> {
    fn from(value: GroupVar<G>) -> Self {
        Term::from(value).into()
    }
}

impl<G: Group> From<Weighted<GroupVar<G>, G::Scalar>> for Weighted<Term<G>, G::Scalar> {
    fn from(value: Weighted<GroupVar<G>, G::Scalar>) -> Self {
        Weighted {
            term: value.term.into(),
            weight: value.weight,
        }
    }
}

impl<T, F: Field> From<T> for Weighted<T, F> {
    fn from(term: T) -> Self {
        Self {
            term,
            weight: F::ONE,
        }
    }
}

// NOTE: This is implemented directly for each of the key types to avoid collision with the blanket
// Into impl provided by the standard library.
macro_rules! impl_from_for_sum {
    ($($type:ty),+ $(,)?) => {
        $(
        impl<G: Group, T: Into<$type>> From<T> for Sum<$type> {
            fn from(value: T) -> Self {
                Sum(vec![value.into()])
            }
        }

        impl<G: Group, T: Into<$type>> From<Vec<T>> for Sum<$type> {
            fn from(terms: Vec<T>) -> Self {
                Self::from_iter(terms)
            }
        }

        impl<G: Group, T: Into<$type>, const N: usize> From<[T; N]> for Sum<$type> {
            fn from(terms: [T; N]) -> Self {
                Self::from_iter(terms)
            }
        }

        impl<G: Group, T: Into<$type>> FromIterator<T> for Sum<$type> {
            fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
                Self(iter.into_iter().map(|x| x.into()).collect())
            }
        }
        )+
    };
}

impl_from_for_sum!(
    ScalarVar<G>,
    GroupVar<G>,
    Term<G>,
    Weighted<ScalarVar<G>, G::Scalar>,
    Weighted<GroupVar<G>, G::Scalar>,
    Weighted<Term<G>, G::Scalar>,
);

/// Into the scalar algebra's canonical sum.
///
/// Spelled out per source type rather than generated from a
/// `T: Into<Weighted<ScalarTerm<G>, G::Scalar>>` bound the way
/// `impl_from_for_sum!` does, because the field-element conversion above is
/// itself blanket over `T: Field`: a bound like that would overlap `Vec<T>`
/// and `[T; N]`, since nothing rules out a `Field` implemented for those.
macro_rules! impl_from_for_scalar_sum {
    ($($source:ty),+ $(,)?) => {
        $(
        impl<G: Group> From<$source> for Sum<Weighted<ScalarTerm<G>, G::Scalar>> {
            fn from(value: $source) -> Self {
                Sum(vec![value.into()])
            }
        }
        )+
    };
}

impl_from_for_scalar_sum!(
    ScalarVar<G>,
    ScalarTerm<G>,
    Weighted<ScalarVar<G>, G::Scalar>,
    Weighted<ScalarTerm<G>, G::Scalar>,
);

// NOTE: as above, Rust does not accept an impl over `From<G::Scalar>`.
impl<T: Field + Into<G::Scalar>, G: Group> From<T> for Sum<Weighted<ScalarTerm<G>, G::Scalar>> {
    fn from(value: T) -> Self {
        Sum(vec![Weighted::from(value)])
    }
}

impl<T, F: Field> From<Sum<T>> for Sum<Weighted<T, F>> {
    fn from(sum: Sum<T>) -> Self {
        Self(sum.0.into_iter().map(|x| x.into()).collect())
    }
}

/// The remaining routes into a canonical sum: those whose element conversion
/// changes the term type as well as weighting it, which the blanket above
/// cannot express. Together with it, every sum an expression can produce
/// converts to the canonical sum of its algebra, which is what lets
/// [`Add`][core::ops::Add] be written once per operand in [`super::ops`].
macro_rules! impl_from_sum_for_sum {
    ($canonical:ty; $($source:ty),+ $(,)?) => {
        $(
        impl<G: Group> From<Sum<$source>> for Sum<$canonical> {
            fn from(sum: Sum<$source>) -> Self {
                Self(sum.0.into_iter().map(Into::into).collect())
            }
        }
        )+
    };
}

impl_from_sum_for_sum!(
    Weighted<ScalarTerm<G>, G::Scalar>;
    ScalarVar<G>,
    Weighted<ScalarVar<G>, G::Scalar>,
);

impl_from_sum_for_sum!(
    Weighted<Term<G>, G::Scalar>;
    GroupVar<G>,
    Weighted<GroupVar<G>, G::Scalar>,
);
