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
    ($($type:ty),+) => {
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
    Weighted<Term<G>, G::Scalar>
);

impl<T, F: Field> From<Sum<T>> for Sum<Weighted<T, F>> {
    fn from(sum: Sum<T>) -> Self {
        Self(sum.0.into_iter().map(|x| x.into()).collect())
    }
}
