use core::ops::{Add, Mul, Neg, Sub};
use ff::Field;
use group::Group;

use super::{GroupVar, ScalarTerm, ScalarVar, Sum, Term, Weighted};

mod add {
    use super::*;

    /// `+` over the two expression algebras, written once per left operand.
    ///
    /// A scalar-side operand normalizes to `Sum<Weighted<ScalarTerm<G>,
    /// G::Scalar>>` and a group-side one to `Sum<Weighted<Term<G>,
    /// G::Scalar>>` — the `LinearCombination` a relation is built from — and
    /// then the two term lists are concatenated. One body therefore serves
    /// every pair of operand shapes.
    ///
    /// The alternative, an `Add` per ordered pair, is quadratic in the shapes
    /// the operators can produce, and its gaps are silent in both directions:
    /// an expression reaching a pair nobody wrote fails to compile, and a pair
    /// written the other way round — `rhs + self`, to borrow an impl that
    /// exists — silently reverses the terms. Term order is not cosmetic: it is
    /// the order [`compile`][super::super::LinearRelation::compile] emits, and
    /// so the order the instance encoding binds.
    ///
    /// Here the terms are concatenated left to right, always.
    macro_rules! impl_add {
        ($canonical:ty; $($operand:ty),+ $(,)?) => {
            $(
            impl<G: Group, Rhs: Into<$canonical>> Add<Rhs> for $operand {
                type Output = $canonical;

                fn add(self, rhs: Rhs) -> Self::Output {
                    let mut terms = <$canonical>::from(self);
                    terms.0.extend(rhs.into().0);
                    terms
                }
            }
            )+
        };
    }

    impl_add!(
        Sum<Weighted<ScalarTerm<G>, G::Scalar>>;
        ScalarVar<G>,
        ScalarTerm<G>,
        Weighted<ScalarVar<G>, G::Scalar>,
        Weighted<ScalarTerm<G>, G::Scalar>,
        Sum<ScalarVar<G>>,
        Sum<ScalarTerm<G>>,
        Sum<Weighted<ScalarVar<G>, G::Scalar>>,
        Sum<Weighted<ScalarTerm<G>, G::Scalar>>,
    );

    impl_add!(
        Sum<Weighted<Term<G>, G::Scalar>>;
        GroupVar<G>,
        Term<G>,
        Weighted<GroupVar<G>, G::Scalar>,
        Weighted<Term<G>, G::Scalar>,
        Sum<GroupVar<G>>,
        Sum<Term<G>>,
        Sum<Weighted<GroupVar<G>, G::Scalar>>,
        Sum<Weighted<Term<G>, G::Scalar>>,
    );
}

mod mul {
    use super::*;

    impl<G> Mul<ScalarVar<G>> for GroupVar<G> {
        type Output = Term<G>;

        /// Multiply a [ScalarVar] by a [GroupVar] to form a new [Term].
        fn mul(self, rhs: ScalarVar<G>) -> Term<G> {
            Term {
                elem: self,
                scalar: rhs.into(),
            }
        }
    }

    impl<G> Mul<GroupVar<G>> for ScalarVar<G> {
        type Output = Term<G>;

        /// Multiply a [ScalarVar] by a [GroupVar] to form a new [Term].
        fn mul(self, rhs: GroupVar<G>) -> Term<G> {
            rhs * self
        }
    }

    impl<G> Mul<ScalarTerm<G>> for GroupVar<G> {
        type Output = Term<G>;

        fn mul(self, rhs: ScalarTerm<G>) -> Term<G> {
            Term {
                elem: self,
                scalar: rhs,
            }
        }
    }

    impl<G> Mul<GroupVar<G>> for ScalarTerm<G> {
        type Output = Term<G>;

        fn mul(self, rhs: GroupVar<G>) -> Term<G> {
            rhs * self
        }
    }

    impl<Rhs: Clone, Lhs: Mul<Rhs>> Mul<Rhs> for Sum<Lhs> {
        type Output = Sum<<Lhs as Mul<Rhs>>::Output>;

        /// Multiplication of the sum by a term, implemented as a general distributive property.
        fn mul(self, rhs: Rhs) -> Self::Output {
            Sum(self.0.into_iter().map(|x| x * rhs.clone()).collect())
        }
    }

    // NOTE: Rust forbids implementation of foreign traits (e.g. Mul) over bare generic types (e.g. F:
    // Field). It can be implemented over specific types (e.g. curve25519_dalek::Scalar or u64). As a
    // result, this generic implements `var * scalar`, but not `scalar * var`.
    // See issue #66.

    macro_rules! impl_scalar_mul_term {
        ($($type:ty),+) => {
            $(
            // NOTE: Rust does not like this impl when F is replaced by G::Scalar.
            impl<F: Field + Into<G::Scalar>, G: Group> Mul<F> for $type {
                type Output = Weighted<$type, G::Scalar>;

                fn mul(self, rhs: F) -> Self::Output {
                    Weighted {
                        term: self,
                        weight: rhs.into(),
                    }
                }
            }
            )+
        };
    }

    impl_scalar_mul_term!(ScalarVar<G>, ScalarTerm<G>, GroupVar<G>, Term<G>);

    impl<T, F: Field> Mul<F> for Weighted<T, F> {
        type Output = Weighted<T, F>;

        fn mul(self, rhs: F) -> Self::Output {
            Weighted {
                term: self.term,
                weight: self.weight * rhs,
            }
        }
    }

    impl<G: Group> Mul<ScalarVar<G>> for Weighted<GroupVar<G>, G::Scalar> {
        type Output = Weighted<Term<G>, G::Scalar>;

        fn mul(self, rhs: ScalarVar<G>) -> Self::Output {
            Weighted {
                term: self.term * rhs,
                weight: self.weight,
            }
        }
    }

    impl<G: Group> Mul<Weighted<GroupVar<G>, G::Scalar>> for ScalarVar<G> {
        type Output = Weighted<Term<G>, G::Scalar>;

        fn mul(self, rhs: Weighted<GroupVar<G>, G::Scalar>) -> Self::Output {
            rhs * self
        }
    }

    impl<G: Group> Mul<GroupVar<G>> for Weighted<ScalarVar<G>, G::Scalar> {
        type Output = Weighted<Term<G>, G::Scalar>;

        fn mul(self, rhs: GroupVar<G>) -> Self::Output {
            Weighted {
                term: self.term * rhs,
                weight: self.weight,
            }
        }
    }

    impl<G: Group> Mul<Weighted<ScalarVar<G>, G::Scalar>> for GroupVar<G> {
        type Output = Weighted<Term<G>, G::Scalar>;

        fn mul(self, rhs: Weighted<ScalarVar<G>, G::Scalar>) -> Self::Output {
            rhs * self
        }
    }

    impl<G: Group> Mul<ScalarTerm<G>> for Weighted<GroupVar<G>, G::Scalar> {
        type Output = Weighted<Term<G>, G::Scalar>;

        fn mul(self, rhs: ScalarTerm<G>) -> Self::Output {
            Weighted {
                term: self.term * rhs,
                weight: self.weight,
            }
        }
    }

    impl<G: Group> Mul<Weighted<GroupVar<G>, G::Scalar>> for ScalarTerm<G> {
        type Output = Weighted<Term<G>, G::Scalar>;

        fn mul(self, rhs: Weighted<GroupVar<G>, G::Scalar>) -> Self::Output {
            rhs * self
        }
    }

    impl<G: Group> Mul<GroupVar<G>> for Weighted<ScalarTerm<G>, G::Scalar> {
        type Output = Weighted<Term<G>, G::Scalar>;

        fn mul(self, rhs: GroupVar<G>) -> Self::Output {
            Weighted {
                term: self.term * rhs,
                weight: self.weight,
            }
        }
    }

    impl<G: Group> Mul<Weighted<ScalarTerm<G>, G::Scalar>> for GroupVar<G> {
        type Output = Weighted<Term<G>, G::Scalar>;

        fn mul(self, rhs: Weighted<ScalarTerm<G>, G::Scalar>) -> Self::Output {
            rhs * self
        }
    }
}

mod neg {
    use super::*;

    impl<T: Neg> Neg for Sum<T> {
        type Output = Sum<<T as Neg>::Output>;

        /// Negation a sum, implemented as a general distributive property.
        fn neg(self) -> Self::Output {
            Sum(self.0.into_iter().map(|x| x.neg()).collect())
        }
    }

    impl<T, F: Field> Neg for Weighted<T, F> {
        type Output = Weighted<T, F>;

        /// Negation of a weighted term, implemented as negation of its weight.
        fn neg(self) -> Self::Output {
            Weighted {
                term: self.term,
                weight: -self.weight,
            }
        }
    }

    macro_rules! impl_neg_term {
        ($($type:ty),+) => {
            $(
            impl<G: Group> Neg for $type {
                type Output = Weighted<$type, G::Scalar>;

                fn neg(self) -> Self::Output {
                    Weighted {
                        term: self,
                        weight: -G::Scalar::ONE,
                    }
                }
            }
            )+
        };
    }

    impl_neg_term!(ScalarVar<G>, ScalarTerm<G>, GroupVar<G>, Term<G>);
}

mod sub {
    use super::*;

    /// `a - b` is `a + (-b)`, over the same operands [`super::add`] lists.
    macro_rules! impl_sub {
        ($($operand:ty),+ $(,)?) => {
            $(
            impl<G: Group, Rhs> Sub<Rhs> for $operand
            where
                Rhs: Neg,
                Self: Add<<Rhs as Neg>::Output>,
            {
                type Output = <Self as Add<<Rhs as Neg>::Output>>::Output;

                #[allow(clippy::suspicious_arithmetic_impl)]
                fn sub(self, rhs: Rhs) -> Self::Output {
                    self + rhs.neg()
                }
            }
            )+
        };
    }

    impl_sub!(
        ScalarVar<G>,
        ScalarTerm<G>,
        Weighted<ScalarVar<G>, G::Scalar>,
        Weighted<ScalarTerm<G>, G::Scalar>,
        Sum<ScalarVar<G>>,
        Sum<ScalarTerm<G>>,
        Sum<Weighted<ScalarVar<G>, G::Scalar>>,
        Sum<Weighted<ScalarTerm<G>, G::Scalar>>,
        GroupVar<G>,
        Term<G>,
        Weighted<GroupVar<G>, G::Scalar>,
        Weighted<Term<G>, G::Scalar>,
        Sum<GroupVar<G>>,
        Sum<Term<G>>,
        Sum<Weighted<GroupVar<G>, G::Scalar>>,
        Sum<Weighted<Term<G>, G::Scalar>>,
    );
}
