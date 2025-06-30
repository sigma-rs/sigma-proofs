use core::ops::{Add, Mul, Neg, Sub};
use ff::Field;
use group::Group;

use super::{GroupVar, ScalarVar, Sum, Term, Weighted};

mod add {
    use super::*;

    macro_rules! impl_add_term {
        ($($type:ty),+) => {
            $(
            impl<G> Add<$type> for $type {
                type Output = Sum<$type>;

                fn add(self, rhs: $type) -> Self::Output {
                    Sum(vec![self, rhs])
                }
            }
            )+
        };
    }

    impl_add_term!(ScalarVar<G>, GroupVar<G>, Term<G>);

    impl<T> Add<T> for Sum<T> {
        type Output = Sum<T>;

        fn add(mut self, rhs: T) -> Self::Output {
            self.0.push(rhs);
            self
        }
    }

    macro_rules! impl_add_sum_term {
        ($($type:ty),+) => {
            $(
            impl<G> Add<Sum<$type>> for $type {
                type Output = Sum<$type>;

                fn add(self, rhs: Sum<$type>) -> Self::Output {
                    rhs + self
                }
            }
            )+
        };
    }

    impl_add_sum_term!(ScalarVar<G>, GroupVar<G>, Term<G>);

    impl<T> Add<Sum<T>> for Sum<T> {
        type Output = Sum<T>;

        fn add(mut self, rhs: Sum<T>) -> Self::Output {
            self.0.extend(rhs.0);
            self
        }
    }

    impl<T, F> Add<Weighted<T, F>> for Weighted<T, F> {
        type Output = Sum<Weighted<T, F>>;

        fn add(self, rhs: Weighted<T, F>) -> Self::Output {
            Sum(vec![self, rhs])
        }
    }

    impl<T, F: Field> Add<T> for Weighted<T, F> {
        type Output = Sum<Weighted<T, F>>;

        fn add(self, rhs: T) -> Self::Output {
            Sum(vec![self, rhs.into()])
        }
    }

    macro_rules! impl_add_weighted_term {
        ($($type:ty),+) => {
            $(
            impl<G: Group> Add<Weighted<$type, G::Scalar>> for $type {
                type Output = Sum<Weighted<$type, G::Scalar>>;

                fn add(self, rhs: Weighted<$type, G::Scalar>) -> Self::Output {
                    rhs + self
                }
            }
            )+
        };
    }

    impl_add_weighted_term!(ScalarVar<G>, GroupVar<G>, Term<G>);

    impl<T, F: Field> Add<T> for Sum<Weighted<T, F>> {
        type Output = Sum<Weighted<T, F>>;

        fn add(mut self, rhs: T) -> Self::Output {
            self.0.push(rhs.into());
            self
        }
    }

    macro_rules! impl_add_weighted_sum_term {
        ($($type:ty),+) => {
            $(
            impl<G: Group> Add<Sum<Weighted<$type, G::Scalar>>> for $type {
                type Output = Sum<Weighted<$type, G::Scalar>>;

                fn add(self, rhs: Sum<Weighted<$type, G::Scalar>>) -> Self::Output {
                    rhs + self
                }
            }
            )+
        };
    }

    impl_add_weighted_sum_term!(ScalarVar<G>, GroupVar<G>, Term<G>);
}

mod mul {
    use super::*;

    impl<G> Mul<ScalarVar<G>> for GroupVar<G> {
        type Output = Term<G>;

        /// Multiply a [ScalarVar] by a [GroupVar] to form a new [Term].
        fn mul(self, rhs: ScalarVar<G>) -> Term<G> {
            Term {
                elem: self,
                scalar: rhs,
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

    impl_scalar_mul_term!(ScalarVar<G>, GroupVar<G>, Term<G>);

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

    // TODO: Find a way to negate ScalarVar, GroupVar, and Term. One option would be to make these
    // types generic, such that they carry with them what type they can be multiplied by. Another
    // option is to add a Negated struct, that acts like weighted by specifically for negative one
    // (and without the requirement that the field by known at that point).
}

mod sub {
    use super::*;

    impl<T, Rhs> Sub<Rhs> for Sum<T>
    where
        Rhs: Neg,
        <Rhs as Neg>::Output: Add<Self>,
    {
        type Output = <<Rhs as Neg>::Output as Add<Self>>::Output;

        #[allow(clippy::suspicious_arithmetic_impl)]
        fn sub(self, rhs: Rhs) -> Self::Output {
            rhs.neg() + self
        }
    }

    impl<T, F, Rhs> Sub<Rhs> for Weighted<T, F>
    where
        Rhs: Neg,
        <Rhs as Neg>::Output: Add<Self>,
    {
        type Output = <<Rhs as Neg>::Output as Add<Self>>::Output;

        #[allow(clippy::suspicious_arithmetic_impl)]
        fn sub(self, rhs: Rhs) -> Self::Output {
            rhs.neg() + self
        }
    }

    // TODO: Add additionall impls
}
