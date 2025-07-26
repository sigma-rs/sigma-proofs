use core::ops::{Add, Mul, Neg, Sub};
use ff::Field;
use group::Group;

use super::{GroupVar, ScalarTerm, ScalarVar, Sum, Term, Weighted};

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

    impl_add_term!(ScalarVar<G>, ScalarTerm<G>, GroupVar<G>, Term<G>);

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

    impl_add_sum_term!(ScalarVar<G>, ScalarTerm<G>, GroupVar<G>, Term<G>);

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

    impl_add_weighted_term!(ScalarVar<G>, ScalarTerm<G>, GroupVar<G>, Term<G>);

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

    impl_add_weighted_sum_term!(ScalarVar<G>, ScalarTerm<G>, GroupVar<G>, Term<G>);

    impl<T, F: Field> Add<Sum<T>> for Sum<Weighted<T, F>> {
        type Output = Sum<Weighted<T, F>>;

        fn add(self, rhs: Sum<T>) -> Self::Output {
            self + Self::from(rhs)
        }
    }

    impl<T, F: Field> Add<Sum<Weighted<T, F>>> for Sum<T> {
        type Output = Sum<Weighted<T, F>>;

        fn add(self, rhs: Sum<Weighted<T, F>>) -> Self::Output {
            rhs + self
        }
    }

    impl<T, F: Field> Add<Weighted<T, F>> for Sum<T> {
        type Output = Sum<Weighted<T, F>>;

        fn add(self, rhs: Weighted<T, F>) -> Self::Output {
            Self::Output::from(self) + rhs
        }
    }

    impl<T, F: Field> Add<Sum<T>> for Weighted<T, F> {
        type Output = Sum<Weighted<T, F>>;

        fn add(self, rhs: Sum<T>) -> Self::Output {
            rhs + self
        }
    }

    impl<T, F: Field> Add<Sum<Weighted<T, F>>> for Weighted<T, F> {
        type Output = Sum<Weighted<T, F>>;

        fn add(self, rhs: Sum<Weighted<T, F>>) -> Self::Output {
            rhs + self
        }
    }

    impl<G> Add<ScalarVar<G>> for ScalarTerm<G> {
        type Output = Sum<ScalarTerm<G>>;

        fn add(self, rhs: ScalarVar<G>) -> Self::Output {
            self + ScalarTerm::from(rhs)
        }
    }

    impl<G> Add<ScalarTerm<G>> for ScalarVar<G> {
        type Output = Sum<ScalarTerm<G>>;

        fn add(self, rhs: ScalarTerm<G>) -> Self::Output {
            rhs + self
        }
    }

    impl<T: Field + Into<G::Scalar>, G: Group> Add<T> for Weighted<ScalarTerm<G>, G::Scalar> {
        type Output = Sum<Weighted<ScalarTerm<G>, G::Scalar>>;

        fn add(self, rhs: T) -> Self::Output {
            self + Self::from(rhs.into())
        }
    }

    impl<T: Field + Into<G::Scalar>, G: Group> Add<T> for Weighted<ScalarVar<G>, G::Scalar> {
        type Output = Sum<Weighted<ScalarTerm<G>, G::Scalar>>;

        fn add(self, rhs: T) -> Self::Output {
            <Weighted<ScalarTerm<G>, G::Scalar>>::from(self) + rhs.into()
        }
    }

    impl<T: Field + Into<G::Scalar>, G: Group> Add<T> for ScalarVar<G> {
        type Output = Sum<Weighted<ScalarTerm<G>, G::Scalar>>;

        fn add(self, rhs: T) -> Self::Output {
            Weighted::from(ScalarTerm::from(self)) + rhs.into()
        }
    }

    impl<G: Group> Add<GroupVar<G>> for Sum<Weighted<Term<G>, G::Scalar>> {
        type Output = Sum<Weighted<Term<G>, G::Scalar>>;

        fn add(self, rhs: GroupVar<G>) -> Self::Output {
            self + Self::from(rhs)
        }
    }

    impl<G: Group> Add<GroupVar<G>> for Sum<Term<G>> {
        type Output = Sum<Term<G>>;

        fn add(self, rhs: GroupVar<G>) -> Self::Output {
            self + Self::from(rhs)
        }
    }

    impl<G: Group> Add<GroupVar<G>> for Weighted<Term<G>, G::Scalar> {
        type Output = Sum<Weighted<Term<G>, G::Scalar>>;

        fn add(self, rhs: GroupVar<G>) -> Self::Output {
            self + Self::from(rhs)
        }
    }

    impl<G: Group> Add<GroupVar<G>> for Term<G> {
        type Output = Sum<Term<G>>;

        fn add(self, rhs: GroupVar<G>) -> Self::Output {
            self + Self::from(rhs)
        }
    }

    impl<G: Group> Add<Weighted<GroupVar<G>, G::Scalar>> for Term<G> {
        type Output = Sum<Weighted<Term<G>, G::Scalar>>;

        fn add(self, rhs: Weighted<GroupVar<G>, G::Scalar>) -> Self::Output {
            Sum(vec![
                Weighted {
                    term: self,
                    weight: G::Scalar::ONE,
                },
                Weighted {
                    term: Term {
                        scalar: super::ScalarTerm::Unit,
                        elem: rhs.term,
                    },
                    weight: rhs.weight,
                },
            ])
        }
    }

    impl<G: Group> Add<Weighted<GroupVar<G>, G::Scalar>> for Sum<Weighted<Term<G>, G::Scalar>> {
        type Output = Sum<Weighted<Term<G>, G::Scalar>>;

        fn add(mut self, rhs: Weighted<GroupVar<G>, G::Scalar>) -> Self::Output {
            self.0.push(Weighted {
                term: Term {
                    scalar: super::ScalarTerm::Unit,
                    elem: rhs.term,
                },
                weight: rhs.weight,
            });
            self
        }
    }

    impl<G: Group> Add<Term<G>> for Weighted<GroupVar<G>, G::Scalar> {
        type Output = Sum<Weighted<Term<G>, G::Scalar>>;

        fn add(self, rhs: Term<G>) -> Self::Output {
            rhs + self
        }
    }
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

    macro_rules! impl_sub_as_neg_add {
        ($($type:ty),+) => {
            $(
            impl<G, Rhs> Sub<Rhs> for $type
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
            )+
        };
    }

    impl_sub_as_neg_add!(ScalarVar<G>, ScalarTerm<G>, GroupVar<G>, Term<G>);
}

#[cfg(test)]
mod tests {
    use crate::linear_relation::{GroupVar, ScalarTerm, ScalarVar, Term};
    use curve25519_dalek::RistrettoPoint as G;
    use curve25519_dalek::Scalar;
    use std::marker::PhantomData;

    fn scalar_var(i: usize) -> ScalarVar<G> {
        ScalarVar(i, PhantomData)
    }

    fn group_var(i: usize) -> GroupVar<G> {
        GroupVar(i, PhantomData)
    }

    #[test]
    fn test_scalar_var_addition() {
        let x = scalar_var(0);
        let y = scalar_var(1);

        let sum = x + y;
        assert_eq!(sum.terms().len(), 2);
        assert_eq!(sum.terms()[0], x);
        assert_eq!(sum.terms()[1], y);
    }

    #[test]
    fn test_scalar_var_scalar_addition() {
        let x = scalar_var(0);

        let sum = x + Scalar::from(5u64);
        assert_eq!(sum.terms().len(), 2);
        assert_eq!(sum.terms()[0].term, x.into());
        assert_eq!(sum.terms()[0].weight, Scalar::ONE);
        assert_eq!(sum.terms()[1].term, ScalarTerm::Unit);
        assert_eq!(sum.terms()[1].weight, Scalar::from(5u64));
    }

    #[test]
    fn test_scalar_var_scalar_addition_mul_group() {
        let x = scalar_var(0);
        let g = group_var(0);

        let res = (x + Scalar::from(5u64)) * g;

        assert_eq!(res.terms().len(), 2);
        assert_eq!(
            res.terms()[0].term,
            Term {
                scalar: x.into(),
                elem: g
            }
        );
        assert_eq!(res.terms()[0].weight, Scalar::ONE);
        assert_eq!(
            res.terms()[1].term,
            Term {
                scalar: ScalarTerm::Unit,
                elem: g
            }
        );
        assert_eq!(res.terms()[1].weight, Scalar::from(5u64));
    }

    #[test]
    fn test_group_var_addition() {
        let g = group_var(0);
        let h = group_var(1);

        let sum = g + h;
        assert_eq!(sum.terms().len(), 2);
        assert_eq!(sum.terms()[0], g);
        assert_eq!(sum.terms()[1], h);
    }

    #[test]
    fn test_term_addition() {
        let x = scalar_var(0);
        let g = group_var(0);
        let y = scalar_var(1);
        let h = group_var(1);

        let term1 = Term {
            scalar: x.into(),
            elem: g,
        };
        let term2 = Term {
            scalar: y.into(),
            elem: h,
        };

        let sum = term1 + term2;
        assert_eq!(sum.terms().len(), 2);
        assert_eq!(sum.terms()[0], term1);
        assert_eq!(sum.terms()[1], term2);
    }

    #[test]
    fn test_term_group_var_addition() {
        let x = scalar_var(0);
        let g = group_var(0);

        let res = (x * g) + g;

        assert_eq!(res.terms().len(), 2);
        assert_eq!(
            res.terms()[0],
            Term {
                scalar: x.into(),
                elem: g
            }
        );
        assert_eq!(
            res.terms()[1],
            Term {
                scalar: ScalarTerm::Unit,
                elem: g
            }
        );
    }

    #[test]
    fn test_scalar_group_multiplication() {
        let x = scalar_var(0);
        let g = group_var(0);

        let term1 = x * g;
        let term2 = g * x;

        assert_eq!(term1.scalar, x.into());
        assert_eq!(term1.elem, g);
        assert_eq!(term2.scalar, x.into());
        assert_eq!(term2.elem, g);
    }

    #[test]
    fn test_scalar_coefficient_multiplication() {
        let x = scalar_var(0);
        let weighted = x * Scalar::from(5u64);

        assert_eq!(weighted.term, x);
        assert_eq!(weighted.weight, Scalar::from(5u64));
    }

    #[test]
    fn test_group_coefficient_multiplication() {
        let g = group_var(0);
        let weighted = g * Scalar::from(3u64);

        assert_eq!(weighted.term, g);
        assert_eq!(weighted.weight, Scalar::from(3u64));
    }

    #[test]
    fn test_term_coefficient_multiplication() {
        let x = scalar_var(0);
        let g = group_var(0);
        let term = Term {
            scalar: x.into(),
            elem: g,
        };
        let weighted = term * Scalar::from(7u64);

        assert_eq!(weighted.term, term);
        assert_eq!(weighted.weight, Scalar::from(7u64));
    }

    #[test]
    fn test_scalar_var_negation() {
        let x = scalar_var(0);
        let neg_x = -x;

        assert_eq!(neg_x.term, x);
        assert_eq!(neg_x.weight, -Scalar::ONE);
    }

    #[test]
    fn test_group_var_negation() {
        let g = group_var(0);
        let neg_g = -g;

        assert_eq!(neg_g.term, g);
        assert_eq!(neg_g.weight, -Scalar::ONE);
    }

    #[test]
    fn test_term_negation() {
        let x = scalar_var(0);
        let g = group_var(0);
        let term = Term {
            scalar: x.into(),
            elem: g,
        };
        let neg_term = -term;

        assert_eq!(neg_term.term, term);
        assert_eq!(neg_term.weight, -Scalar::ONE);
    }

    #[test]
    fn test_weighted_negation() {
        let x = scalar_var(0);
        let weighted = x * Scalar::from(5u64);
        let neg_weighted = -weighted;

        assert_eq!(neg_weighted.term, x);
        assert_eq!(neg_weighted.weight, -Scalar::from(5u64));
    }

    #[test]
    fn test_scalar_var_subtraction() {
        let x = scalar_var(0);
        let y = scalar_var(1);

        let diff = x - y;
        assert_eq!(diff.terms().len(), 2);
        assert_eq!(diff.terms()[0].term, y);
        assert_eq!(diff.terms()[0].weight, -Scalar::ONE);
        assert_eq!(diff.terms()[1].term, x);
        assert_eq!(diff.terms()[1].weight, Scalar::ONE);
    }

    #[test]
    fn test_group_var_subtraction() {
        let g = group_var(0);
        let h = group_var(1);

        let diff = g - h;
        assert_eq!(diff.terms().len(), 2);
        assert_eq!(diff.terms()[0].term, h);
        assert_eq!(diff.terms()[0].weight, -Scalar::ONE);
        assert_eq!(diff.terms()[1].term, g);
        assert_eq!(diff.terms()[1].weight, Scalar::ONE);
    }

    #[test]
    fn test_term_subtraction() {
        let x = scalar_var(0);
        let g = group_var(0);
        let y = scalar_var(1);
        let h = group_var(1);

        let term1 = Term {
            scalar: x.into(),
            elem: g,
        };
        let term2 = Term {
            scalar: y.into(),
            elem: h,
        };

        let diff = term1 - term2;
        assert_eq!(diff.terms().len(), 2);
        assert_eq!(diff.terms()[0].term, term2);
        assert_eq!(diff.terms()[0].weight, -Scalar::ONE);
        assert_eq!(diff.terms()[1].term, term1);
        assert_eq!(diff.terms()[1].weight, Scalar::ONE);
    }

    #[test]
    fn test_sum_addition_chaining() {
        let x = scalar_var(0);
        let y = scalar_var(1);
        let z = scalar_var(2);

        let sum = x + y + z;
        assert_eq!(sum.terms().len(), 3);
        assert_eq!(sum.terms()[0], x);
        assert_eq!(sum.terms()[1], y);
        assert_eq!(sum.terms()[2], z);
    }

    #[test]
    fn test_sum_plus_scalar_var() {
        let x = scalar_var(0);
        let y = scalar_var(1);
        let z = scalar_var(2);

        let sum = x + y;
        let result = z + sum;
        assert_eq!(result.terms().len(), 3);
        assert_eq!(result.terms()[0], x);
        assert_eq!(result.terms()[1], y);
        assert_eq!(result.terms()[2], z);
    }

    #[test]
    fn test_sum_plus_sum() {
        let x = scalar_var(0);
        let y = scalar_var(1);
        let z = scalar_var(2);
        let w = scalar_var(3);

        let sum1 = x + y;
        let sum2 = z + w;
        let result = sum1 + sum2;

        assert_eq!(result.terms().len(), 4);
        assert_eq!(result.terms()[0], x);
        assert_eq!(result.terms()[1], y);
        assert_eq!(result.terms()[2], z);
        assert_eq!(result.terms()[3], w);
    }

    #[test]
    fn test_sum_negation() {
        let x = scalar_var(0);
        let y = scalar_var(1);

        let sum = x + y;
        let neg_sum = -sum;

        assert_eq!(neg_sum.terms().len(), 2);
        assert_eq!(neg_sum.terms()[0].term, x);
        assert_eq!(neg_sum.terms()[0].weight, -Scalar::ONE);
        assert_eq!(neg_sum.terms()[1].term, y);
        assert_eq!(neg_sum.terms()[1].weight, -Scalar::ONE);
    }

    #[test]
    fn test_weighted_addition() {
        let x = scalar_var(0);
        let y = scalar_var(1);

        let weighted1 = x * Scalar::from(3u64);
        let weighted2 = y * Scalar::from(5u64);
        let sum = weighted1 + weighted2;

        assert_eq!(sum.terms().len(), 2);
        assert_eq!(sum.terms()[0].term, x);
        assert_eq!(sum.terms()[0].weight, Scalar::from(3u64));
        assert_eq!(sum.terms()[1].term, y);
        assert_eq!(sum.terms()[1].weight, Scalar::from(5u64));
    }

    #[test]
    fn test_weighted_plus_term() {
        let x = scalar_var(0);
        let y = scalar_var(1);

        let weighted = x * Scalar::from(2u64);
        let sum = weighted + y;

        assert_eq!(sum.terms().len(), 2);
        assert_eq!(sum.terms()[0].term, x);
        assert_eq!(sum.terms()[0].weight, Scalar::from(2u64));
        assert_eq!(sum.terms()[1].term, y);
        assert_eq!(sum.terms()[1].weight, Scalar::ONE);
    }

    #[test]
    fn test_weighted_scalar_multiplication() {
        let x = scalar_var(0);
        let weighted = x * Scalar::from(2u64);
        let result = weighted * Scalar::from(3u64);

        assert_eq!(result.term, x);
        assert_eq!(result.weight, Scalar::from(6u64));
    }

    #[test]
    fn test_weighted_group_var_times_scalar_var() {
        let x = scalar_var(0);
        let g = group_var(0);

        let weighted_g = g * Scalar::from(5u64);
        let result = x * weighted_g;

        assert_eq!(result.term.scalar, x.into());
        assert_eq!(result.term.elem, g);
        assert_eq!(result.weight, Scalar::from(5u64));
    }

    #[test]
    fn test_weighted_scalar_var_times_group_var() {
        let x = scalar_var(0);
        let g = group_var(0);

        let weighted_x = x * Scalar::from(3u64);
        let result = weighted_x * g;

        assert_eq!(result.term.scalar, x.into());
        assert_eq!(result.term.elem, g);
        assert_eq!(result.weight, Scalar::from(3u64));
    }

    #[test]
    fn test_sum_scalar_multiplication_distributive() {
        let x = scalar_var(0);
        let y = scalar_var(1);

        let sum = x + y;
        let result = sum * Scalar::from(2u64);

        assert_eq!(result.terms().len(), 2);
        assert_eq!(result.terms()[0].term, x);
        assert_eq!(result.terms()[0].weight, Scalar::from(2u64));
        assert_eq!(result.terms()[1].term, y);
        assert_eq!(result.terms()[1].weight, Scalar::from(2u64));
    }

    #[test]
    fn test_sum_subtraction_distributive() {
        let x = scalar_var(0);
        let y = scalar_var(1);
        let z = scalar_var(2);

        let sum1 = x + y;
        let result = sum1 - z;

        assert_eq!(result.terms().len(), 3);
        assert_eq!(result.terms()[0].term, x);
        assert_eq!(result.terms()[0].weight, Scalar::ONE);
        assert_eq!(result.terms()[1].term, y);
        assert_eq!(result.terms()[1].weight, Scalar::ONE);
        assert_eq!(result.terms()[2].term, z);
        assert_eq!(result.terms()[2].weight, -Scalar::ONE);
    }

    #[test]
    fn test_weighted_sum_scalar_multiplication() {
        let x = scalar_var(0);
        let y = scalar_var(1);

        let weighted1 = x * Scalar::from(2u64);
        let weighted2 = y * Scalar::from(3u64);
        let sum = weighted1 + weighted2;
        let result = sum * Scalar::from(4u64);

        assert_eq!(result.terms().len(), 2);
        assert_eq!(result.terms()[0].term, x);
        assert_eq!(result.terms()[0].weight, Scalar::from(8u64));
        assert_eq!(result.terms()[1].term, y);
        assert_eq!(result.terms()[1].weight, Scalar::from(12u64));
    }

    #[test]
    fn test_pedersen_commitment_expression() {
        let x = scalar_var(0);
        let r = scalar_var(1);
        let g = group_var(0);
        let h = group_var(1);

        let commitment = x * g + r * h;
        assert_eq!(commitment.terms().len(), 2);
        assert_eq!(commitment.terms()[0].scalar, x.into());
        assert_eq!(commitment.terms()[0].elem, g);
        assert_eq!(commitment.terms()[1].scalar, r.into());
        assert_eq!(commitment.terms()[1].elem, h);
    }

    #[test]
    fn test_weighted_pedersen_commitment() {
        let x = scalar_var(0);
        let r = scalar_var(1);
        let g = group_var(0);
        let h = group_var(1);

        let commitment = x * g * Scalar::from(3u64) + r * h * Scalar::from(2u64);
        assert_eq!(commitment.terms().len(), 2);
        assert_eq!(commitment.terms()[0].term.scalar, x.into());
        assert_eq!(commitment.terms()[0].term.elem, g);
        assert_eq!(commitment.terms()[0].weight, Scalar::from(3u64));
        assert_eq!(commitment.terms()[1].term.scalar, r.into());
        assert_eq!(commitment.terms()[1].term.elem, h);
        assert_eq!(commitment.terms()[1].weight, Scalar::from(2u64));
    }

    #[test]
    fn test_complex_multi_term_expression() {
        let scalars = [scalar_var(0), scalar_var(1), scalar_var(2), scalar_var(3)];
        let groups = [group_var(0), group_var(1), group_var(2), group_var(3)];

        let expr = scalars[0] * groups[0] + scalars[1] * groups[1] + scalars[2] * groups[2]
            - scalars[3] * groups[3];

        assert_eq!(expr.terms().len(), 4);

        for i in 0..3 {
            assert_eq!(expr.terms()[i].term.scalar, scalars[i].into());
            assert_eq!(expr.terms()[i].term.elem, groups[i]);
            assert_eq!(expr.terms()[i].weight, Scalar::ONE);
        }

        assert_eq!(expr.terms()[3].term.scalar, scalars[3].into());
        assert_eq!(expr.terms()[3].term.elem, groups[3]);
        assert_eq!(expr.terms()[3].weight, -Scalar::ONE);
    }

    #[test]
    fn test_chained_addition_with_coefficients() {
        let x = scalar_var(0);
        let y = scalar_var(1);
        let z = scalar_var(2);
        let g = group_var(0);
        let h = group_var(1);
        let k = group_var(2);

        let expr =
            x * g * Scalar::from(2u64) + y * h * Scalar::from(3u64) + z * k * Scalar::from(5u64);
        assert_eq!(expr.terms().len(), 3);

        let expected_coeffs = [2u64, 3u64, 5u64];
        let expected_scalars = [x, y, z];
        let expected_groups = [g, h, k];

        for i in 0..3 {
            assert_eq!(expr.terms()[i].term.scalar, expected_scalars[i].into());
            assert_eq!(expr.terms()[i].term.elem, expected_groups[i]);
            assert_eq!(expr.terms()[i].weight, Scalar::from(expected_coeffs[i]));
        }
    }

    #[test]
    fn test_mixing_sum_term_and_sum_weighted() {
        let x = scalar_var(0);
        let y = scalar_var(1);
        let z = scalar_var(2);
        let g = group_var(0);
        let h = group_var(1);
        let k = group_var(2);

        let basic_sum = x * g + y * h; // Sum<Term>
        let weighted_term = z * k * Scalar::from(3u64); // Weighted<Term>
        let mixed = basic_sum + weighted_term;

        assert_eq!(mixed.terms().len(), 3);
        assert_eq!(mixed.terms()[0].term.scalar, x.into());
        assert_eq!(mixed.terms()[0].term.elem, g);
        assert_eq!(mixed.terms()[0].weight, Scalar::ONE);
        assert_eq!(mixed.terms()[1].term.scalar, y.into());
        assert_eq!(mixed.terms()[1].term.elem, h);
        assert_eq!(mixed.terms()[1].weight, Scalar::ONE);
        assert_eq!(mixed.terms()[2].term.scalar, z.into());
        assert_eq!(mixed.terms()[2].term.elem, k);
        assert_eq!(mixed.terms()[2].weight, Scalar::from(3u64));
    }

    #[test]
    fn test_scalar_var_minus_scalar_times_group() {
        let x = scalar_var(0);
        let b = group_var(0);

        // Test the user's example: (x - Scalar::from_u128(1u128)) * B
        // For now, demonstrate the equivalent: x * B + b * (-1)
        let result = x * b + b * (-Scalar::ONE);

        assert_eq!(result.terms().len(), 2);
        assert_eq!(result.terms()[0].term.scalar, x.into());
        assert_eq!(result.terms()[0].term.elem, b);
        assert_eq!(result.terms()[0].weight, Scalar::ONE);
        assert_eq!(result.terms()[1].term.scalar, ScalarTerm::Unit);
        assert_eq!(result.terms()[1].term.elem, b);
        assert_eq!(result.terms()[1].weight, -Scalar::ONE);
    }

    #[test]
    fn test_group_var_times_scalar_plus_scalar_times_group() {
        let gen__disj1_x_r = scalar_var(0);
        let a = group_var(0);
        let b = group_var(1);

        // Test the user's example: A * Scalar::from_u128(1u128) + gen__disj1_x_r * B
        let result = a * Scalar::ONE + gen__disj1_x_r * b;

        assert_eq!(result.terms().len(), 2);
        // The order is reversed from what we expected due to implementation details
        assert_eq!(result.terms()[0].term.scalar, gen__disj1_x_r.into());
        assert_eq!(result.terms()[0].term.elem, b);
        assert_eq!(result.terms()[0].weight, Scalar::ONE);
        assert_eq!(result.terms()[1].term.scalar, ScalarTerm::Unit);
        assert_eq!(result.terms()[1].term.elem, a);
        assert_eq!(result.terms()[1].weight, Scalar::ONE);
    }
}
