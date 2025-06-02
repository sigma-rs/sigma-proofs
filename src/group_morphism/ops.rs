use core::ops::{Add, Mul, Neg, Sub};

use ff::Field;
use group::Group;

use super::{LinearCombination, PointVar, ScalarVar, Term};

impl<G: Group> Neg for Term<G> {
    type Output = Self;

    fn neg(self) -> Self {
        Self {
            weight: -self.weight,
            ..self
        }
    }
}

impl<G: Group> Neg for LinearCombination<G> {
    type Output = LinearCombination<G>;

    fn neg(mut self) -> Self::Output {
        for term in self.0.iter_mut() {
            *term = -*term
        }
        self
    }
}

impl<G: Group> Add<LinearCombination<G>> for LinearCombination<G> {
    type Output = Self;

    fn add(mut self, mut rhs: LinearCombination<G>) -> Self {
        self.0.append(&mut rhs.0);
        self
    }
}

impl<G: Group> Add<Term<G>> for LinearCombination<G> {
    type Output = LinearCombination<G>;

    fn add(mut self, rhs: Term<G>) -> LinearCombination<G> {
        self.0.push(rhs);
        self
    }
}

impl<G: Group> Add<LinearCombination<G>> for Term<G> {
    type Output = LinearCombination<G>;

    fn add(self, rhs: LinearCombination<G>) -> LinearCombination<G> {
        rhs + self
    }
}

impl<G: Group> Add<Term<G>> for Term<G> {
    type Output = LinearCombination<G>;

    fn add(self, rhs: Term<G>) -> LinearCombination<G> {
        LinearCombination::<G>::from(self) + rhs
    }
}

impl<G: Group> Sub<LinearCombination<G>> for LinearCombination<G> {
    type Output = Self;

    fn sub(self, rhs: LinearCombination<G>) -> Self {
        self + (-rhs)
    }
}

impl<G: Group> Sub<Term<G>> for Term<G> {
    type Output = LinearCombination<G>;

    fn sub(self, rhs: Term<G>) -> LinearCombination<G> {
        self + (-rhs)
    }
}

impl<G: Group> Sub<Term<G>> for LinearCombination<G> {
    type Output = LinearCombination<G>;

    fn sub(self, rhs: Term<G>) -> LinearCombination<G> {
        self + (-rhs)
    }
}

impl<G: Group> Sub<LinearCombination<G>> for Term<G> {
    type Output = LinearCombination<G>;

    fn sub(self, rhs: LinearCombination<G>) -> LinearCombination<G> {
        self + (-rhs)
    }
}

// TODO: Find a way to get right-multiplication by a scalar working.
impl<G: Group> Mul<G::Scalar> for Term<G> {
    type Output = Self;

    fn mul(self, rhs: G::Scalar) -> Self {
        Self {
            weight: self.weight * rhs,
            ..self
        }
    }
}

// TODO: Find a way to get right-multiplication by a scalar working.
impl<G: Group> Mul<G::Scalar> for LinearCombination<G> {
    type Output = Self;

    fn mul(mut self, rhs: G::Scalar) -> Self {
        for term in self.0.iter_mut() {
            *term = *term * rhs;
        }
        self
    }
}

impl<G: Group> Mul<ScalarVar> for PointVar<G> {
    type Output = Term<G>;

    fn mul(self, rhs: ScalarVar) -> Term<G> {
        Term {
            scalar: rhs,
            elem: self,
            weight: G::Scalar::ONE,
        }
    }
}

impl<G: Group> Mul<PointVar<G>> for ScalarVar {
    type Output = Term<G>;

    fn mul(self, rhs: PointVar<G>) -> Term<G> {
        rhs * self
    }
}
