use core::ops::{Add, Mul};

use super::{GroupVar, LinearCombination, ScalarVar, Term};

impl Add<LinearCombination> for LinearCombination {
    type Output = Self;

    fn add(mut self, mut rhs: LinearCombination) -> Self {
        self.0.append(&mut rhs.0);
        self
    }
}

impl Add<Term> for LinearCombination {
    type Output = LinearCombination;

    fn add(mut self, rhs: Term) -> LinearCombination {
        self.0.push(rhs);
        self
    }
}

impl Add<LinearCombination> for Term {
    type Output = LinearCombination;

    fn add(self, rhs: LinearCombination) -> LinearCombination {
        rhs + self
    }
}

impl Add<Term> for Term {
    type Output = LinearCombination;

    fn add(self, rhs: Term) -> LinearCombination {
        LinearCombination::from(self) + rhs
    }
}

impl Mul<ScalarVar> for GroupVar {
    type Output = Term;

    fn mul(self, rhs: ScalarVar) -> Term {
        Term {
            elem: self,
            scalar: rhs,
        }
    }
}

impl Mul<GroupVar> for ScalarVar {
    type Output = Term;

    fn mul(self, rhs: GroupVar) -> Term {
        rhs * self
    }
}
