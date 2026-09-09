//! # Linear maps and relations
//!
//! Utilities for describing and manipulating **linear maps over groups**, the
//! basis of Sigma protocols for group statements such as discrete logarithms
//! and DLEQ proofs (see Maurer09):
//!
//! - [`LinearCombination`]: a sparse representation of scalar multiplication relations.
//! - [`LinearMap`]: a collection of linear combinations acting on group elements.
//! - [`LinearRelation`]: a linear map paired with its image.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::vec::Vec;
use core::iter;
use core::marker::PhantomData;

use crate::codec::{GroupCodec, ScalarCodec};
use crate::errors::InvalidInstance;
use crate::msm::MultiScalarMul;
use ff::Field;
use group::prime::PrimeGroup;

/// Implementations of conversion operations such as From and FromIterator for var and term types.
mod convert;
/// The scalar/element variable, term, and sum expression types.
mod expr;
/// Implementations of core ops for the linear combination types.
mod ops;

/// The validated instance of the sigma-protocols specification.
mod instance;
/// The Sigma protocol and NIZK implementations over the validated instance.
mod protocol;
pub use expr::{GroupVar, ScalarTerm, ScalarVar, Sum, Term, Weighted};
pub use instance::{Equation, Instance};

/// A sparse linear combination of scalars and group elements, such as
/// `w_1 * (s_1 * P_1) + w_2 * (s_2 * P_2) + ... + w_n * (s_n * P_n)`, where:
///
/// - `(s_i * P_i)` are the terms, with `s_i` scalars (referenced by `scalar_vars`)
///   and `P_i` group elements (referenced by `element_vars`);
/// - `w_i` are the constant weights.
///
/// The indices refer to external lists managed by the containing [`LinearMap`].
pub type LinearCombination<G> = Sum<Weighted<Term<G>, <G as group::Group>::Scalar>>;

/// Ordered mapping of [GroupVar] to group elements assignments.
#[derive(Clone, Debug)]
pub struct GroupMap<G>(Vec<Option<G>>);

impl<G: PrimeGroup> GroupMap<G> {
    /// Assigns a group element value to a point variable.
    ///
    /// # Panics
    ///
    /// Panics if the given assignment conflicts with the existing assignment.
    /// The indexing does not: the branch above either grew the map past
    /// `var.0` or established that it was already long enough.
    #[allow(clippy::indexing_slicing)]
    pub fn assign_element(&mut self, var: GroupVar<G>, element: G) {
        if self.0.len() <= var.0 {
            self.0.resize(var.0 + 1, None);
        } else if let Some(assignment) = self.0[var.0] {
            assert_eq!(
                assignment, element,
                "conflicting assignments for var {var:?}"
            )
        }
        self.0[var.0] = Some(element);
    }

    /// Assigns group elements to the given point variables.
    ///
    /// # Panics
    ///
    /// Panics if the collection contains two conflicting assignments for the same variable.
    pub fn assign_elements(&mut self, assignments: impl IntoIterator<Item = (GroupVar<G>, G)>) {
        for (var, elem) in assignments.into_iter() {
            self.assign_element(var, elem);
        }
    }

    /// Returns the element assigned to the given point variable, or
    /// [`InvalidInstance`] if it has none.
    pub fn get(&self, var: GroupVar<G>) -> Result<G, InvalidInstance> {
        match self.0.get(var.0) {
            Some(Some(elem)) => Ok(*elem),
            Some(None) | None => Err(InvalidInstance::new(format!(
                "unassigned group variable {}",
                var.0
            ))),
        }
    }
}

impl<G> Default for GroupMap<G> {
    fn default() -> Self {
        Self(Vec::default())
    }
}

impl<G: PrimeGroup> FromIterator<(GroupVar<G>, G)> for GroupMap<G> {
    fn from_iter<T: IntoIterator<Item = (GroupVar<G>, G)>>(iter: T) -> Self {
        iter.into_iter()
            .fold(Self::default(), |mut instance, (var, val)| {
                instance.assign_element(var, val);
                instance
            })
    }
}

/// A list of linear combinations over group elements.
///
/// Scalars and elements are allocated dynamically, and evaluation is by
/// multi-scalar multiplication.
#[derive(Clone, Default, Debug)]
pub struct LinearMap<G: PrimeGroup> {
    /// The set of linear combination constraints (equations).
    pub linear_combinations: Vec<LinearCombination<G>>,
    /// The list of group elements referenced in the linear map.
    ///
    /// Uninitialized group elements are represented by `None`.
    pub group_elements: GroupMap<G>,
    /// The total number of scalar variables allocated.
    pub num_scalars: usize,
    /// The total number of group element variables allocated.
    pub num_elements: usize,
}

impl<G: PrimeGroup> LinearMap<G> {
    /// Creates a new empty [`LinearMap`].
    pub fn new() -> Self {
        Self {
            linear_combinations: Vec::new(),
            group_elements: GroupMap::default(),
            num_scalars: 0,
            num_elements: 0,
        }
    }

    /// Returns the number of constraints (equations) in this linear map.
    pub fn num_constraints(&self) -> usize {
        self.linear_combinations.len()
    }

    /// Adds a new linear combination constraint to the linear map.
    pub fn append(&mut self, lc: LinearCombination<G>) {
        self.linear_combinations.push(lc);
    }

    /// Evaluates all linear combinations in the linear map with the provided scalars.
    ///
    /// `scalars` must contain exactly one value per allocated scalar variable, in allocation
    /// order. A different length returns [`InvalidInstance`].
    pub fn evaluate(&self, scalars: &[G::Scalar]) -> Result<Vec<G>, InvalidInstance>
    where
        G: MultiScalarMul,
    {
        if scalars.len() != self.num_scalars {
            return Err(InvalidInstance::new(format!(
                "witness has {} scalars; expected {}",
                scalars.len(),
                self.num_scalars
            )));
        }

        self.linear_combinations
            .iter()
            .map(|lc| {
                // TODO: The multiplication by the (public) weight is potentially wasteful in the
                // weight is most commonly 1, but multiplication is constant time.
                let weighted_coefficients =
                    lc.0.iter()
                        .map(|weighted| weighted.term.scalar.value(scalars) * weighted.weight)
                        .collect::<Vec<_>>();
                let elements =
                    lc.0.iter()
                        .map(|weighted| self.group_elements.get(weighted.term.elem))
                        .collect::<Result<Vec<_>, _>>()?;
                Ok(G::msm(&weighted_coefficients, &elements))
            })
            .collect()
    }
}

/// A [`LinearMap`] coupled with its expected output (image) elements.
///
/// This is the *preimage problem* for a group linear map: given scalar inputs,
/// does their image under the map match a target set of group elements?
///
/// The constraint system is held in two parts:
/// - the group elements and linear equations (the [`LinearMap`] field),
/// - the [`GroupVar`] indices (`image`) giving the expected output of each constraint.
#[derive(Clone, Debug)]
pub struct LinearRelation<G: PrimeGroup> {
    /// The underlying linear map describing the structure of the statement.
    pub linear_map: LinearMap<G>,
    /// Indices pointing to elements representing the "target" images for each constraint.
    pub image: Vec<GroupVar<G>>,
}

impl<G: PrimeGroup> Default for LinearRelation<G> {
    fn default() -> Self {
        Self::new()
    }
}

impl<G: PrimeGroup> LinearRelation<G> {
    /// Create a new empty [`LinearRelation`].
    ///
    /// Element indices `0` and `1` are reserved for the identity and group
    /// generator, respectively, and are assigned on construction.
    pub fn new() -> Self {
        let mut relation = Self {
            linear_map: LinearMap::new(),
            image: Vec::new(),
        };
        let identity_var = relation.allocate_element();
        debug_assert_eq!(identity_var.0, 0);
        relation.set_element(identity_var, G::identity());
        let generator_var = relation.allocate_element();
        debug_assert_eq!(generator_var.0, 1);
        relation.set_element(generator_var, G::generator());
        relation
    }

    /// The variable referencing the identity, fixed at element index `0`.
    pub fn identity(&self) -> GroupVar<G> {
        GroupVar(0, PhantomData)
    }

    /// The variable referencing the group generator, fixed at element index `1`.
    pub fn generator(&self) -> GroupVar<G> {
        GroupVar(1, PhantomData)
    }

    /// Adds a new equation to the statement of the form:
    /// `lhs = Σ weight_i * (scalar_i * point_i)`.
    pub fn append_equation(&mut self, lhs: GroupVar<G>, rhs: impl Into<LinearCombination<G>>) {
        self.linear_map.append(rhs.into());
        self.image.push(lhs);
    }

    /// Adds a new equation to the statement of the form:
    /// `lhs = Σ weight_i * (scalar_i * point_i)`, allocating `lhs` without assigning it.
    pub fn allocate_eq(&mut self, rhs: impl Into<LinearCombination<G>>) -> GroupVar<G> {
        let var = self.allocate_element();
        self.append_equation(var, rhs);
        var
    }

    /// Adds an equation whose left-hand side is already known.
    ///
    /// This is the public-statement counterpart of [`LinearRelation::allocate_eq`].
    /// It is equivalent to calling `allocate_eq(rhs)` followed by
    /// `set_element(var, lhs)` and produces the same compiled representation.
    pub fn allocate_eq_with(
        &mut self,
        lhs: G,
        rhs: impl Into<LinearCombination<G>>,
    ) -> GroupVar<G> {
        let var = self.allocate_element_with(lhs);
        self.append_equation(var, rhs);
        var
    }

    /// Allocates a scalar variable for use in the linear map.
    pub fn allocate_scalar(&mut self) -> ScalarVar<G> {
        self.linear_map.num_scalars += 1;
        ScalarVar(self.linear_map.num_scalars - 1, PhantomData)
    }

    /// Allocates space for `N` new scalar variables, so
    /// `let [x, y] = relation.allocate_scalars()` allocates two at once.
    pub fn allocate_scalars<const N: usize>(&mut self) -> [ScalarVar<G>; N] {
        let mut vars = [ScalarVar(usize::MAX, PhantomData); N];
        for var in vars.iter_mut() {
            *var = self.allocate_scalar();
        }
        vars
    }

    /// Allocates a vector of new scalar variables.
    pub fn allocate_scalars_vec(&mut self, n: usize) -> Vec<ScalarVar<G>> {
        (0..n).map(|_| self.allocate_scalar()).collect()
    }

    /// Allocates a point variable (group element) for use in the linear map.
    pub fn allocate_element(&mut self) -> GroupVar<G> {
        self.linear_map.num_elements += 1;
        GroupVar(self.linear_map.num_elements - 1, PhantomData)
    }

    /// Allocates a point variable (group element) and immediately sets it to the given value.
    pub fn allocate_element_with(&mut self, element: G) -> GroupVar<G> {
        let var = self.allocate_element();
        self.set_element(var, element);
        var
    }

    /// Allocates `N` point variables (group elements) for use in the linear map.
    pub fn allocate_elements<const N: usize>(&mut self) -> [GroupVar<G>; N] {
        let mut vars = [GroupVar(usize::MAX, PhantomData); N];
        for var in vars.iter_mut() {
            *var = self.allocate_element();
        }
        vars
    }

    /// Allocates a vector of new point variables (group elements).
    pub fn allocate_elements_vec(&mut self, n: usize) -> Vec<GroupVar<G>> {
        (0..n).map(|_| self.allocate_element()).collect()
    }

    /// Assigns a group element value to a point variable.
    ///
    /// # Panics
    ///
    /// Panics if the given assignment conflicts with the existing assignment.
    pub fn set_element(&mut self, var: GroupVar<G>, element: G) {
        self.linear_map.group_elements.assign_element(var, element)
    }

    /// Assigns group elements to the given point variables.
    ///
    /// # Panics
    ///
    /// Panics if the collection contains two conflicting assignments for the same variable.
    pub fn set_elements(&mut self, assignments: impl IntoIterator<Item = (GroupVar<G>, G)>) {
        self.linear_map.group_elements.assign_elements(assignments)
    }

    /// Evaluates all linear combinations in the linear map at the provided scalars, computing the
    /// left-hand side of each constraint (i.e. the image).
    ///
    /// The slice must contain exactly one scalar per allocated scalar variable, in allocation
    /// order. On success every previously-unassigned image variable is assigned, and any
    /// preassigned image is checked against the computed value. A mismatch returns
    /// [`InvalidInstance`]. The update is transactional: on any error, including
    /// a missing base element or conflicting image, no image assignment is changed.
    pub fn compute_image(&mut self, scalars: &[G::Scalar]) -> Result<(), InvalidInstance>
    where
        G: MultiScalarMul,
    {
        if self.linear_map.num_constraints() != self.image.len() {
            return Err(InvalidInstance::new(
                "constraint and image counts do not match",
            ));
        }

        let mapped_scalars = self.linear_map.evaluate(scalars)?;

        // Stage assignments on a clone so two equations sharing an image variable are checked
        // against one another and an error cannot leave a partly-solved relation behind.
        let mut group_elements = self.linear_map.group_elements.clone();

        for (mapped_scalar, lhs) in iter::zip(mapped_scalars, &self.image) {
            if let Some(assigned) = group_elements.0.get(lhs.0).copied().flatten() {
                if assigned != mapped_scalar {
                    return Err(InvalidInstance::new(
                        "witness does not match a preassigned image",
                    ));
                }
            } else {
                group_elements.assign_element(*lhs, mapped_scalar);
            }
        }
        self.linear_map.group_elements = group_elements;
        Ok(())
    }

    /// Computes this relation's image from `witness` and compiles the resulting statement.
    ///
    /// This is a convenience for prover-side construction when the public image is derived from
    /// a locally-held witness. It is equivalent to [`LinearRelation::compute_image`] followed by
    /// [`LinearRelation::compile`]. Preassigned image values are checked rather than overwritten,
    /// so this method also rejects a witness that does not satisfy an already-complete public
    /// statement.
    ///
    /// The witness must contain exactly one scalar per allocated scalar variable, in allocation
    /// order. As with `compute_image`, a failure while computing the image does not partially
    /// assign image variables.
    pub fn compile_with_witness(
        &mut self,
        witness: &[G::Scalar],
    ) -> Result<Instance<G>, InvalidInstance>
    where
        G: MultiScalarMul + GroupCodec,
        G::Scalar: ScalarCodec,
    {
        self.compute_image(witness)?;
        let instance = self.compile()?;
        if instance.num_scalars() != witness.len() {
            return Err(InvalidInstance::new(format!(
                "witness has {} scalars; expected {}",
                witness.len(),
                instance.num_scalars()
            )));
        }
        Ok(instance)
    }

    /// Compile this relation into a validated [`Instance`] — the single gate
    /// through which provers and verifiers accept a statement.
    ///
    /// The compiled form is the specification's representation: coefficients
    /// are kept verbatim (no folding, no synthetic elements), witness-carrying
    /// terms become right-hand-side terms `(scalar_index, element_index,
    /// coeff)`, and constant terms cross to the image with their coefficient
    /// negated. Every group element of the statement is individually indexed
    /// and bound by the serialization.
    ///
    /// Because this is trusted local construction (the relation is built by
    /// this process, not received from the wire), the statement is normalized
    /// before validation — deterministically, so a prover and a verifier
    /// building the same relation serialize the same instance:
    ///
    /// - A term-free (constant) equation is a public claim, not a
    ///   sigma-protocol statement: it is evaluated here. A true one is
    ///   stripped; a false one fails compilation, since the statement is
    ///   false.
    /// - Group elements no longer used by any remaining equation are dropped
    ///   and the indices are re-packed in allocation order (the identity and
    ///   generator keep indices 0 and 1). A statement already satisfying the
    ///   specification's checks is left byte-for-byte unchanged.
    /// - If no equation remains, compilation produces the valid empty
    ///   relation.
    ///
    /// The result is checked by the specification's `ValidateInstance`;
    /// unassigned elements fail unless normalization dropped them.
    pub fn compile(&self) -> Result<Instance<G>, InvalidInstance>
    where
        G: MultiScalarMul + GroupCodec,
        G::Scalar: ScalarCodec,
    {
        if self.image.len() != self.linear_map.linear_combinations.len() {
            return Err(InvalidInstance::new(
                "different number of equations and image variables",
            ));
        }

        let mut equations = Vec::new();
        for (lhs, combination) in iter::zip(&self.image, &self.linear_map.linear_combinations) {
            // The image is the left-hand-side variable with coefficient one,
            // plus each constant term crossed over with its coefficient
            // negated (never folded into a single value).
            let mut image = alloc::vec![(
                u32::try_from(lhs.0)
                    .map_err(|_| InvalidInstance::new("element index exceeds 2^32"))?,
                G::Scalar::ONE,
            )];
            let mut terms = Vec::new();
            for weighted in combination.terms() {
                let element_index = u32::try_from(weighted.term.elem.0)
                    .map_err(|_| InvalidInstance::new("element index exceeds 2^32"))?;
                match weighted.term.scalar {
                    ScalarTerm::Var(scalar_var) => {
                        let scalar_index = u32::try_from(scalar_var.0)
                            .map_err(|_| InvalidInstance::new("scalar index exceeds 2^32"))?;
                        terms.push((scalar_index, element_index, weighted.weight));
                    }
                    ScalarTerm::Unit => image.push((element_index, -weighted.weight)),
                }
            }
            if terms.is_empty() {
                // Constant equation: evaluate the public claim instead of
                // shipping it (see the normalization notes above).
                let (coeffs, points): (Vec<_>, Vec<_>) = image
                    .iter()
                    .map(|&(element_index, coeff)| {
                        self.linear_map
                            .group_elements
                            .get(GroupVar(element_index as usize, PhantomData))
                            .map(|element| (coeff, element))
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .unzip();
                if !bool::from(G::msm_vartime(&coeffs, &points).is_identity()) {
                    return Err(InvalidInstance::new(
                        "term-free equation does not hold: the statement is false",
                    ));
                }
                continue;
            }
            equations.push(instance::Equation { image, terms });
        }

        // Drop elements no remaining equation uses, keeping allocation order.
        let mut used = BTreeSet::new();
        used.insert(0u32);
        used.insert(1u32);
        for equation in &equations {
            used.extend(
                equation
                    .image
                    .iter()
                    .map(|&(element_index, _)| element_index),
            );
            used.extend(
                equation
                    .terms
                    .iter()
                    .map(|&(_, element_index, _)| element_index),
            );
        }
        let remap: BTreeMap<u32, u32> = used
            .iter()
            .enumerate()
            .map(|(new_index, &old_index)| {
                (
                    old_index,
                    u32::try_from(new_index).expect("element count exceeds 2^32"),
                )
            })
            .collect();
        // `used` was collected from these same equations just above, so
        // `remap` has a key for every index they carry.
        #[allow(clippy::indexing_slicing)]
        for equation in &mut equations {
            for (element_index, _) in &mut equation.image {
                *element_index = remap[element_index];
            }
            for (_, element_index, _) in &mut equation.terms {
                *element_index = remap[element_index];
            }
        }

        let elements = used
            .iter()
            .skip(2)
            .map(|&old_index| {
                self.linear_map
                    .group_elements
                    .get(GroupVar(old_index as usize, PhantomData))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Instance::new(elements, equations)
    }
}
