use std::marker::PhantomData;
use group::{Group, GroupEncoding};

pub struct LinearCombinaison {
    pub scalar_indices: Vec<usize>,
    pub element_indices: Vec<usize>,
}

pub struct Morphism<G: Group> {
    pub linear_combinaison: Vec<LinearCombinaison>,
    pub group_elements: Vec<G>,
    pub num_scalars: usize,
    pub num_elements: usize,
}

fn msm_pr<G: Group>(scalars: &[G::Scalar], bases: &[G]) -> G {
    let mut acc = G::identity();
    for (s, p) in scalars.iter().zip(bases.iter()) {
        acc = acc + (*p * s.clone());
    }
    acc
}

impl<G: Group> Morphism<G> {
    pub fn new() -> Self {
        Self {
            linear_combinaison: Vec::new(),
            group_elements: Vec::new(),
            num_scalars: 0,
            num_elements: 0,
        }
    }

    pub fn append(&mut self, lc: LinearCombinaison) {
        self.linear_combinaison.push(lc);
    }

    pub fn num_statements(&self) -> usize {
        self.linear_combinaison.len()
    }

    pub fn evaluate(&self, scalars: &[<G as Group>::Scalar]) -> Vec<G> {
        self.linear_combinaison.iter().map(|lc| {
            let coefficients: Vec<_> = lc.scalar_indices.iter().map(|&i| scalars[i].clone()).collect();
            let elements: Vec<_> = lc.element_indices.iter().map(|&i| self.group_elements[i].clone()).collect();
            msm_pr(&coefficients, &elements)
        }).collect()
    }
}

pub struct GroupMorphismPreimage<G>
where
    G: Group + GroupEncoding,
{
    pub morphism: Morphism<G>,
    pub image: Vec<G>,
    _marker: PhantomData<G>,
}

impl<G> GroupMorphismPreimage<G>
where 
    G: Group + GroupEncoding,
{
    pub fn new() -> Self {
        Self {
            morphism: Morphism::new(),
            image: Vec::new(),
            _marker: PhantomData,
        }
    }

    pub fn commit_bytes_len(&self) -> usize {
        let repr_len = <G::Repr as Default>::default()
            .as_ref()
            .len();  // size of encoded point
        self.morphism.num_statements() * repr_len  // total size of a commit
    }

    pub fn append_equation(&mut self, lhs: G, rhs: &[(usize, usize)]) {
        let lc = LinearCombinaison {
            scalar_indices: rhs.iter().map(|&(s, _)| s).collect(),
            element_indices: rhs.iter().map(|&(_, e)| e).collect(),
        };
        self.morphism.append(lc);
        self.image.push(lhs);
    }

    // Allocate n new Scalar's
    pub fn allocate_scalars(&mut self, n: usize) -> Vec<usize> {
        let start = self.morphism.num_scalars;
        let indices: Vec<usize> = (start..start + n).collect();
        self.morphism.num_scalars += n;
        indices
    }

    // Allocate n new emplacments for Group elements (completed with set_elements for assignation)
    pub fn allocate_elements(&mut self, n: usize) -> Vec<usize> {
        let start = self.morphism.num_elements;
        let indices: Vec<usize> = (start..start + n).collect();
        for _ in 0..n {
            self.morphism.group_elements.push(G::identity());
        }
        self.morphism.num_elements += n;
        indices
    }

    pub fn set_elements(&mut self, elements: &[(usize, G)]) {
        for &(i, ref elt) in elements {
            self.morphism.group_elements[i] = elt.clone();
        }
    }

    pub fn image(&self) -> Vec<G> {
        let mut result = Vec::new();
        for g in &(self.image) {
            result.push(g.clone());
        }
        result
    }
}