//xxx example, not zk.

use crate::errors::Error as ProofError;
use crate::errors::Result as ProofResult;
use crate::linear_relation;
use crate::serialization::deserialize_elements;
use crate::serialization::deserialize_scalars;
use crate::traits::InteractiveProof;
use ff::Field;
use group::prime::PrimeGroup;

use crate::{
    group::msm::VariableMultiScalarMul,
    linear_relation::CanonicalLinearRelation,
    serialization::{read_elements, serialize_elements, serialize_scalars},
};

struct SquashedLinearRelation<G: PrimeGroup> {
    generators: Vec<G>,
    image: G,
}

pub(crate) fn powers<F: Field>(element: F, len: usize) -> Vec<F> {
    let mut powers = vec![F::ONE; len];
    for i in 1..len {
        powers[i] = element * powers[i - 1];
    }
    powers
}

impl<G: PrimeGroup> CanonicalLinearRelation<G> {
    // not really needed but will simplify the code.
    fn squash(&self, challenge: G::Scalar) -> SquashedLinearRelation<G> {
        let powers = powers(challenge, self.image.len());

        let squashed_image = G::msm(&powers, &self.image);

        // Determine the number of scalar variables
        let num_scalars = self.num_scalars;

        let mut squashed_generators = vec![G::identity(); num_scalars];

        // the matrix for a linear relation is sparse, and stored in yale format.
        for (row, linear_combination) in self.linear_combinations.iter().enumerate() {
            for (scalar_var, group_var) in linear_combination.iter() {
                let col = scalar_var.index();
                let element = self.group_elements.get(*group_var).unwrap();
                squashed_generators[col] += element * powers[row];
            }
        }

        SquashedLinearRelation {
            generators: squashed_generators,
            image: squashed_image,
        }
    }
}

fn fold_generators<G: PrimeGroup>(
    left: &[G],
    right: &[G],
    x_inv: &G::Scalar,
    x: &G::Scalar,
) -> Vec<G> {
    left.iter()
        .zip(right.iter())
        .map(|(l, r)| *l * (*x_inv) + *r * (*x))
        .collect()
}

fn fold_scalars<F: Field>(left: &[F], right: &[F], x: &F, x_inv: &F) -> Vec<F> {
    left.iter()
        .zip(right.iter())
        .map(|(&l, &r)| l * x + r * x_inv)
        .collect()
}

enum CompressedProofMessage<G: PrimeGroup> {
    FinalMessage(G::Scalar),
    IntermediateMessage([G; 2]),
}

impl<G: PrimeGroup> CompressedProofMessage<G> {
    fn new_from_intermediate_message(intermediate_message: [G; 2]) -> Self {
        Self::IntermediateMessage(intermediate_message)
    }

    fn new_from_final_message(final_message: G::Scalar) -> Self {
        Self::FinalMessage(final_message)
    }
}

impl<G: PrimeGroup> InteractiveProof for SquashedLinearRelation<G> {
    type ProverState = (Vec<G::Scalar>, SquashedLinearRelation<G>);

    type ProverMessage = CompressedProofMessage<G>;

    type VerifierState = SquashedLinearRelation<G>;

    type Challenge = G::Scalar;

    type Witness = Vec<G::Scalar>;

    fn get_initial_prover_state(&self, witness: &Self::Witness) -> Self::ProverState {
        (
            witness.to_vec(),
            SquashedLinearRelation {
                generators: self.generators.clone(),
                image: self.image,
            },
        )
    }

    fn get_initial_verifier_state(&self) -> Self::VerifierState {
        SquashedLinearRelation {
            generators: self.generators.clone(),
            image: self.image,
        }
    }

    fn prover_message(
        &self,
        state: &mut Self::ProverState,
        challenge: &Self::Challenge,
    ) -> Result<Self::ProverMessage, ProofError> {
        let (witness, statement) = state;
        assert_eq!(witness.len(), statement.generators.len());
        assert_eq!(
            G::msm(&witness, &statement.generators),
            statement.image,
            "Invalid witness"
        );
        if statement.generators.len() == 1 {
            let computed = statement.generators[0] * witness[0];
            let final_message = witness[0];
            assert_eq!(statement.image, computed);
            return Ok(CompressedProofMessage::new_from_final_message(
                final_message,
            ));
        }
        let n = witness.len() / 2;
        let (w_left, w_right) = witness.split_at(n);
        let (g_left, g_right) = self.generators.split_at(n);

        // round messages
        let A = G::msm_unchecked(w_left, &g_right);
        let B = G::msm_unchecked(w_right, &g_left);
        let new_witness = fold_scalars(w_left, w_right, &G::Scalar::ONE, &challenge);
        let new_generators = fold_generators(g_left, g_right, &challenge, &G::Scalar::ONE);
        let new_image = A + statement.image * challenge + B * challenge.square();
        statement.generators = new_generators;
        statement.image = new_image;

        Ok(CompressedProofMessage::new_from_intermediate_message([
            A, B,
        ]))
    }

    fn update_verifier_state(
        prover_message: &Self::ProverMessage,
        state: &mut Self::VerifierState,
        challenge: &Self::Challenge,
    ) -> Result<(), ProofError> {
        if state.generators.len() == 1 {
            match prover_message {
                CompressedProofMessage::FinalMessage(witness) => {
                    let computed = state.generators[0] * witness;
                    if computed == state.image {
                        return Ok(());
                    } else {
                        return Err(ProofError::VerificationFailure);
                    }
                }
                CompressedProofMessage::IntermediateMessage(_) => {
                    return Err(ProofError::VerificationFailure);
                }
            }
        }
        match prover_message {
            CompressedProofMessage::FinalMessage(_) => {
                return Err(ProofError::VerificationFailure);
            }
            CompressedProofMessage::IntermediateMessage([A, B]) => {
                let n = state.generators.len() / 2;
                let (g_left, g_right) = state.generators.split_at(n);
                let new_generators = fold_generators(g_left, g_right, &challenge, &G::Scalar::ONE);
                let new_image = *A + state.image * challenge + *B * challenge.square();
                state.generators = new_generators;
                state.image = new_image;
                Ok(())
            }
        }
    }

    fn serialize_message(&self, prover_message: &Self::ProverMessage) -> Vec<u8> {
        match prover_message {
            CompressedProofMessage::FinalMessage(witness) => serialize_scalars::<G>(&[*witness]),
            CompressedProofMessage::IntermediateMessage(prover_message) => {
                serialize_elements(prover_message)
            }
        }
    }

    fn serialize_challenge(&self, challenge: &Self::Challenge) -> Vec<u8> {
        serialize_scalars::<G>(&[*challenge])
    }

    fn deserialize_message(
        &self,
        data: &[u8],
        is_final_message: bool,
    ) -> Result<Self::ProverMessage, ProofError> {
        if is_final_message {
            let witness =
                deserialize_scalars::<G>(data, 1).ok_or(ProofError::VerificationFailure)?;
            Ok(CompressedProofMessage::new_from_final_message(witness[0]))
        } else {
            let elements =
                deserialize_elements::<G>(data, 2).ok_or(ProofError::VerificationFailure)?;
            let intermediate_message: [G; 2] = [elements[0], elements[1]];
            Ok(CompressedProofMessage::IntermediateMessage(
                intermediate_message,
            ))
        }
    }

    fn deserialize_challenge(&self, data: &[u8]) -> Result<Self::Challenge, ProofError> {
        let scalars = deserialize_scalars::<G>(data, 1).ok_or(ProofError::VerificationFailure)?;
        Ok(scalars[0])
    }

    fn protocol_identifier(&self) -> impl AsRef<[u8]> {
        "TODO"
    }

    fn instance_label(&self) -> impl AsRef<[u8]> {
        "TODO"
    }

    fn num_rounds(&self) -> usize {
        self.generators.len().next_power_of_two().ilog2() as usize + 1
    }
}

impl<G: PrimeGroup> SquashedLinearRelation<G> {
    // XXX. We need to define a trait InteractiveProof for working with Fiat-Shamir, or rely on `spongefish`.
    fn prove(&self, witness: &[G::Scalar], xxx_challenges: &[G::Scalar]) -> ProofResult<Vec<u8>> {
        assert_eq!(witness.len(), self.generators.len());
        assert_eq!(
            G::msm(&witness, &self.generators),
            self.image,
            "Invalid witness"
        );

        if self.generators.len() == 1 {
            let computed = self.generators[0] * witness[0];
            return Ok(serialize_scalars::<G>(witness));
        }

        let n = witness.len() / 2;
        let (w_left, w_right) = witness.split_at(n);
        let (g_left, g_right) = self.generators.split_at(n);

        // round messages
        let A = G::msm_unchecked(w_left, &g_right);
        let B = G::msm_unchecked(w_right, &g_left);
        let round_message = serialize_elements(&[A, B]);

        let challenge = xxx_challenges[0];
        let new_witness = fold_scalars(w_left, w_right, &G::Scalar::ONE, &challenge);
        let new_generators = fold_generators(g_left, g_right, &challenge, &G::Scalar::ONE);
        let new_image = A + self.image * challenge + B * challenge.square();
        let new_instance = SquashedLinearRelation {
            generators: new_generators,
            image: new_image,
        };
        let narg_string = new_instance.prove(&new_witness, &xxx_challenges[1..])?;

        Ok(round_message.into_iter().chain(narg_string).collect())
    }

    fn verify(&self, narg_string: &[u8], xxx_challenges: &[G::Scalar]) -> ProofResult<()> {
        if self.generators.len() == 1 {
            let witness =
                deserialize_scalars::<G>(narg_string, 1).ok_or(ProofError::VerificationFailure)?;
            let computed = self.generators[0] * witness[0];
            if computed == self.image {
                return Ok(());
            } else {
                return Err(ProofError::VerificationFailure);
            }
        }

        let (round_message, new_narg_string) =
            read_elements::<G>(narg_string, 2).ok_or(ProofError::VerificationFailure)?;
        let [A, B] = [round_message[0], round_message[1]];
        let n = self.generators.len() / 2;
        let (g_left, g_right) = self.generators.split_at(n);
        let challenge = xxx_challenges[0];

        let new_generators = fold_generators(g_left, g_right, &challenge, &G::Scalar::ONE);
        let new_image = A + self.image * challenge + B * challenge.square();
        let new_instance = SquashedLinearRelation {
            generators: new_generators,
            image: new_image,
        };
        new_instance.verify(new_narg_string, &xxx_challenges[1..])
    }
}

#[test]
fn test_compressed_bbs_nyms() {
    use curve25519_dalek::ristretto::RistrettoPoint as G;
    use curve25519_dalek::Scalar;

    let rng = &mut rand::thread_rng();
    let mut statement = linear_relation::LinearRelation::<G>::new();
    // bbs variables
    const N: usize = 127;
    let var_ms = statement.allocate_scalars::<N>();
    let var_G0 = statement.allocate_element();
    let var_Gs = statement.allocate_elements::<N>();
    // xxx
    // let var_X = statement.allocate_element();
    let var_e = statement.allocate_scalar();
    let var_A = statement.allocate_element();
    // nym group elements
    let var_Ts = statement.allocate_elements::<N>();

    // bbs verification equation
    // x A = G_0 + sum_{i=1}^n m_i G_i + e A
    let var_Z = statement.allocate_eq(
        var_Gs
            .iter()
            .zip(var_ms.iter())
            .map(|(g, m)| *g * *m)
            .sum::<crate::linear_relation::Sum<_>>()
            + var_G0
            + var_e * var_A,
    );
    // pseudonym
    let var_NYM = statement.allocate_eq(
        var_Ts
            .iter()
            .zip(var_ms)
            .map(|(t, m)| *t * m)
            .sum::<crate::linear_relation::Sum<_>>(),
    );

    let challenge = Scalar::random(rng); // Random squash challenge
    let G0 = G::random(rng);
    let Gs = (0..N).map(|_| G::random(rng)).collect::<Vec<_>>();
    let ms = (0..N).map(|_| Scalar::random(rng)).collect::<Vec<_>>();
    // xxx
    let Ts = (0..N).map(|_| G::random(rng)).collect::<Vec<_>>();
    let x = Scalar::random(rng);
    // computed by the server
    let e = Scalar::random(rng);
    let A = (x - e).invert() * (G0 + G::msm(&ms, &Gs));
    let Z = x * A;
    // computed by the user
    let NYM = G::msm(&ms, &Ts);

    // the public elements
    statement.set_elements(
        [(var_G0, G0), (var_A, A), (var_NYM, NYM), (var_Z, Z)]
            .into_iter()
            .chain(var_Gs.iter().copied().zip(Gs.iter().copied()))
            .chain(var_Ts.iter().copied().zip(Ts.iter().copied())),
    );
    // the private witness
    let witness = [ms.as_slice(), &[e]].concat();
    let round_challenges = (0..7).map(|_| Scalar::random(rng)).collect::<Vec<_>>();

    assert_eq!(
        statement
            .canonical()
            .unwrap()
            .is_witness_valid(&witness)
            .unwrap_u8(),
        1
    );
    // All random challenges now
    let squashed_statement = statement.canonical().unwrap().squash(challenge);

    let witness_check = G::msm(&witness, &squashed_statement.generators);
    let narg_string = squashed_statement
        .prove(&witness, &round_challenges)
        .unwrap();
    assert!(squashed_statement
        .verify(&narg_string, &round_challenges)
        .is_ok());
}
