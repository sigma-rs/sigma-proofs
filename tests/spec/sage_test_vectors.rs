use bls12_381::{G1Projective, Scalar};
use group::{Group, GroupEncoding};
use hex::encode;
use rand::{CryptoRng, Rng};

use sigma_rs::{
    codec::{ByteSchnorrCodec, KeccakDuplexSponge},
    group_morphism::msm_pr,
    GroupMorphismPreimage, NISigmaProtocol,
};

use crate::{
    custom_schnorr_protocol::SchnorrProtocolCustom, 
    random::SRandom, 
    test_drng::TestDRNG
};

type Preimage<G> = GroupMorphismPreimage<G>;

type Gp = G1Projective;
type Codec = ByteSchnorrCodec<Gp, KeccakDuplexSponge>;
type SigmaP = SchnorrProtocolCustom<Gp>;
type NISigmaP = NISigmaProtocol<SigmaP, Codec, Gp>;

#[allow(non_snake_case)]
fn discrete_logarithm<G: SRandom + Group + GroupEncoding>(
    rng: &mut (impl Rng + CryptoRng),
) -> (Preimage<G>, Vec<G::Scalar>) {
    let mut morphismp: Preimage<G> = Preimage::new();

    let scalars = morphismp.allocate_scalars(1);
    let var_x = scalars[0];

    let points = morphismp.allocate_elements(2);
    let (var_G, var_X) = (points[0], points[1]);

    morphismp.append_equation(var_X, &[(var_x, var_G)]);

    let G = G::generator();
    morphismp.set_elements(&[(var_G, G)]);

    let x = G::srandom(rng);
    let X = G * x;
    assert!(vec![X] == morphismp.morphism.evaluate(&[x]));
    morphismp.set_elements(&[(var_X, X)]);
    (morphismp, vec![x])
}

#[allow(non_snake_case)]
fn dleq<G: Group + GroupEncoding + SRandom>(
    rng: &mut (impl Rng + CryptoRng),
) -> (Preimage<G>, Vec<G::Scalar>) {
    let mut morphismp: Preimage<G> = Preimage::new();

    let G = G::generator();
    let x = G::srandom(rng);
    let H = G::prandom(rng);
    let X = G * x;
    let Y = H * x;

    let scalars = morphismp.allocate_scalars(1);
    let var_x = scalars[0];

    let points = morphismp.allocate_elements(4);
    let (var_G, var_H, var_X, var_Y) = (points[0], points[1], points[2], points[3]);

    morphismp.set_elements(&[(var_G, G), (var_H, H), (var_X, X), (var_Y, Y)]);
    morphismp.append_equation(var_X, &[(var_x, var_G)]);
    morphismp.append_equation(var_Y, &[(var_x, var_H)]);

    assert!(vec![X, Y] == morphismp.morphism.evaluate(&[x]));
    (morphismp, vec![x])
}

#[allow(non_snake_case)]
fn pedersen_commitment<G: Group + GroupEncoding + SRandom>(
    rng: &mut (impl Rng + CryptoRng),
) -> (Preimage<G>, Vec<G::Scalar>) {
    let mut morphismp: Preimage<G> = Preimage::new();

    let G = G::generator();
    let H = G::prandom(rng);
    let x = G::srandom(rng);
    let r = G::srandom(rng);
    let witness = vec![x, r];

    let C = G * x + H * r;

    let scalars = morphismp.allocate_scalars(2);
    let (var_x, var_r) = (scalars[0], scalars[1]);

    let points = morphismp.allocate_elements(3);
    let (var_G, var_H, var_C) = (points[0], points[1], points[2]);

    morphismp.set_elements(&[(var_H, H), (var_G, G), (var_C, C)]);
    morphismp.append_equation(var_C, &[(var_x, var_G), (var_r, var_H)]);

    assert!(vec![C] == morphismp.morphism.evaluate(&witness));
    (morphismp, witness)
}

#[allow(non_snake_case)]
fn pedersen_commitment_dleq<G: Group + GroupEncoding + SRandom>(
    rng: &mut (impl Rng + CryptoRng),
) -> (Preimage<G>, Vec<G::Scalar>) {
    let mut morphismp: Preimage<G> = Preimage::new();

    let mut generators = Vec::<G>::new();
    generators.push(G::prandom(rng));
    generators.push(G::prandom(rng));
    generators.push(G::prandom(rng));
    generators.push(G::prandom(rng));

    let mut witness = Vec::<G::Scalar>::new();
    witness.push(G::srandom(rng));
    witness.push(G::srandom(rng));

    let X = msm_pr::<G>(&witness, &[generators[0], generators[1]]);
    let Y = msm_pr::<G>(&witness, &[generators[2], generators[3]]);

    let scalars = morphismp.allocate_scalars(2);
    let (var_x, var_r) = (scalars[0], scalars[1]);

    let points = morphismp.allocate_elements(6);
    let var_Gs = (points[0], points[1], points[2], points[3]);
    let (var_X, var_Y) = (points[4], points[5]);

    morphismp.set_elements(&[
        (var_Gs.0, generators[0]),
        (var_Gs.1, generators[1]),
        (var_Gs.2, generators[2]),
        (var_Gs.3, generators[3]),
    ]);
    morphismp.set_elements(&[(var_X, X), (var_Y, Y)]);

    morphismp.append_equation(var_X, &[(var_x, var_Gs.0), (var_r, var_Gs.1)]);
    morphismp.append_equation(var_Y, &[(var_x, var_Gs.2), (var_r, var_Gs.3)]);

    assert!(vec![X, Y] == morphismp.morphism.evaluate(&witness));
    (morphismp, witness)
}

#[allow(non_snake_case)]
fn bbs_blind_commitment_computation<G: Group + GroupEncoding + SRandom>(
    rng: &mut (impl Rng + CryptoRng),
) -> (Preimage<G>, Vec<G::Scalar>) {
    let mut morphismp: Preimage<G> = Preimage::new();

    // length (committed_messages)
    let M = 3;
    // BBS.create_generators(M + 1, "BLIND_" || api_id)
    let (Q_2, J_1, J_2, J_3) = (
        G::prandom(rng),
        G::prandom(rng),
        G::prandom(rng),
        G::prandom(rng),
    );
    // BBS.messages_to_scalars(committed_messages,  api_id)
    let (msg_1, msg_2, msg_3) = (G::srandom(rng), G::srandom(rng), G::srandom(rng));

    // these are computed before the proof in the specification
    let secret_prover_blind = G::srandom(rng);
    let C = Q_2 * secret_prover_blind + J_1 * msg_1 + J_2 * msg_2 + J_3 * msg_3;

    // This is the part that needs to be changed in the specification of blind bbs.
    let scalars = morphismp.allocate_scalars(M + 1);
    let (var_secret_prover_blind, var_msg_1, var_msg_2, var_msg_3) =
        (scalars[0], scalars[1], scalars[2], scalars[3]);

    let points = morphismp.allocate_elements(M + 2);
    let (var_Q_2, var_J_1, var_J_2, var_J_3) = (points[0], points[1], points[2], points[3]);
    let var_C = points[M + 1];

    morphismp.set_elements(&[
        (var_Q_2, Q_2),
        (var_J_1, J_1),
        (var_J_2, J_2),
        (var_J_3, J_3),
        (var_C, C),
    ]);

    morphismp.append_equation(
        var_C,
        &[
            (var_secret_prover_blind, var_Q_2),
            (var_msg_1, var_J_1),
            (var_msg_2, var_J_2),
            (var_msg_3, var_J_3),
        ],
    );

    let witness = vec![secret_prover_blind, msg_1, msg_2, msg_3];

    assert!(vec![C] == morphismp.morphism.evaluate(&witness));
    (morphismp, witness)
}

/// This part tests the implementation of the SigmaProtocol trait for the
/// SchnorrProtocol structure as well as the Fiat-Shamir NISigmaProtocol transform
#[allow(non_snake_case)]
fn NI_discrete_logarithm(seed: &[u8], context: &[u8]) -> (Vec<Scalar>, Vec<u8>) {
    let mut rng = TestDRNG::new(seed);
    let (morphismp, witness) = discrete_logarithm::<Gp>(&mut rng);

    let protocol = SchnorrProtocolCustom { morphismp };
    let domain_sep: Vec<u8> = context.to_vec();
    let mut nizk = NISigmaP::new(&domain_sep, protocol);

    let proof_bytes = nizk.prove_batchable(&witness, &mut rng);
    let verified = nizk.verify_batchable(&proof_bytes).is_ok();
    assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
    assert!(encode(&proof_bytes).as_bytes() == b"80c96c2822d816de609d4b72dd0b2a9409a3402338c977467225e7f506a60f3153a7f447450d7336c0ef15e4151349d91495306d216d5fe2ff3e660bcaf227c4794cb0e0887f5bcff6d4a6189cf9a494");
    (witness, proof_bytes)
}

#[allow(non_snake_case)]
fn NI_dleq(seed: &[u8], context: &[u8]) -> (Vec<Scalar>, Vec<u8>) {
    let mut rng = TestDRNG::new(seed);
    let (morphismp, witness) = dleq::<Gp>(&mut rng);

    let protocol = SchnorrProtocolCustom { morphismp };
    let domain_sep: Vec<u8> = context.to_vec();
    let mut nizk = NISigmaP::new(&domain_sep, protocol);

    let proof_bytes = nizk.prove_batchable(&witness, &mut rng);
    let verified = nizk.verify_batchable(&proof_bytes).is_ok();
    assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
    assert!(encode(&proof_bytes).as_bytes() == b"a01abd54895b7df2d476b2371e1796278a114f7dd1514e05cc1c0c07d40957268684c8887aa3f8cee33856ca325412f5a4fffa7226a983c8fcd9bb59dbb7a72e5c4eacd80958c3685d7abaa477ba6d738b35998ea1d0089166d17ea0a206d2991bf0b87f1f5c977f93fdccf9ec820d989656662f146460d48e56bfc2f6482285");
    (witness, proof_bytes)
}

#[allow(non_snake_case)]
fn NI_pedersen_commitment(seed: &[u8], context: &[u8]) -> (Vec<Scalar>, Vec<u8>) {
    let mut rng = TestDRNG::new(seed);
    let (morphismp, witness) = pedersen_commitment::<Gp>(&mut rng);

    let protocol = SchnorrProtocolCustom { morphismp };
    let domain_sep: Vec<u8> = context.to_vec();
    let mut nizk = NISigmaP::new(&domain_sep, protocol);

    let proof_bytes = nizk.prove_batchable(&witness, &mut rng);
    let verified = nizk.verify_batchable(&proof_bytes).is_ok();
    assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
    assert!(encode(&proof_bytes).as_bytes() == b"91c620e60e68502ab1e0f0fa6b9f7e3225f678596da80c0e950e4149078562518ad37ed6177c71ebd6e2ca5fc32457d8228aa82bf0293a2d70def71e0e1f434af472458907c4827b694987a903126dd050b3ed6234dcd4d176f05582d3dab5515f790c5cdc927972d631a2ddceb53edb");
    (witness, proof_bytes)
}

#[allow(non_snake_case)]
fn NI_pedersen_commitment_dleq(seed: &[u8], context: &[u8]) -> (Vec<Scalar>, Vec<u8>) {
    let mut rng = TestDRNG::new(seed);
    let (morphismp, witness) = pedersen_commitment_dleq::<Gp>(&mut rng);

    let protocol = SchnorrProtocolCustom { morphismp };
    let domain_sep: Vec<u8> = context.to_vec();
    let mut nizk = NISigmaP::new(&domain_sep, protocol);

    let proof_bytes = nizk.prove_batchable(&witness, &mut rng);
    let verified = nizk.verify_batchable(&proof_bytes).is_ok();
    assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
    assert!(encode(&proof_bytes).as_bytes() == b"8e670749a002c02e0b343a47c0194743d9164d5026ddec0a9572a742748305f83b2fc679858f2f97debd72a08ec59dc38e5d6c8cc6cb284f4012d4eb41a807d1463ad0d8976f78baff1da1fdf2ad39027e8c66e0625b15740a72fc9e866f1d1014a32947fd44c55553eb2c13d21d639640b5d070987d8befea62367b235278d80a313d50f72e5c70de5fc1db95e042b3723344136144cc71c5515c5aa03d95d1");
    (witness, proof_bytes)
}

#[allow(non_snake_case)]
fn NI_bbs_blind_commitment_computation(seed: &[u8], context: &[u8]) -> (Vec<Scalar>, Vec<u8>) {
    let mut rng = TestDRNG::new(seed);
    let (morphismp, witness) = bbs_blind_commitment_computation::<Gp>(&mut rng);

    let protocol = SchnorrProtocolCustom { morphismp };
    let domain_sep: Vec<u8> = context.to_vec();
    let mut nizk = NISigmaP::new(&domain_sep, protocol);

    let proof_bytes = nizk.prove_batchable(&witness, &mut rng);
    let verified = nizk.verify_batchable(&proof_bytes).is_ok();
    assert!(verified, "Fiat-Shamir Schnorr proof verification failed");
    assert!(encode(&proof_bytes).as_bytes() == b"803d5d4fdb311967832758ae7402d03304b570f97c0756e5385a50622d0ac7b5de87fe14d15041b1564ba4893a1187304ed12592b9ca9c5ca92a87c3960f0bcae541ddf880271c361cca15c67e13bc504cf96235363e99bb3e126b111c220c77427873389d2397cf0798d251ec82ced1649b5d0e9b2f95410a68b5b66158e50832488e540853a8c79a17d8b8290266ec150af102dd9ca4a6f076399da893b1f2caa78d192590708c02ab561eb3a01aa1");
    (witness, proof_bytes)
}

#[allow(non_snake_case)]
#[test]
fn sage_test_vectors() {
    let seed = b"hello world";
    let context = b"yellow submarineyellow submarine";

    let functions: [fn(seed: &[u8], context: &[u8]) -> (Vec<Scalar>, Vec<u8>); 5] = [
        NI_discrete_logarithm,
        NI_dleq,
        NI_pedersen_commitment,
        NI_pedersen_commitment_dleq,
        NI_bbs_blind_commitment_computation,
    ];

    for f in functions.iter() {
        let (witness, proof_bytes) = f(seed, context);
        println!("Context : {:?}", encode(context));
        println!("Witness : {:?}", witness);
        println!("Proof : {:?} \n", encode(proof_bytes));
    }
}
