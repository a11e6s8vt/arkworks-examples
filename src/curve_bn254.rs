use ark_bn254::{Bn254, Config};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::bn::Bn;
use ark_ff::ToConstraintField;
use ark_groth16::{Groth16, Proof};
use ark_std::rand::rngs::StdRng;
use arkworks_examples::{test_rng, Sha256Circuit};

pub type Bn254ProveConfig = ark_groth16::ProvingKey<ark_ec::models::bn::Bn<ark_bn254::Config>>;
pub type Bn254VerifyConfig = ark_groth16::VerifyingKey<ark_ec::models::bn::Bn<ark_bn254::Config>>;
pub type GrothSetup = Groth16<Bn254>;

pub fn bn254_test_arkworks_sha256(num_of_64_bytes: usize, expect: Vec<u8>) {
    let input_size = 64 * num_of_64_bytes;
    let input_str = vec![0u8; input_size];
    let circuit = Sha256Circuit {
        data: input_str,
        expect: expect.clone(),
    };

    let mut test_rng = test_rng();
    let (pk, vk) = circuit_setup(&circuit, &mut test_rng);

    let proof = prove_stmt(circuit.clone(), &mut test_rng, pk);
    verify_proof(expect, vk, proof);
}

fn circuit_setup(
    circuit: &Sha256Circuit,
    test_rng: &mut StdRng,
) -> (Bn254ProveConfig, Bn254VerifyConfig) {
    GrothSetup::circuit_specific_setup(circuit.clone(), test_rng).unwrap()
}

fn prove_stmt(
    circuit: Sha256Circuit,
    test_rng: &mut StdRng,
    pk: Bn254ProveConfig,
) -> Proof<Bn<Config>> {
    GrothSetup::prove(&pk, circuit, test_rng).unwrap()
}

fn verify_proof(expect: Vec<u8>, vk: Bn254VerifyConfig, proof: Proof<Bn<Config>>) {
    let res = GrothSetup::verify(&vk, &expect.to_field_elements().unwrap(), &proof).unwrap();
    assert!(res);
}
