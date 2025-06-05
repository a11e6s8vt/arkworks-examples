use ark_bls12_377::{Bls12_377, Config as Bls12_377Config};
use ark_bls12_381::{Bls12_381, Config as Bls12_381Config};
use ark_ec::bls12::Bls12;
use ark_ff::ToConstraintField;
use ark_groth16::{Groth16, Proof};
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use arkworks_examples::test_rng;
use arkworks_examples::Sha256Circuit;

/*
 * BLS12-381 Curve
 */
pub type Bls12_381ProveConfig =
    ark_groth16::ProvingKey<ark_ec::models::bls12::Bls12<Bls12_381Config>>;
pub type Bls12_381VerifyConfig =
    ark_groth16::VerifyingKey<ark_ec::models::bls12::Bls12<Bls12_381Config>>;
pub type Bls12_381GrothSetup = Groth16<Bls12_381>;

pub fn bls12_381_test_arkworks_sha256(num_of_64_bytes: usize, expect: Vec<u8>) {
    let input_size = 64 * num_of_64_bytes;
    let input_str = vec![0u8; input_size];
    let circuit = Sha256Circuit {
        data: input_str,
        expect: expect.clone(),
    };

    let mut test_rng = test_rng();
    let (pk, vk) = bls12_381_circuit_setup(&circuit, &mut test_rng);
    let proof = bls12_381_prove_stmt(circuit, &mut test_rng, pk);
    bls12_381_verify_proof(expect, vk, proof);
}

fn bls12_381_circuit_setup(
    circuit: &Sha256Circuit,
    test_rng: &mut StdRng,
) -> (Bls12_381ProveConfig, Bls12_381VerifyConfig) {
    Bls12_381GrothSetup::circuit_specific_setup(circuit.clone(), test_rng).unwrap()
}

fn bls12_381_prove_stmt(
    circuit: Sha256Circuit,
    test_rng: &mut StdRng,
    pk: Bls12_381ProveConfig,
) -> Proof<Bls12<Bls12_381Config>> {
    Bls12_381GrothSetup::prove(&pk, circuit, test_rng).unwrap()
}

fn bls12_381_verify_proof(
    expect: Vec<u8>,
    vk: Bls12_381VerifyConfig,
    proof: Proof<Bls12<Bls12_381Config>>,
) {
    let res =
        Bls12_381GrothSetup::verify(&vk, &expect.to_field_elements().unwrap(), &proof).unwrap();
    assert!(res);
}
/*
 * BLS12-377 Curve
 */
pub type Bls12_377ProveConfig =
    ark_groth16::ProvingKey<ark_ec::models::bls12::Bls12<Bls12_377Config>>;
pub type Bls12_377VerifyConfig =
    ark_groth16::VerifyingKey<ark_ec::models::bls12::Bls12<Bls12_377Config>>;
pub type Bls12_377GrothSetup = Groth16<Bls12_377>;

pub fn bls12_377_test_arkworks_sha256(num_of_64_bytes: usize, expect: Vec<u8>) {
    let input_size = 64 * num_of_64_bytes;
    let input_str = vec![0u8; input_size];
    let circuit = Sha256Circuit {
        data: input_str,
        expect: expect.clone(),
    };

    let mut test_rng = test_rng();
    let (pk, vk) = bls12_377_circuit_setup(&circuit, &mut test_rng);
    let proof = bls12_377_prove_stmt(circuit, &mut test_rng, pk);
    bls12_377_verify_proof(expect, vk, proof);
}

fn bls12_377_circuit_setup(
    circuit: &Sha256Circuit,
    test_rng: &mut StdRng,
) -> (Bls12_377ProveConfig, Bls12_377VerifyConfig) {
    Bls12_377GrothSetup::circuit_specific_setup(circuit.clone(), test_rng).unwrap()
}

fn bls12_377_prove_stmt(
    circuit: Sha256Circuit,
    test_rng: &mut StdRng,
    pk: Bls12_377ProveConfig,
) -> Proof<Bls12<Bls12_377Config>> {
    Bls12_377GrothSetup::prove(&pk, circuit, test_rng).unwrap()
}

fn bls12_377_verify_proof(
    expect: Vec<u8>,
    vk: Bls12_377VerifyConfig,
    proof: Proof<Bls12<Bls12_377Config>>,
) {
    let res =
        Bls12_377GrothSetup::verify(&vk, &expect.to_field_elements().unwrap(), &proof).unwrap();
    assert!(res);
}
