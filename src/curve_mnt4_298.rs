use ark_ec::mnt4::MNT4;
use ark_ff::ToConstraintField;
use ark_groth16::{Groth16, Proof};
use ark_mnt4_298::{Config, MNT4_298};
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use arkworks_examples::test_rng;
use arkworks_examples::Sha256Circuit;

/*
 * MNT4-298 Curve
 */
pub type ProveConfig = ark_groth16::ProvingKey<ark_ec::models::mnt4::MNT4<Config>>;
pub type VerifyConfig = ark_groth16::VerifyingKey<ark_ec::models::mnt4::MNT4<Config>>;
pub type GrothSetup = Groth16<MNT4_298>;

pub fn mnt4_298_test_arkworks_sha256(num_of_64_bytes: usize, expect: Vec<u8>) {
    let input_size = 64 * num_of_64_bytes;
    let input_str = vec![0u8; input_size];
    let circuit = Sha256Circuit {
        data: input_str,
        expect: expect.clone(),
    };

    let mut test_rng = test_rng();
    let (pk, vk) = mnt4_298_circuit_setup(&circuit, &mut test_rng);
    let proof = mnt4_298_prove_stmt(circuit, &mut test_rng, pk);
    mnt4_298_verify_proof(expect, vk, proof);
}

fn mnt4_298_circuit_setup(
    circuit: &Sha256Circuit,
    test_rng: &mut StdRng,
) -> (ProveConfig, VerifyConfig) {
    GrothSetup::circuit_specific_setup(circuit.clone(), test_rng).unwrap()
}

fn mnt4_298_prove_stmt(
    circuit: Sha256Circuit,
    test_rng: &mut StdRng,
    pk: ProveConfig,
) -> Proof<MNT4<Config>> {
    GrothSetup::prove(&pk, circuit, test_rng).unwrap()
}

fn mnt4_298_verify_proof(expect: Vec<u8>, vk: VerifyConfig, proof: Proof<MNT4<Config>>) {
    let res = GrothSetup::verify(&vk, &expect.to_field_elements().unwrap(), &proof).unwrap();
    assert!(res);
}
