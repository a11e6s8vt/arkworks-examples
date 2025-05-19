//
//
// https://github.com/celer-network/arkworks-sha256-bench/blob/master/benches/sha_bench.rs
//
// For benchmark, run:
//     RAYON_NUM_THREADS=N cargo bench --no-default-features --features "std parallel" -- --nocapture
// where N is the number of threads you want to use (N = 1 for single-thread).

use std::env;

use ark_bn254::{Bn254, Config};
use ark_crypto_primitives::{
    crh::sha256::constraints::{DigestVar, Sha256Gadget},
    snark::SNARK,
};
use ark_ec::bn::Bn;
use ark_ff::{PrimeField, ToConstraintField};
use ark_groth16::{Groth16, Proof};
use ark_r1cs_std::{prelude::EqGadget, uint8::UInt8};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{self, rngs::StdRng};

type Bn254ProveConfig = ark_groth16::ProvingKey<ark_ec::models::bn::Bn<ark_bn254::Config>>;
type Bn254VerifyConfig = ark_groth16::VerifyingKey<ark_ec::models::bn::Bn<ark_bn254::Config>>;
type GrothSetup = Groth16<Bn254>;

struct Sha256Circuit {
    pub data: Vec<u8>,
    pub expect: Vec<u8>,
}

impl Clone for Sha256Circuit {
    fn clone(&self) -> Self {
        Sha256Circuit {
            data: self.data.as_slice().to_vec(),
            expect: self.expect.as_slice().to_vec(),
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for Sha256Circuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let data = UInt8::new_witness_vec(cs.clone(), &self.data).unwrap();
        let expect = UInt8::new_input_vec(cs.clone(), &self.expect).unwrap();

        let mut sha256_var = Sha256Gadget::default();
        sha256_var.update(&data).unwrap();

        sha256_var
            .finalize()?
            .enforce_equal(&DigestVar(expect.clone()))?;

        println!(
            "num_constraints of sha256 with input size {} bytes : {}",
            self.data.len(),
            cs.num_constraints()
        );

        Ok(())
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let num_of_64_bytes = args[1].parse::<usize>().unwrap();
    let expect = hex::decode(args[2].parse::<String>().unwrap()).unwrap();
    let setup_only = args[3].parse::<bool>().unwrap();
    test_arkworks_sha256(num_of_64_bytes, expect, setup_only);
}

fn test_arkworks_sha256(num_of_64_bytes: usize, expect: Vec<u8>, setup_only: bool) {
    let input_size = 64 * num_of_64_bytes;
    let input_str = vec![0u8; input_size];
    let circuit = Sha256Circuit {
        data: input_str,
        expect: expect.clone(),
    };

    let mut test_rng = test_rng();
    let (pk, vk) = circuit_setup(input_size, &circuit, &mut test_rng);

    if setup_only {
        return;
    }

    let proof = prove_stmt(input_size, circuit.clone(), &mut test_rng, pk);
    verify_proof(input_size, expect, vk, proof);
}

fn circuit_setup(
    input_size: usize,
    circuit: &Sha256Circuit,
    test_rng: &mut StdRng,
) -> (Bn254ProveConfig, Bn254VerifyConfig) {
    let start = ark_std::time::Instant::now();
    let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), test_rng).unwrap();
    println!(
        "setup time for sha256 with input size {} bytes: {} ms. pk size: {}",
        input_size,
        start.elapsed().as_millis(),
        pk.uncompressed_size(),
    );

    (pk, vk)
}

fn prove_stmt(
    input_size: usize,
    circuit: Sha256Circuit,
    test_rng: &mut StdRng,
    pk: Bn254ProveConfig,
) -> Proof<Bn<Config>> {
    let start = ark_std::time::Instant::now();
    let proof = GrothSetup::prove(&pk, circuit, test_rng).unwrap();
    println!(
        "proving time for sha256 with input size {} bytes: {} ms. proof size: {}",
        input_size,
        start.elapsed().as_millis(),
        proof.serialized_size(ark_serialize::Compress::Yes),
    );

    proof
}

fn verify_proof(
    input_size: usize,
    expect: Vec<u8>,
    vk: Bn254VerifyConfig,
    proof: Proof<Bn<Config>>,
) {
    let start = ark_std::time::Instant::now();
    let res = GrothSetup::verify(&vk, &expect.to_field_elements().unwrap(), &proof).unwrap();
    println!(
        "verifying time for sha256 with input size {} bytes: {} ms",
        input_size,
        start.elapsed().as_millis()
    );
    assert!(res);
}

fn test_rng() -> StdRng {
    use rand::SeedableRng;
    // arbitrary seed
    let seed = [
        1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];
    rand::rngs::StdRng::from_seed(seed)
}
