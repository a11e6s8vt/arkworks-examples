use ark_crypto_primitives::crh::sha256::constraints::{DigestVar, Sha256Gadget};
use ark_ff::PrimeField;
use ark_r1cs_std::{prelude::EqGadget, uint8::UInt8};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::rand::{self, rngs::StdRng};

pub struct Sha256Circuit {
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

pub fn test_rng() -> StdRng {
    use rand::SeedableRng;
    // arbitrary seed
    let seed = [
        1, 0, 0, 0, 23, 0, 0, 0, 200, 1, 0, 0, 210, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];
    rand::rngs::StdRng::from_seed(seed)
}
