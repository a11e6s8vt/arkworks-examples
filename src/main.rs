use curve_bls::{bls12_377_test_arkworks_sha256, bls12_381_test_arkworks_sha256};
use curve_bn254::bn254_test_arkworks_sha256;
use curve_mnt4_298::mnt4_298_test_arkworks_sha256;
use curve_mnt6_298::mnt6_298_test_arkworks_sha256;

mod curve_bls;
mod curve_bn254;
mod curve_bw6_761;
mod curve_mnt4_298;
mod curve_mnt6_298;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let num_of_64_bytes = args[1].parse::<usize>().unwrap();
    let expect = hex::decode(args[2].parse::<String>().unwrap()).unwrap();
    bn254_test_arkworks_sha256(num_of_64_bytes, expect.clone());
    bls12_381_test_arkworks_sha256(num_of_64_bytes, expect.clone());
    bls12_377_test_arkworks_sha256(num_of_64_bytes, expect.clone());
    mnt4_298_test_arkworks_sha256(num_of_64_bytes, expect.clone());
    mnt6_298_test_arkworks_sha256(num_of_64_bytes, expect.clone());
}
