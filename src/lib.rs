#![no_std]

use curve25519_dalek::{RistrettoPoint, Scalar};

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct NonHardenedIndex(u32);

impl NonHardenedIndex {
    pub const fn new(index: u32) -> Self {
        Self(index & !(1 << 31))
    }
}

pub fn derive_public_shift(
    chain_code: &[u8; 32],
    child_index: NonHardenedIndex,
    public_key: &RistrettoPoint,
) -> (Scalar, [u8; 32]) {
    let (mut first_half, mut second_half) = ([0; 32], [0; 32]);

    extract_digest(&mut first_half, &mut second_half, {
        let mut hasher = blake3::Hasher::new_keyed(chain_code);

        hasher
            .update(&public_key.compress().to_bytes())
            .update(&child_index.0.to_le_bytes());

        hasher
    });

    (Scalar::from_bytes_mod_order(first_half), second_half)
}

pub fn derive_child_public_key(
    chain_code: &[u8; 32],
    child_index: NonHardenedIndex,
    basepoint: &RistrettoPoint,
    public_key: &RistrettoPoint,
) -> (RistrettoPoint, [u8; 32]) {
    let (shift, chain_code) = derive_public_shift(chain_code, child_index, public_key);
    (public_key + basepoint * shift, chain_code)
}

pub fn derive_child_public_key_from_path<I>(
    chain_code: &[u8; 32],
    path: I,
    basepoint: &RistrettoPoint,
    public_key: &RistrettoPoint,
) -> RistrettoPoint
where
    I: IntoIterator<Item = NonHardenedIndex>,
{
    let mut chain_code = *chain_code;
    let mut public_key = *public_key;

    for child_index in path {
        let (new_public_key, new_chain_code) =
            derive_child_public_key(&chain_code, child_index, basepoint, &public_key);
        chain_code = new_chain_code;
        public_key = new_public_key;
    }

    public_key
}

pub fn derive_child_secret_key(
    chain_code: &[u8; 32],
    child_index: NonHardenedIndex,
    basepoint: &RistrettoPoint,
    secret_key: &Scalar,
) -> (Scalar, [u8; 32]) {
    let (shift, chain_code) =
        derive_public_shift(chain_code, child_index, &(basepoint * secret_key));
    (secret_key + shift, chain_code)
}

pub fn derive_child_secret_key_from_path<I>(
    chain_code: &[u8; 32],
    path: I,
    basepoint: &RistrettoPoint,
    secret_key: &Scalar,
) -> Scalar
where
    I: IntoIterator<Item = NonHardenedIndex>,
{
    let mut chain_code = *chain_code;
    let mut secret_key = *secret_key;

    for child_index in path {
        let (new_secret_key, new_chain_code) =
            derive_child_secret_key(&chain_code, child_index, basepoint, &secret_key);
        chain_code = new_chain_code;
        secret_key = new_secret_key;
    }

    secret_key
}

fn extract_digest(first_half: &mut [u8; 32], second_half: &mut [u8; 32], hasher: blake3::Hasher) {
    let mut digest = hasher.finalize_xof();
    digest.fill(first_half);
    digest.fill(second_half);
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use rand_core::OsRng;

    use super::*;

    const CHAIN_CODE: [u8; 32] = [0xbe_u8; 32];

    #[test]
    fn derive_same_pubkey() {
        derive_same_pubkey_inner(&RISTRETTO_BASEPOINT_POINT);
        derive_same_pubkey_inner(&RistrettoPoint::random(&mut OsRng));
    }

    fn derive_same_pubkey_inner(generator: &RistrettoPoint) {
        let parent_key = Scalar::random(&mut OsRng);

        let child_pubkey = derive_child_public_key_from_path(
            &CHAIN_CODE,
            core::iter::repeat(0u32).map(NonHardenedIndex::new).take(5),
            generator,
            &(generator * parent_key),
        );
        let child_seckey = derive_child_secret_key_from_path(
            &CHAIN_CODE,
            core::iter::repeat(0u32).map(NonHardenedIndex::new).take(5),
            generator,
            &parent_key,
        );

        assert_eq!(child_seckey * generator, child_pubkey);
    }
}
