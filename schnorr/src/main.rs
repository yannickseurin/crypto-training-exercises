use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_secp256k1::{Affine, Fr};
use ark_serialize::{CanonicalSerialize, CanonicalSerializeHashExt};
use ark_std::{ops::Mul, UniformRand};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use schnorr_scheme::*;

mod schnorr_scheme;

fn main() {
    // Take a look at module `schnorr_scheme`
    // In particular, look at `schnorr_keygen`, `schnorr_sign`, and `schnorr_verif`
    // This implements the randomized Schnorr scheme we have seen in the slides
    // We can check correctness:
    let (sk, pk) = schnorr_keygen();
    let m = "Crypto training exercises!".as_bytes();
    let sig = schnorr_sign(&sk, m);
    assert!(schnorr_verif(&pk, m, &sig));

    // Now look at function `wrong_schnorr_verif`
    // The developer seems to have forgotten something somewhere...
    // Q1: Break this scheme by forging a signature that will pass this flawed verification algorithm for an arbitrary message
    // You are only given the public key (no signing oracle)
    // Write a function `break_wrong_schnorr` that forges a signature
    let (_, pk) = schnorr_keygen();
    let m = "Let's forge a signature for this message".as_bytes();
    let sig = break_wrong_schnorr(&pk, m);
    assert!(wrong_schnorr_verif(&pk, m, &sig));

    // Now look at the variant of the signing algorithm `flawed_randomized_schnorr_sign`
    // The developer tried something catchy
    // Q2: Let's break `flawed_randomized_schnorr_sign`
    // You have free access to method `flawed_randomized_sign_oracle` implemented on some secret key instance `sk`
    // Write a function `break_flawed_randomized_schnorr` that retrieves this secret key
    let (sk, pk) = schnorr_keygen();
    let computed_sk = break_flawed_randomized_schnorr(&sk, &pk);
    assert_eq!(sk, computed_sk);

    // Now look at the variant of the signing algorithm `flawed_deterministic_schnorr_sign`
    // The developer wanted to do things good and followed RFC6979
    // But there's a problem though...
    // Q3: Let's break `flawed_deterministic_schnorr_sign`
    // You have free access to method `flawed_deterministic_sign_oracle` implemented on some secret key instance `sk`
    // Write a function `break_flawed_deterministic_schnorr` that retrieves this secret key
    let (sk, pk) = schnorr_keygen();
    let computed_sk = break_flawed_deterministic_schnorr(&sk, &pk);
    assert_eq!(sk, computed_sk);

    // BIP32 allows to derive child keys from a master key pair (msk, psk)
    // Without entering into details, the way it works for "unhardened" child keys
    // is that a "tweak" t is computed as H(mpk, i) where i is an index
    // and the master secret key is offset by the tweak so that the child key
    // is sk_i = msk + t (mod scalar field order)
    // Take a look at `two_for_one_schnorr sign`
    // The developer found an optimized way to generate signatures for two child keys at once
    // Q4: Let's break `two_for_one_schnorr sign`
    // You have free access to method `two_for_one_schnorr_sign_oracle`
    // implemented on some master secret key instance `msk`
    // Write a function `break_two_for_one_schnorr_sign` that retrieves this master secret key
    let (msk, psk) = schnorr_keygen();
    let computed_msk = break_two_for_one_schnorr_sign(&msk, &psk);
    assert_eq!(msk, computed_msk);

    println!("Good job!");
}

fn break_wrong_schnorr(pk: &PublicKey, m: &[u8]) -> SchnorrSig {
    todo!()
}

fn break_flawed_randomized_schnorr(sk: &SecretKey, pk: &PublicKey) -> SecretKey {
    todo!()
    // all you are allowed do with `sk` is call `sk.flawed_randomized_sign_oracle` on messages of your choice
}

fn break_flawed_deterministic_schnorr(sk: &SecretKey, pk: &PublicKey) -> SecretKey {
    todo!()
    // all you are allowed do is with `sk` is call `sk.flawed_deterministic_sign_oracle` on inputs of your choice
}

fn break_two_for_one_schnorr_sign(msk: &SecretKey, mpk: &PublicKey) -> SecretKey {
    todo!()
    // all you are allowed do is with `sk` is call `sk.flawed_deterministic_sign_oracle` on inputs of your choice
}
