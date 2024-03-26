use ark_bls12_381::{g2::Config, Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::Pairing,
    AffineRepr, CurveGroup,
};
use ark_ff::{field_hashers::DefaultFieldHasher, Field, PrimeField};
use ark_serialize::{CanonicalSerialize, CanonicalSerializeHashExt};
use ark_std::{rand::SeedableRng, UniformRand, Zero};
use bls_scheme::*;
use rand_chacha::ChaChaRng;
use sha2::{Sha256, Sha512};
use std::ops::Mul;

mod bls_scheme;

const PROOF_MSG: &[u8] = "I swear I own this public key".as_bytes();

fn main() {
    // Take a look at module `bls_scheme`.
    // In particular, look at `bls_keygen`, `bls_sign`, and `bls_verif`.
    // This implements the BLS scheme we have seen in the slides.
    // But note that public keys are in G1 and signatures and G2.
    // We can check correctness:
    let (sk, pk) = bls_keygen();
    let m = "Crypto training exercises!".as_bytes();
    let sig = bls_sign(&sk, m);
    assert!(bls_verif(&pk, m, &sig));

    // Now let's take a look at `bls_sign_with_wrong_hash` and `bls_verif_with_wrong_hash`.
    // The developer replaced the complicated Wahby-Boneh hash-to-curve function with something lighter.
    // Q1: break `bls_sign_with_wrong_hash`
    // Write a function `break_sign_with_wrong_hash` that makes one single call to the signature oracle `sign_with_wrong_hash_oracle`
    // and then forges a signature for message `m`.
    // You can call the signature oracle on any message of your choice (except `m` of course!)
    let (sk, pk) = bls_keygen();
    let m = "Let's forge a signature for this message".as_bytes();
    let forged_sig = break_sign_with_wrong_hash(&sk, m);
    assert!(bls_verif_with_wrong_hash(&pk, m, &forged_sig));

    // Let's take a look at `bls_agg_verif`.
    // It checks an aggregate signature on some common message m for a vector of public keys [pk_0, ..., pk_{n-1}].
    let mut secret_keys = Vec::new();
    let mut public_keys = Vec::new();
    for _ in 0..10 {
        let (sk, pk) = bls_keygen();
        secret_keys.push(sk);
        public_keys.push(pk);
    }
    // So if the n signers compute a signature S_i on the same message m,
    // we can aggregate these signatures into a single aggregate signature S = S_1 + ... + S_n and check it.
    let m = "We attest block 103,568".as_bytes();
    // The line below computes the aggregate signature which is just the sum of all individual signatures S_0 + ... + S_{n-1}
    let agg_sig = BlsSig(
        secret_keys
            .iter()
            .fold(G2Projective::zero(), |acc, sk| acc + bls_sign(sk, m).0)
            .into_affine(),
    );
    assert!(bls_agg_verif(&public_keys, m, &agg_sig));

    // Q2: Break this basic aggregation verification scheme.
    // Add a new public key to `public_keys` and forge an aggregate signature attesting a new block on your own.
    // Concretely, write a function `break_basic_aggregation` which returns a new public key and a forged signature on `m`
    // The forged signature must be valid for the set of public keys `public_keys` once `new_key` has been appended.
    let m = "We attest block 103,569".as_bytes();
    let (new_key, forged_sig) = break_basic_aggregation(&public_keys, m);
    public_keys.push(new_key);
    assert!(bls_agg_verif(&public_keys, m, &forged_sig));

    // The problem with the previous aggregate signature verification is that it didn't check
    // that signers know the secret key associated with their public key.
    // So let's add such a proof: now each public must come with a signature on some fixed message `PROOF_MSG`.
    // Take a look at `bls_agg_verif_with_proofs`.
    // This function now checks that each public key comes with a valid proof,
    // i.e. a valid signature proving knowledge of the corresponding secret key.
    let mut secret_keys = Vec::new();
    let mut public_keys = Vec::new();
    let mut proofs = Vec::new();
    for _ in 0..10 {
        let (sk, pk) = bls_keygen();
        secret_keys.push(sk);
        public_keys.push(pk);
        proofs.push(bls_sign(&sk, PROOF_MSG));
    }
    let m = "We attest block 103,570".as_bytes();
    let agg_sig = BlsSig(
        secret_keys
            .iter()
            .fold(G2Projective::zero(), |acc, sk| acc + bls_sign(sk, m).0)
            .into_affine(),
    );
    assert!(bls_agg_verif_with_proofs(
        &public_keys,
        &proofs,
        m,
        &agg_sig
    ));

    // Q3: Break this aggregation verification scheme
    // As before, write a function `break_aggregation_with_proofs` which returns a new key,
    // a proof of possession of the corresponding secret key, and a forged signature on message `m`.
    let m = "We attest block 103,571".as_bytes();
    let (new_key, new_proof, forged_sig) = break_aggregation_with_proofs(&public_keys, &proofs, m);
    public_keys.push(new_key);
    proofs.push(new_proof);
    assert!(bls_agg_verif_with_proofs(
        &public_keys,
        &proofs,
        m,
        &forged_sig
    ));

    // The problem in the previous scheme was that all signers used the same message to prove possession of their secret key.
    // Instead, the signers will now sign their own public key.
    // This way, they all sign a different message when proving possession of their secret key.
    // Take a look at `bls_agg_verif_with_better_proofs`.
    // It works as before, except that the message signed for proving possession of the secret key is different.
    let mut secret_keys = Vec::new();
    let mut public_keys = Vec::new();
    let mut proofs = Vec::new();
    for _ in 0..10 {
        let (sk, pk) = bls_keygen();
        secret_keys.push(sk);
        public_keys.push(pk);
        let proof_msg = Into::<num_bigint::BigUint>::into(pk.0.x).to_bytes_le();
        proofs.push(bls_sign(&sk, &proof_msg));
    }
    let m = "We attest block 103,572".as_bytes();
    let agg_sig = BlsSig(
        secret_keys
            .iter()
            .fold(G2Projective::zero(), |acc, sk| acc + bls_sign(sk, m).0)
            .into_affine(),
    );
    assert!(bls_agg_verif_with_better_proofs(
        &public_keys,
        &proofs,
        m,
        &agg_sig
    ));

    // Q4: Break this aggregation verification scheme
    // Write a function `break_aggregation_with_better_proofs` which returns
    // a list of new public keys, a list of corresponding proofs, and a forged signature for message `m`.
    // The forged signature must be valid for `public_keys` once the list of new public keys has been appended to it.
    let m = "We attest block 103,573".as_bytes();
    let (mut new_keys, mut new_proofs, forged_sig) =
        break_aggregation_with_better_proofs(&public_keys, &proofs, m);
    public_keys.append(&mut new_keys);
    proofs.append(&mut new_proofs);
    assert!(bls_agg_verif_with_better_proofs(
        &public_keys,
        &proofs,
        m,
        &forged_sig
    ));
}

fn break_sign_with_wrong_hash(sk: &SecretKey, m: &[u8]) -> BlsSig {
    todo!()
}

fn break_basic_aggregation(public_keys: &[PublicKey], m: &[u8]) -> (PublicKey, BlsSig) {
    todo!()
}

fn break_aggregation_with_proofs(
    public_keys: &[PublicKey],
    proofs: &[BlsSig],
    m: &[u8],
) -> (PublicKey, BlsSig, BlsSig) {
    todo!()
}

fn break_aggregation_with_better_proofs(
    public_keys: &[PublicKey],
    proofs: &[BlsSig],
    m: &[u8],
) -> (Vec<PublicKey>, Vec<BlsSig>, BlsSig) {
    todo!()
}
