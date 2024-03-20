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
    // We can see that R is missing from the input to the hash function when computing the challenge
    // If you think of it as an interactive protocol, this means we can choose R after having computed c
    // So we can just choose a random value for s, compute c = H(X,m), and let R = sG - cX
    // This will pass the verification which checks whether sG = R + cX
    let mut rng = ChaChaRng::from_seed(*b"let's break this scheme!!!!!!!!!");
    let response = Fr::rand(&mut rng);
    let challenge = hash_to_scalar_field(&(pk.0, m));
    let commitment = (Affine::generator().mul(response) - pk.0.mul(challenge)).into_affine();
    SchnorrSig {
        commitment,
        response,
    }
}

fn break_flawed_randomized_schnorr(sk: &SecretKey, pk: &PublicKey) -> SecretKey {
    // We can notice that this signing function seeds a RNG with the secret key
    // Hence, the nonce is always the same at each signature!
    // We can just ask two signatures on different messages to the signing oracle
    // and apply the nonce reuse attack we saw in the slides
    let m1 = "message1".as_bytes();
    let m2 = "message2".as_bytes();
    let sig1 = sk.flawed_randomized_sign_oracle(m1);
    let sig2 = sk.flawed_randomized_sign_oracle(m2);
    // We can check that the public nonces are equal
    assert_eq!(sig1.commitment, sig2.commitment);
    let c1 = hash_to_scalar_field(&(*pk, sig1.commitment, m1));
    let c2 = hash_to_scalar_field(&(*pk, sig2.commitment, m2));
    let s1 = sig1.response;
    let s2 = sig2.response;
    let x = (s1 - s2) * (c1 - c2).inverse().unwrap();
    SecretKey::new(x)
}

fn break_flawed_deterministic_schnorr(sk: &SecretKey, pk: &PublicKey) -> SecretKey {
    // We can notice that the signing function takes as input a public key...
    // But it does not check that this public key corresponds to the secret key instance!
    // Moreover, the public key is not given as input to the hash function when deriving the secret nonce
    // This means that if we ask to sign the same message with different public keys, the nonces
    // will be the same but the challenges will be different
    // Hence, we can apply the nonce reuse attack even though the nonce is deterministically derived
    let mut rng = ChaChaRng::from_seed(*b"let's break this scheme!!!!!!!!!");
    let pk_alt = PublicKey(Affine::rand(&mut rng));
    let m = "message".as_bytes();
    // We ask a first signature with the correct public key
    let sig1 = sk.flawed_deterministic_sign_oracle(pk, m);
    // Then we ask another signature on the same message with a different public key
    let sig2 = sk.flawed_deterministic_sign_oracle(&pk_alt, m);
    // We check that the public nonces are equal
    assert_eq!(sig1.commitment, sig2.commitment);
    let c1 = hash_to_scalar_field(&(*pk, sig1.commitment, m));
    let c2 = hash_to_scalar_field(&(pk_alt, sig2.commitment, m));
    let s1 = sig1.response;
    let s2 = sig2.response;
    let x = (s1 - s2) * (c1 - c2).inverse().unwrap();
    SecretKey::new(x)
}

fn break_two_for_one_schnorr_sign(msk: &SecretKey, mpk: &PublicKey) -> SecretKey {
    // The function computes two signatures from a single secret key and a single secret nonce
    // Again, we should be able to find two equations with just two unknowns
    // The two child keys are sk1 = msk + t1 and sk2 = msk + t2
    // where t_1 = H(mpk, 1) and t_2 = H(mpk, 2) are the tweaks that we can compute
    // This means we can compute the child public keys from the master public key:
    // pk1 = (sk1) G = msk G + t1 G = mpk + t1 G
    // pk2 = (sk2) G = msk G + t2 G = mpk + t2 G
    // We can also compute the challenges c1 = H(pk1, R1, m1) and c2 = H(pk2, R2, m2)
    // Now we write the two equations defining s1 and s2:
    // s1 = r + t1 + c1(x + t1)
    // s2 = r + t2 + c2(x + t2)
    // We known all values here except r and x so we can solve the system
    // Actually we can rewrite the system as
    // s1 - t1 - c1*t1 = r + c1*x
    // s2 - t2 - c2*t2 = r + c2*x
    // These are the same equations as for a standard nonce reuse attack with s values shifted
    let m1 = "message1".as_bytes();
    let m2 = "message2".as_bytes();
    let (sig1, sig2) = msk.two_for_one_schnorr_sign_oracle(m1, m2);
    let t1 = hash_to_scalar_field(&(*mpk, "1".as_bytes()));
    let pk1 = (mpk.0 + Affine::generator().mul(t1)).into_affine();
    let c1 = hash_to_scalar_field(&(pk1, sig1.commitment, m1));
    let t2 = hash_to_scalar_field(&(*mpk, "2".as_bytes()));
    let pk2 = (mpk.0 + Affine::generator().mul(t2)).into_affine();
    let c2 = hash_to_scalar_field(&(pk2, sig2.commitment, m2));
    let s1 = sig1.response;
    let s2 = sig2.response;
    let shift_s1 = s1 - t1 - c1 * t1;
    let shift_s2 = s2 - t2 - c2 * t2;
    let x = (shift_s1 - shift_s2) * (c1 - c2).inverse().unwrap();
    SecretKey::new(x)
}
