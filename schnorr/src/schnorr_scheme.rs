use crate::*;

#[derive(CanonicalSerialize, Clone, Copy, Debug, PartialEq)]
pub struct SecretKey(Fr);

#[derive(CanonicalSerialize, Clone, Copy, Debug)]
pub struct PublicKey(pub Affine);

pub struct SchnorrSig {
    pub commitment: Affine, // R
    pub response: Fr,       // s
}

pub fn schnorr_keygen() -> (SecretKey, PublicKey) {
    let mut rng = rand::thread_rng();
    let sk = Fr::rand(&mut rng);
    let pk = Affine::generator().mul(sk).into_affine();
    (SecretKey(sk), PublicKey(pk))
}

// hash the inputs into the scalar field of secp256k1
// used to compute the "challenge" c = H(X,R,m)
pub fn hash_to_scalar_field<C: CanonicalSerialize>(input: &C) -> Fr {
    let bytes = input.hash::<sha2::Sha512>();
    Fr::from_le_bytes_mod_order(&bytes)
}

pub fn schnorr_sign(sk: &SecretKey, m: &[u8]) -> SchnorrSig {
    let mut rng = rand::thread_rng();
    let pk = Affine::generator().mul(sk.0).into_affine();
    // r unif. random
    let random_scalar = Fr::rand(&mut rng);
    // R := rG
    let commitment = Affine::generator().mul(random_scalar).into_affine();
    // c := H(X,R,m)
    let challenge = hash_to_scalar_field(&(pk, commitment, m));
    // s := r + cx
    let response = random_scalar + (challenge * sk.0);
    SchnorrSig {
        commitment,
        response,
    }
}

pub fn schnorr_verif(pk: &PublicKey, m: &[u8], sig: &SchnorrSig) -> bool {
    let commitment = sig.commitment;
    let response = sig.response;
    let challenge = hash_to_scalar_field(&(pk.0, commitment, m));
    // sG = R + cX ?
    let lhs = Affine::generator().mul(response).into_affine();
    let rhs = (commitment + pk.0.mul(challenge)).into_affine();
    lhs == rhs
}

pub fn wrong_schnorr_verif(pk: &PublicKey, m: &[u8], sig: &SchnorrSig) -> bool {
    let commitment = sig.commitment;
    let response = sig.response;
    let challenge = hash_to_scalar_field(&(pk.0, m));
    let lhs = Affine::generator().mul(response).into_affine();
    let rhs = (commitment + pk.0.mul(challenge)).into_affine();
    lhs == rhs
}

pub fn flawed_randomized_schnorr_sign(sk: &SecretKey, m: &[u8]) -> SchnorrSig {
    let x: num_bigint::BigUint = sk.0.into();
    let seed: [u8; 32] = x.to_bytes_le().try_into().unwrap();
    let mut rng = ChaChaRng::from_seed(seed);
    let pk = Affine::generator().mul(sk.0).into_affine();
    let random_scalar = Fr::rand(&mut rng);
    let commitment = Affine::generator().mul(random_scalar).into_affine();
    let challenge = hash_to_scalar_field(&(pk, commitment, m));
    let response = random_scalar + (challenge * sk.0);
    SchnorrSig {
        commitment,
        response,
    }
}

pub fn flawed_deterministic_schnorr_sign(sk: &SecretKey, pk: &PublicKey, m: &[u8]) -> SchnorrSig {
    let pseudorandom_scalar = hash_to_scalar_field(&(*sk, m));
    let commitment = Affine::generator().mul(pseudorandom_scalar).into_affine();
    let challenge = hash_to_scalar_field(&(*pk, commitment, m));
    let response = pseudorandom_scalar + (challenge * sk.0);
    SchnorrSig {
        commitment,
        response,
    }
}

pub fn two_for_one_schnorr_sign(msk: &SecretKey, m1: &[u8], m2: &[u8]) -> (SchnorrSig, SchnorrSig) {
    let mut rng = rand::thread_rng();
    let mpk = Affine::generator().mul(msk.0).into_affine();
    let tweak1 = hash_to_scalar_field(&(mpk, "1".as_bytes()));
    let tweak2 = hash_to_scalar_field(&(mpk, "2".as_bytes()));
    let sk1 = msk.0 + tweak1;
    let sk2 = msk.0 + tweak2;
    let pk1 = Affine::generator().mul(sk1).into_affine();
    let pk2 = Affine::generator().mul(sk2).into_affine();
    let random_scalar = Fr::rand(&mut rng);
    let commitment = Affine::generator()
        .mul(random_scalar + tweak1)
        .into_affine();
    let challenge = hash_to_scalar_field(&(pk1, commitment, m1));
    let response = random_scalar + tweak1 + (challenge * sk1);
    let sig1 = SchnorrSig {
        commitment,
        response,
    };
    let commitment = Affine::generator()
        .mul(random_scalar + tweak2)
        .into_affine();
    let challenge = hash_to_scalar_field(&(pk2, commitment, m2));
    let response = random_scalar + tweak2 + (challenge * sk2);
    let sig2 = SchnorrSig {
        commitment,
        response,
    };
    (sig1, sig2)
}

impl SecretKey {
    // the field `0` of the tuple struct SecretKey is private, but this function allows to create an instance
    pub fn new(x: Fr) -> SecretKey {
        SecretKey(x)
    }

    pub fn flawed_randomized_sign_oracle(&self, m: &[u8]) -> SchnorrSig {
        flawed_randomized_schnorr_sign(self, m)
    }

    pub fn flawed_deterministic_sign_oracle(&self, pk: &PublicKey, m: &[u8]) -> SchnorrSig {
        flawed_deterministic_schnorr_sign(self, pk, m)
    }

    pub fn two_for_one_schnorr_sign_oracle(
        &self,
        m1: &[u8],
        m2: &[u8],
    ) -> (SchnorrSig, SchnorrSig) {
        two_for_one_schnorr_sign(self, m1, m2)
    }
}
