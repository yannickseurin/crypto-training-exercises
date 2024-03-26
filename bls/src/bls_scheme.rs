use crate::*;

#[derive(Clone, Copy, Debug)]
pub struct SecretKey(Fr);

#[derive(Clone, Copy, Debug)]
pub struct PublicKey(pub G1Affine);

#[derive(Clone, Copy, Debug)]
pub struct BlsSig(pub G2Affine);

pub fn bls_keygen() -> (SecretKey, PublicKey) {
    let mut rng = rand::thread_rng();
    let sk = Fr::rand(&mut rng);
    let pk = G1Affine::generator().mul(sk).into_affine();
    (SecretKey(sk), PublicKey(pk))
}

// defines a secure hash-to-curve function with outputs in G2 based on the Wahby-Boneh (WB) hash function
pub fn hash_to_curve(
) -> MapToCurveBasedHasher<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<Config>> {
    MapToCurveBasedHasher::<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<Config>>::new(&[
        1, 3, 3, 7,
    ])
    .unwrap()
}

pub fn bls_sign(sk: &SecretKey, m: &[u8]) -> BlsSig {
    // compute S = x H(m)
    BlsSig(hash_to_curve().hash(m).unwrap().mul(sk.0).into_affine())
}

pub fn bls_verif(pk: &PublicKey, m: &[u8], sig: &BlsSig) -> bool {
    // check wheter e(G1, S) = e(X, H(m))
    Bls12_381::pairing(G1Affine::generator(), sig.0)
        == Bls12_381::pairing(pk.0, hash_to_curve().hash(m).unwrap())
}

pub fn hash_to_scalar_field<C: CanonicalSerialize>(input: &C) -> Fr {
    let bytes = input.hash::<Sha512>();
    Fr::from_le_bytes_mod_order(&bytes)
}

pub fn wrong_hash_to_curve<C: CanonicalSerialize>(input: &C) -> G2Affine {
    let x = hash_to_scalar_field(input);
    G2Affine::generator().mul(x).into_affine()
}

pub fn bls_sign_with_wrong_hash(sk: &SecretKey, m: &[u8]) -> BlsSig {
    BlsSig(wrong_hash_to_curve(&m).mul(sk.0).into_affine())
}

pub fn bls_verif_with_wrong_hash(pk: &PublicKey, m: &[u8], sig: &BlsSig) -> bool {
    Bls12_381::pairing(G1Affine::generator(), sig.0)
        == Bls12_381::pairing(pk.0, wrong_hash_to_curve(&m))
}

pub fn bls_agg_verif(public_keys: &[PublicKey], m: &[u8], agg_sig: &BlsSig) -> bool {
    // This simply computes the sum of all public keys
    let agg_pk = PublicKey(
        public_keys
            .iter()
            .fold(G1Projective::zero(), |acc, pk| acc + pk.0)
            .into_affine(),
    );
    bls_verif(&agg_pk, m, agg_sig)
}

pub fn bls_agg_verif_with_proofs(
    public_keys: &[PublicKey],
    proofs: &[BlsSig],
    m: &[u8],
    agg_sig: &BlsSig,
) -> bool {
    for (pk, proof) in public_keys.iter().zip(proofs.iter()) {
        if !bls_verif(pk, PROOF_MSG, proof) {
            return false;
        }
    }
    let agg_pk = PublicKey(
        public_keys
            .iter()
            .fold(G1Projective::zero(), |acc, pk| acc + pk.0)
            .into_affine(),
    );
    bls_verif(&agg_pk, m, agg_sig)
}

pub fn bls_agg_verif_with_better_proofs(
    public_keys: &[PublicKey],
    proofs: &[BlsSig],
    m: &[u8],
    agg_sig: &BlsSig,
) -> bool {
    for (pk, proof) in public_keys.iter().zip(proofs.iter()) {
        let proof_msg = Into::<num_bigint::BigUint>::into(pk.0.x).to_bytes_le();
        if !bls_verif(pk, &proof_msg, proof) {
            return false;
        }
    }
    let agg_pk = PublicKey(
        public_keys
            .iter()
            .fold(G1Projective::zero(), |acc, pk| acc + pk.0)
            .into_affine(),
    );
    bls_verif(&agg_pk, m, agg_sig)
}

impl SecretKey {
    pub fn sign_with_wrong_hash_oracle(&self, m: &[u8]) -> BlsSig {
        bls_sign_with_wrong_hash(self, m)
    }
}
