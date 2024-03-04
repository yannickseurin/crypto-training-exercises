use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInt, Field, Fp64, MontBackend, MontConfig, PrimeField};
use ark_secp256k1::{Affine, Fq, Fr, Projective};
use ark_std::{ops::Mul, One, UniformRand, Zero};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

fn main() {
    // We initialize a random number generator to sample random field and group elements
    let mut rng = ChaChaRng::from_seed(*b"Advanced cryptography training 1");
    // Now we can sample an element of type `T` by calling `T::rand(&mut rng)`

    // Let us experiment a bit with a small field with 89 elements
    #[derive(MontConfig)]
    #[modulus = "89"]
    #[generator = "3"] // we need to provide a generator of F*, the multiplicative group of the field
    pub struct FqConfig;
    pub type F = Fp64<MontBackend<FqConfig, 1>>;
    // `F` is now the type of an element in the field F_89
    // We can define field elements from integers with `F::from(i)`
    let a = F::from(5);
    let b = F::from(27);
    assert_eq!(a, F::from(94)); // 94 = 5 mod 89

    // We can compute in the field
    assert_eq!(a + b, F::from(32)); // 5+27 = 32 mod 89
    assert_eq!(a - b, F::from(67)); // 5-27 = 67 mod 89
    assert_eq!(a * b, F::from(46)); // 5*27 = 46 mod 89
    assert_eq!(a.square(), F::from(25)); // 5^2 = 25 mod 17
    assert_eq!(b.double(), F::from(54)); // 2*27 = 54 mod 17
    assert_eq!(F::from(0xff), F::from(77)); // 255 = 77 mod 89

    // One can also compute a^n in the field; n must be converted into a "big integer" over a 64-bit limb
    assert_eq!(a.pow(BigInt::<1>::from(7 as u32)), F::from(72)); // 5^7 = 72 mod 89
    
    // The multiplicative identity of `F` can be obtained with `F::one()`
    assert_eq!(F::one(), F::from(1));
    
    // We can inverse field elements; NB: we must unwrap as it may return an Error if called on zero
    let c = F::rand(&mut rng);
    let d = c.inverse().unwrap();
    assert_eq!(c * d, F::one());
    
    // The size of `F` can be obtained with `F::MODULUS`
    let p = F::MODULUS;
    
    // one can check Fermat's little theorem: for a in F, one has a^p = a mod p
    let a = F::rand(&mut rng);
    assert_eq!(a.pow(p), a);

    // Q1: find all generators of the multiplicative group of F_89
    // put them in vector `gen`
    let mut gen_list: Vec<i32> = Vec::new();
    for i in 2..89 {
        // write your test here to check whether i is a generator of F_89
        let mut is_gen = true;
        for j in 1..88 {
            let i_pw_j = F::from(i).pow(BigInt::<1>::from(j as u32));
            if i_pw_j == F::one() {
                is_gen = false;
                break;
            }
        }
        if is_gen {
            gen_list.push(i);
        }
    }
    println!(
        "There are {} generators of F_89 and they are {:?}\n",
        gen_list.len(),
        gen_list
    );
    // uncomment the following line to check your solution (it shouldn't panic for the correct solution)
    assert_eq!(gen_list.iter().sum::<i32>(), 1780);

    // The crate ark-secp256k1 implements the secp256k1 elliptic curve used in Bitcoin
    // We bring four types from this crate into scope: `Fq`, `Fr`, `Affine` and `Projective`
    // `Fq` is the type of elements of the *base* field of the curve
    // `Fr` is the type of elements of the *scalar* field of the curve
    // `Affine` is the type of points on the secp256k1 curve in affine representation (x,y)
    // `Projective` is the type of points in jacobian projective coordinates (X:Y:Z)
    // The point at infinity (i.e., the zero of the group law) can be obtained with `Affine::zero()` or `Projective::zero()`
    // An affine point `g` is encoded as a struct with three fields, its coordinates `x` and `y` and a boolean `infinity`
    let zero_aff = Affine::zero();
    
    // Obviously, field `infinity` is set to `true` for the point at infinity
    assert!(zero_aff.infinity);
    
    // Let's take a look at a random point
    let g_aff = Affine::rand(&mut rng);
    println!("g_aff.x = {}", g_aff.x);
    println!("g_aff.y = {}", g_aff.y);
    println!("g_aff.infinity = {}\n", g_aff.infinity);

    // Q2: check that the coordinates of point `g_aff` satisfy the curve equation y^2 = x^3 + 7
    // Compute the left-hand side `lhs` and the right-hand side `rhs` of this equation and check that they are equal
    let lhs = g_aff.y.square();
    let rhs = g_aff.x.square() * g_aff.x + Fq::from(7);
    assert_eq!(lhs, rhs);

    // We can convert from affine to projective representations using `into_group()`
    // and vice-versa with `into_affine()`
    let zero_proj = zero_aff.into_group();
    
    // The point at infinity in jacobian projective coordinates is [1 : 1 : 0]
    assert!(zero_proj.x.is_one());
    assert!(zero_proj.y.is_one());
    assert!(zero_proj.z.is_zero());

    let g_proj = Projective::rand(&mut rng);
    
    // Q3: check that the coordinates of point `g_proj` satisfy the curve equation in Jacobian projective coordinates Y^2 = X^3 + 7*Z^6
    // Compute the left-hand side `lhs` and the right-hand side `rhs` of this equation and check that they are equal
    let lhs = g_proj.y.square();
    let rhs =
        g_proj.x.square() * g_proj.x + Fq::from(7) * g_proj.z.square() * g_proj.z.square().square();
    assert_eq!(lhs, rhs);

    // One can check that a field element x is a square with a.legendre().is_qr()
    // Q4: Is there a point on secp256k1 with x-coordinate 0? 1? and 5?
    println!("Is 7 a square? {}", Fq::from(7).legendre().is_qr());
    let a = Fq::from(1).square() * Fq::from(1) + Fq::from(7);
    println!("Is 1^3+7 a square? {}", a.legendre().is_qr());
    let b = Fq::from(5).square() * Fq::from(5) + Fq::from(7);
    println!("Is 5^3+7 a square? {}\n", b.legendre().is_qr());

    // The "standard" generator G (that everyone uses in cryptographic schemes) of the curve can be obtained with Affine::generator() or Projective::generator()
    let gen = Affine::generator();
    
    // We can add points with +
    // We can also compute scalar multiplication with method `mul` which takes an element from the scalar field as argument
    // The result is in projective form even if applied to an affine point, if we want the affine form we must convert back to affine explicitly
    let c = gen.mul(Fr::from(4)).into_affine();
    let d = (gen.mul(Fr::from(2)) + gen.mul(Fr::from(2))).into_affine();
    assert_eq!(c, d);

    // Q5: compute the affine coordinates of 2G using the doubling formulas in the slides
    let lambda =
        Fq::from(3) * gen.x.square() * Fq::from(2).inverse().unwrap() * gen.y.inverse().unwrap();
    let x = lambda.square() - Fq::from(2) * gen.x;
    let y = lambda * (gen.x - x) - gen.y;
    // Check they are the same as the one you get by computing `gen.mul(Fr::from(2)` by uncommenting the following two lines
    assert_eq!(x, gen.mul(Fr::from(2)).into_affine().x);
    assert_eq!(y, gen.mul(Fr::from(2)).into_affine().y);

    println!("Good job!");
}
