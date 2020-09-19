use bls12_381 as bls;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::io;

use crate::error::{Error, Result};
use crate::serial::{Decodable, Encodable, ReadExt, WriteExt};

// This code provides the ability to create a random scalar using a trait
pub trait RngInstance {
    fn fill_bytes(dest: &mut [u8]);
}

pub struct OsRngInstance;

impl RngInstance for OsRngInstance {
    fn fill_bytes(dest: &mut [u8]) {
        OsRng.fill_bytes(dest);
    }
}

pub trait RandomScalar {
    fn new_random<R: RngInstance>() -> Self;
}

// Extend bls::Scalar with a new_random() method.
impl RandomScalar for bls::Scalar {
    fn new_random<R: RngInstance>() -> Self {
        loop {
            let mut random_bytes = [0u8; 32];
            R::fill_bytes(&mut random_bytes);
            let scalar = bls::Scalar::from_bytes(&random_bytes);
            if scalar.is_some().unwrap_u8() == 1 {
                break scalar.unwrap();
            }
        }
    }
}

pub struct HasherToScalar {
    scalar_datas: Vec<[u8; 32]>,
    g1_datas: Vec<[u8; 48]>,
    g2_datas: Vec<[u8; 96]>,
    numbers: Vec<u32>,
}

impl HasherToScalar {
    pub fn new() -> Self {
        Self {
            scalar_datas: Vec::new(),
            g1_datas: Vec::new(),
            g2_datas: Vec::new(),
            numbers: Vec::new(),
        }
    }

    pub fn add(&mut self, scalar: bls::Scalar) {
        let data = scalar.to_bytes();
        self.scalar_datas.push(data);
    }

    pub fn add_g1(&mut self, point: &bls::G1Projective) {
        let point = bls::G1Affine::from(point);
        self.add_g1_affine(&point);
    }

    pub fn add_g2(&mut self, point: &bls::G2Projective) {
        let point = bls::G2Affine::from(point);
        self.add_g2_affine(&point);
    }

    pub fn add_g1_affine(&mut self, point: &bls::G1Affine) {
        let data = point.to_compressed();
        self.g1_datas.push(data);
    }

    pub fn add_g2_affine(&mut self, point: &bls::G2Affine) {
        let data = point.to_compressed();
        self.g2_datas.push(data);
    }

    pub fn add_u32(&mut self, number: u32) {
        self.numbers.push(number);
    }

    pub fn finish(&self) -> bls::Scalar {
        for i in 0u32.. {
            let mut hasher = Sha256::new();

            let i_data = i.to_le_bytes();
            hasher.input(&i_data);

            for number in &self.numbers {
                let data = number.to_le_bytes();
                hasher.input(&data);
            }

            for data in &self.scalar_datas {
                hasher.input(&data[0..32]);
            }

            for data in &self.g1_datas {
                hasher.input(&data[0..32]);
                hasher.input(&data[32..]);
            }
            for data in &self.g2_datas {
                hasher.input(&data[0..32]);
                hasher.input(&data[32..64]);
                hasher.input(&data[64..]);
            }
            let hash_result = hasher.result();

            // TODO: how can I fix this? Why not &hash_result[0...32]??
            let mut hash_data = [0u8; 32];
            hash_data.copy_from_slice(hash_result.as_slice());

            let challenge = bls::Scalar::from_bytes(&hash_data);
            if challenge.is_some().unwrap_u8() == 1 {
                return challenge.unwrap();
            }
        }
        unreachable!();
    }
}

macro_rules! from_slice {
    ($data:expr, $len:literal) => {{
        let mut array = [0; $len];
        // panics if not enough data
        let bytes = &$data[..array.len()];
        array.copy_from_slice(bytes);
        array
    }};
}

pub trait BlsStringConversion {
    fn to_string(&self) -> String;
    fn from_string(object: &str) -> Self;
}

impl BlsStringConversion for bls::Scalar {
    fn to_string(&self) -> String {
        hex::encode(self.to_bytes())
    }
    fn from_string(object: &str) -> Self {
        let bytes = from_slice!(&hex::decode(object).unwrap(), 32);
        bls::Scalar::from_bytes(&bytes).unwrap()
    }
}

impl BlsStringConversion for bls::G1Affine {
    fn to_string(&self) -> String {
        hex::encode(self.to_compressed().to_vec())
    }
    fn from_string(object: &str) -> Self {
        let bytes = from_slice!(&hex::decode(object).unwrap(), 48);
        bls::G1Affine::from_compressed(&bytes).unwrap()
    }
}

impl BlsStringConversion for bls::G2Affine {
    fn to_string(&self) -> String {
        hex::encode(self.to_compressed().to_vec())
    }
    fn from_string(object: &str) -> Self {
        let bytes = from_slice!(&hex::decode(object).unwrap(), 96);
        bls::G2Affine::from_compressed(&bytes).unwrap()
    }
}

impl BlsStringConversion for bls::G1Projective {
    fn to_string(&self) -> String {
        bls::G1Affine::from(self).to_string()
    }
    fn from_string(object: &str) -> Self {
        bls::G1Affine::from_string(object).into()
    }
}

impl BlsStringConversion for bls::G2Projective {
    fn to_string(&self) -> String {
        bls::G2Affine::from(self).to_string()
    }
    fn from_string(object: &str) -> Self {
        bls::G2Affine::from_string(object).into()
    }
}

macro_rules! serialization_bls {
    ($type:ty, $to_x:ident, $from_x:ident, $size:literal) => {
        impl Encodable for $type {
            fn encode<S: io::Write>(&self, mut s: S) -> Result<usize> {
                let data = self.$to_x();
                assert_eq!(data.len(), $size);
                s.write_slice(&data)?;
                Ok(data.len())
            }
        }

        impl Decodable for $type {
            fn decode<D: io::Read>(mut d: D) -> Result<Self> {
                let mut slice = [0u8; $size];
                d.read_slice(&mut slice)?;
                let result = Self::$from_x(&slice);
                if bool::from(result.is_none()) {
                    return Err(Error::ParseFailed("$t conversion from slice failed"));
                }
                Ok(result.unwrap())
            }
        }
    };
}

serialization_bls!(bls::Scalar, to_bytes, from_bytes, 32);
serialization_bls!(bls::G1Affine, to_compressed, from_compressed, 48);
serialization_bls!(bls::G2Affine, to_compressed, from_compressed, 96);

macro_rules! serialization_bls_derived {
    ($type:ty, $affine_type:ty) => {
        impl Encodable for $type {
            fn encode<S: io::Write>(&self, s: S) -> Result<usize> {
                let affine = <$affine_type>::from(self);
                affine.encode(s)
            }
        }

        impl Decodable for $type {
            fn decode<D: io::Read>(d: D) -> Result<Self> {
                let affine = <$affine_type>::decode(d)?;
                Ok(Self::from(affine))
            }
        }
    };
}

serialization_bls_derived!(bls::G1Projective, bls::G1Affine);
serialization_bls_derived!(bls::G2Projective, bls::G2Affine);

macro_rules! make_serialize_deserialize_test {
    ($name:ident, $type:ty, $default_func:ident) => {
        #[test]
        fn $name() {
            let point = <$type>::$default_func();

            let mut data: Vec<u8> = vec![];
            let result = point.encode(&mut data);
            assert!(result.is_ok());

            let point2 = <$type>::decode(&data[..]);
            assert!(point2.is_ok());
            let point2 = point2.unwrap();

            assert_eq!(point, point2);
        }
    };
}

make_serialize_deserialize_test!(serial_test_scalar, bls::Scalar, zero);
make_serialize_deserialize_test!(serial_test_g1_affine, bls::G1Affine, identity);
make_serialize_deserialize_test!(serial_test_g1_projective, bls::G1Projective, identity);
make_serialize_deserialize_test!(serial_test_g2_affine, bls::G2Affine, identity);
make_serialize_deserialize_test!(serial_test_g2_projective, bls::G2Projective, identity);

// Why can I not use Borrow<Scalar> here? Complains about it not being Sized
pub fn sum_scalar<'a, I>(iter: I) -> bls::Scalar
where
    I: Iterator<Item = &'a bls::Scalar>,
{
    iter.fold(bls::Scalar::zero(), |acc, item| acc + item)
}

#[test]
fn test_sum_scalar() {
    let scalars = vec![bls::Scalar::one(), bls::Scalar::one()];
    let two = bls::Scalar::one() + bls::Scalar::one();
    assert_eq!(two, sum_scalar(scalars.iter()));
}
