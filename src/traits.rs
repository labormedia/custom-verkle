use std::ops::{ Add, Mul, AddAssign };
use std::iter::Sum;
use crate::{ Commitment, Scalar, RistrettoPoint, RISTRETTO_BASEPOINT_POINT }; // wrapper on crate curve25519_dalek

impl From<(RistrettoPoint, Scalar)> for Commitment {
    fn from(value: (RistrettoPoint, Scalar)) -> Self {
        Commitment(value.0, value.1)
    }
}

impl Add for Commitment {
    type Output = Self;
    fn add(self, other: Commitment) -> Self::Output {
        (self.0 + other.0, self.1 + other.1).into()
    }
}

impl Sum for Commitment {
    fn sum<I: Iterator<Item = Self>>(mut iter: I) -> Self {
        if let Some(first) = iter.next() {
            iter.fold(first, |mut acc, x| {
                acc += x;
                acc
            })            
        } else {
            (RISTRETTO_BASEPOINT_POINT, Scalar::from(0_u64)).into()
        }
    }
}

impl AddAssign for Commitment {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs
    }
}