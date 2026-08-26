use std::path::Path;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::vio::{Fs, Rng};

/// in bytes
pub const KEY_LEGNTH: usize = 1024;
pub struct Key([u8; KEY_LEGNTH]);

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Key {
    pub fn zeroes() -> Self {
        Self([0; _])
    }
    pub fn regenerate_key_pair(
        system_key: &mut Self,
        device_key: &mut Self,
        rng: &mut impl Rng,
    ) -> std::io::Result<()> {
        rng.getrandom(&mut system_key.0)?;
        device_key.0.copy_from_slice(&system_key.0);
        Ok(())
    }
    pub fn xor(&mut self, rhs: &Key) {
        for i in 0..KEY_LEGNTH {
            self.0[i] ^= rhs.0[i];
        }
    }

    pub fn read_from_file(
        &mut self,
        fs: &mut impl Fs,
        path: impl AsRef<Path>,
    ) -> std::io::Result<()> {
        fs.read_exact(path, &mut self.0)
    }
    pub fn write_to_file(&self, fs: &mut impl Fs, path: impl AsRef<Path>) -> std::io::Result<()> {
        fs.write(path, &self.0)
    }

    pub fn check(a: &Self, b: &Self) -> bool {
        a.0.ct_eq(&b.0).into()
    }
}
