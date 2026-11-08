use dybw_core::ports::{PortError, Random};

#[cfg_attr(not(test), expect(dead_code, reason = "the core encrypts with it from B5 (writes)"))]
pub struct OsRandom;

impl Random for OsRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), PortError> {
        rand::fill(buf);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_fills_the_buffer() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        OsRandom.fill(&mut a).unwrap_or_default();
        OsRandom.fill(&mut b).unwrap_or_default();
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }
}
