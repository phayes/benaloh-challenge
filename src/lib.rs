use digest::Digest;
use failure::Error as FailError;
use failure::Fail;
use rand::Rng;
use zeroize::Zeroize;

mod rng;
pub use rng::PlaybackRng;
pub use rng::RecordingRng;

/// Error types
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "benaloh_challenge: failed verification - commitments do not match")]
    VerificationFailed,
    #[fail(display = "benaloh_challenge: failed verification: {}", 0)]
    VerificationError(FailError),
}

pub struct Challenge<'a, R: Rng, C>
where
    C: Fn(&mut RecordingRng<'a, R>) -> Vec<u8>, // TODO: Return a result.
{
    rng: RecordingRng<'a, R>,
    computation: C,
    result: Vec<u8>,
    cached_random: Vec<u8>,
    committed: bool,
}

impl<'a, R: Rng, C> Challenge<'a, R, C>
where
    C: Fn(&mut RecordingRng<'a, R>) -> Vec<u8>,
{
    pub fn new(rng: &'a mut R, untrusted_computation: C) -> Self {
        let recording_rng = RecordingRng::new(rng);
        Challenge {
            rng: recording_rng,
            computation: untrusted_computation,
            result: Vec::<u8>::new(),
            cached_random: Vec::<u8>::new(),
            committed: false,
        }
    }

    /// Commit the results and get the commitment
    pub fn commit<H: Digest>(&mut self, hasher: &mut H) -> Vec<u8> {
        self.result = (self.computation)(&mut self.rng);
        self.cached_random = self.rng.fetch_recorded();
        hasher.input(&self.result);
        let commitment = hasher.result_reset().to_vec();
        self.committed = true;

        commitment
    }

    pub fn challenge(&mut self) -> Vec<u8> {
        if !self.committed {
            panic!("benaloh_challenge: Challenge.commit() must be invoked before calling Challenge.challlenge()")
        }
        self.result.zeroize();
        let mut cached_random = Vec::new();
        std::mem::swap(&mut cached_random, &mut self.cached_random);
        self.committed = false;
        cached_random
    }

    pub fn into_results(mut self) -> Vec<u8> {
        if !self.committed {
            panic!("benaloh_challenge: Challenge.commit() must be invoked before calling Challenge.into_results()")
        }
        self.cached_random.zeroize();
        self.result
    }
}

pub fn check_commitment<H: Digest, C>(
    hasher: &mut H,
    commitment: &[u8],
    revealed_random: &[u8],
    untrusted_computation: C,
) -> Result<(), Error>
where
    C: Fn(&mut PlaybackRng) -> Vec<u8>,
{
    let mut playback = PlaybackRng::new(revealed_random);
    let result = (untrusted_computation)(&mut playback);
    hasher.input(result);
    if hasher.result_reset().to_vec() != commitment.to_vec() {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::check_commitment;
    use crate::{Challenge, Error};
    use rand;
    use rand::Rng;
    use sha2::{Digest, Sha256};

    #[test]
    fn copy_rng_test() -> Result<(), Error> {
        fn untrusted_computation<R: Rng>(rng: &mut R, _foo: i32) -> Vec<u8> {
            let mut bytes = vec![0; 8];
            rng.fill_bytes(&mut bytes);
            return bytes.to_vec();
        };

        let mut rng = rand::thread_rng();
        let mut hasher = Sha256::new();
        let some_foo = 123;

        let mut challenge = Challenge::new(&mut rng, |rng: _| untrusted_computation(rng, some_foo));
        let commitment = challenge.commit(&mut hasher);
        let revealed = challenge.challenge();

        // Check the challenge on a different (trusted) device.
        check_commitment(&mut hasher, &commitment, &revealed, |rng: _| {
            untrusted_computation(rng, some_foo)
        })?;

        challenge.commit(&mut hasher);

        let _results = challenge.into_results();

        Ok(())
    }

    #[test]
    fn rsa_test() -> Result<(), Error> {
        use rsa::padding::PaddingScheme;
        use rsa::{PublicKey, RSAPrivateKey};

        fn untrusted_computation<R: Rng, K: PublicKey>(
            rng: &mut R,
            public_key: &K,
            message: &[u8],
        ) -> Vec<u8> {
            // TODO: return Result<(), Error>

            let ciphertext = public_key
                .encrypt(rng, PaddingScheme::PKCS1v15, message)
                .unwrap();

            ciphertext
        };

        let mut rng = rand::thread_rng();
        let mut hasher = Sha256::new();
        let key = RSAPrivateKey::new(&mut rng, 512).unwrap();
        let message = b"Barak Obama";

        let mut challenge =
            Challenge::new(&mut rng, |rng: _| untrusted_computation(rng, &key, message));

        // Get the commitment
        let commitment = challenge.commit(&mut hasher);

        // Reveal the secret random factors used in the encryption
        let revealed = challenge.challenge();

        // Check the challenge on a different (trusted) device.
        check_commitment(&mut hasher, &commitment, &revealed, |rng: _| {
            untrusted_computation(rng, &key, message)
        })?;

        // Get the real results, discarding the random factors.
        challenge.commit(&mut hasher);
        let _ciphertext = challenge.into_results();

        Ok(())
    }

    #[test]
    fn cheat_test() -> Result<(), Error> {
        use crate::PlaybackRng;
        fn untrusted_computation<R: Rng>(rng: &mut R) -> Vec<u8> {
            let mut bytes = vec![0; 8];
            rng.fill_bytes(&mut bytes);
            return bytes.to_vec();
        };

        let incrementing = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut rng = PlaybackRng::new(&incrementing);
        let mut hasher = Sha256::new();

        let mut challenge = Challenge::new(&mut rng, |rng: _| untrusted_computation(rng));
        let commitment = challenge.commit(&mut hasher);
        let _revealed = challenge.challenge();

        // Cheat!  Replace revealed with out cheat values.
        let revealed = vec![0, 0, 0, 0, 0, 0, 0, 0, 0];

        // Check the challenge on a different (trusted) device.
        let ok = check_commitment(&mut hasher, &commitment, &revealed, |rng: _| {
            untrusted_computation(rng)
        });

        assert!(ok.is_err());
        Ok(())
    }
}
