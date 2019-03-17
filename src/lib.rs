use digest::Digest;
use rand::Rng;
use rand_core::{impls, Error, RngCore};
use zeroize::Zeroize;

mod rng;
pub use rng::PlaybackRng as CheckRng;
pub use rng::RecordingRng as BenalohRng;

struct BenalohChallenge<'a, R: Rng, C>
where
    C: Fn(&mut BenalohRng<'a, R>) -> Vec<u8>,
{
    rng: BenalohRng<'a, R>,
    calculation: C,
    result: Vec<u8>,
    cached_random: Vec<u8>,
}

impl<'a, R: Rng, C> BenalohChallenge<'a, R, C>
where
    C: Fn(&mut BenalohRng<'a, R>) -> Vec<u8>,
{
    pub fn new(rng: &'a mut R, calculation: C) -> Self {
        let recording_rng = BenalohRng::new(rng);
        BenalohChallenge {
            rng: recording_rng,
            calculation: calculation,
            result: Vec::<u8>::new(),
            cached_random: Vec::<u8>::new(),
        }
    }

    /// Commit the results and get the commitment
    pub fn commit<H: Digest>(&mut self) -> Vec<u8> {
        self.result = (self.calculation)(&mut self.rng);
        self.cached_random = self.rng.fetch_recorded();
        let mut hasher = H::new();
        hasher.input(&self.result);
        let commitment = hasher.result().to_vec();
        return commitment;
    }

    pub fn challenge(&mut self) -> Vec<u8> {
        self.result.zeroize();
        let mut cached_random = Vec::new();
        std::mem::swap(&mut cached_random, &mut self.cached_random);
        cached_random
    }

    pub fn into_results(mut self) -> Vec<u8> {
        self.cached_random.zeroize();
        self.result
    }
}

pub fn check_challenge<H: Digest, C>(
    commitment: &[u8],
    revealed_random: &[u8],
    calculation: C,
) -> Result<(), ()>
where
    C: Fn(&mut CheckRng) -> Vec<u8>,
{
    let mut playback = CheckRng::new(revealed_random);
    let result = (calculation)(&mut playback);
    let mut hasher = H::new();
    hasher.input(result);
    if hasher.result().to_vec() != commitment.to_vec() {
        panic!("TODO: Verification Error");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::check_challenge;
    use crate::BenalohChallenge;
    use crate::{BenalohRng, CheckRng};
    use rand;
    use rand::Rng;
    use rand_core::RngCore;
    use sha2::Sha256;

    #[test]
    fn it_works() {
        fn untrusted_computation<R: Rng>(rng: &mut R, foo: i32) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(8);
            rng.fill_bytes(&mut bytes);
            return bytes.to_vec();
        };

        let mut rng = rand::thread_rng();
        let some_foo = 123;

        let mut challenge = BenalohChallenge::new(&mut rng, |rng: &mut BenalohRng<_>| {
            untrusted_computation(rng, some_foo)
        });

        let commitment = challenge.commit::<Sha256>();

        let revealed = challenge.challenge();

        // Check the challenge on a different (trusted) device.
        check_challenge::<Sha256, _>(&commitment, &revealed, |rng: &mut CheckRng| {
            untrusted_computation(rng, some_foo)
        });

        let _results = challenge.into_results();
    }
}
