use digest::Digest;
use rand::Rng;
use zeroize::Zeroize;

struct BenalohChallenge<R: Rng, C>
where
    C: Fn(&mut R) -> Vec<u8>,
{
    rng: R,
    calculation: C,
    result: Vec<u8>,
    cached_random: Vec<u8>,
}

impl<R: Rng, C> BenalohChallenge<R, C>
where
    C: Fn(&mut R) -> Vec<u8>,
{
    pub fn new(rng: R, calculation: C) -> Self {
        BenalohChallenge {
            rng: rng,
            calculation: calculation,
            result: Vec::<u8>::new(),
            cached_random: Vec::<u8>::new(),
        }
    }

    /// Get the precommitment
    pub fn precommitment<H: Digest>(&mut self) -> (Vec<u8>, Vec<u8>) {
        let result = (self.calculation)(&mut self.rng);
        let mut hasher = H::new();
        hasher.input(&result);
        let precommitment = hasher.result().to_vec();
        return (result, precommitment);
    }

    pub fn challenge(mut self) -> Vec<u8> {
        self.result.zeroize();
        self.cached_random
    }

    pub fn release_results(mut self) -> Vec<u8> {
        self.cached_random.zeroize();
        self.result
    }
}

pub fn check_challenge<R: Rng, C>(precommitment: &[u8], revealed_random: &[u8]) -> Result<(), ()>
where
    C: Fn(&mut R) -> Vec<u8>,
{
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
