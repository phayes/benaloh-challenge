//! Implements the Benaloh Challenge (also known as an Interactive Device Challenge), a crytographic technique to ensure the honesty of an untrusted device. While orignially conceived in the context of voting using an electronic device, it is useful for all untrusted computations that are deterministic with the exception of using an RNG. Most cryptography fits in this category.
//!
//! ## Example
//!
//! ```
//! use benaloh_challenge;
//! use rand::{Rng, CryptoRng};
//! use sha2::{Sha256, Digest};
//! use rsa::padding::PaddingScheme;
//! use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey};
//!
//! // Untrusted computation that is deterministic with the exception of an RNG
//! // For this example we encrypt a vote for an election using RSA.
//! fn untrusted_computation<R: Rng + CryptoRng>(rng: &mut R, key: &RsaPublicKey, message: &[u8]) -> Vec<u8> {
//!     let ciphertext = key.encrypt(rng, PaddingScheme::PKCS1v15Encrypt, message).unwrap();
//!     return ciphertext;
//! };
//!
//! let mut rng = rand::thread_rng();
//! let mut hasher = Sha256::new();
//! let public_key = RsaPrivateKey::new(&mut rng, 512).unwrap().to_public_key();
//! let vote = b"Barak Obama";
//!
//! let mut challenge = benaloh_challenge::Challenge::new(&mut rng, |rng: _| {
//!     untrusted_computation(rng, &public_key, vote)
//! });
//!
//! // Get the commitment
//! let commitment = challenge.commit(&mut hasher);
//!
//! // Reveal the secret random factors used in the encryption. This also invalidates the results.
//! let revealed = challenge.challenge();
//!
//! // Check the commitment on a different (trusted) device.
//! let result = benaloh_challenge::check_commitment(&mut hasher, &commitment, &revealed, |rng: _| {
//!     untrusted_computation(rng, &public_key, vote)
//! });
//! if result.is_err() {
//!   panic!("cheater!")
//! }
//!
//! // In a real voting application, the user would be given the choice to change their vote here.
//!
//! // Get another commitment
//! challenge.commit(&mut hasher);
//!
//! // We could challenge here again if we wanted
//! // but instead we get the results, discarding the random factors.
//! let ciphertext = challenge.into_results();
//!
//! ```
//!
//! ## Protocol Description
//! This protocol takes place between a user, a trusted device, and an untrusted device. In this example the user will be Alice, the trusted device will be her cellphone, and the untrusted device will be a voting machine. The voting machine needs to do some untrusted computation using an RNG (encrypting Alice's vote), the details of which need to be kept secret from Alice so she can't prove to a 3rd party how she voted. However, the voting machine needs to assure Alice that it encrypted the vote correctly and didn't change her vote, without letting her know the secret random factors it used in it's encryption.
//!
//! 1. Alice marks her ballot on the voting machine.
//!
//! 2. When Alice is done, the voting machine encrypts her marked-ballot (using random factors from an RNG) and presents a one-way hash of her encrypted vote (for example via QR code). This one-way hash is known as the commitment. The voting machine provides two options to Alice: she may cast or challenge.
//!
//! 3. If alice chooses "cast" the voting machine writes the encrypted vote to disk and the process is done.
//!
//! 4. If alice wishes to challenge she scans the commitment (hash of the encrypted vote) with her cellphone and selects "challenge" on the voting machine.
//!
//! 5. The voting machine transmits the marked-ballot and the random factors to Alice's cellphone (eg via video QR code). The cellphone checks the commitment by re-computing the commiment using the marked ballot and random factors, and compares it to the commitment that was scanned in step 4. If they are the same, the voting machine was honest with it's encryption of the vote. If they are different, the voting machine cheated and is now caught.
//!
//! 6. Alice checks that the marked ballot shown on her cellphone is the same that she inputted into the voting machine.
//!
//! 7. Alice, being satiesfied that the voting machine passed the challange, returns to step 1, (optionally) re-marking her ballot. Alice may repeat the protocol as many times as she wishes until she casts her ballot as per step 3.
//!
//! The voting machine must produce the commitment before it knows wether it will be challanged or not. If the voting machine tries to cheat (change the vote), it does not know if it will be challanged or if the vote will be cast before it must commit to the ciphertext of the encrytpted vote. This means that any attempt at cheating by the voting machine will have a chance of being caught.
//!
//! In the context of an election, the Benaloh Challange ensues that systematic cheating by voting machines will be discoverd with a very high probability. Changing a few votes has a decent chance of going undetected, but every time the voting machine cheats, it risks being caught if misjudges when a user might choose to challenge.=

use digest::{Digest, FixedOutputReset};
use thiserror::Error;
use rand::{RngCore, CryptoRng};
use zeroize::Zeroize;

mod rng;
pub use rng::PlaybackRng;
pub use rng::RecordingRng;

/// Error types
#[derive(Error, Debug)]
pub enum Error {
    #[error("benaloh_challenge: failed verification - commitments do not match")]
    VerificationFailed,
}

/// A benaloh challenge that wraps untrusted computation in a way that can be challanged.
pub struct Challenge<'a, R: RngCore + CryptoRng, C>
where
    C: Fn(&mut RecordingRng<'a, R>) -> Vec<u8>, // TODO: Return a result.
{
    rng: RecordingRng<'a, R>,
    computation: C,
    result: Vec<u8>,
    cached_random: Vec<u8>,
    committed: bool,
}

impl<'a, R: RngCore + CryptoRng, C> Challenge<'a, R, C>
where
    C: Fn(&mut RecordingRng<'a, R>) -> Vec<u8>,
{
    /// Create a new benaloh challenge with the given RNG and untrusted computation.
    ///
    /// While this method takes a closure, it is generally recommended to create a separate `untrusted_computation` function and wrap it in the closure.
    ///
    /// ## Example:
    ///
    /// ```ignore
    ///fn untrusted_computation<R: Rng>(rng: &mut R, some_data: foo, other_data: bar) -> Vec<u8> {
    ///  // Some unstrusted computation that uses an RNG and other data.
    ///  // The results of this computation must be a vector of bytes.
    ///};
    ///
    ///let mut rng = rand::thread_rng();
    ///let mut hasher = Sha256::new();
    ///let foo = "foo";
    ///let bar = "bar";
    ///
    ///let mut challenge = benaloh_challenge::Challenge::new(&mut rng, |rng: _| {
    ///    untrusted_computation(rng, &foo, &bar)
    ///});
    /// ```
    ///
    /// Note that in this example `untrusted_computation` is not given the original rng direcly.
    /// The RNG is first wrapped in a `RecordingRNG` befor being passed to `untrusted_computation`.
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
    ///
    /// This method generates both the results and the commitment, so must be called before `into_results()` is called.
    pub fn commit<H: Digest + FixedOutputReset>(&mut self, hasher: &mut H) -> Vec<u8> {
        self.result = (self.computation)(&mut self.rng);
        self.cached_random = self.rng.fetch_recorded();
        Digest::update(hasher, &self.result);
        let commitment = hasher.finalize_fixed_reset().to_vec();
        self.committed = true;

        commitment
    }

    /// Challange the results, revealing the random factors and invalidating the results of the computaton.
    ///
    /// The revealing random factors must be given to the challenging device so it may validate the commitment.
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

    /// Get the results of the untrusted computation, discarding (zeroing) the secret random factors.
    ///
    /// This method will panic if called before `commit()` is called (since `commit()` generates the results).
    pub fn into_results(mut self) -> Vec<u8> {
        if !self.committed {
            panic!("benaloh_challenge: Challenge.commit() must be invoked before calling Challenge.into_results()")
        }
        self.cached_random.zeroize();
        self.result
    }
}

/// Check the commitment given by a challenge.
/// This should be done on a different device seperately from the device being challenged.
///
/// This function will return an error if verification of the challenge failed (meaning the challenged device attempted to cheat).
pub fn check_commitment<H: Digest + FixedOutputReset, C>(
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
    Digest::update( hasher, result);
    if hasher.finalize_fixed_reset().to_vec() != commitment.to_vec() {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::check_commitment;
    use crate::{Challenge, Error};
    use rand::{self, Rng, CryptoRng, RngCore};
    use sha2::{Digest, Sha256};

    #[test]
    fn copy_rng_test() -> Result<(), Error> {
        fn untrusted_computation<R: Rng>(rng: &mut R, _foo: i32) -> Vec<u8> {
            let mut bytes = vec![0; 8];
            rng.fill_bytes(&mut bytes);
            return bytes.to_vec();
        }

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
        use rsa::{PublicKey, RsaPrivateKey};

        fn untrusted_computation<R: RngCore + CryptoRng, K: PublicKey>(
            rng: &mut R,
            public_key: &K,
            message: &[u8],
        ) -> Vec<u8> {
            // TODO: return Result<(), Error>

            let ciphertext = public_key
                .encrypt(rng, PaddingScheme::PKCS1v15Encrypt, message)
                .unwrap();

            ciphertext
        }

        let mut rng = rand::thread_rng();
        let mut hasher = Sha256::new();
        let key = RsaPrivateKey::new(&mut rng, 512).unwrap();
        let public_key = key.to_public_key();
        let message = b"Barak Obama";

        let mut challenge = Challenge::new(&mut rng, |rng: _| {
            untrusted_computation(rng, &public_key, message)
        });

        // Get the commitment
        let commitment = challenge.commit(&mut hasher);

        // Reveal the secret random factors used in the encryption
        let revealed = challenge.challenge();

        // Check the challenge on a different (trusted) device.
        check_commitment(&mut hasher, &commitment, &revealed, |rng: _| {
            untrusted_computation(rng, &public_key, message)
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
        }

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
