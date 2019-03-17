Benaloh Challenge
-----------------

[![Build Status](https://travis-ci.org/phayes/benaloh-challenge.svg?branch=master)](https://travis-ci.org/phayes/benaloh-challenge)
[![codecov](https://codecov.io/gh/phayes/benaloh-challenge/branch/master/graph/badge.svg)](https://codecov.io/gh/phayes/benaloh-challenge)


Implements the Benaloh Challenge (also known as an Interactive Device Challenge), a crytographic technique to ensure the honesty of an untrusted device. While orignially conceived in the context of voting using an electronic device, it is useful for all untrusted computations that are deterministic with the exception of using an RNG. Most cryptography fits in this category.

The protocol was invented by Josh Benaloh, and is decribed in detail here: https://www.usenix.org/legacy/event/evt07/tech/full_papers/benaloh/benaloh.pdf

### Example

```rust
use benaloh_challenge;
use rand::Rng;
use sha2::Sha256;
use rsa::padding::PaddingScheme;
use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey};

// Untrusted computation that is deterministic with the exception of an RNG
// For this example we encrypt a vote for an election using RSA.
fn untrusted_computation<R: Rng>(
    rng: &mut R,
    public_key: &RSAPublicKey,
    message: &[u8],
) -> Vec<u8> {
    let ciphertext = public_key.encrypt(rng, PaddingScheme::PKCS1v15, message).unwrap();
    return ciphertext;
};

let mut rng = rand::thread_rng();
let mut hasher = Sha256::new();
let public_key = RSAPrivateKey::new(&mut rng, 512).unwrap().extract_public();
let vote = b"Barak Obama";

let mut challenge = benaloh_challenge::Challenge::new(&mut rng, |rng: _| {
    untrusted_computation(rng, &public_key, vote)
});

// Get the commitment
let commitment = challenge.commit(&mut hasher);

// Reveal the secret random factors used in the encryption. This also invalidates the results.
let revealed = challenge.challenge();

// Check the commitment on a different (trusted) device.
benaloh_challenge::check_commitment(&mut hasher, &commitment, &revealed, |rng: _| {
    untrusted_computation(rng, &public_key, vote)
})?;

// In a real voting application, the user would be given the choice to change their vote here.

// Get another commitment
challenge.commit(&mut hasher);

// We could challenge here again if we wanted
// but instead we get the results, discarding the random factors.
let ciphertext = challenge.into_results();
```
