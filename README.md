Implements the Benaloh Challenge (also known as an Interactive Device Challenge), a crytographic technique to ensure the honesty of an untrusted device. Orignially conceived in the context of voting using an electronic device, is useful for all untrusted computations that are deterministic with the exception of using an RNG. Most cryptography fits in this category.

The protocol was invented by Josh Benaloh, and is decribed in detail here: https://www.usenix.org/legacy/event/evt07/tech/full_papers/benaloh/benaloh.pdf

### Example

```rust
use benaloh_challenge;
use rand::Rng;
use sha2::Sha256;

// Untrustd computation that is deterministic with the exception of an RNG
// For this example we are just honestly reporting the values of the RNG. 
fn untrusted_computation<R: Rng>(rng: &mut R) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8);
    rng.fill_bytes(&mut bytes);
    return bytes.to_vec();
};

let mut rng = rand::thread_rng();
let mut challenge = benaloh_challenge::Challenge::new(&mut rng, |rng: &mut BenalohRng<_>| {
    untrusted_computation(rng)
});

// Get a commitment hash of the results of the untrusted computation.
let commitment = challenge.commit::<Sha256>();

// Flip a coin to see if we will challenge the results, or accept the results.

// Challenge the results, revealing the RNG values used (and invalidating the results)
let revealed = challenge.challenge();

// Check the challenge on a different (trusted) device.
benaloh_challenge::check_commitment::<Sha256, _>(&commitment, &revealed, |rng: &mut CheckRng| {
    untrusted_computation(rng)
})?;

// Get a new commitment
let commitment = challenge.commit::<Sha256>();

// Flip a coin to see if we will challenge the results again, or accept the results.

// Accept the results
let results = challenge.into_results();
```
