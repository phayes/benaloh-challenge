## Benaloh Challenge

[![Build Status](https://travis-ci.org/phayes/benaloh-challenge.svg?branch=master)](https://travis-ci.org/phayes/benaloh-challenge)
[![codecov](https://codecov.io/gh/phayes/benaloh-challenge/branch/master/graph/badge.svg)](https://codecov.io/gh/phayes/benaloh-challenge)
[![docs](https://docs.rs/fdh/badge.svg)](https://docs.rs/benaloh-challenge)
[![crates.io](https://meritbadge.herokuapp.com/fdh)](https://crates.io/crates/benaloh-challenge)
[![patreon](https://img.shields.io/badge/patreon-donate-green.svg)](https://patreon.com/phayes)
[![patreon](https://img.shields.io/badge/flattr-donate-green.svg)](https://flattr.com/@phayes)

Implements the Benaloh Challenge (also known as an Interactive Device Challenge), a crytographic technique to ensure the honesty of an untrusted device. While orignially conceived in the context of voting using an electronic device, it is useful for all untrusted computations that are deterministic with the exception of using an RNG. Most cryptography fits in this category.

More details on the protocol can be found here:

- _Ballot Casting Assurance via Voter-Initiated Poll Station Auditing_ by Josh Benaloh, 2007 [[pdf](https://www.usenix.org/legacy/event/evt07/tech/full_papers/benaloh/benaloh.pdf)]
- _Proof of Vote: An end-to-end verifiable digital voting protocol using distributed ledger
  technology_ by Becker et al, 2018 - section 3.2.7 [[pdf](https://github.com/votem/proof-of-vote/raw/master/proof-of-vote-whitepaper.pdf)]

### Example

```rust
use benaloh_challenge;
use rand::Rng;
use sha2::Sha256;
use rsa::padding::PaddingScheme;
use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey};

// Untrusted computation that is deterministic with the exception of an RNG
// For this example we encrypt a vote for an election using RSA.
fn untrusted_computation<R: Rng>(rng: &mut R, key: &RSAPublicKey, message: &[u8]) -> Vec<u8> {
    let ciphertext = key.encrypt(rng, PaddingScheme::PKCS1v15, message).unwrap();
    return ciphertext;
};

let mut rng = rand::thread_rng();
let mut hasher = Sha256::new();
let public_key = RSAPrivateKey::new(&mut rng, 512).unwrap().to_public_key();
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

### Protocol Description

This protocol takes place between a user, a trusted device, and an untrusted device. In this example the user will be Alice, the trusted device will be her cellphone, and the untrusted device will be a voting machine. The voting machine needs to do some untrusted computation using an RNG (encrypting Alice's vote), the details of which need to be kept secret from Alice so she can't prove to a 3rd party how she voted. However, the voting machine needs to assure Alice that it encrypted the vote correctly and didn't change her vote, without letting her know the secret random factors it used in it's encryption.

1. Alice marks her ballot on the voting machine.

2. When Alice is done, the voting machine encrypts her marked-ballot (using random factors from an RNG) and presents a one-way hash of her encrypted vote (for example via QR code). This one-way hash is known as the commitment. The voting machine provides two options to Alice: she may cast or challenge.

3. If alice chooses "cast" the voting machine writes the encrypted vote to disk and the process is done.

4. If alice wishes to challenge she scans the commitment (hash of the encrypted vote) with her cellphone and selects "challenge" on the voting machine.

5. The voting machine transmits the marked-ballot and the random factors to Alice's cellphone (eg via video QR code). The cellphone checks the commitment by re-computing the commiment using the marked ballot and random factors, and compares it to the commitment that was scanned in step 4. If they are the same, the voting machine was honest with it's encryption of the vote. If they are different, the voting machine cheated and is now caught.

6. Alice checks that the marked ballot shown on her cellphone is the same that she inputted into the voting machine.

7. Alice, being satiesfied that the voting machine passed the challange, returns to step 1, (optionally) re-marking her ballot. Alice may repeat the protocol as many times as she wishes until she casts her ballot as per step 3.

The voting machine must produce the commitment before it knows wether it will be challanged or not. If the voting machine tries to cheat (change the vote), it does not know if it will be challanged or if the vote will be cast before it must commit to the ciphertext of the encrytpted vote. This means that any attempt at cheating by the voting machine will have a _chance_ of being caught.

In the context of an election, the Benaloh Challange ensues that systematic cheating by voting machines will be discoverd with a very high probability. Changing a few votes has a decent chance of going undetected, but every time the voting machine cheats, it risks being caught if misjudges when a user might choose to challenge.

## Contributors

1.  Patrick Hayes ([linkedin](https://www.linkedin.com/in/patrickdhayes/)) ([github](https://github.com/phayes)) - Available for hire.
