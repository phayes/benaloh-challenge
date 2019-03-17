use rand::Rng;
use rand_core::{impls, Error, ErrorKind, RngCore};
use zeroize::Zeroize;

pub struct RecordingRng<'a, R: Rng> {
  inner: &'a mut R,
  recorded: Vec<u8>,
}

impl<'a, R: Rng> RecordingRng<'a, R> {
  pub fn new(rng: &'a mut R) -> Self {
    RecordingRng {
      inner: rng,
      recorded: Vec::new(),
    }
  }

  pub fn fetch_recorded(&mut self) -> Vec<u8> {
    let recorded = self.recorded.drain(..).collect();
    self.recorded.zeroize();
    recorded
  }

  pub fn into_playback(self) -> PlaybackRng {
    PlaybackRng {
      recorded: self.recorded,
    }
  }
}

impl<'a, R: Rng> RngCore for RecordingRng<'a, R> {
  fn next_u32(&mut self) -> u32 {
    impls::next_u32_via_fill(self)
  }

  fn next_u64(&mut self) -> u64 {
    impls::next_u64_via_fill(self)
  }

  fn fill_bytes(&mut self, dest: &mut [u8]) {
    self.inner.fill_bytes(dest);
    self.recorded.extend_from_slice(dest);
  }

  fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
    Ok(self.fill_bytes(dest))
  }
}

pub struct PlaybackRng {
  recorded: Vec<u8>,
}

impl PlaybackRng {
  pub fn new(recorded: &[u8]) -> Self {
    PlaybackRng {
      recorded: recorded.to_vec(),
    }
  }
}

impl RngCore for PlaybackRng {
  fn next_u32(&mut self) -> u32 {
    impls::next_u32_via_fill(self)
  }

  fn next_u64(&mut self) -> u64 {
    impls::next_u64_via_fill(self)
  }

  fn fill_bytes(&mut self, dest: &mut [u8]) {
    if self.recorded.len() < dest.len() {
      // If we are being asked for data beyond the end of our buffer, just fill it with zeroes.
      self.recorded.append(&mut vec![0u8; dest.len()]);
    }
    let items: Vec<u8> = self.recorded.drain(..dest.len()).collect();
    dest.clone_from_slice(&items);
  }

  fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
    if self.recorded.len() < dest.len() {
      Err(Error::new(
        ErrorKind::Unavailable,
        "benaloh_challenge: commitment-check read more RNG values than commitment",
      ))
    } else {
      Ok(self.fill_bytes(dest))
    }
  }
}
