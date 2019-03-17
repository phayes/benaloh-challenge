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
    self.fill_bytes(dest);
    Ok(())
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
      self.fill_bytes(dest);
      Ok(())
    }
  }
}

mod test {
  use rand_core::{impls, Error, RngCore};

  #[allow(dead_code)]
  struct CountingRng {
    count: u64,
  }

  impl RngCore for CountingRng {
    fn next_u32(&mut self) -> u32 {
      self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
      self.count += 1;
      self.count
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
      impls::fill_bytes_via_next(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
      Ok(self.fill_bytes(dest))
    }
  }

  #[test]
  fn test_rng() {
    use crate::rng::RecordingRng;

    let mut rng = CountingRng { count: 0 };
    let mut recorder = RecordingRng::new(&mut rng);

    assert_eq!(recorder.next_u64(), 1);
    assert_eq!(recorder.next_u64(), 2);

    let mut buffer: [u8; 8] = [0x00; 8];
    recorder.try_fill_bytes(&mut buffer).unwrap();
    assert_eq!(buffer, [0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    let mut playback = recorder.into_playback();
    assert_eq!(playback.next_u64(), 1);
    assert_eq!(playback.next_u64(), 2);
    playback.try_fill_bytes(&mut buffer).unwrap();
    assert_eq!(buffer, [0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // We've run out of playack - try some failure modes.
    assert!(playback.try_fill_bytes(&mut buffer).is_err());

    // It will be all zeroes, since we have no more playback
    playback.fill_bytes(&mut buffer);
    assert_eq!(buffer, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
  }

}
