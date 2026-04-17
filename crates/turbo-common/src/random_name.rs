const ADJECTIVES: &[&str] = &[
    "brave", "bright", "calm", "clever", "cool", "crisp", "dark", "eager", "fast", "fierce",
    "fond", "free", "glad", "grand", "happy", "keen", "kind", "lively", "lucky", "mild", "noble",
    "proud", "quiet", "rapid", "sharp", "sleek", "smart", "smooth", "solid", "steady", "still",
    "stout", "strong", "sure", "swift", "tall", "true", "vivid", "warm", "wild",
];

const ANIMALS: &[&str] = &[
    "badger", "bear", "bison", "bobcat", "cobra", "condor", "crane", "crow", "deer", "eagle",
    "elk", "falcon", "ferret", "fox", "gopher", "hawk", "heron", "horse", "husky", "ibex",
    "jackal", "jay", "koala", "leopard", "lion", "lynx", "marten", "moose", "newt", "otter", "owl",
    "panther", "parrot", "puma", "raven", "robin", "salmon", "shark", "snake", "sparrow", "stork",
    "tiger", "viper", "walrus", "wolf", "wren",
];

#[must_use]
pub fn random_name() -> String {
    let adj = ADJECTIVES[random_index(ADJECTIVES.len())];
    let animal = ANIMALS[random_index(ANIMALS.len())];
    format!("{adj}-{animal}")
}

/// Uniform random index in `0..len` using rejection sampling to avoid the
/// modulo bias of a naive `% len`.
fn random_index(len: usize) -> usize {
    assert!(len > 0, "random_index requires len > 0");
    let threshold = usize::MAX - (usize::MAX % len);
    loop {
        let mut buf = [0u8; 8];
        // OS RNG failure is unrecoverable at this layer.
        #[allow(clippy::expect_used)]
        {
            getrandom::fill(&mut buf).expect("getrandom failed");
        }
        let n = usize::from_ne_bytes(buf);
        if n < threshold {
            return n % len;
        }
    }
}
