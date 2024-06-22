/// This file contains all of the logic necessary to implement a crude mutator

#[derive(Clone, Default)]
pub struct Mutator {
    pub rng: usize,
    pub input: Vec<u8>,
    pub corpus: Vec<Vec<u8>>,
    pub max_size: usize,
}

impl Mutator {
    pub fn new(seed: Option<usize>, max_size: usize) -> Self {
        // If pRNG seed not provided, make our own
        let rng = if let Some(seed_val) = seed {
            seed_val
        } else {
            unsafe { core::arch::x86_64::_rdtsc() as usize }
        };

        // Initialize corpus
        let corpus = vec![vec![0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41]];

        Mutator {
            rng,
            input: Vec::with_capacity(max_size),
            corpus,
            max_size
        }        
    }

    #[inline]
    fn rand(&mut self) -> usize {
        // Save off current value
        let curr = self.rng;

        // Mutate current state with xorshift for next call
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 17;
        self.rng ^= self.rng << 43;

        // Return saved off value
        curr
    }

    pub fn generate_input(&mut self) {
        // Clear current input
        self.input.clear();

        // Randomly pick input from corpus to use
        let chosen_idx = self.rand() % self.corpus.len();

        // Copy it over
        self.input.extend_from_slice(&self.corpus[chosen_idx]);

        // Pick a number of bytes to mutate
        let mutations = self.rand() % self.input.len();

        // Mutate bytes randomly in input
        for _ in 0..mutations {
            // Pick an index to mutate
            let idx = self.rand() % self.input.len();

            // Set the value there randomly
            self.input[idx] = (self.rand() % 256) as u8;
        }
    }

    pub fn save_input(&mut self) {
        self.corpus.push(self.input.clone());
    }
}