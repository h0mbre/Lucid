//! This file contains all of the logic pertaining to code coverage feedback

/// This is the size of coverage map, this *has* to be a power of 2
const COVERAGE_MAP_SIZE: usize = 65536;

/// All of the information we need to track coverage feedback. Bochs updates the
/// curr_map from its side so it needs the cur_map_addr to get its address. The
/// Rust side uses the history_map to compare the curr_map hitcounts to what we
/// have already seen. If the curr_map hits a new edge pair, or registers a
/// new all-time-high hitcount, we save the input as having reached new coverage
#[derive(Clone)]
#[repr(C)]
pub struct CoverageMap {
    pub curr_map: Vec<u8>,    // The hit count map updated by Bochs
    history_map: Vec<u8>,     // Historical record of hit counts per edge pair
    curr_map_addr: *const u8, // Address of the curr_map used by Bochs
}

impl CoverageMap {
    /// Create a new CoverageMap struct
    pub fn new() -> Self {
        let curr_map = vec![0u8; COVERAGE_MAP_SIZE];
        let curr_map_addr = curr_map.as_ptr();

        CoverageMap {
            curr_map,
            history_map: vec![0u8; COVERAGE_MAP_SIZE],
            curr_map_addr,
        }
    }

    pub fn addr(&self) -> usize {
        self.curr_map_addr as usize
    }

    /// After a fuzzing iteration, Bochs will have updated the curr_map with
    /// hit counts for each edge pair that was reached during that fuzzing
    /// iteration. Instead of keeping the hit counts literal, we instead "bucket"
    /// the hit counts into categories. So for instance if we hit an edge pair
    /// 19 times, it will be placed in the 32 hitcount bucket. This algorithm
    /// is stolen directly from AFL++ who obviously has a ton of empirical
    /// evidence showing that this is beneficial
    #[inline(always)]
    fn bucket(hitcount: u8) -> u8 {
        match hitcount {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 4,
            4..=7 => 8,
            8..=15 => 16,
            16..=31 => 32,
            32..=127 => 64,
            128..=255 => 128,
        }
    }

    /// Walk the historical edge pair map and determine the total number of
    /// edge pairs that we've seen
    pub fn get_edge_count(&mut self) -> usize {
        let mut edge_count = 0;
        self.history_map.iter().for_each(|&hist| {
            if hist > 0 {
                edge_count += 1;
            }
        });

        edge_count
    }

    /// Walks the curr_map and the history_map concurrently comparing the two
    /// values at each index, if curr_map has a new bucket value for a specific
    /// edge pair we return that we found new coverage. curr_map is zeroed out
    /// after the walk is completed.
    pub fn update_coverage(&mut self) -> bool {
        let mut new_coverage = false;

        // Iterate over the current map and the history map together and update
        // the history map, if we discover some new coverage, report true
        self.curr_map
            .iter_mut()
            // Use zip to add history map to the iterator, now we get tuple back
            .zip(self.history_map.iter_mut())
            // For the tuple pair
            .for_each(|(curr, hist)| {
                // If we got a hitcount of at least 1
                if *curr > 0 {
                    // Convert hitcount into bucket count
                    let bucket = CoverageMap::bucket(*curr);

                    // If the old record for this edge pair is lower, update
                    if *hist < bucket {
                        *hist = bucket;
                        new_coverage = true;
                    }
                }
            });

        // Zero out the current map for next fuzzing iteration (it's weirdly
        // much faster to do this here, probably because of SIMD, than while
        // visiting each index)
        self.curr_map.fill(0);

        // Return coverage bool
        new_coverage
    }
}
