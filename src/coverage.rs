/// This file contains all of the logic pertaining to code coverage feedback

const COVERAGE_MAP_SIZE: usize = 65536;

#[derive(Clone)]
#[repr(C)]
pub struct CoverageMap {
    pub curr_map: Vec<u8>,          // The hit count map updated by Bochs
    history_map: Vec<u8>,           // The map from the previous run
    curr_map_addr: *const u8,       // Address of the curr_map used by Bochs
}

impl CoverageMap {
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

    // Roughly sort ranges of hitcounts into buckets, based on AFL++ logic
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

    // Walk the coverage map in tandem with the history map looking for new
    // bucket thresholds for hitcounts or brand new coverage
    //    
    // Note: normally I like to write things as naively as possible, but we're
    // using chained iterator BS because the compiler spits out faster code
    pub fn update(&mut self) -> (bool, usize) {
        let mut new_coverage = false;
        let mut edge_count = 0;

        // Iterate over the current map that was updated by Bochs during fc
        self.curr_map.iter_mut()                         

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

                    // Zero out the current map for next fuzzing iteration
                    *curr = 0;
                }
            })
        ;

        // If we have new coverage, take the time to walk the map again and 
        // count the number of edges we've hit
        if new_coverage {
            self.history_map.iter().for_each(|&hist| {
                if hist > 0 {
                    edge_count += 1;
                }
            });
        } 

        (new_coverage, edge_count)
    }

    // Reset the current coverage map, usually called because we ran an input 
    // with Cmplog mode enabled so we aren't anticipating new coverage but
    // Bochs would be updating the coverage map because it doesn't know any
    // better
    pub fn reset(&mut self) {
        self.curr_map.fill(0);
    }
}