//! This file contains all of the logic necessary to formulate a coherent
//! Config data structure that we'll pass around with the LucidContext so that
//! we can parse args appropriately. We use the `clap` crate and parse args here
//!
//! SPDX-License-Identifier: MIT
//! Copyright (c) 2026 h0mbre

use clap::{Arg, ArgAction, Command};

use crate::err::LucidErr;
use crate::{prompt, prompt_warn};

/// How often the fuzzers in multi-process sync their in memory corpus with disk
/// to capture findings of the other fuzzers
const DEFAULT_SYNC_INTERVAL: usize = 1800; // 30 mins

/// Default timeout for instruction count in a fuzzcase, Bochs can do around 250
/// million instructions per second in testing
const DEFAULT_ICOUNT_TIMEOUT: usize = 250_000_000;

/// The default maximum amount of output we can use in disk space which
/// includes inputs and crashes
const DEFAULT_OUTPUT_MAX: usize = 1_000_000_000;
const MEG: usize = 1_000_000;

/// Default batch time for stat reporting in milliseconds
const DEFAULT_BATCH_TIME: u128 = 2_000;

/// Default number of slots in the edge-pair coverage map
const DEFAULT_COVERAGE_MAP_SIZE: usize = 1 << 16;

/// Struct that contains all of the configurable information we need to pass
/// around in the LucidContext
#[derive(Clone)]
pub struct Config {
    pub input_max_size: usize, // The max size
    pub input_signature: String,
    pub coverage_map_size: usize,
    pub verbose: bool,
    pub dryrun: bool,
    pub bochs_image: String,
    pub bochs_args: Vec<String>,
    pub mutator_seed: Option<usize>,
    pub seeds_dir: Option<String>,
    pub output_dir: String,
    pub output_limit: usize,
    pub stat_interval: u128,
    pub sync_interval: usize,
    pub icount_timeout: usize,
    pub num_fuzzers: usize,
    pub mutator: String,
    pub redqueen: bool,
    pub colorize: bool,
}

/// Parses the command line arguments and creates a Config which is used to
/// configure the LucidContext in most cases for the duration of the campaign
pub fn parse_args() -> Result<Config, LucidErr> {
    let matches = Command::new("lucid")
    .version("0.0.1")
    .author("h0mbre")
    .about("x86_64 Full-System Snapshot Fuzzer Powered by Bochs")
    .arg(Arg::new("input-max-size")
        .long("input-max-size")
        .value_name("SIZE")
        .help("Sets the maximum input size for mutator to use (usize)")
        .required(true))
    .arg(Arg::new("input-signature")
        .long("input-signature")
        .value_name("SIGNATURE")
        .help("Sets the input signature for Lucid to search for in target (128-bit hex string)")
        .required(true))
    .arg(Arg::new("coverage-map-size")
        .long("coverage-map-size")
        .value_name("SIZE")
        .help("Number of edge-pair coverage map slots (power of 2; 65536 default)"))
    .arg(Arg::new("seeds-dir")
        .long("seeds-dir")
        .value_name("SEEDS_DIR")
        .help("Directory containing seed inputs (optional)"))
    .arg(Arg::new("output-dir")
        .long("output-dir")
        .value_name("OUTPUT_DIR")
        .help("Directory to store fuzzer output (inputs, crashes, etc)")
        .required(true))
    .arg(Arg::new("verbose")
        .long("verbose")
        .help("Enables printing of Bochs stdout and stderr")
        .action(ArgAction::SetTrue))
    .arg(Arg::new("dryrun")
        .long("dryrun")
        .help("Replay seed inputs before fuzzing to initialize coverage (slow)")
        .action(ArgAction::SetTrue))
    .arg(Arg::new("mutator-seed")
        .long("mutator-seed")
        .value_name("SEED")
        .help("Optional seed value provided to mutator pRNG (usize)"))
    .arg(Arg::new("output-limit")
        .long("output-limit")
        .value_name("LIMIT")
        .help("Number of megabytes available for output (inputs, crashes, etc; 1000 default)"))
    .arg(Arg::new("fuzzers")
        .long("fuzzers")
        .value_name("COUNT")
        .help("Number of fuzzers we spawn (1 default)"))
    .arg(Arg::new("stat-interval")
        .long("stat-interval")
        .value_name("INTERVAL")
        .help("Number of seconds between stat reports (2 default)"))
    .arg(Arg::new("sync-interval")
        .long("sync-interval")
        .value_name("INTERVAL")
        .help("Number of seconds between corpus syncs (1800 default)"))
    .arg(Arg::new("icount-timeout")
        .long("icount-timeout")
        .value_name("INSTRUCTION_COUNT")
        .help("Execution timeout in millions of guest instructions (250 default)"))
    .arg(Arg::new("bochs-image")
        .long("bochs-image")
        .value_name("IMAGE")
        .help("File path for the Bochs binary compatible with Lucid")
        .required(true))
    .arg(Arg::new("bochs-config")
        .long("bochs-config")
        .value_name("BOCHS_CONFIG")
        .help("File path for the Bochs runtime config file (bochsrc.txt)")
        .required(true))
    .arg(Arg::new("bochs-snapshot-dir")
        .long("bochs-snapshot-dir")
        .value_name("BOCHS_SNAPSHOT_DIR")
        .help("File path for the Bochs snapshot dir created with GUI Bochs")
        .required(true))
    .arg(Arg::new("mutator")
        .long("mutator")
        .value_name("MUTATOR")
        .help("Mutator to use: 'toy' (default) or 'netlink'"))
    .arg(Arg::new("redqueen")
        .long("redqueen")
        .help("Enable Redqueen comparison-guided input processing")
        .action(ArgAction::SetTrue))
    .arg(Arg::new("colorize")
        .long("colorize")
        .help("Enable slower Redqueen operand colorization (requires --redqueen)")
        .requires("redqueen")
        .action(ArgAction::SetTrue))
    .get_matches();

    // Convert the string to a usize
    let max_size_str = matches.get_one::<String>("input-max-size").unwrap();
    let Ok(input_max_size) = max_size_str.parse::<usize>() else {
        return Err(LucidErr::from("Invalid --input-max-size value"));
    };

    // The Bochs edge instrumentation masks hashes with size - 1, which only
    // implements modulo correctly when the map has a nonzero power-of-two size.
    let coverage_map_size = match matches.get_one::<String>("coverage-map-size") {
        None => DEFAULT_COVERAGE_MAP_SIZE,
        Some(str_repr) => {
            let Ok(size) = str_repr.parse::<usize>() else {
                return Err(LucidErr::from("Invalid --coverage-map-size value"));
            };

            if !size.is_power_of_two() {
                return Err(LucidErr::from(
                    "--coverage-map-size must be a nonzero power of 2",
                ));
            }

            size
        }
    };

    // String arguments, unwraps safe on required args
    let output_dir = matches.get_one::<String>("output-dir").unwrap().to_string();
    let input_signature = matches
        .get_one::<String>("input-signature")
        .unwrap()
        .to_string();
    let verbose = matches.get_flag("verbose");
    let dryrun = matches.get_flag("dryrun");
    let bochs_image = matches
        .get_one::<String>("bochs-image")
        .unwrap()
        .to_string();
    let bochs_config = matches
        .get_one::<String>("bochs-config")
        .unwrap()
        .to_string();
    let bochs_snapshot_dir = matches
        .get_one::<String>("bochs-snapshot-dir")
        .unwrap()
        .to_string();

    // Create Bochs args for loading
    let bochs_args = vec![
        "./lucid_bochs".to_string(), // argv[0]
        "-f".to_string(),            // argv[1], config file path option
        bochs_config,                // argv[2], config file path value
        "-q".to_string(),            // argv[3], skip prompting, quick start
        "-r".to_string(),            // argv[4], resume from snapshot directory option
        bochs_snapshot_dir,          // argv[5], resume from snapshot directory value
    ];

    // Reverse args
    let bochs_args = bochs_args.into_iter().rev().collect();

    // See if a mutator seed was provided
    let seed_str = matches.get_one::<String>("mutator-seed");
    let mutator_seed = match seed_str {
        None => None,
        Some(str_repr) => {
            let Ok(seed) = str_repr.parse::<usize>() else {
                return Err(LucidErr::from("Invalid --mutator-seed value"));
            };

            Some(seed)
        }
    };

    // See if a seeds dir was provided
    let seeds_str = matches.get_one::<String>("seeds-dir");
    let seeds_dir = seeds_str.map(|str_repr| str_repr.to_string());

    // See if an output limit was provided
    let limit_str = matches.get_one::<String>("output-limit");
    let output_limit = match limit_str {
        None => {
            prompt!(
                "No output limit specified, defaulting to {}MB",
                DEFAULT_OUTPUT_MAX / MEG
            );
            DEFAULT_OUTPUT_MAX
        }
        Some(str_repr) => {
            let Ok(limit) = str_repr.parse::<usize>() else {
                return Err(LucidErr::from("Invalid --output_limit"));
            };

            // Multiply the passed in limit by a megabyte
            let limit = limit.wrapping_mul(MEG);
            prompt!("Output limit set to {}MB", limit / MEG);

            limit
        }
    };

    // See if a stat batch reporting interval was provided
    let interval_str = matches.get_one::<String>("stat-interval");
    let stat_interval = match interval_str {
        None => {
            prompt_warn!(
                "No stat interval provided, defaulting to {} secs",
                DEFAULT_BATCH_TIME / 1_000
            );
            DEFAULT_BATCH_TIME
        }
        Some(str_repr) => {
            let Ok(interval) = str_repr.parse::<usize>() else {
                return Err(LucidErr::from("Invalid --stat-interval"));
            };

            interval.wrapping_mul(1_000) as u128
        }
    };

    // See if a corpus sync interval was provided
    let interval_str = matches.get_one::<String>("sync-interval");
    let sync_interval = match interval_str {
        None => {
            prompt_warn!(
                "No sync interval specified, defaulting to: {} secs",
                DEFAULT_SYNC_INTERVAL
            );

            DEFAULT_SYNC_INTERVAL
        }
        Some(str_repr) => {
            let Ok(interval) = str_repr.parse::<usize>() else {
                return Err(LucidErr::from("Invalid --sync-interval"));
            };

            interval
        }
    };

    // See if a timeout threshold was provided
    let timeout_str = matches.get_one::<String>("icount-timeout");
    let icount_timeout = match timeout_str {
        None => {
            prompt_warn!(
                "No icount timeout specified, defaulting to {}M instructions",
                DEFAULT_ICOUNT_TIMEOUT / 1_000_000
            );
            DEFAULT_ICOUNT_TIMEOUT
        }
        Some(str_repr) => {
            let Ok(timeout) = str_repr.parse::<usize>() else {
                return Err(LucidErr::from("Invalid --icount-timeout"));
            };

            timeout.wrapping_mul(1_000_000)
        }
    };

    // Convert the number of fuzzers
    let num_fuzzers_str = matches.get_one::<String>("fuzzers");
    let num_fuzzers = match num_fuzzers_str {
        None => 1,
        Some(str_repr) => {
            let Ok(mut fuzzers) = str_repr.parse::<usize>() else {
                return Err(LucidErr::from("Invalid --fuzzers"));
            };

            // Get the number of CPUs
            let num_cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) };
            if num_cpus <= 0 {
                return Err(LucidErr::from("Failed to get number of CPUs"));
            }

            // Change number and warn if necessary
            if fuzzers > num_cpus as usize {
                prompt_warn!(
                    "More fuzzers than CPUs, only spawning {} fuzzers!",
                    num_cpus
                );
                fuzzers = num_cpus as usize;
            }

            // Make sure we have at least one
            if fuzzers == 0 {
                prompt_warn!("Bumping number of fuzzers up to 1",);
                fuzzers = 1;
            }

            fuzzers
        }
    };

    // Get the mutator name
    let mutator_str = matches.get_one::<String>("mutator");
    let mutator = match mutator_str {
        None => {
            prompt_warn!("No mutator specified, defaulting to 'toy'");
            "toy".to_string()
        }
        Some(mutator_str) => mutator_str.to_string(),
    };

    // Detect opting into Redqueen and its optional colorization pass
    let redqueen = matches.get_flag("redqueen");
    let colorize = matches.get_flag("colorize");
    if colorize {
        prompt_warn!("Colorization is enabled, this is VERY slow");
    }

    // Create and return Config
    Ok(Config {
        input_max_size,
        input_signature,
        coverage_map_size,
        verbose,
        dryrun,
        bochs_image,
        bochs_args,
        mutator_seed,
        seeds_dir,
        output_dir,
        output_limit,
        stat_interval,
        sync_interval,
        icount_timeout,
        num_fuzzers,
        mutator,
        redqueen,
        colorize,
    })
}
