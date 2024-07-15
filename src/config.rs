/// This file contains all of the logic necessary to formulate a coherent
/// Config data structure that we'll pass around with the LucidContext so that
/// we can parse args appropriately. We use the `clap` crate and parse args here
use clap::{Arg, ArgAction, Command};

use crate::err::LucidErr;

// Struct that contains all of the configurable information we need to pass
// around in the LucidContext
#[derive(Clone)]
pub struct Config {
    pub input_max_size: usize,
    pub input_signature: String,
    pub verbose: bool,
    pub skip_dryrun: bool,
    pub bochs_image: String,
    pub bochs_args: Vec<String>,
    pub mutator_seed: Option<usize>,
    pub seeds_dir: Option<String>,
    pub output_dir: String,
    pub findings_limit: Option<usize>,
    pub stat_interval: Option<usize>,
    pub icount_timeout: Option<usize>,
}

pub fn parse_args() -> Result<Config, LucidErr> {
    let matches = Command::new("lucid")
    .version("0.0.1")
    .author("h0mbre")
    .about("x86_64 Full-system Snapshot Fuzzer Powered by Bochs")
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
    .arg(Arg::new("seeds-dir")
        .long("seeds-dir")
        .value_name("SEEDS_DIR")
        .help("Directory containing seed inputs (optional)"))
    .arg(Arg::new("output-dir")
        .long("output-dir")
        .value_name("OUTPUT_DIR")
        .help("Directory to store fuzzer findings")
        .required(true))
    .arg(Arg::new("verbose")
        .long("verbose")
        .help("Enables printing of Bochs stdout and stderr")
        .action(ArgAction::SetTrue))
    .arg(Arg::new("skip-dryrun")
        .long("skip-dryrun")
        .help("Skip dry-run of seed inputs to set coverage map")
        .action(ArgAction::SetTrue))
    .arg(Arg::new("mutator-seed")
        .long("mutator-seed")
        .value_name("SEED")
        .help("Optional seed value provided to mutator pRNG (usize)"))
    .arg(Arg::new("findings-limit")
        .long("findings-limit")
        .value_name("LIMIT")
        .help("Number of megabytes we can save to disk for findings (100 default)"))
    .arg(Arg::new("stat-interval")
        .long("stat-interval")
        .value_name("INTERVAL")
        .help("Number of seconds we wait in between stat reports (1 default)"))
    .arg(Arg::new("icount-timeout")
        .long("icount-timeout")
        .value_name("INSTRUCTION_COUNT")
        .help("Number of instructions we can execute before a timeout (in millions)"))
    .arg(Arg::new("bochs-image")
        .long("bochs-image")
        .value_name("IMAGE")
        .help("File path for the Bochs binary compatible with Lucid")
        .required(true))
        .arg(Arg::new("bochs-args")
        .long("bochs-args")
        .value_name("ARGS")
        .help("Arguments to pass to Bochs once it's loaded")
        .num_args(1..)
        .value_delimiter(' ')
        .allow_hyphen_values(true)
        .required(true))
    .get_matches();

    // Convert the string to a usize
    let max_size_str = matches.get_one::<String>("input-max-size").unwrap();
    let Ok(input_max_size) = max_size_str.parse::<usize>() else {
        return Err(LucidErr::from("Invalid --input-max-size value"));
    };

    // String arguments, unwraps safe on required args
    let output_dir = matches.get_one::<String>("output-dir").unwrap().to_string();
    let input_signature = matches
        .get_one::<String>("input-signature")
        .unwrap()
        .to_string();
    let verbose = matches.get_flag("verbose");
    let skip_dryrun = matches.get_flag("skip-dryrun");
    let bochs_image = matches
        .get_one::<String>("bochs-image")
        .unwrap()
        .to_string();
    let bochs_args = matches
        .get_many::<String>("bochs-args")
        .unwrap()
        .cloned()
        .collect();

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

    // See if a findings limit was provided
    let limit_str = matches.get_one::<String>("findings-limit");
    let findings_limit = match limit_str {
        None => None,
        Some(str_repr) => {
            let Ok(limit) = str_repr.parse::<usize>() else {
                return Err(LucidErr::from("Invalid --findings_limit"));
            };

            Some(limit)
        }
    };

    // See if a stat batch reporting interval was provided
    let interval_str = matches.get_one::<String>("stat-interval");
    let stat_interval = match interval_str {
        None => None,
        Some(str_repr) => {
            let Ok(interval) = str_repr.parse::<usize>() else {
                return Err(LucidErr::from("Invalid --stat-interval"));
            };

            Some(interval)
        }
    };

    // See if a timeout threshold was provided
    let timeout_str = matches.get_one::<String>("icount-timeout");
    let icount_timeout = match timeout_str {
        None => None,
        Some(str_repr) => {
            let Ok(timeout) = str_repr.parse::<usize>() else {
                return Err(LucidErr::from("Invalid --icount-timeout"));
            };

            Some(timeout.wrapping_mul(1_000_000))
        }
    };

    // Create and return Config
    Ok(Config {
        input_max_size,
        input_signature,
        verbose,
        skip_dryrun,
        bochs_image,
        bochs_args,
        mutator_seed,
        seeds_dir,
        output_dir,
        findings_limit,
        stat_interval,
        icount_timeout,
    })
}
