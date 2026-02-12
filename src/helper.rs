use std::{collections::HashMap, string::FromUtf8Error};
use cookie::{Cookie, CookieJar};
use regex::Regex;
use serde_json::Value;
use strum_macros::Display;
use clap::ValueEnum;
use base64::prelude::*;
use urlencoding::{decode, encode};

use crate::oracle::HTTPOracle;

#[derive(Display, Debug, Clone, ValueEnum)]
pub enum Encoding {
    HEX,
    B64,
    B64Url,
    URL,
}

#[derive(Debug)]
pub enum Messages {
    OracleConfirmed,
    ByteFound(u8, usize),
    AttackComplete,
    NoOracleFound,
}

#[derive(Clone)]
pub struct Config(HashMap<String, String>);

impl Config {
    pub fn new() -> Self {
        Self(HashMap::new())
    }
    pub fn from_hashmap(config: HashMap<String, String>) -> Self {
        Self(config)
    }
    fn get_base<F, N>(&self, key: String, default: N, convert: F) -> N
    where
        F: Fn(String) -> N,
    {
        match self.0.get(&key) {
            Some(val) => convert(val.into()),
            None => default,
        }
    }
    pub fn get(&self, key: String, default: String) -> String {
        self.get_base(key, default, |val| val)
    }
    pub fn get_int(&self, key: String, default: i64) -> i64 {
        self.get_base(key, default, |val| val.parse().unwrap_or(default))
    }
    pub fn get_bool(&self, key: String, default: bool) -> bool {
        self.get_base(key, default, |val| val.eq("true"))
    }
    pub fn set(&mut self, key: String, val: String) {
        self.0.insert(key, val);
    }
}

pub fn encode_ct(ct: &[u8], encoding: Vec<Encoding>) -> Result<String, FromUtf8Error> {
    let mut res = Vec::from(ct);
    // encode bytes
    for enc in encoding.clone().iter().rev() {
        res = match enc {
            Encoding::HEX => hex::encode(res).as_bytes().to_vec(),
            Encoding::B64 => BASE64_STANDARD.encode(res).as_bytes().to_vec(),
            Encoding::B64Url => BASE64_URL_SAFE.encode(res).as_bytes().to_vec(),
            Encoding::URL => {
                encode(&String::from_utf8(res).expect("Error: invalid string when url encoding"))
                    .as_bytes()
                    .to_vec()
            }
        };
    }
    return String::from_utf8(res);
}

pub fn decode_ct(ct: String, encoding: Vec<Encoding>) -> Vec<u8> {
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

pub fn set_injection_points(oracle: &mut HTTPOracle) -> Option<String> {
    let mut found_ct = None;
    let injection_point = String::from("@{INJECT_HERE}@");
    for p in oracle.params.clone() {
        for i in 0..oracle.headers.len() {
            if oracle.headers[i].0 == p {
                found_ct = Some(oracle.headers[i].1.clone());
                oracle.headers[i].1 = injection_point.clone();
            }
            //find cookies
            if oracle.headers[i].0.to_ascii_lowercase().eq("cookie") {
                let cookies = Cookie::split_parse(oracle.headers[i].1.clone());
                let mut jar = CookieJar::new();
                for cookie in cookies {
                    if let Ok(cookie) = cookie {
                        if cookie.name().eq(&p) {
                            found_ct = Some(cookie.value().to_string());
                            jar.add((cookie.name().to_owned(), injection_point.clone()));
                        } else {
                            jar.add(cookie);
                        }
                    }
                }
                oracle.headers[i].1 = jar
                    .iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<String>>()
                    .join("; ");
            }
        }
        let temp_url = oracle.url.clone();
        let url = url_encoded_data::from(&temp_url);
        for query_param in url.as_pairs() {
            if p.eq(query_param.0) {
                let mut replace_str = query_param.1.to_string();
                // url param parser removes url encoding so we may need to add it back
                let upper_hex_url_replace = urlencoding::encode(&replace_str).to_string();
                let re = Regex::new(r"%([0-9a-fA-F]{2})").unwrap();
                let lower_hex_url_replace = re
                    .replace_all(&upper_hex_url_replace, |cap: &regex::Captures| {
                        format!("%{}", cap[1].to_ascii_lowercase())
                    })
                    .to_string();

                if oracle.url.contains(&lower_hex_url_replace) {
                    replace_str = lower_hex_url_replace;
                } else if oracle.url.contains(&upper_hex_url_replace) {
                    replace_str = upper_hex_url_replace;
                }
                found_ct = Some(query_param.1.to_string());
                oracle.url = oracle.url.replace(&replace_str, &injection_point);
            }
        }

        if let Some(ref mut body_data) = oracle.data {
            //parse from json data
            let json_data_res = serde_json::from_str(&body_data.clone());
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