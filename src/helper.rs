use base64::prelude::*;
use clap::ValueEnum;
use cookie::{Cookie, CookieJar};
use regex::Regex;
use serde_json::Value;
use std::{collections::HashMap, string::FromUtf8Error};
use strum_macros::Display;
use urlencoding::{decode, encode};
use itertools::Itertools;


use crate::transport::HTTPTransport;

#[derive(Display, Debug, Clone, ValueEnum)]
pub enum Encoding {
    HEX,
    B64,
    B64Url,
    URL,
}

/// Strip standard PKCS#7 padding from a decrypted plaintext.
///
/// Returns the plaintext with the trailing padding bytes removed. If the
/// padding is invalid (the last byte is 0, larger than the block size, or the
/// trailing bytes don't all match the padding length), the original plaintext
/// is returned unchanged so the user still sees the raw output.
pub fn strip_pkcs7(pt: &[u8], block_size: usize) -> Vec<u8> {
    if pt.is_empty() || block_size == 0 {
        return pt.to_vec();
    }
    let pad_len = *pt.last().unwrap() as usize;
    if pad_len == 0 || pad_len > block_size || pad_len > pt.len() {
        // invalid or no padding, return as-is
        return pt.to_vec();
    }
    // all trailing pad_len bytes must equal pad_len
    if pt[pt.len() - pad_len..].iter().all(|b| *b as usize == pad_len) {
        pt[..pt.len() - pad_len].to_vec()
    } else {
        pt.to_vec()
    }
}

/// Automatically detect the encoding layers of a captured ciphertext string.
///
/// Detection is performed by repeatedly peeling off the outermost encoding
/// layer until the string no longer matches a known encoding. The order of
/// detection is:
///   1. URL encoding (if the string contains `%XX` sequences)
///   2. Hex (only `[0-9a-fA-F]`, even length)
///   3. Base64-URL (only `[-_A-Za-z0-9]`, no padding)
///   4. Base64 (only `[A-Za-z0-9+/=]`)
///
/// The returned `Vec<Encoding>` is ordered outer-to-inner so it can be passed
/// directly to `decode_ct`. If no encoding is recognized, `[Encoding::B64]` is
/// returned as a sensible default (the original implicit default).
pub fn detect_encoding(ct: &str) -> Vec<Encoding> {
    let mut layers = Vec::new();
    let mut current = ct.to_string();
    // cap the number of layers we peel off to avoid pathological loops
    for _ in 0..4 {
        let url_re = Regex::new(r"%[0-9a-fA-F]{2}").unwrap();
        if url_re.is_match(&current) {
            // only treat as url-encoded if there's actually a %XX sequence
            layers.push(Encoding::URL);
            if let Ok(decoded) = decode(&current) {
                current = decoded.to_string();
                continue;
            } else {
                break;
            }
        }
        if !current.is_empty()
            && current.chars().all(|c| c.is_ascii_hexdigit())
            && current.len() % 2 == 0
        {
            layers.push(Encoding::HEX);
            break;
        }
        if !current.is_empty()
            && current.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            && current.chars().any(|c| c == '-' || c == '_')
        {
            // contains the url-safe base64 chars '-' or '_', treat as b64-url
            layers.push(Encoding::B64Url);
            break;
        }
        if !current.is_empty()
            && current
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
            && current.chars().any(|c| c.is_alphanumeric())
        {
            layers.push(Encoding::B64);
            break;
        }
        // fall back to default base64
        if layers.is_empty() {
            layers.push(Encoding::B64);
        }
        break;
    }
    if layers.is_empty() {
        layers.push(Encoding::B64);
    }
    layers
}

#[derive(Debug)]
pub enum Messages {
    OracleConfirmed,
    ByteFound(u8, usize),
    AttackComplete,
    NoOracleFound,
    FoundCradle,
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

/// Search the transport's url, headers, and body for a `@{<ciphertext>}@`
/// marker. The first match found has its inner ciphertext captured and the
/// whole marker replaced with `injection_point` (`@{INJECT_HERE}@`). This lets
/// a user mark an injection point inline (e.g. via a Burp request file)
/// without having to name the parameter with `-p`.
fn find_inline_injection_point(
    transport: &mut HTTPTransport,
    injection_point: &str,
) -> Option<String> {
    // match @{...}@, capturing the inner ciphertext. The inner match is
    // non-greedy so it stops at the first "}@". This is unambiguous for the
    // common encodings (base64, hex, url) which never contain the "}@" sequence.
    let re = Regex::new(r"@\{([^@]*?)\}@").unwrap();
    let extract = |text: String| -> Option<(String, String)> {
        re.captures(&text)
            .map(|cap| (cap[1].to_string(), cap[0].to_string()))
    };

    // url
    if let Some((inner, full)) = extract(transport.url.clone()) {
        transport.url = transport.url.replace(&full, injection_point);
        return Some(inner);
    }

    // headers
    for header in transport.headers.iter_mut() {
        if let Some((inner, full)) = extract(header.1.clone()) {
            header.1 = header.1.replace(&full, injection_point);
            return Some(inner);
        }
    }

    // body
    if let Some(ref mut body) = transport.data {
        if let Some((inner, full)) = extract(body.clone()) {
            *body = body.replace(&full, injection_point);
            return Some(inner);
        }
    }

    None
}

pub fn set_injection_points(transport: &mut HTTPTransport) -> Option<String> {
    let mut found_ct = None;
    let injection_point = String::from("@{INJECT_HERE}@");

    // Support the "@{<ciphertext>}@" marker syntax as an alternative to -p.
    // A user can wrap the value they want to analyze directly in the url,
    // headers, or body, e.g. `--url "https://t/@{BASE64CT}@"`. Here we find
    // the first occurrence, capture the wrapped ciphertext, and replace the
    // whole marker with the internal "@{INJECT_HERE}@" placeholder so the
    // transport's exec() can substitute the modified ciphertext later.
    if found_ct.is_none() {
        found_ct = find_inline_injection_point(transport, &injection_point);
    }

    for p in transport.params.clone().into_iter().unique() {
        for i in 0..transport.headers.len() {
            if transport.headers[i].0 == p {
                found_ct = Some(transport.headers[i].1.clone());
                transport.headers[i].1 = injection_point.clone();
            }
            //find cookies
            if transport.headers[i].0.to_ascii_lowercase().eq("cookie") {
                let cookies = Cookie::split_parse(transport.headers[i].1.clone());
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
                transport.headers[i].1 = jar
                    .iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<String>>()
                    .join("; ");
            }
        }
        let temp_url = transport.url.clone();
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

                if transport.url.contains(&lower_hex_url_replace) {
                    replace_str = lower_hex_url_replace;
                } else if transport.url.contains(&upper_hex_url_replace) {
                    replace_str = upper_hex_url_replace;
                }
                found_ct = Some(query_param.1.to_string());
                transport.url = transport.url.replace(&replace_str, &injection_point);
            }
        }

        if let Some(ref mut body_data) = transport.data {
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

/// A parsed raw HTTP request (e.g. one copied from Burp Suite).
#[derive(Debug, Clone)]
pub struct ParsedRequest {
    pub method: String,
    /// The full URL (scheme + host + path + query). If the raw request only
    /// contains a path, `base_url` is used to complete it.
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    /// Whether the URL scheme was inferred (rather than explicitly provided via
    /// an absolute request line or `--url`). When true, the scheme should be
    /// probed to confirm whether http or https is in use.
    pub scheme_inferred: bool,
}

/// Parse a raw HTTP request as it might be exported from Burp Suite.
///
/// The raw request must start with a request line like:
///   `GET /path HTTP/1.1`
/// followed by headers and, after a blank line, an optional body.
///
/// Since raw requests typically only include the path (not the scheme/host),
/// `base_url` should be the origin (e.g. `https://example.com`) that the path
/// is relative to. It is ignored if the request line already contains an
/// absolute URL. If `base_url` is empty, the origin is derived from the
/// request's `Host` header (defaulting to `https://`).
pub fn parse_request_file(
    content: String,
    base_url: Option<&str>,
    headers: Option<&[(String, String)]>,
) -> Result<ParsedRequest, String> {
    let mut lines = content.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| "request file is empty".to_string())?
        .trim();

    // split request line into METHOD SP PATH SP VERSION
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "request line is missing method".to_string())?
        .to_uppercase();
    let target = parts
        .next()
        .ok_or_else(|| "request line is missing target".to_string())?
        .to_string();

    let mut req_headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            // remaining lines are the body
            break;
        }
        if let Some(idx) = line.find(':') {
            let name = line[..idx].trim().to_string();
            let value = line[idx + 1..].trim().to_string();
            req_headers.push((name, value));
        }
    }

    // body is everything after the first blank line
    let body = content
        .split_once("\r\n\r\n")
        .or_else(|| content.split_once("\n\n"))
        .map(|(_, body)| body.trim_end_matches('\n').to_string())
        .filter(|b| !b.is_empty());

    // build the url. If the target is already absolute, use it directly.
    let (url, scheme_inferred) = if target.starts_with("http://") || target.starts_with("https://") {
        (target, false)
    } else {
        // prefer an explicit base_url, otherwise derive from the Host header
        let origin = if let Some(b) = base_url.filter(|b| !b.is_empty()) {
            b.trim_end_matches('/').to_string()
        } else {
            let host = req_headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.trim().to_string())
                .or_else(|| {
                    headers
                        .and_then(|h| h.iter().find(|(n, _)| n.eq_ignore_ascii_case("host")))
                        .map(|(_, v)| v.trim().to_string())
                })
                .ok_or_else(|| {
                    "no --url provided and request has no Host header to derive the origin from"
                        .to_string()
                })?;
            // default to https since raw requests don't carry the scheme. The
            // scheme is inferred here, so the caller should probe to confirm.
            format!("https://{host}", host = host.trim_end_matches('/'))
        };
        (
            format!("{origin}{}", if target.starts_with('/') { target } else { format!("/{target}") }),
            base_url.is_none() || base_url.is_some_and(|b| b.is_empty()),
        )
    };

    Ok(ParsedRequest {
        method,
        url,
        headers: req_headers,
        body,
        scheme_inferred,
    })
}

pub fn unescape(char_str: String) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chars = char_str.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'x') {
            chars.next(); // consume 'x'

            let hi = chars.next().unwrap_or('0');
            let lo = chars.next().unwrap_or('0');

            let hex = format!("{}{}", hi, lo);
            let value = u8::from_str_radix(&hex, 16).unwrap_or(0);

            bytes.push(value);
        } else {
            bytes.push(c as u8);
        }
    }
    return bytes;
}
