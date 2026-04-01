use std::{error::Error, sync::Arc, time::Duration};

use async_trait::async_trait;
use reqwest::{Client, Method, Proxy, redirect::Policy};

use crate::helper::{Encoding, decode_ct, encode_ct, set_injection_points};

#[async_trait]
pub trait Transport: 'static + Send + Sync {
    async fn exec(
        &self,
        ct: &[u8],
        ct_prefix: Option<Vec<u8>>,
        ct_suffix: Option<Vec<u8>>,
    ) -> Result<String, Box<dyn Error + Send>>;
}

#[async_trait]
impl<T: Transport> Transport for Arc<T> {
    async fn exec(
        &self,
        ct: &[u8],
        ct_prefix: Option<Vec<u8>>,
        ct_suffix: Option<Vec<u8>>,
    ) -> Result<String, Box<dyn Error + Send>> {
        self.as_ref().exec(ct, ct_prefix, ct_suffix).await
    }
}

#[async_trait]
impl<T: Transport + ?Sized> Transport for Box<T> {
    async fn exec(
        &self,
        ct: &[u8],
        ct_prefix: Option<Vec<u8>>,
        ct_suffix: Option<Vec<u8>>,
    ) -> Result<String, Box<dyn Error + Send>> {
        self.as_ref().exec(ct, ct_prefix, ct_suffix).await
    }
}

#[derive(Clone)]
pub struct HTTPTransport {
    pub(crate) url: String,
    pub(crate) headers: Vec<(String, String)>,
    method: Method,
    pub(crate) data: Option<String>,
    encoding: Vec<Encoding>,
    pub(crate) params: Vec<String>,
    pub(crate) base_ct: Vec<u8>,
    proxy: Option<Proxy>,
}

#[async_trait]
impl Transport for HTTPTransport {
    async fn exec(
        &self,
        ct: &[u8],
        ct_prefix: Option<Vec<u8>>,
        ct_suffix: Option<Vec<u8>>,
    ) -> Result<String, Box<dyn Error + Send>> {
        let ct_prefix = ct_prefix.unwrap_or(vec![]);
        let ct_suffix = ct_suffix.unwrap_or(vec![]);
        let ct = [ct_prefix.as_slice(), ct, ct_suffix.as_slice()].concat();
        let modified_ct =
            encode_ct(&ct, self.encoding.clone()).expect("Invalid utf-8 string after encoding");
        let injection_point = String::from("@{INJECT_HERE}@");
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

        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(Policy::none())
            .http1_title_case_headers();

        //add proxy
        if let Some(p) = &self.proxy {
            client_builder = client_builder.proxy(p.clone())
        }

        let client = client_builder
            .build()
            .expect("Error: could not build request");
        // println!("Sending request");
        let mut req = client.request(self.method.clone(), &url);
        // add request body
        if let Some(ref body) = data {
            req = req.body(body.to_string());
        }

        //add request headers
        for header in headers.clone() {
            req = req.header(header.0, header.1);
        }
        let mut response = req.try_clone().unwrap().send().await;

        // loop with retry for timeout
        if response.is_err() && response.as_ref().err().unwrap().is_timeout() {
            for _ in 0..10 {
                let retry_response = req.try_clone().unwrap().send().await;
                if retry_response.is_ok() {
                    response = retry_response;
                    break;
                } else if let Some(err) = retry_response.err()
                    && !err.is_timeout()
                {
                    return Err(Box::new(err));
                }
            }
        }
        if response.is_err() {
            return Err(Box::new(response.err().unwrap()));
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
        // if let Some(search) = &self.search_pat {
        //     return match search.find(&response_text) {
        //         Some(_) => String::from("matches"),
        //         None => String::from("no match"),
        //     };
        // }
        return Ok(response_text);
    }
}

impl HTTPTransport {
    pub fn new(
        url: String,
        headers: Vec<(String, String)>,
        method: Method,
        data: Option<String>,
        encoding: Vec<Encoding>,
        params: Vec<String>,
        proxy: Option<String>,
    ) -> Self {
        // let mut pat = None;
        // if let Some(search_pat) = search_pat {
        //     let re = RegexBuilder::new(&search_pat)
        //         .multi_line(true)
        //         .build()
        //         .expect(&("Error: Failed to compile regex ".to_owned() + &search_pat));
        //     pat = Some(re);
        // }
        let mut prox = None;
        if let Some(p) = proxy {
            prox = Some(Proxy::all(p).expect("Error: Invalid proxy"));
        }
        let mut transport = Self {
            url,
            headers,
            method,
            data,
            encoding,
            params,
            base_ct: vec![],
            proxy: prox,
        };
        let ct = set_injection_points(&mut transport).expect("Error: No injection points found");
        let ct = decode_ct(ct, transport.encoding.clone());
        transport.base_ct = ct;
        return transport;
    }
}
