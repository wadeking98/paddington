use std::{collections::HashMap, sync::Arc};

use futures::future::join_all;
use rand::{Rng, RngCore, random_range, rng, seq::{IndexedRandom, IteratorRandom, SliceRandom}};
use tokio::{
    sync::{Mutex, Semaphore},
    task::JoinSet,
};

use crate::{errors::DecryptError, oracle::Oracle};

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum DETECT {
    BASELINE,
    OUTLIER,
}

#[allow(async_fn_in_trait)]
pub trait Detector {
    async fn init(
        ct: &[u8],
        oracle: impl Oracle,
        blk_size: usize,
        threads: usize,
    ) -> Result<Self, DecryptError>
    where
        Self: Sized;
    fn check(
        &self,
        ct: &[u8],
    ) -> impl std::future::Future<Output = Result<DETECT, DecryptError>> + Send;
}

pub struct IntermediateDetector {
    base_detector: SimpleDetector,
    pub(crate) block_prefix: Vec<u8>,
    pub(crate) block_suffix: Vec<u8>
}

pub async fn check_byte_creates_invalid_pt(detector: &IntermediateDetector,test_byte:u8,blk_pos:usize, ct_block_left:&[u8], ct_block_right:&[u8], ct_prefix: &[u8], ct_suffix:&[u8], retry: usize) -> Result<bool, DecryptError>{
    for _ in 0..retry{
        let mut test_block = ct_block_left.to_vec();
        let pos = (0..test_block.len()).filter(|p| *p!=blk_pos).choose(&mut rand::rng()).unwrap();
        test_block[pos] = test_block[pos] ^ 1 << random_range(0..8);
        test_block[blk_pos] = test_byte;
        let ct = [ct_prefix,test_block.as_slice(), ct_block_right, ct_suffix].concat();
        let check = detector.check(&ct).await?;
        // if check == DETECT::OUTLIER{
        //     println!("check: {:?}", check);
        // }
        // if we ever detect a different response then we know that test byte doesn't produce an invalid byte
        // in the next plaintext. If it did, all checks would return the same since the plaintext is always invalid
        if check == DETECT::OUTLIER{
            return Ok(false);
        }
    }
    return Ok(true);
}

fn find_satisfying_bytes(bad_chars: &[u8], creates_valid_chars: &[u8]) -> Vec<u8>{
    let mut satisfying_bytes: Vec<u8> = vec![];
    for byte in 0..255{
        //if we find a byte that should produce a valid character when combined with the test byte
        // but instead it produces a character in the bad_chars array, we know we've made a wrong guess 
        let is_guess_valid = creates_valid_chars.iter().find(|v_ch| bad_chars.contains(&(byte ^ **v_ch))).is_none();
        if is_guess_valid{
            satisfying_bytes.push(byte);
        }
    }
    return satisfying_bytes
}

/// Calculates the plaintext of a byte at a certain block position.
/// It returns the plaintext byte and a set of valid characters it found while
/// searching for the valid byte
pub async fn calculate_byte(detector:&IntermediateDetector, blk_pos:usize, bad_chars: &[u8], ct_block_left:&[u8], ct_block_right:&[u8], ct_prefix: &[u8], ct_suffix:&[u8]) -> Option<(u8, Vec<u8>)>{
    let mut creates_valid_chars = vec![];
    let mut satisfying_bytes = vec![];
    
    for _ in 0..30{
        let bytes = (0..255).filter(|b|!creates_valid_chars.contains(b)).map(|b|b).collect::<Vec<u8>>();
        for xor_byte in bytes{

            // if all responses are the same then we've found an invalid char
            let check_byte = xor_byte ^ ct_block_left[blk_pos];
            let resp = check_byte_creates_invalid_pt(detector, check_byte, blk_pos, ct_block_left, ct_block_right,ct_prefix,ct_suffix, 5).await;
            if resp.is_ok_and(|is_invalid| !is_invalid){
                creates_valid_chars.push(xor_byte);
            }
        }
        satisfying_bytes = find_satisfying_bytes(bad_chars, &creates_valid_chars);
        if satisfying_bytes.len() == 1{
            break;
        }else if satisfying_bytes.len() == 0 {
            //if there's no satisfying bytes then something went wrong and we need to try again
            creates_valid_chars = vec![];
        }
    }
    
    if satisfying_bytes.len() >= 1{
        return Some((satisfying_bytes[0], creates_valid_chars.iter().map(|b| b ^ satisfying_bytes[0]).collect()));
    }else{
        return None;
    }
}

/// Use ct_block_left to decrypt ct_block_right.
/// It returns the plaintext and an array of valid bytes
pub async fn decrypt_intermediate_block(detector:&IntermediateDetector,bad_chars: &[u8], iv:&[u8], ct_block_left:&[u8], ct_block_right:&[u8], ct_prefix: &[u8], ct_suffix:&[u8], blk_size: usize) -> (Vec<u8>, Vec<u8>){
    let pt_bytes_shared = Arc::new(Mutex::new(vec![0u8;blk_size]));
    let valid_bytes_shared = Arc::new(Mutex::new(vec![]));
    let mut futures = vec![];
    for blk_pos in 0..blk_size{
        let pt_bytes_copy = pt_bytes_shared.clone();
        let valid_bytes_copy = valid_bytes_shared.clone();
        futures.push(async move{
            if let Some(res) = calculate_byte(detector, blk_pos, bad_chars, ct_block_left, ct_block_right, ct_prefix, ct_suffix).await{
                let pt_byte = res.0;
                pt_bytes_copy.lock().await[blk_pos] = pt_byte;
                let mut valid_bytes = valid_bytes_copy.lock().await;
                let mut new_valid_bytes = res.1.into_iter().filter(|b| !valid_bytes.contains(b)).collect::<Vec<u8>>();
                valid_bytes.append(&mut new_valid_bytes);
                valid_bytes.sort();
                println!("found valid byte: {} {:?}",pt_byte, valid_bytes);
            }
        });
        
    }
    join_all(futures).await;
    let almost_pt = pt_bytes_shared.lock().await.to_vec();
    let xor_diff = ct_block_left.iter().zip(iv.iter()).map(|(b1, b2)| b1^b2).collect::<Vec<u8>>();
    let pt = almost_pt.iter().zip(xor_diff.iter()).map(|(b1,b2)| b1 ^ b2).collect::<Vec<u8>>();
    return (pt, valid_bytes_shared.lock().await.to_vec())
}

impl Detector for IntermediateDetector{
    async fn init(
        ct: &[u8],
        oracle: impl Oracle,
        blk_size: usize,
        threads: usize,
    ) -> Result<Self, DecryptError>
    where
        Self: Sized,
    {
        let oracle_shared = Arc::new(oracle);
        let blocks: Vec<Vec<u8>> = ct
        .chunks(blk_size.into())
        .map(|val| Vec::from(val))
        .collect();
        if blocks.len() < 2 {
            return Err(DecryptError::InvalidInput(
                "Not enough blocks for classic attack".into(),
            ));
        }
        let mut found_oracle: Option<(SimpleDetector, Vec<u8>, Vec<u8>)> = None;
        for i in 1..blocks.len(){
            let retry = 10;
            for r in 1..retry{
                // additive intermediate algorithm
                
                let ct_prefix = ct[..i*blk_size].to_vec();
                let ct_suffix = ct[(i+1)*blk_size..].to_vec();
                let mut inter_ct = [blocks[i-1].clone(), blocks[i].clone()].concat();
                //scramble the inter ciphertext block in such a way it doesn't affect the suffix much
                inter_ct[0] = inter_ct[0] ^ r as u8;
                let res = _detect(&inter_ct, Some(ct_prefix.clone()), Some(ct_suffix.clone()), oracle_shared.clone(), blk_size, threads).await;
                if let Ok(detector) = res {
                    found_oracle = Some((detector, ct[..i*blk_size].to_vec(), ct[i*blk_size..].to_vec()));
                    break;
                }
            }
            if found_oracle.is_some(){
                break
            }
        }
        
        if let Some((detector, block_prefix, block_suffix)) = found_oracle{
            return Ok(Self{base_detector:detector, block_prefix, block_suffix })
        }
        Err(DecryptError::DifferentialResponses("".to_string()))
    }

    async fn check(&self, ct: &[u8]) -> Result<DETECT, DecryptError> {
        self.base_detector.check(&ct).await
    }
}

pub struct SimpleDetector {
    padding_valid_resp: String,
    oracle: Arc<dyn Oracle>,
    semaphore: Arc<Semaphore>,
}

impl Detector for SimpleDetector {
    async fn init(
        ct: &[u8],
        oracle: impl Oracle,
        blk_size: usize,
        threads: usize,
    ) -> Result<Self, DecryptError>
    where
        Self: Sized,
    {
        _detect(ct, None, None, oracle, blk_size, threads).await
    }

    async fn check(&self, ct: &[u8]) -> Result<DETECT, DecryptError> {
        let sem_acquire = self
            .semaphore
            .acquire()
            .await
            .expect("Error: semaphore closed");
        let mut res = DETECT::BASELINE;
        if self.oracle.exec(ct, None, None).await == self.padding_valid_resp {
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
    oracle: impl Oracle,
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
    // though we could use anything for the first block for a basic padding oracle, when we're doing the intermediate oracle attack,
    // we need to take the first block as is
    let last_blocks_shared = Vec::from([blocks[blocks.len() - 2].clone(), blocks[blocks.len() - 1].clone()]);

    let response_map_shared: Arc<Mutex<HashMap<String, u16>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let oracle_shared = Arc::new(oracle);

    let mut futures_set = JoinSet::new();
    for i in 0..=255 {
        let sem_acquire = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("Error: semaphore closed");
        let mut last_blocks = last_blocks_shared.clone();
        let response_map = response_map_shared.clone();
        let oracle = oracle_shared.clone();
        let ct_prefix_copy = ct_prefix.clone();
        let ct_suffix_copy = ct_suffix.clone();
        futures_set.spawn(async move {
            last_blocks[0][blk_size as usize - 1] = i;
            let response = oracle
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
        println!("no unique responses found");
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
        oracle: oracle_shared.clone(),
        semaphore,
    };
    return Ok(detector);
}