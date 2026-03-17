use std::{cmp::max, collections::HashMap, hash::{DefaultHasher, Hash, Hasher}, sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}}};

use async_stream::stream;
use futures::{Stream, future::join_all, lock::Mutex, pin_mut};
use futures::stream::StreamExt;
use rand::{random_range, seq::IteratorRandom};
use tokio::{select, sync::mpsc::Sender};
use tokio_util::sync::CancellationToken;

use crate::{crypt::detector::{DETECT, Detector, IntermediateDetector}, errors::DecryptError, helper::Messages};

#[derive(Clone, Debug)]
pub struct ComputeCache{
    valid_bytes: Vec<u8>,
    c1_prime: Vec<u8>,
    // 0 is the ciphertext and 1 is the plaintext
    c2_prime: (Vec<u8>, Vec<u8>)
}
impl ComputeCache{
    pub fn new() -> Self{
        return ComputeCache { valid_bytes: vec![], c1_prime: vec![], c2_prime: (vec![], vec![]) }
    }
}

#[derive(Clone, Hash)]
struct MakePrimeOptions {
    high_entropy: Option<bool>,
    fixed_blk_pos: Option<Vec<usize>>,
    valid_bytes: Option<Vec<(usize, Vec<u8>)>>
}
impl MakePrimeOptions {
    fn new() -> Self{
        return MakePrimeOptions { high_entropy: None, fixed_blk_pos: None, valid_bytes: None };
    }
}

pub async fn check_byte_creates_invalid_pt(detector: &IntermediateDetector,test_byte:u8,blk_pos:usize, ct_block_left:&[u8], ct_block_right:&[u8], ct_prefix: &[u8], ct_suffix:&[u8], retry: usize) -> Result<bool, DecryptError>{
    let is_invalid = Arc::new(AtomicBool::new(true));
    let mut futures_set = vec![];
    let canceled = CancellationToken::new();
    for _ in 0..retry{
        let mut test_block = ct_block_left.to_vec();
        let pos = (0..test_block.len()).filter(|p| *p!=blk_pos).choose(&mut rand::rng()).unwrap();
        test_block[pos] = test_block[pos] ^ 1 << random_range(0..8);
        test_block[blk_pos] = test_byte;
        let ct = [ct_prefix,test_block.as_slice(), ct_block_right, ct_suffix].concat();
        let canceled = canceled.clone();
        let is_invalid = is_invalid.clone();
        futures_set.push(async move{
            if is_invalid.load(Ordering::SeqCst) && detector.check(&ct).await.is_ok_and(|c| c == DETECT::OUTLIER){
                is_invalid.store(false, Ordering::SeqCst);
                canceled.cancel();
            }
        });
    }
    select! {
        _ = join_all(futures_set) =>{}
        _ = canceled.cancelled() =>{}
    }
    return Ok(is_invalid.load(Ordering::SeqCst))
}

/// finds all possible decrypted bytes that could make a given pattern of creates_valid_chars
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
pub async fn calculate_byte(detector:&IntermediateDetector, blk_pos:usize, bad_chars: &[u8], ct_block_left:&[u8], ct_block_right:&[u8], ct_prefix: &[u8], ct_suffix:&[u8]) -> Result<(Vec<u8>, Vec<u8>), DecryptError>{
    let mut creates_valid_chars = vec![];
    let mut satisfying_bytes = vec![];
    let retry = 20;
    for _ in 0..retry{
        let bytes = (0..255).filter(|b|!creates_valid_chars.contains(b)).map(|b|b).collect::<Vec<u8>>();
        let mut success = false;
        for xor_byte in bytes{

            // if all responses are the same then we've found an invalid char
            let check_byte = xor_byte ^ ct_block_left[blk_pos];
            let resp = check_byte_creates_invalid_pt(detector, check_byte, blk_pos, ct_block_left, ct_block_right,ct_prefix,ct_suffix, 15).await;
            //if byte creates a valid string
            if resp.is_ok_and(|is_invalid| !is_invalid){
                creates_valid_chars.push(xor_byte);
                satisfying_bytes = find_satisfying_bytes(bad_chars, &creates_valid_chars);
                if satisfying_bytes.len() == 1{
                    success = true;
                    break;
                }
            }
        }
        if success{
            break;
        }
        else if satisfying_bytes.len() == 0 {
            //if there's no satisfying bytes then something went wrong and we need to try again
            creates_valid_chars = vec![];
        }
    }

    if satisfying_bytes.len() > 1{
        let mut success = false;
        for _ in 0..max(retry, satisfying_bytes.len()*2){
            for possible_char in satisfying_bytes.clone(){
                for xor_byte in bad_chars{
                    let check_byte = xor_byte ^ possible_char ^ ct_block_left[blk_pos];
                    let resp = check_byte_creates_invalid_pt(detector, check_byte, blk_pos, ct_block_left, ct_block_right,ct_prefix,ct_suffix, 15).await;
                    // valid response on bad char, so the satisfying byte must be invalid
                    if resp.is_ok_and(|is_invalid| !is_invalid){
                        satisfying_bytes = satisfying_bytes.clone().into_iter().filter(|b|*b != possible_char).collect::<Vec<u8>>();
                        if satisfying_bytes.len() == 1{
                            success = true;
                            break;
                        }
                    }
                }
                if success{
                    break;
                }
            }
            if success{
                break;
            }
        }
    }
    if satisfying_bytes.len()> 1{
        println!("Could not narrow down to 1 byte");
    }
    if satisfying_bytes.len() >= 1{
        return Ok((vec![*satisfying_bytes.first().unwrap()], creates_valid_chars.iter().map(|b| b ^ satisfying_bytes[0]).collect::<Vec<u8>>()));
    }else{
        return Err(DecryptError::BadByteIssue("".to_string()));
    }
}

/// when multiple bytes are returned from the calc byte function, this removes the most common byte
/// from the set, which is usually the incorrect byte. Also it normalizes the valid bytes
fn calc_multi_to_single_bytes(multi_bytes: Vec<(usize, Vec<u8>, u8)>) -> Vec<(usize, u8,u8)>{
    //handle the multiple bytes
    let mut counts: HashMap<u8, usize> = HashMap::new();

    multi_bytes.iter().map(|e| e.1.clone()).collect::<Vec<Vec<u8>>>().concat().iter().for_each(|b|{
        counts.insert(*b, counts.get(b).unwrap_or(&0)+1);
    });
    let (common_byte,_) = counts.iter().max_by_key(|&(_,val)|val).unwrap_or((&0,&0));
    let single_bytes = multi_bytes.iter().map(|e| {
        let filtered_byte = e.1.clone().into_iter().filter(|b| b != common_byte).next().unwrap_or(0);
        return (e.0, filtered_byte, e.2);
    }).collect::<Vec<(usize, u8,u8)>>();
    return single_bytes;
}

/// Use ct_block_left to decrypt ct_block_right.
/// It returns the plaintext and an array of valid bytes
pub async fn decrypt_intermediate_block(detector:&IntermediateDetector,bad_chars: &[u8], iv:&[u8], ct_block_left:&[u8], ct_block_right:&[u8], ct_prefix: &[u8], ct_suffix:&[u8], blk_size: usize, tx: Sender<Messages>) -> Result<(Vec<u8>, Vec<u8>), DecryptError>{
    let pt_bytes_shared = Arc::new(Mutex::new(vec![0u8;blk_size]));
    let valid_bytes_shared = Arc::new(Mutex::new(vec![]));
    let multi_bytes = Arc::new(Mutex::new(vec![]));
    let mut futures = vec![];
    let has_error = CancellationToken::new();
    for blk_pos in 0..blk_size{
        let pt_bytes_copy = pt_bytes_shared.clone();
        let valid_bytes_copy = valid_bytes_shared.clone();
        let has_error = has_error.clone();
        let multi_bytes = multi_bytes.clone();
        let tx = tx.clone();
        futures.push(async move{
            if let Ok(res) = calculate_byte(detector, blk_pos, bad_chars, ct_block_left, ct_block_right, ct_prefix, ct_suffix).await{
                if res.0.len() == 1{
                    let pt_byte = res.0[0] ^ (ct_block_left[blk_pos]^iv[blk_pos]);
                    pt_bytes_copy.lock().await[blk_pos] = pt_byte;
                    let _ = tx.send(Messages::ByteFound(pt_byte, blk_pos)).await;
                }else if res.0.len() > 1{
                    multi_bytes.lock().await.push((blk_pos, res.0.clone(), 0));
                }
                let mut valid_bytes = valid_bytes_copy.lock().await;
                let mut new_valid_bytes = res.1.into_iter().filter(|b| !valid_bytes.contains(b)).collect::<Vec<u8>>();
                valid_bytes.append(&mut new_valid_bytes);
                valid_bytes.sort();
            }else{
                // signal that we ran into an error decrypting a byte
                has_error.cancel();
            }
        });
        
    }
    select! {
        _ = join_all(futures) =>{},
        _ = has_error.cancelled() =>{}
    }
    if has_error.is_cancelled(){
        return Err(DecryptError::BadByteIssue("".to_string()));
    }
    
    // find most commonly occurring byte. when the calculate byte functionality returned two satisfying bytes instead of one, the incorrect byte it returned
    // was almost always 0xdd, idk why. 
    let single_bytes = calc_multi_to_single_bytes(multi_bytes.lock().await.to_vec());
    for (i, byte, _) in single_bytes{
        pt_bytes_shared.lock().await[i] = byte ^ (ct_block_left[i] ^ iv[i]);
        let _ = tx.send(Messages::ByteFound(byte, i)).await;
    }

    // let almost_pt = pt_bytes_shared.lock().await.to_vec();
    // let xor_diff = ct_block_left.iter().zip(iv.iter()).map(|(b1, b2)| b1^b2).collect::<Vec<u8>>();
    // let pt = almost_pt.iter().zip(xor_diff.iter()).map(|(b1,b2)| b1 ^ b2).collect::<Vec<u8>>();
    let pt = pt_bytes_shared.lock().await.to_vec();
    return Ok((pt, valid_bytes_shared.lock().await.to_vec()))
}


fn _make_prime(detector: &IntermediateDetector, ct: &[u8],ct_prefix: &[u8], ct_suffix:&[u8], retry: u16, options: Option<MakePrimeOptions>, cache: Option<Arc<Mutex<HashMap<String, Vec<Vec<u8>>>>>>) -> impl Stream<Item = Option<Vec<u8>>>{
    let options = options.unwrap_or(MakePrimeOptions::new());
    let cache_idx = AtomicUsize::new(0);
    let mut hasher = DefaultHasher::new();
    [ct_prefix, ct, ct_suffix].concat().hash(&mut hasher);
    options.hash(&mut hasher);
    let cache_key = hasher.finish().to_string();
    let stream = stream! {
        loop{
            let cached_vals;
            if let Some(cache_lock) = cache.clone() {
                let cache = cache_lock.lock().await.clone();
                cached_vals = cache.get(&cache_key).unwrap_or(&vec![]).clone();
            }else{
                cached_vals = vec![];
            }
            let idx = cache_idx.load(Ordering::Relaxed);
            if cached_vals.len() > idx{
                cache_idx.store(idx + 1, Ordering::Relaxed);
                yield Some(cached_vals[idx].clone())
            }
            let ct_prime = ct.to_vec();
            let success = Arc::new(AtomicBool::new(false));
            let mut futures_set = vec![];
            let valid_ct_prime = Arc::new(Mutex::new(ct.to_vec()));
            let cancelled = CancellationToken::new();
            for _ in 0..retry{
                // make small modification to ct_prime and check if valid
                let mut ct_prime = ct_prime.clone();
                let valid_ct_prime = valid_ct_prime.clone();
                let high_entropy = options.clone().high_entropy.unwrap_or(false);
                let fixed_blk_pos = options.clone().fixed_blk_pos.unwrap_or(vec![]);
                let byte_options = options.clone().valid_bytes.unwrap_or(vec![]);
                let success = success.clone();
                let cancelled = cancelled.clone();
                futures_set.push(async move{
                    if byte_options.len() > 0{
                        for (pos, bytes) in byte_options.clone().into_iter().filter(|(p,_)| !fixed_blk_pos.contains(p)){
                            ct_prime[pos] = bytes.into_iter().choose(&mut rand::rng()).unwrap();
                        }
                    }else{
                        let mut pos_array = (0..ct.len()).filter(|c| !fixed_blk_pos.contains(c)).collect::<Vec<usize>>();
                        if !high_entropy{
                            pos_array = vec![pos_array.into_iter().choose(&mut rand::rng()).unwrap()];
                        }
                        for pos in pos_array{
                            ct_prime[pos] = ct_prime[pos] ^ (1 << random_range(0..8));
                        }
                    }
                    let full_ct = [ct_prefix, ct_prime.as_slice(), ct_suffix].concat();
                
                    if success.load(Ordering::SeqCst){
                        return;
                    }
                    if detector.check(&full_ct).await.is_ok_and(|d| d == DETECT::OUTLIER){
                        success.store(true, Ordering::SeqCst);
                        let mut prime = valid_ct_prime.lock().await;
                        *prime = ct_prime;
                        cancelled.cancel();
                        return;
                    }
                });
            }
            select! {
                _ = join_all(futures_set) =>{},
                _ = cancelled.cancelled() =>{}
            }
            if success.load(Ordering::SeqCst){
                let prime = valid_ct_prime.lock().await.to_vec().clone();
                if let Some(cache) = cache.clone(){
                    let mut cache_lock = cache.lock().await;
                    let mut cache_val = cache_lock.get(&cache_key).unwrap_or(&vec![]).clone();
                    cache_val.push(prime.clone());
                    cache_lock.insert(cache_key.clone(), cache_val);
                }
                yield Some(prime);
            }else{
                yield None;
            }
        }
    };
    return Box::pin(stream);
}

pub async fn build_cradle_simple(detector: &IntermediateDetector, cradle_block: &[u8], ct_prefix: &[u8], ct_suffix:&[u8], retry:u16, prime_cache: Option<Arc<Mutex<HashMap<String, Vec<Vec<u8>>>>>>) -> Result<(Vec<u8>, Vec<u8>), DecryptError>{
    let blk_size = cradle_block.len();
    let c1 = ct_prefix[ct_prefix.len()-blk_size..].to_vec();
    let mut retry_counter = retry;
    let mut c2_generator = _make_prime(detector, &c1, ct_prefix, ct_suffix, retry, None, prime_cache.clone());
    if let Some(Some(c2_prime)) = _make_prime(detector, &c1, ct_prefix, ct_suffix, retry, None, prime_cache.clone()).next().await{
        let suffix = [c2_prime, ct_suffix.to_vec()].concat();
        let mut c1_generator = _make_prime(detector, &c1, ct_prefix,&suffix, retry, Some(MakePrimeOptions{high_entropy: Some(true), fixed_blk_pos:None, valid_bytes:None}), prime_cache.clone());
        while retry_counter > 0 {
            let c2_prime = c2_generator.next().await;
            if let Some(Some(c2_prime)) = c2_prime{
                let c1_prime = c1_generator.next().await;
                if let Some(Some(c1_prime)) = c1_prime{
                    let test_ct = [ct_prefix, &c1_prime, cradle_block, &c2_prime, ct_suffix].concat();
                    let detect_res = detector.check(&test_ct).await;
                    if detect_res.is_ok_and(|d| d == DETECT::OUTLIER){
                        return Ok((c1_prime, c2_prime));
                    }else{
                        retry_counter = retry_counter - 1;
                    }
                }
            }
        }
    }
    return Err(DecryptError::CradleBuildIssue("Could not find simple cradle".to_string()))
}

pub async fn build_cradle(detector: &IntermediateDetector, bad_chars: &[u8], cradle_block: &[u8], ct_prefix: &[u8], ct_suffix:&[u8], cache_opt: &mut Option<ComputeCache>, retry:u16, prime_cache: Option<Arc<Mutex<HashMap<String, Vec<Vec<u8>>>>>>) -> Result<(Vec<u8>, Vec<u8>), DecryptError>{
    let blk_size = cradle_block.len();
    // Find [c1’] such that [c1][c1’][c2][c3][c4] is valid
    let c1 = ct_prefix[ct_prefix.len()-blk_size..].to_vec();
    let mut c1_prime;
    let mut cache_used = false;
    let mut c2_prime = vec![];

    if let Some(c) = cache_opt && c.c1_prime.len() > 0 && c.c2_prime.0.len() > 0 && detector.check(&[ct_prefix,&c.c1_prime, &c.c2_prime.0, ct_suffix].concat()).await.is_ok_and(|d| d== DETECT::OUTLIER){
        c2_prime = c.c2_prime.0.clone();
        c1_prime = c.c1_prime.clone();
        cache_used = true;
    }else{
        let res = _make_prime(detector, &c1,ct_prefix, ct_suffix, retry,None, prime_cache.clone()).next().await;
        if res.is_none() || res.as_ref().unwrap().is_none(){
            return Err(DecryptError::CradleBuildIssue("Could not find c1_prime".to_string()));
        }
        c1_prime = res.unwrap().unwrap().clone();
    }
    let mut fixed_pos = vec![];
    let mut byte_options = vec![];

    let cached_valid_bytes = match cache_opt {
        Some(c) => c.valid_bytes.clone(),
        None => vec![]
    };
    let valid_bytes = Arc::new(Mutex::new(cached_valid_bytes.clone()));
    loop {
        //Find second c1_prime such that [c1][c1''][c1'][c2][c3][c4] is valid
        let c2 = c1.clone();

        //check cache for valid c2_prime before computing
        if !cache_used {
            // else find a new c2_prime and add it to the cache
            let res = _make_prime(detector, &c2,&[ct_prefix, &c1_prime].concat(),ct_suffix, retry,None, prime_cache.clone()).next().await;
            if res.is_none() || res.as_ref().unwrap().is_none(){
                return Err(DecryptError::CradleBuildIssue("Could not find c2_prime".to_string()));
            }
            c2_prime = res.unwrap().unwrap();
            //add new cache entry if it has not been initialized
            if let Some(c) = cache_opt && c.c2_prime.0.len() <= 0{
                c.c2_prime = (c2_prime.clone(), vec![0u8;blk_size]);
                c.c1_prime = c1_prime.clone();
            }
        }

        let found_intermediate_block_bytes = Arc::new(Mutex::new(vec![]));
        let multi_bytes = Arc::new(Mutex::new(vec![]));
        let mut futures_set = vec![];
        // only decrypt bytes that need to be decrypted for insertion
        for pos in (0..blk_size).filter(|p| !fixed_pos.contains(p)){
            // copy everything for the async move
            let valid_bytes = valid_bytes.clone();
            let found_intermediate_block_bytes = found_intermediate_block_bytes.clone();
            let c2_prime = c2_prime.clone();
            let c1_prime = c1_prime.clone();
            let (cached_c2_pt,cached_c2_ct) = match cache_opt {
                Some(c) => (c.c2_prime.1.clone(), c.c2_prime.0.clone()),
                None => (vec![], vec![])
            };
            let multi_bytes = multi_bytes.clone();
            futures_set.push(async move{
                //check if byte position is already decrypted
                if cache_used && c2_prime == cached_c2_ct{
                    // skip computation and add cached value to list of found bytes
                    found_intermediate_block_bytes.lock().await.push((pos, cached_c2_pt[pos]));
                    // else decrypt the byte
                } else if let Ok((satisfying_bytes, found_valid_bytes)) = calculate_byte(detector, pos, &bad_chars, &c1_prime, &c2_prime, ct_prefix, ct_suffix).await{
                    if satisfying_bytes.len() == 1{
                        let byte = satisfying_bytes[0];
                        let intermediate_block_byte = byte ^ c1_prime[pos];
                        found_intermediate_block_bytes.lock().await.push((pos, intermediate_block_byte));
                    }else if satisfying_bytes.len() > 1 {
                        multi_bytes.lock().await.push((pos, satisfying_bytes, c1_prime[pos]));
                    }
                    let mut valid_bytes = valid_bytes.lock().await;
                    let valid_bytes_copy = valid_bytes.clone();
                    valid_bytes.append(&mut found_valid_bytes.into_iter().filter(|v| !valid_bytes_copy.contains(v)).collect::<Vec<u8>>());
                }
            });
        }
        join_all(futures_set).await;

        // find most commonly occurring byte. when the calculate byte functionality returned two satisfying bytes instead of one, the incorrect byte it returned
        // was almost always 0xdd, idk why. 
        let single_bytes = calc_multi_to_single_bytes(multi_bytes.lock().await.to_vec());
        for entry in single_bytes{
            found_intermediate_block_bytes.lock().await.push((entry.0, entry.1 ^ entry.2));
        }

        let found_intermediate_block_bytes = found_intermediate_block_bytes.lock().await.to_vec();
        
        // add plaintext bytes to finish initializing the cache
        if let Some(c) = cache_opt && c.c2_prime.0 == c2_prime && !cache_used{
            for (pos, byte) in found_intermediate_block_bytes.clone(){
                c.c2_prime.1[pos] = byte;
            }
        }

        let valid_bytes = valid_bytes.lock().await.to_vec();
        for (pos, byte) in found_intermediate_block_bytes{
            // if inserting cradle block byte into c1_prime at pos would create a valid byte, then do it
            if valid_bytes.contains(&(byte ^ cradle_block[pos])){
                c1_prime[pos] = cradle_block[pos];
                fixed_pos.push(pos);
            }else{
                byte_options.push((pos, valid_bytes.iter().map(|v| *v ^ byte).collect::<Vec<u8>>()));
            }
        }
        // if we're not finished and we have some unfixed bytes in c1_prime, find a c1_prime that's valid
        if !c1_prime.eq(cradle_block){
            let mut success = false;
            let suffix = [&c2_prime, ct_suffix].concat();
            let c1_copy = c1_prime.clone();
            let mut c1_generator = _make_prime(detector, &c1_copy, ct_prefix, &suffix, retry, Some(MakePrimeOptions { high_entropy: None, fixed_blk_pos: Some(fixed_pos.clone()), valid_bytes: Some(byte_options.clone()) }), prime_cache.clone());
            let mut c1_generator_high_entropy = _make_prime(detector, &c1_copy, ct_prefix, &suffix, retry, Some(MakePrimeOptions { high_entropy: Some(true), fixed_blk_pos: Some(fixed_pos.clone()), valid_bytes: None }), prime_cache.clone());
            while !success && fixed_pos.len() > 0{
                if let Some(Some(res)) = c1_generator.next().await{
                    c1_prime = res;
                    success = true;
                // try high entropy if valid bytes approach fails
                }else if let Some(Some(res)) = c1_generator_high_entropy.next().await{
                    c1_prime = res;
                    success = true;
                }else{
                    fixed_pos = fixed_pos[..fixed_pos.len()-1].to_vec()
                }
            }
        }
        cache_used = false;

        if c1_prime.eq(cradle_block){
            break;
        }
    }


    //build a list of multiple c1_primes
    let res = _make_prime(detector, &c1,ct_prefix, ct_suffix, retry,None, prime_cache.clone()).next().await;
    if res.is_none() || res.as_ref().unwrap().is_none(){
        return Err(DecryptError::CradleBuildIssue("Could not find c1_prime while finishing cradle".to_string()));
    }
    let c1_prime_init = res.unwrap().unwrap();

    let c2 = c1.clone();
    let res = _make_prime(detector, &c2,&[ct_prefix, &c1_prime_init].concat(),ct_suffix, retry,None, prime_cache.clone()).next().await;
    if res.is_none() || res.as_ref().unwrap().is_none(){
        return Err(DecryptError::CradleBuildIssue("Could not find c2_prime while finishing cradle".to_string()));
    }
    let c2_prime_init = res.unwrap().unwrap();

    //let futures_set = vec![];
    let mut valid_prime;
    let suffix = [&c2_prime_init, ct_suffix].concat();
    let mut final_generator =  _make_prime(detector, &c1_prime_init, ct_prefix, &suffix, retry,Some(MakePrimeOptions{high_entropy:Some(true), fixed_blk_pos:None, valid_bytes:None}), prime_cache.clone());
    loop{
        if let Some(Some(v)) = final_generator.next().await{
            valid_prime = v;
            if detector.check(&[ct_prefix, &valid_prime, &c1_prime, &c2_prime, ct_suffix].concat()).await.is_ok_and(|d| d == DETECT::OUTLIER){
                break;
            }
        }
    }
    // update cached valid bytes
    if let Some(c) = cache_opt{
        c.valid_bytes = valid_bytes.lock().await.to_vec();
    }
    return Ok((valid_prime, c2_prime))
}
