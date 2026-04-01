use std::{
    cmp::max,
    collections::HashMap,
    hash::{DefaultHasher, Hash, Hasher},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use async_stream::stream;
use futures::stream::StreamExt;
use futures::{Stream, future::join_all, lock::Mutex};
use rand::{random_range, seq::IteratorRandom};
use statrs::statistics::Statistics;
use tokio::{select, sync::mpsc::Sender};
use tokio_util::sync::CancellationToken;

use crate::{
    crypt::detector::{DETECT, Detector, IntermediateDetector},
    errors::DecryptError,
    helper::Messages,
};

#[derive(Clone, Debug)]
pub struct ComputeCache {
    valid_bytes: Vec<u8>,
    c1_prime: Vec<u8>,
    // 0 is the ciphertext and 1 is the plaintext
    c2_prime: (Vec<u8>, Vec<u8>),
}
impl ComputeCache {
    pub fn new() -> Self {
        return ComputeCache {
            valid_bytes: vec![],
            c1_prime: vec![],
            c2_prime: (vec![], vec![]),
        };
    }
}

#[derive(Clone, Hash)]
struct MakePrimeOptions {
    high_entropy: Option<bool>,
    fixed_blk_pos: Option<Vec<usize>>,
    valid_bytes: Option<Vec<(usize, Vec<u8>)>>,
}
impl MakePrimeOptions {
    fn new() -> Self {
        return MakePrimeOptions {
            high_entropy: None,
            fixed_blk_pos: None,
            valid_bytes: None,
        };
    }
}

fn compare_fingerprints(fingerprint_1: &[bool], fingerprint_2: &[bool]) -> u8 {
    let mut counter = 0;
    fingerprint_1
        .iter()
        .zip(fingerprint_2)
        .for_each(|(f1, f2)| {
            if *f1 && *f2 {
                counter += 1;
            }
        });
    return counter;
}

async fn gen_byte_fingerprint(
    detector: &IntermediateDetector,
    blk_pos: usize,
    ct_prefix: &[u8],
    ct_suffix: &[u8],
    cradle_left: &[u8],
    cradle_right: &[u8],
    second_last_block: &[u8],
    last_block: &[u8],
    retry: u16,
) -> Result<Vec<bool>, DecryptError> {
    let mut valid_bytes_fingerprint = vec![false; 256];
    for byte_raw in 0..=255 {
        let byte_normalized = byte_raw ^ second_last_block[blk_pos];
        let res = check_byte_creates_invalid_pt(
            detector,
            byte_normalized,
            blk_pos,
            cradle_left,
            last_block,
            ct_prefix,
            &[cradle_right, ct_suffix].concat(),
            retry.into(),
        )
        .await?;
        valid_bytes_fingerprint[byte_raw as usize] = res;
    }
    return Ok(valid_bytes_fingerprint);
}

fn get_bad_bytes(last_byte_fingerprint_set: Vec<Vec<bool>>, padding_byte: u8) -> Vec<u8> {
    return last_byte_fingerprint_set[0]
        .iter()
        .enumerate()
        .filter(|(i, b)| **b && last_byte_fingerprint_set.iter().all(|set| set[*i]))
        .map(|(i, _)| (i as u8) ^ padding_byte)
        .collect::<Vec<u8>>();
}

// use padding from last block to discover invalid bytes. we can determine how many bytes in the last block
// are the same based on the output of check_byte_creates_invalid_pt which builds a rough "fingerprint" for a plaintext byte
pub async fn discover_bad_bytes(
    detector: &IntermediateDetector,
    ct_prefix: &[u8],
    ct_suffix: &[u8],
    second_last_block: &[u8],
    last_block: &[u8],
    retry: u16,
) -> Result<Vec<u8>, DecryptError> {
    // work really hard to find a simple cradle. We can't use a complex cradle because we don't know what the bad bytes are yet.
    let cradle = build_cradle_2(detector, last_block, ct_prefix, ct_suffix, 1000, None).await?;
    let fingerprint_set = Arc::new(Mutex::new(vec![]));
    let mut futures_set = vec![];
    for _ in 0..6 {
        let fingerprint_set = fingerprint_set.clone();
        let cradle = cradle.clone();
        futures_set.push(async move {
            if let Ok(fingerprint) = gen_byte_fingerprint(
                detector,
                last_block.len() - 1,
                ct_prefix,
                ct_suffix,
                &cradle.0,
                &cradle.1,
                second_last_block,
                last_block,
                retry,
            )
            .await
            {
                fingerprint_set.lock().await.push(fingerprint);
            }
        });
    }
    join_all(futures_set).await;
    let fingerprint_set = fingerprint_set.lock().await.clone();
    let mut distance_set = vec![];
    let mut points_visited = vec![];
    // generate a measure of how "close" two of the same byte fingerprints should be.
    // a baseline is established by looking at the average fingerprint "distance"
    for (i, fingerprint_1) in fingerprint_set.iter().enumerate() {
        for fingerprint_2 in fingerprint_set
            .iter()
            .enumerate()
            .filter(|(j, _)| i != *j && !points_visited.contains(j))
            .map(|(_, f)| f)
        {
            distance_set.push(compare_fingerprints(fingerprint_1, fingerprint_2));
        }
        points_visited.push(i);
    }
    let distance_floats: Vec<f64> = distance_set.iter().map(|d| *d as f64).collect();
    let std_dev = distance_floats.clone().std_dev();
    let mean = distance_floats.mean();

    // use the standard deviation and mean to find outliers and calculate padding length
    let fingerprint_compare = fingerprint_set[0].clone();
    let mut padding_byte = 1u8;
    for i in (0..last_block.len() - 1).rev() {
        let fingerprint = gen_byte_fingerprint(
            detector,
            i,
            ct_prefix,
            ct_suffix,
            &cradle.0,
            &cradle.1,
            second_last_block,
            last_block,
            retry,
        )
        .await?;
        let distance = compare_fingerprints(&fingerprint, &fingerprint_compare);
        let deviation = mean - distance as f64;
        if distance == 0 || deviation >= mean + std_dev * 3.0 || deviation <= mean - std_dev * 3.0 {
            // found outlier
            padding_byte = i as u8;
            break;
        }
    }

    // convert fingerprint to byte string
    let mut bad_bytes = get_bad_bytes(fingerprint_set, padding_byte);
    bad_bytes.sort();
    return Ok(bad_bytes);
}

pub async fn check_byte_creates_invalid_pt(
    detector: &IntermediateDetector,
    test_byte: u8,
    blk_pos: usize,
    ct_block_left: &[u8],
    ct_block_right: &[u8],
    ct_prefix: &[u8],
    ct_suffix: &[u8],
    retry: usize,
) -> Result<bool, DecryptError> {
    let is_invalid = Arc::new(AtomicBool::new(true));
    let mut futures_set = vec![];
    let canceled = CancellationToken::new();
    for _ in 0..retry {
        let mut test_block = ct_block_left.to_vec();
        let pos = (0..test_block.len())
            .filter(|p| *p != blk_pos)
            .choose(&mut rand::rng())
            .unwrap();
        test_block[pos] = test_block[pos] ^ 1 << random_range(0..8);
        test_block[blk_pos] = test_byte;
        let ct = [ct_prefix, test_block.as_slice(), ct_block_right, ct_suffix].concat();
        let canceled = canceled.clone();
        let is_invalid = is_invalid.clone();
        futures_set.push(async move {
            if is_invalid.load(Ordering::SeqCst)
                && detector
                    .check(&ct)
                    .await
                    .is_ok_and(|c| c == DETECT::OUTLIER)
            {
                is_invalid.store(false, Ordering::SeqCst);
                canceled.cancel();
            }
        });
    }
    select! {
        _ = join_all(futures_set) =>{}
        _ = canceled.cancelled() =>{}
    }
    return Ok(is_invalid.load(Ordering::SeqCst));
}

/// finds all possible decrypted bytes that could make a given pattern of creates_valid_chars
fn find_satisfying_bytes(bad_chars: &[u8], creates_valid_chars: &[u8]) -> Vec<u8> {
    let mut satisfying_bytes: Vec<u8> = vec![];
    for byte in 0..=255 {
        //if we find a byte that should produce a valid character when combined with the test byte
        // but instead it produces a character in the bad_chars array, we know we've made a wrong guess
        let is_guess_valid = creates_valid_chars
            .iter()
            .find(|v_ch| bad_chars.contains(&(byte ^ **v_ch)))
            .is_none();
        if is_guess_valid {
            satisfying_bytes.push(byte);
        }
    }
    return satisfying_bytes;
}

/// Calculates the plaintext of a byte at a certain block position.
/// It returns the plaintext byte and a set of valid characters it found while
/// searching for the valid byte
pub async fn calculate_byte(
    detector: &IntermediateDetector,
    blk_pos: usize,
    bad_chars: &[u8],
    ct_block_left: &[u8],
    ct_block_right: &[u8],
    ct_prefix: &[u8],
    ct_suffix: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), DecryptError> {
    let mut creates_valid_chars = vec![];
    let mut satisfying_bytes = vec![];
    let retry = 20;
    for _ in 0..retry {
        let bytes = (0..=255)
            .filter(|b| !creates_valid_chars.contains(b))
            .map(|b| b)
            .collect::<Vec<u8>>();
        let mut success = false;
        for xor_byte in bytes {
            // if all responses are the same then we've found an invalid char
            let check_byte = xor_byte ^ ct_block_left[blk_pos];
            let resp = check_byte_creates_invalid_pt(
                detector,
                check_byte,
                blk_pos,
                ct_block_left,
                ct_block_right,
                ct_prefix,
                ct_suffix,
                15,
            )
            .await;
            //if byte creates a valid string
            if resp.is_ok_and(|is_invalid| !is_invalid) {
                creates_valid_chars.push(xor_byte);
                satisfying_bytes = find_satisfying_bytes(bad_chars, &creates_valid_chars);
                if satisfying_bytes.len() == 1 {
                    success = true;
                    break;
                }
            }
        }
        if success {
            break;
        } else if satisfying_bytes.len() == 0 {
            //if there's no satisfying bytes then something went wrong and we need to try again
            creates_valid_chars = vec![];
        }
    }

    if satisfying_bytes.len() > 1 {
        let mut success = false;
        for _ in 0..max(retry, satisfying_bytes.len() * 2) {
            for possible_char in satisfying_bytes.clone() {
                for xor_byte in bad_chars {
                    let check_byte = xor_byte ^ possible_char ^ ct_block_left[blk_pos];
                    let resp = check_byte_creates_invalid_pt(
                        detector,
                        check_byte,
                        blk_pos,
                        ct_block_left,
                        ct_block_right,
                        ct_prefix,
                        ct_suffix,
                        15,
                    )
                    .await;
                    // valid response on bad char, so the satisfying byte must be invalid
                    if resp.is_ok_and(|is_invalid| !is_invalid) {
                        satisfying_bytes = satisfying_bytes
                            .clone()
                            .into_iter()
                            .filter(|b| *b != possible_char)
                            .collect::<Vec<u8>>();
                        if satisfying_bytes.len() == 1 {
                            success = true;
                            break;
                        }
                    }
                }
                if success {
                    break;
                }
            }
            if success {
                break;
            }
        }
    }
    if satisfying_bytes.len() > 1 {
        println!("Could not narrow down to 1 byte");
    }
    if satisfying_bytes.len() >= 1 {
        return Ok((
            vec![*satisfying_bytes.first().unwrap()],
            creates_valid_chars
                .iter()
                .map(|b| b ^ satisfying_bytes[0])
                .collect::<Vec<u8>>(),
        ));
    } else {
        return Err(DecryptError::BadByteIssue("".to_string()));
    }
}

/// when multiple bytes are returned from the calc byte function, this removes the most common byte
/// from the set, which is usually the incorrect byte. Also it normalizes the valid bytes
fn calc_multi_to_single_bytes(multi_bytes: Vec<(usize, Vec<u8>, u8)>) -> Vec<(usize, u8, u8)> {
    //handle the multiple bytes
    let mut counts: HashMap<u8, usize> = HashMap::new();

    multi_bytes
        .iter()
        .map(|e| e.1.clone())
        .collect::<Vec<Vec<u8>>>()
        .concat()
        .iter()
        .for_each(|b| {
            counts.insert(*b, counts.get(b).unwrap_or(&0) + 1);
        });
    let (common_byte, _) = counts
        .iter()
        .max_by_key(|&(_, val)| val)
        .unwrap_or((&0, &0));
    let single_bytes = multi_bytes
        .iter()
        .map(|e| {
            let filtered_byte =
                e.1.clone()
                    .into_iter()
                    .filter(|b| b != common_byte)
                    .next()
                    .unwrap_or(0);
            return (e.0, filtered_byte, e.2);
        })
        .collect::<Vec<(usize, u8, u8)>>();
    return single_bytes;
}

/// Use ct_block_left to decrypt ct_block_right.
/// It returns the plaintext and an array of valid bytes
pub async fn decrypt_intermediate_block(
    detector: &IntermediateDetector,
    bad_chars: &[u8],
    iv: &[u8],
    ct_block_left: &[u8],
    ct_block_right: &[u8],
    ct_prefix: &[u8],
    ct_suffix: &[u8],
    blk_size: usize,
    tx: Sender<Messages>,
) -> Result<(Vec<u8>, Vec<u8>), DecryptError> {
    let pt_bytes_shared = Arc::new(Mutex::new(vec![0u8; blk_size]));
    let valid_bytes_shared = Arc::new(Mutex::new(vec![]));
    let multi_bytes = Arc::new(Mutex::new(vec![]));
    let mut futures = vec![];
    let has_error = CancellationToken::new();
    for blk_pos in 0..blk_size {
        let pt_bytes_copy = pt_bytes_shared.clone();
        let valid_bytes_copy = valid_bytes_shared.clone();
        let has_error = has_error.clone();
        let multi_bytes = multi_bytes.clone();
        let tx = tx.clone();
        futures.push(async move {
            if let Ok(res) = calculate_byte(
                detector,
                blk_pos,
                bad_chars,
                ct_block_left,
                ct_block_right,
                ct_prefix,
                ct_suffix,
            )
            .await
            {
                if res.0.len() == 1 {
                    let pt_byte = res.0[0] ^ (ct_block_left[blk_pos] ^ iv[blk_pos]);
                    pt_bytes_copy.lock().await[blk_pos] = pt_byte;
                    let _ = tx.send(Messages::ByteFound(pt_byte, blk_pos)).await;
                } else if res.0.len() > 1 {
                    multi_bytes.lock().await.push((blk_pos, res.0.clone(), 0));
                }
                let mut valid_bytes = valid_bytes_copy.lock().await;
                let mut new_valid_bytes = res
                    .1
                    .into_iter()
                    .filter(|b| !valid_bytes.contains(b))
                    .collect::<Vec<u8>>();
                valid_bytes.append(&mut new_valid_bytes);
                valid_bytes.sort();
            } else {
                // signal that we ran into an error decrypting a byte
                has_error.cancel();
            }
        });
    }
    select! {
        _ = join_all(futures) =>{},
        _ = has_error.cancelled() =>{}
    }
    if has_error.is_cancelled() {
        return Err(DecryptError::BadByteIssue("".to_string()));
    }

    // find most commonly occurring byte. when the calculate byte functionality returned two satisfying bytes instead of one, the incorrect byte it returned
    // was almost always 0xdd, idk why.
    let single_bytes = calc_multi_to_single_bytes(multi_bytes.lock().await.to_vec());
    for (i, byte, _) in single_bytes {
        pt_bytes_shared.lock().await[i] = byte ^ (ct_block_left[i] ^ iv[i]);
        let _ = tx.send(Messages::ByteFound(byte, i)).await;
    }

    // let almost_pt = pt_bytes_shared.lock().await.to_vec();
    // let xor_diff = ct_block_left.iter().zip(iv.iter()).map(|(b1, b2)| b1^b2).collect::<Vec<u8>>();
    // let pt = almost_pt.iter().zip(xor_diff.iter()).map(|(b1,b2)| b1 ^ b2).collect::<Vec<u8>>();
    let pt = pt_bytes_shared.lock().await.to_vec();
    return Ok((pt, valid_bytes_shared.lock().await.to_vec()));
}

fn _make_prime(
    detector: &IntermediateDetector,
    ct: &[u8],
    ct_prefix: &[u8],
    ct_suffix: &[u8],
    retry: u16,
    options: Option<MakePrimeOptions>,
    cache: Option<Arc<Mutex<HashMap<String, Vec<Vec<u8>>>>>>,
) -> impl Stream<Item = Option<Vec<u8>>> {
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

pub async fn build_cradle_2(
    detector: &IntermediateDetector,
    cradle_block: &[u8],
    ct_prefix: &[u8],
    ct_suffix: &[u8],
    retry: u16,
    prime_cache: Option<Arc<Mutex<HashMap<String, Vec<Vec<u8>>>>>>,
) -> Result<(Vec<u8>, Vec<u8>), DecryptError> {
    let block_size = cradle_block.len();
    let c1 = ct_prefix[ct_prefix.len() - block_size..].to_vec();
    let c1_prime = _make_prime(
        detector,
        &c1,
        ct_prefix,
        ct_suffix,
        retry,
        None,
        prime_cache.clone(),
    )
    .next()
    .await
    .unwrap();
    if c1_prime.is_none() {
        return Err(DecryptError::CradleBuildIssue(
            "Could not find valid prime".to_string(),
        ));
    }
    let mut c1_prime = c1_prime.unwrap();
    let prefix = [ct_prefix, &c1_prime].concat();
    let mut c2_prime_generator = _make_prime(
        detector,
        &c1,
        &prefix,
        ct_suffix,
        retry,
        Some(MakePrimeOptions {
            high_entropy: Some(true),
            fixed_blk_pos: None,
            valid_bytes: None,
        }),
        prime_cache.clone(),
    );

    let c2_prime = c2_prime_generator.next().await.unwrap();
    if c2_prime.is_none() {
        return Err(DecryptError::CradleBuildIssue(
            "Could not find valid prime".to_string(),
        ));
    }
    let mut c2_prime = c2_prime.unwrap();

    let mut cradle_indexes_to_set = (0..block_size).collect::<Vec<usize>>();
    while c1_prime != cradle_block {
        let mut new_c1_prime = c1_prime.clone();
        for i in cradle_indexes_to_set.clone() {
            let cradle_byte = cradle_block[i];
            if let Ok(is_invalid) = check_byte_creates_invalid_pt(
                detector,
                cradle_byte,
                i,
                &c1_prime,
                &c2_prime,
                ct_prefix,
                ct_suffix,
                20,
            )
            .await
                && !is_invalid
            {
                // on success, set the c1_prime byte to slowly make it into the cradle block
                new_c1_prime[i] = cradle_byte;
                cradle_indexes_to_set = cradle_indexes_to_set
                    .iter()
                    .filter(|idx| **idx != i)
                    .map(|b| *b)
                    .collect();
            }
        }
        c1_prime = new_c1_prime;
        let suffix = [&c2_prime, ct_suffix].concat();
        let mut fixed_pos = (0..block_size)
            .filter(|pos| !cradle_indexes_to_set.contains(pos))
            .collect::<Vec<usize>>();
        let new_c1_prime = _make_prime(
            detector,
            &c1_prime,
            ct_prefix,
            &suffix,
            retry,
            Some(MakePrimeOptions {
                high_entropy: Some(true),
                fixed_blk_pos: Some(fixed_pos.clone()),
                valid_bytes: None,
            }),
            prime_cache.clone(),
        )
        .next()
        .await
        .unwrap();
        if new_c1_prime.is_none() {
            // could not find new c1_prime, back off and try again
            if fixed_pos.len() > 1 {
                cradle_indexes_to_set.push(fixed_pos.pop().unwrap());
                continue;
            } else {
                return Err(DecryptError::CradleBuildIssue(
                    "Could not find valid prime".to_string(),
                ));
            }
        }
        c1_prime = new_c1_prime.unwrap();
        // modify c2_prime for the next round
        let prefix = [ct_prefix, &c1_prime].concat();
        if let Some(new_c2) = _make_prime(
            detector,
            &c2_prime.clone(),
            &prefix,
            ct_suffix,
            retry,
            None,
            prime_cache.clone(),
        )
        .next()
        .await
        .unwrap()
        {
            c2_prime = new_c2;
        }
    }
    let mut c1_prime_generator = _make_prime(
        detector,
        &c1,
        ct_prefix,
        ct_suffix,
        retry,
        Some(MakePrimeOptions {
            high_entropy: Some(true),
            fixed_blk_pos: None,
            valid_bytes: None,
        }),
        prime_cache.clone(),
    );
    for _ in 0..retry {
        let maybe_cradle_left = c1_prime_generator.next().await.unwrap();
        if maybe_cradle_left.is_none() {
            continue;
        }
        let maybe_cradle_left = maybe_cradle_left.unwrap();
        let test_ct = [
            ct_prefix,
            &maybe_cradle_left,
            &c1_prime,
            &c2_prime,
            ct_suffix,
        ]
        .concat();
        if let Ok(res) = detector.check(&test_ct).await
            && res == DETECT::OUTLIER
        {
            return Ok((maybe_cradle_left, c2_prime));
        }
    }
    return Err(DecryptError::CradleBuildIssue(
        "Could not find last prime to finish cradle".to_string(),
    ));
}
