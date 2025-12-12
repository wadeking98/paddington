use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

use tokio::{sync::Mutex, task::JoinSet};

use crate::{
    crypt::{calc_intermediate_vector, detector::{Detector, Oracle, SimpleDetector}},
    errors::DecryptError,
    helper::Config,
};

pub async fn padding_oracle_decrypt<O: Oracle>(
    ct: &[u8],
    oracle: O,
    config: Config,
) -> Result<Vec<u8>, DecryptError> {
    let blk_size = config.get_int("blk_size".to_owned(), 16) as usize;
    let threads = config.get_int("threads".to_owned(), 10) as usize;
    // classic padding oracle
    if let Ok(classic_detector) = SimpleDetector::init(ct, oracle, blk_size, threads).await {
        return _padding_decrypt(ct, classic_detector, blk_size).await;
    } 
    Err(DecryptError::CouldNotDecryptClassic(
        "No padding oracle found".into(),
    ))
}

async fn _padding_decrypt<D: Detector + 'static + Send + Sync>(
    ct: &[u8],
    detector: D,
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

    let plaintext_blocks_shared: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(vec![vec![]; blocks.len()-1]));
    let mut futures_set = JoinSet::new();
    let decrypt_error_shared = Arc::new(AtomicBool::new(false));
    // decrypt ct
    for block_index in 0..blocks.len() - 1 {
        let plaintext_blocks = plaintext_blocks_shared.clone();
        let detector = detector_shared.clone();
        let mut current_blocks = Vec::from(&blocks[block_index..block_index + 2]);
        let decrypt_error = decrypt_error_shared.clone();
        //get next two blocks
        futures_set.spawn(async move {
            let orig_first_block = current_blocks[0].clone();
            current_blocks[0] = vec![0u8; blk_size as usize];

            let intermediate_vector =
                calc_intermediate_vector(&current_blocks[0], &current_blocks[1], detector).await;
            if intermediate_vector.is_err(){
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
    futures_set.join_all().await;
    if decrypt_error_shared.load(Ordering::SeqCst){
        return Err(DecryptError::CouldNotDecryptClassic("Error: could not find intermediate block".to_string()));
    }
    let plaintext_blocks_acquired = plaintext_blocks_shared.lock().await;
    Ok(plaintext_blocks_acquired.iter().flatten().cloned().collect())
}
