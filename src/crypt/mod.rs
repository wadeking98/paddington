use std::{
    cmp::max,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use tokio::{
    select, spawn,
    sync::{
        Mutex,
        mpsc::{self, Sender},
    },
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

use crate::{
    crypt::detector::{DETECT, Detector},
    errors::DecryptError,
    helper::Messages,
};

pub mod decrypt;
pub mod detector;
pub mod forge;

struct MessageForwarder {
    join_handle: JoinHandle<()>,
    local_tx: Sender<Messages>,
}

impl Drop for MessageForwarder {
    fn drop(&mut self) {
        self.join_handle.abort();
    }
}

impl MessageForwarder {
    fn new(tx: Sender<Messages>, msg_op: Box<dyn Fn(Messages) -> Messages + Send>) -> Self {
        let (local_tx, mut local_rx) = mpsc::channel::<Messages>(255);
        let join_handle = spawn(async move {
            loop {
                match local_rx.recv().await {
                    None => break,
                    Some(msg) => {
                        let _ = tx.send(msg_op(msg)).await;
                    }
                }
            }
        });
        Self {
            join_handle,
            local_tx,
        }
    }
}

async fn loop_with_retry<T, E>(
    retry: u8,
    range: Vec<u8>,
    try_func: impl AsyncFn(u8) -> Result<T, E>,
) -> bool {
    let mut curr_retry = retry;
    let mut index: usize = 0;
    let mut retry_reset: usize = 0;
    loop {
        // terminate loop
        if index >= range.len() {
            break;
        }
        let i = range[index];
        let res = try_func(i).await;
        if res.is_err() && curr_retry <= 0 {
            return false;
        } else if res.is_err() {
            // decrement retry counter and go back if possible
            curr_retry -= 1;
            if index > 0 {
                index -= 1;
            }
            retry_reset = max(retry_reset, index + 1);
            continue;
        } else if index >= retry_reset {
            // reset the retry counter if we've made progress in the loop
            curr_retry = retry;
        }
        index += 1;
    }
    return true;
}

async fn calc_intermediate_vector<D: Detector + Send + Sync + 'static>(
    iv: Vec<u8>,
    ct_block: Vec<u8>,
    detector: Arc<D>,
    retry: u8,
    tx: Sender<Messages>,
) -> Result<Vec<u8>, DecryptError> {
    let blk_size = iv.len() as u8;
    let intermediate_vector_shared = Arc::new(Mutex::new(vec![0u8; blk_size as usize]));
    let intermediate_vector_shared_copy = intermediate_vector_shared.clone();
    let detector_shared = Arc::new(detector);
    let res = loop_with_retry(retry, (0..blk_size).rev().collect(), async |i| {
        let mut iv = Vec::from(iv.clone());
        let curr_padding = blk_size - i;
        //set the padding except for the current byte we're working on: \x02, \x03\x03, \x04\x04\x04, etc
        for k in (blk_size - (curr_padding - 1))..blk_size {
            let zero = intermediate_vector_shared_copy.clone().lock().await[k as usize];
            iv[k as usize] = zero ^ curr_padding;
        }

        let mut futures_set = JoinSet::new();
        let success_shared = Arc::new(AtomicBool::new(false));
        let cancellation_token = CancellationToken::new();
        for j in 0..=255 {
            let intermediate_vector = intermediate_vector_shared_copy.clone();
            let mut iv_copy = iv.clone();
            let ct_block = ct_block.to_vec();
            let detector = detector_shared.clone();
            let success = success_shared.clone();
            let tx = tx.clone();
            let cancellation_token = cancellation_token.clone();
            futures_set.spawn(async move {
                // mark if we're actually updating this byte
                let changed_byte = iv_copy[i as usize] != j;
                iv_copy[i as usize] = j;
                if !success.load(Ordering::SeqCst)
                    && let Ok(response) = detector
                        .check(
                            &iv_copy
                                .iter()
                                .chain(&ct_block)
                                .cloned()
                                .collect::<Vec<u8>>(),
                        )
                        .await
                {
                    // found a valid padding
                    if response == DETECT::OUTLIER {
                        // ensures we don't write to the intermediate vector after all requests are success
                        let mut intermediate_vector = intermediate_vector.lock().await;
                        if !success.load(Ordering::SeqCst) {
                            let zero_byte = j ^ curr_padding;
                            let _ = tx.send(Messages::ByteFound(zero_byte, i as usize)).await;
                            intermediate_vector[i as usize] = zero_byte;
                            if changed_byte {
                                // we want to prioritize valid paddings where a byte was changed, since if the byte wasn't changed
                                // then the tool might think it's written a padding of \x01 when really it wrote \x02 and the plaintext just happened to end with \x02\x02
                                success.fetch_or(true, Ordering::SeqCst);
                                cancellation_token.cancel();
                            }
                        }
                    }
                }
            });
        }
        select! {
            _ = futures_set.join_all() =>{},
            _ = cancellation_token.cancelled() =>{}
        }
        if !success_shared.load(Ordering::SeqCst) {
            return Err(DecryptError::CouldNotDecryptClassic(
                "Could not find valid padding".to_string(),
            ));
        }
        Ok(())
    })
    .await;

    if !res {
        return Err(DecryptError::CouldNotDecryptClassic(
            "Could not find valid padding".to_string(),
        ));
    }

    /////////////////

    return Ok(intermediate_vector_shared.clone().lock().await.to_vec());
}
