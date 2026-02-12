use std::sync::Arc;

use tokio::sync::mpsc::Sender;

use crate::{
    crypt::{
        MessageForwarder, calc_intermediate_vector,
        detector::{Detector, SimpleDetector},
    },
    errors::DecryptError,
    helper::{Config, Messages}, oracle::Oracle,
};

pub async fn padding_oracle_forge<O: Oracle>(
    pt: &[u8],
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
        return _padding_forge(pt, ct, classic_detector, retry, tx, blk_size).await;
    }
    let _ = tx.send(Messages::NoOracleFound).await;
    Err(DecryptError::CouldNotDecryptClassic(
        "No padding oracle found".into(),
    ))
}

// we don't really need the cipher text, we could make our own, but it keeps the Detector consistent with the decryption step
async fn _padding_forge<D: Detector + Send + Sync + 'static>(
    pt: &[u8],
    ct: &[u8],
    detector: D,
    retry: u8,
    tx: Sender<Messages>,
    blk_size: usize,
) -> Result<Vec<u8>, DecryptError> {
    if pt.len() <= 0 {
        return Err(DecryptError::CouldNotDecryptClassic(
            "Invalid plaintext length".into(),
        ));
    }
    let mut blocks: Vec<Vec<u8>> = pt
        .chunks(blk_size.into())
        .map(|val| Vec::from(val))
        .collect();
    // pad out the text to forge
    {
        let last_block = blocks.last_mut().unwrap();
        if last_block.len() == blk_size {
            blocks.push(vec![blk_size as u8; blk_size]);
        } else {
            let pad_byte = blk_size - last_block.len();
            for _ in 0..pad_byte {
                last_block.push(pad_byte as u8);
            }
        }
    }

    let mut ciphertext_blocks: Vec<Vec<u8>> = ct
        .chunks(blk_size.into())
        .map(|val| Vec::from(val))
        .collect();
    // trim ciphertext if longer
    if ciphertext_blocks.len() > blocks.len() + 1 {
        ciphertext_blocks = ciphertext_blocks[..blocks.len() + 1].to_vec();
    }
    // add to ciphertext if shorter
    while ciphertext_blocks.len() < blocks.len() + 1 {
        ciphertext_blocks.push(ciphertext_blocks.last().unwrap().to_vec());
    }
    let detector_shared = Arc::new(detector);
    // decrypt ct
    for block_index in (0..blocks.len()).rev() {
        let detector = detector_shared.clone();
        //get next two blocks
        let current_blocks = Vec::from(&ciphertext_blocks[block_index..block_index + 2]);
        let orig_first_block_copy = blocks[block_index].clone();

        let tx = tx.clone();

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

        let intermediate_vector = calc_intermediate_vector(
            current_blocks[1].clone(),
            detector,
            retry,
            msg_forwarder.local_tx.clone(),
        )
        .await?;
        let ciphertext_block: Vec<u8> = blocks[block_index]
            .iter()
            .zip(intermediate_vector.iter())
            .map(|(x, y)| x ^ y)
            .collect();
        ciphertext_blocks[block_index] = ciphertext_block;
    }
    Ok(ciphertext_blocks.iter().flatten().cloned().collect())
}
