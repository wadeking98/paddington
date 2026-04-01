use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use futures::{future::join_all, lock::Mutex};
use tokio::sync::mpsc::Sender;

use crate::{
    crypt::{
        MessageForwarder,
        cradlehelpers::{build_cradle_2, decrypt_intermediate_block},
        decrypt::_padding_decrypt,
        detector::{Detector, IntermediateDetector},
        forge::_padding_forge,
    },
    errors::DecryptError,
    helper::Messages,
};

#[async_trait]
pub trait Oracle: 'static + Send + Sync {
    async fn decrypt(&self, ct: &[u8]) -> Result<Vec<u8>, DecryptError>;
    async fn forge(&self, ct: &[u8], pt: &[u8]) -> Result<Vec<u8>, DecryptError>;
}

pub struct SingleOracle<D: Detector> {
    detector: D,
    tx: Sender<Messages>,
    block_size: usize,
    retry: usize,
}

impl<D: Detector> SingleOracle<D> {
    pub fn new(detector: D, tx: Sender<Messages>, block_size: usize, retry: usize) -> Self {
        return Self {
            detector,
            tx,
            block_size,
            retry,
        };
    }
}

#[async_trait]
impl<D: Detector + Clone + Send> Oracle for SingleOracle<D> {
    async fn decrypt(&self, ct: &[u8]) -> Result<Vec<u8>, DecryptError> {
        return _padding_decrypt(
            &vec![],
            ct,
            self.detector.clone(),
            self.retry,
            self.tx.clone(),
            self.block_size,
        )
        .await;
    }
    async fn forge(&self, ct: &[u8], pt: &[u8]) -> Result<Vec<u8>, DecryptError> {
        return _padding_forge(
            &vec![],
            pt,
            ct,
            self.detector.clone(),
            self.retry,
            self.tx.clone(),
            self.block_size,
        )
        .await;
    }
}

pub struct DoubleOracle<D: Detector> {
    single_oracle: SingleOracle<D>,
    ct_prefix: Vec<u8>,
}

impl<D: Detector> DoubleOracle<D> {
    pub fn new(
        detector: D,
        tx: Sender<Messages>,
        ct_prefix: &[u8],
        block_size: usize,
        retry: usize,
    ) -> Self {
        return Self {
            single_oracle: SingleOracle::new(detector, tx, block_size, retry),
            ct_prefix: ct_prefix.to_vec(),
        };
    }
}

#[async_trait]
impl<D: Detector + Clone + Send> Oracle for DoubleOracle<D> {
    async fn decrypt(&self, ct: &[u8]) -> Result<Vec<u8>, DecryptError> {
        return _padding_decrypt(
            &self.ct_prefix,
            ct,
            self.single_oracle.detector.clone(),
            self.single_oracle.retry,
            self.single_oracle.tx.clone(),
            self.single_oracle.block_size,
        )
        .await;
    }
    async fn forge(&self, ct: &[u8], pt: &[u8]) -> Result<Vec<u8>, DecryptError> {
        return _padding_forge(
            &self.ct_prefix,
            pt,
            ct,
            self.single_oracle.detector.clone(),
            self.single_oracle.retry,
            self.single_oracle.tx.clone(),
            self.single_oracle.block_size,
        )
        .await;
    }
}

pub struct IntermediateOracle {
    tx: Sender<Messages>,
    detector: IntermediateDetector,
    block_size: usize,
    bad_chars: Vec<u8>,
}

impl IntermediateOracle {
    pub fn new(
        detector: IntermediateDetector,
        tx: Sender<Messages>,
        block_size: usize,
        bad_chars: &[u8],
    ) -> Self {
        return Self {
            tx,
            detector,
            block_size,
            bad_chars: bad_chars.to_vec(),
        };
    }
}

#[async_trait]
impl Oracle for IntermediateOracle {
    async fn decrypt(&self, ct: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let chunks = ct
            .to_vec()
            .chunks(self.block_size)
            .map(|chunk| chunk.to_vec())
            .collect::<Vec<Vec<u8>>>();
        let pt_buffer = Arc::new(Mutex::new(vec![
            vec![0u8; self.block_size];
            chunks.len() - 1
        ]));
        let block_size = self.block_size;
        let cradles = Arc::new(Mutex::new(vec![None; chunks.len() - 1]));
        let mut cradle_futures = vec![];
        let prime_cache = Arc::new(Mutex::new(HashMap::new()));
        for i in 1..chunks.len() {
            let cradles = cradles.clone();
            let block_for_decryption = chunks[i].clone();
            let detector = self.detector.clone();
            let tx = self.tx.clone();
            let prime_cache = prime_cache.clone();
            let bad_chars = self.bad_chars.clone();
            let iv = chunks[i - 1].clone();
            let pt_buffer = pt_buffer.clone();
            let msg_forwarder = MessageForwarder::new(
                self.tx.clone(),
                Box::new(move |msg| match msg {
                    Messages::ByteFound(zero_byte, pos) => {
                        let byte = zero_byte;
                        return Messages::ByteFound(byte, (i - 1) * block_size + pos);
                    }
                    other => other,
                }),
            );
            cradle_futures.push(async move {
                if let Ok(cradle) = build_cradle_2(
                    &detector,
                    &block_for_decryption,
                    &detector.block_prefix,
                    &detector.block_suffix,
                    500,
                    Some(prime_cache),
                )
                .await
                {
                    cradles.lock().await[i - 1] = Some(cradle.clone());
                    let _ = tx.send(Messages::FoundCradle).await;
                    let (pt, _) = decrypt_intermediate_block(
                        &detector,
                        &bad_chars,
                        &iv,
                        &cradle.0,
                        &block_for_decryption,
                        &detector.block_prefix,
                        &[cradle.1, detector.block_suffix.clone()].concat(),
                        self.block_size,
                        msg_forwarder.local_tx.clone(),
                    )
                    .await
                    .unwrap();
                    let mut pt_buff = pt_buffer.lock().await;
                    pt_buff[i - 1] = pt;
                }
            });
        }
        join_all(cradle_futures).await;

        return Ok(pt_buffer.lock().await.concat());
    }

    async fn forge(&self, ct: &[u8], pt: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let block_size = self.block_size;
        let mut chunks = pt
            .to_vec()
            .chunks(self.block_size)
            .map(|chunk| chunk.to_vec())
            .collect::<Vec<Vec<u8>>>();
        // add padding
        if let Some(last_chunk) = chunks.last_mut() {
            if self.block_size == last_chunk.len() {
                chunks.push(vec![self.block_size as u8; self.block_size]);
            } else {
                let padding = self.block_size - last_chunk.len();
                last_chunk.append(&mut vec![padding as u8; padding]);
            }
        }
        // this can be anything to start off with
        let mut block_for_decryption = ct
            .to_vec()
            .chunks(self.block_size)
            .map(|c| c.to_vec())
            .collect::<Vec<Vec<u8>>>()[0]
            .clone();
        let mut ct_buffer = block_for_decryption.clone();
        let prime_cache = Arc::new(Mutex::new(HashMap::new()));
        for i in (0..chunks.len()).rev() {
            let msg_forwarder = MessageForwarder::new(
                self.tx.clone(),
                Box::new(move |msg| match msg {
                    Messages::ByteFound(zero_byte, pos) => {
                        let byte = zero_byte;
                        return Messages::ByteFound(byte, i * block_size + pos);
                    }
                    other => other,
                }),
            );
            let cradle = build_cradle_2(
                &self.detector,
                &block_for_decryption,
                &self.detector.block_prefix,
                &self.detector.block_suffix,
                500,
                Some(prime_cache.clone()),
            )
            .await?;
            let _ = msg_forwarder.local_tx.send(Messages::FoundCradle).await;
            let (pt, _) = decrypt_intermediate_block(
                &self.detector,
                &self.bad_chars,
                &vec![0u8; self.block_size],
                &cradle.0,
                &block_for_decryption,
                &self.detector.block_prefix,
                &[cradle.1, self.detector.block_suffix.clone()].concat(),
                self.block_size,
                msg_forwarder.local_tx.clone(),
            )
            .await
            .unwrap();
            block_for_decryption = pt
                .iter()
                .zip(chunks[i].clone())
                .map(|(x, y)| x ^ y)
                .collect::<Vec<u8>>();
            ct_buffer = [block_for_decryption.clone(), ct_buffer].concat();
        }
        let cradle = build_cradle_2(
            &self.detector,
            &block_for_decryption,
            &self.detector.block_prefix,
            &self.detector.block_suffix,
            1000,
            Some(prime_cache.clone()),
        )
        .await?;
        return Ok([self.detector.block_prefix.clone(), cradle.0, ct_buffer].concat());
    }
}
