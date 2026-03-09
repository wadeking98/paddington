use std::sync::Arc;

use async_trait::async_trait;
use futures::future::join_all;
use tokio::sync::{Mutex, mpsc::Sender};

use crate::{crypt::{MessageForwarder, cradlehelpers::{ComputeCache, build_cradle, build_cradle_simple, decrypt_intermediate_block}, decrypt::_padding_decrypt, detector::{Detector, IntermediateDetector}, forge::_padding_forge}, errors::DecryptError, helper::Messages};

#[async_trait]
pub trait Oracle: 'static + Send + Sync {
    async fn decrypt(&self, ct:&[u8]) -> Result<Vec<u8>, DecryptError>;
    async fn forge(&self, ct:&[u8], pt:&[u8]) -> Result<Vec<u8>, DecryptError>;
}

pub struct SingleOracle<D: Detector> {
    detector: D,
    tx: Sender<Messages>,
    block_size: usize,
    retry: usize
}

impl<D:Detector> SingleOracle<D>{
    pub fn new(detector: D, tx: Sender<Messages>, block_size: usize, retry:usize) -> Self{
        return Self { detector, tx, block_size, retry }
    }
}

#[async_trait]
impl<D:Detector+Clone+Send> Oracle for SingleOracle<D> {
    async fn decrypt(&self, ct:&[u8]) -> Result<Vec<u8>, DecryptError>{
        return _padding_decrypt(&vec![],ct, self.detector.clone(), self.retry, self.tx.clone(), self.block_size).await;
    }
    async fn forge(&self, ct:&[u8], pt:&[u8]) -> Result<Vec<u8>, DecryptError>{
        return _padding_forge(&vec![], pt, ct, self.detector.clone(),self.retry,self.tx.clone(),self.block_size).await;
    }
}

pub struct DoubleOracle<D: Detector>{
    single_oracle: SingleOracle<D>,
    ct_prefix: Vec<u8>
}

impl<D:Detector> DoubleOracle<D>{
    pub fn new(detector: D, tx: Sender<Messages>,ct_prefix: &[u8], block_size: usize, retry:usize) -> Self{
        return Self {single_oracle: SingleOracle::new( detector, tx, block_size, retry ), ct_prefix: ct_prefix.to_vec()}
    }
}

#[async_trait]
impl<D:Detector+Clone+Send> Oracle for DoubleOracle<D> {
    async fn decrypt(&self, ct:&[u8]) -> Result<Vec<u8>, DecryptError>{
        return _padding_decrypt(&self.ct_prefix,ct, self.single_oracle.detector.clone(), self.single_oracle.retry, self.single_oracle.tx.clone(), self.single_oracle.block_size).await;
    }
    async fn forge(&self, ct:&[u8], pt:&[u8]) -> Result<Vec<u8>, DecryptError>{
        return _padding_forge(&self.ct_prefix, pt, ct, self.single_oracle.detector.clone(),self.single_oracle.retry,self.single_oracle.tx.clone(),self.single_oracle.block_size).await;
    }
}

pub struct IntermediateOracle{
    tx: Sender<Messages>,
    detector: IntermediateDetector,
    block_size: usize,
    bad_chars: Vec<u8>
}

impl IntermediateOracle {
    pub fn new(detector: IntermediateDetector, tx: Sender<Messages>, block_size: usize, bad_chars: &[u8]) -> Self{
        return Self { tx, detector, block_size, bad_chars: bad_chars.to_vec() };
    }
}

#[async_trait]
impl Oracle for IntermediateOracle{
    async fn decrypt(&self, ct:&[u8]) -> Result<Vec<u8>, DecryptError>{
        let chunks = ct.to_vec().chunks(self.block_size).map(|chunk| chunk.to_vec()).collect::<Vec<Vec<u8>>>();
        let mut cache = Some(ComputeCache::new());
        let mut futures_set = vec![];
        let pt_buffer = Arc::new(Mutex::new(vec![vec![0u8;self.block_size];chunks.len()-1]));
        let block_size = self.block_size;
        for i in 1..chunks.len(){
            let iv = &chunks[i-1];
            let block_for_decryption = &chunks[i];
            let mut cradle = None;
            if i == 1{
                // println!("trying simple cradle");
                // if let Ok(res) = build_cradle_simple(&self.detector, &block_for_decryption, &self.detector.block_prefix, &self.detector.block_suffix, 50).await{
                //     cradle = Some(res);
                // }else{
                //     println!("trying complex cradle");
                    cradle = Some(build_cradle(&self.detector,&self.bad_chars, &block_for_decryption,&self.detector.block_prefix, &self.detector.block_suffix, &mut cache, 1000).await?);
                //}                
            }
            let mut cradle = cradle.clone();
            let bad_chars = self.bad_chars.clone();
            let mut cache = cache.clone();
            let detector = self.detector.clone();
            let pt_buffer = pt_buffer.clone();
            futures_set.push(async move{
                if cradle.is_none(){
                    // println!("trying simple cradle");
                    // if let Ok(res) = build_cradle_simple(&detector, &block_for_decryption,&detector.block_prefix, &detector.block_suffix, 50).await{
                    //     cradle = Some(res);
                    // }else{
                    //     println!("trying complex cradle");
                        cradle = build_cradle(&detector,&bad_chars, &block_for_decryption,&detector.block_prefix, &detector.block_suffix, &mut cache, 1000).await.ok();
                    //}
                }
                if let Some(cradle) = cradle {

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

                    let _ = msg_forwarder.local_tx.send(Messages::FoundCradle).await;
                    let (pt, _) = decrypt_intermediate_block(&detector, &bad_chars, iv, &cradle.0, block_for_decryption, &detector.block_prefix, &[cradle.1, detector.block_suffix.clone()].concat(), self.block_size, msg_forwarder.local_tx.clone()).await.unwrap();
                    let mut pt_buff = pt_buffer.lock().await;
                    pt_buff[i-1] = pt;
                }
            });
        }
        join_all(futures_set).await;
        return Ok(pt_buffer.lock().await.concat());
    }

    async fn forge(&self, ct:&[u8], pt:&[u8]) -> Result<Vec<u8>, DecryptError>{
        let block_size = self.block_size;
        let mut chunks = pt.to_vec().chunks(self.block_size).map(|chunk| chunk.to_vec()).collect::<Vec<Vec<u8>>>();
        // add padding
        if let Some(last_chunk) = chunks.last_mut(){
            if self.block_size == last_chunk.len(){
                chunks.push(vec![self.block_size as u8;self.block_size]);
            }else{
                let padding = self.block_size - last_chunk.len();
                last_chunk.append(&mut vec![padding as u8;padding]);
            }
        }
        let mut cache = Some(ComputeCache::new());
        // this can be anything to start off with
        let mut block_for_decryption = ct.to_vec().chunks(self.block_size).map(|c|c.to_vec()).collect::<Vec<Vec<u8>>>()[0].clone();
        let mut ct_buffer = block_for_decryption.clone();
        for i in (0..chunks.len()).rev(){
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
            let cradle = build_cradle(&self.detector,&self.bad_chars, &block_for_decryption,&self.detector.block_prefix, &self.detector.block_suffix, &mut cache, 1000).await?;
            let _ = msg_forwarder.local_tx.send(Messages::FoundCradle).await;
            let (pt, _) = decrypt_intermediate_block(&self.detector, &self.bad_chars, &vec![0u8;self.block_size], &cradle.0, &block_for_decryption, &self.detector.block_prefix, &[cradle.1, self.detector.block_suffix.clone()].concat(), self.block_size, msg_forwarder.local_tx.clone()).await.unwrap();
            block_for_decryption = pt.iter().zip(chunks[i].clone()).map(|(x,y)|x^y).collect::<Vec<u8>>();
            ct_buffer = [block_for_decryption.clone(),ct_buffer].concat();
        }
        let cradle = build_cradle(&self.detector,&self.bad_chars, &block_for_decryption,&self.detector.block_prefix, &self.detector.block_suffix, &mut cache, 1000).await?;
        return Ok([self.detector.block_prefix.clone(), cradle.0, ct_buffer].concat());
    }
}

