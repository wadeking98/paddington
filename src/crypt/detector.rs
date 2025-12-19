use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use tokio::{
    sync::{Mutex, Semaphore},
    task::JoinSet,
};

use crate::errors::DecryptError;

#[derive(PartialEq)]
pub enum DETECT {
    BASELINE,
    OUTLIER,
}

#[async_trait]
pub trait Oracle: 'static + Send + Sync {
    async fn exec(&self, ct: &[u8]) -> String;
}

#[async_trait]
impl<O: Oracle> Oracle for Arc<O> {
    async fn exec(&self, ct: &[u8]) -> String {
        self.as_ref().exec(ct).await
    }
}

#[async_trait]
impl<O: Oracle + ?Sized> Oracle for Box<O> {
    async fn exec(&self, ct: &[u8]) -> String {
        self.as_ref().exec(ct).await
    }
}

#[allow(async_fn_in_trait)]
pub trait Detector {
    async fn init(
        ct: &[u8],
        oracle: impl Oracle,
        blk_size: usize,
        threads: usize,
    ) -> Result<Self, DecryptError>
    where
        Self: Sized;
    fn check(
        &self,
        ct: &[u8],
    ) -> impl std::future::Future<Output = Result<DETECT, DecryptError>> + Send;
}

pub struct SimpleDetector {
    padding_invalid_resp: String,
    oracle: Arc<dyn Oracle>,
    semaphore: Arc<Semaphore>,
}

impl Detector for SimpleDetector {
    async fn init(
        ct: &[u8],
        oracle: impl Oracle,
        blk_size: usize,
        threads: usize,
    ) -> Result<Self, DecryptError>
    where
        Self: Sized,
    {
        let semaphore = Arc::new(Semaphore::new(threads));
        let blocks: Vec<Vec<u8>> = ct
            .chunks(blk_size.into())
            .map(|val| Vec::from(val))
            .collect();
        if blocks.len() < 2 {
            return Err(DecryptError::InvalidInput(
                "Not enough blocks for classic attack".into(),
            ));
        }
        let last_blocks_shared = Vec::from([vec![0u8;blk_size],blocks[blocks.len()-1].clone()]);

        let response_map_shared: Arc<Mutex<HashMap<String, u16>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let oracle_shared = Arc::new(oracle);

        let mut futures_set = JoinSet::new();
        for i in 0..=255 {
            let sem_acquire = semaphore
                .clone()
                .acquire_owned()
                .await
                .expect("Error: semaphore closed");
            let mut last_blocks = last_blocks_shared.clone();
            let response_map = response_map_shared.clone();
            let oracle = oracle_shared.clone();
            futures_set.spawn(async move {
                last_blocks[0][blk_size as usize - 1] = i;
                let response = oracle
                    .exec(&last_blocks.iter().flatten().cloned().collect::<Vec<u8>>())
                    .await;
                let mut response_map_acquired = response_map.lock().await;
                let num_response = response_map_acquired
                    .get(&response)
                    .unwrap_or(&0)
                    .to_owned();
                response_map_acquired.insert(response, num_response + 1);
                drop(sem_acquire);
            });
        }
        futures_set.join_all().await;
        let response_map_acquired = response_map_shared.lock().await;
        if response_map_acquired.keys().len() < 2 {
            return Err(DecryptError::DifferentialResponses(
                "No unique responses found".into(),
            ));
        }
        let (padding_invalid_resp, _) = response_map_acquired
            .iter()
            .max_by_key(|(_k, v)| *v)
            .unwrap();
        let detector = Self {
            padding_invalid_resp: padding_invalid_resp.to_owned(),
            oracle: oracle_shared.clone(),
            semaphore,
        };
        return Ok(detector);
    }

    async fn check(&self, ct: &[u8]) -> Result<DETECT, DecryptError> {
        let sem_acquire = self
            .semaphore
            .acquire()
            .await
            .expect("Error: semaphore closed");
        let mut res = DETECT::BASELINE;
        if self.oracle.exec(ct).await != self.padding_invalid_resp {
            res = DETECT::OUTLIER;
        }
        drop(sem_acquire);
        return Ok(res);
    }
}
