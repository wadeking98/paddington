use std::{
    cmp::min,
    collections::HashMap,
    io::{self, Write},
    sync::Arc,
    time::Duration,
};

use colored::Colorize;
use tokio::{
    select, spawn, sync::{Mutex, mpsc::Receiver}, time::sleep
};
use tokio_util::sync::CancellationToken;

use crate::helper::Messages;

pub fn fmt_bytes_custom(bytes: &[u8]) -> String {
    let mut base = String::new();
    for &byte in bytes {
        if byte.is_ascii_graphic() || byte.is_ascii_whitespace() {
            // Cast to char for printing as a character
            base += format!("{}", byte as char).as_str();
        } else {
            // Print as a two-digit uppercase hex value with "0x" prefix
            base += format!("\\x{:02X}", byte).as_str();
        }
    }
    base
}

///displays a progress bar to the terminal. updates to the bytes are received from rx
pub fn progress_bar(ct_len: usize, mut rx: Receiver<Messages>) {
        let curr_results: Vec<u8> = vec![b'-'; ct_len];
        let curr_results_modified: Vec<bool> = vec![false; ct_len];
        let loading_map = HashMap::from([(b'|', b'/'), (b'/', b'-'), (b'-', b'\\'), (b'\\', b'|')]);
        let curr_results_shared = Arc::new(Mutex::new(curr_results));
        let curr_results_modified_shared = Arc::new(Mutex::new(curr_results_modified));
        let curr_results_shared_copy = curr_results_shared.clone();
        let curr_results_modified_shared_copy = curr_results_modified_shared.clone();
        
        let token = CancellationToken::new();
        let cloned_token = token.clone();
        spawn(async move {
            loop {
                let msg = rx.recv().await;
                if let Some(msg) = msg {
                    match msg {
                        Messages::ByteFound(byte, pos) => {
                            let mut curr_results = curr_results_shared.lock().await;
                            let mut curr_results_modified =
                                curr_results_modified_shared.lock().await;
                            curr_results[pos] = byte;
                            curr_results_modified[pos] = true;
                        }
                        Messages::OracleConfirmed => {
                            print!("\r\x1B[2K");
                            io::stdout().flush().unwrap();
                            println!("{}", "Padding Oracle Confirmed!".green());
                        },
                        Messages::NoOracleFound => {
                            token.cancel();
                            return;
                        }
                        _ => (),
                    };
                }
            }
        });
        spawn(async move {
            let truncate_len = 64;
            loop {
                select! {
                    _ = sleep(Duration::from_millis(250)) =>{},
                    _ = cloned_token.cancelled() =>{
                        return;
                    }
                }
                let mut curr_results = curr_results_shared_copy.lock().await;
                let curr_results_modified = curr_results_modified_shared_copy.lock().await;
                // update loop
                for i in 0..curr_results.len() {
                    //skip results that have been modified
                    if curr_results_modified[i] {
                        continue;
                    }
                    curr_results[i] = *loading_map.get(&curr_results[i]).unwrap_or(&b'-');
                }
                let working_chunk = curr_results_modified
                    .chunks(truncate_len)
                    .position(|c| c.contains(&false) && c.contains(&true))
                    .unwrap_or(0);

                let end = min((working_chunk + 1) * truncate_len, curr_results.len());
                let curr_results_slice = &curr_results[working_chunk * truncate_len..end];
                let byte_string = fmt_bytes_custom(&curr_results_slice);
                print!("\r\x1B[2K");
                io::stdout().flush().unwrap();
                print!("{}", byte_string);
                if ct_len > truncate_len {
                    print!("...");
                }

                io::stdout().flush().unwrap();
            }
        });
}
