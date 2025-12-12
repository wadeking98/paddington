use std::collections::HashMap;

#[derive(Clone)]
pub struct Config(HashMap<String, String>);

impl Config {
    pub fn new() -> Self {
        Self(HashMap::new())
    }
    pub fn from_hashmap(config: HashMap<String, String>) -> Self {
        Self(config)
    }
    fn get_base<F, N>(&self, key: String, default: N, convert: F) -> N
    where
        F: Fn(String) -> N,
    {
        match self.0.get(&key) {
            Some(val) => convert(val.into()),
            None => default,
        }
    }
    pub fn get(&self, key: String, default: String) -> String {
        self.get_base(key, default, |val| val)
    }
    pub fn get_int(&self, key: String, default: i64) -> i64 {
        self.get_base(key, default, |val| val.parse().unwrap_or(default))
    }
    pub fn get_bool(&self, key: String, default: bool) -> bool {
        self.get_base(key, default, |val| val.eq("true"))
    }
    pub fn set(&mut self, key: String, val: String) {
        self.0.insert(key, val);
    }
}
