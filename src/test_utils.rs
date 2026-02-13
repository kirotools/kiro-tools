use once_cell::sync::Lazy;
use std::sync::Mutex;

pub static GLOBAL_TEST_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
