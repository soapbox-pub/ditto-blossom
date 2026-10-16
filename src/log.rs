//! One JSON object per line on stdout: `{"t":…,"level":…,"msg":…, fields}`.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

pub fn emit(level: &str, msg: &str, fields: Value) {
    let mut obj = Map::new();
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
    obj.insert("t".into(), t.into());
    obj.insert("level".into(), level.into());
    obj.insert("msg".into(), msg.into());
    if let Value::Object(f) = fields {
        obj.extend(f);
    }
    let mut line = serde_json::to_vec(&Value::Object(obj)).unwrap_or_default();
    line.push(b'\n');
    let _ = std::io::stdout().lock().write_all(&line);
}

/// `info!("msg", "key": value, …)`, the fields as in `serde_json::json!`.
#[macro_export]
macro_rules! info {
    ($msg:expr) => { $crate::log::emit("info", $msg, serde_json::Value::Null) };
    ($msg:expr, $($fields:tt)+) => { $crate::log::emit("info", $msg, serde_json::json!({ $($fields)+ })) };
}

#[macro_export]
macro_rules! warn {
    ($msg:expr) => { $crate::log::emit("warn", $msg, serde_json::Value::Null) };
    ($msg:expr, $($fields:tt)+) => { $crate::log::emit("warn", $msg, serde_json::json!({ $($fields)+ })) };
}

#[macro_export]
macro_rules! error {
    ($msg:expr) => { $crate::log::emit("error", $msg, serde_json::Value::Null) };
    ($msg:expr, $($fields:tt)+) => { $crate::log::emit("error", $msg, serde_json::json!({ $($fields)+ })) };
}
