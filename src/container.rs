use std::collections::HashMap;

use crate::config::Config;

pub struct Container {
    config: Config
}

pub enum Status {
    Creating,
    Created,
    Running,
    Stopped
}

pub struct State {
    pub oci_version: String,
    pub status: Status,
    pub pid: u32,
    pub bundle: String,
    pub annotations: Option<HashMap<String, String>>
}