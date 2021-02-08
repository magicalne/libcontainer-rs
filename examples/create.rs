extern crate libcontainer;

use libcontainer::{config::Config, linux::run, Result};

fn main() -> Result<()> {
    println!("hello libcontainer-rs.");

    let config = Config::read_file("config.json")?;
    run("my_container", &config)?;
    dbg!(std::process::id());
    Ok(())
}
