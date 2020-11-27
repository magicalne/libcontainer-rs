extern crate libcontainer;
fn main() {
    println!("hello libcontainer-rs.");
    dbg!(std::process::id());
    libcontainer::linux::prepare_root_fs("container_id", "rootfs");
}