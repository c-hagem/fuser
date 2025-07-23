//! Hello World filesystem example using io_uring
//!
//! This example demonstrates how to use fuser with io_uring support for improved performance.
//! It creates a simple filesystem with a single file "hello.txt" containing "Hello World!".
//!
//! Usage:
//!   cargo run --example hello_uring --features io_uring -- <mountpoint> [options]
//!
//! Example:
//!   cargo run --example hello_uring --features io_uring -- /tmp/hello --io-uring --queue-depth 64

use clap::{crate_version, Arg, ArgAction, Command};
use fuser::{
    FileAttr, FileType, Filesystem, KernelConfig, MountOption, ReplyAttr, ReplyData,
    ReplyDirectory, ReplyEntry, Request, Session,
};
use libc::ENOENT;
use std::ffi::OsStr;
use std::time::{Duration, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1); // 1 second

const HELLO_DIR_ATTR: FileAttr = FileAttr {
    ino: 1,
    size: 0,
    blocks: 0,
    atime: UNIX_EPOCH, // 1970-01-01 00:00:00
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::Directory,
    perm: 0o755,
    nlink: 2,
    uid: 501,
    gid: 20,
    rdev: 0,
    flags: 0,
    blksize: 512,
};

const HELLO_TXT_CONTENT: &str = "Hello World!\n";

const HELLO_TXT_ATTR: FileAttr = FileAttr {
    ino: 2,
    size: 13,
    blocks: 1,
    atime: UNIX_EPOCH, // 1970-01-01 00:00:00
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::RegularFile,
    perm: 0o644,
    nlink: 1,
    uid: 501,
    gid: 20,
    rdev: 0,
    flags: 0,
    blksize: 512,
};

struct HelloFS;

impl Filesystem for HelloFS {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> Result<(), i32> {
        println!("Initializing HelloFS");

        // Print configuration information
        #[cfg(feature = "io_uring")]
        {
            if config.is_io_uring_enabled() {
                println!(
                    "io_uring enabled with queue depth: {}",
                    config.io_uring_queue_depth()
                );
            } else {
                println!("io_uring disabled, using traditional read/write");
            }
        }

        #[cfg(not(feature = "io_uring"))]
        {
            println!("io_uring support not compiled in, using traditional read/write");
        }

        Ok(())
    }

    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent == 1 && name.to_str() == Some("hello.txt") {
            reply.entry(&TTL, &HELLO_TXT_ATTR, 0);
        } else {
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match ino {
            1 => reply.attr(&TTL, &HELLO_DIR_ATTR),
            2 => reply.attr(&TTL, &HELLO_TXT_ATTR),
            _ => reply.error(ENOENT),
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        _size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        if ino == 2 {
            reply.data(&HELLO_TXT_CONTENT.as_bytes()[offset as usize..]);
        } else {
            reply.error(ENOENT);
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if ino != 1 {
            reply.error(ENOENT);
            return;
        }

        let entries = vec![
            (1, FileType::Directory, "."),
            (1, FileType::Directory, ".."),
            (2, FileType::RegularFile, "hello.txt"),
        ];

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            // i + 1 means the index of the next entry
            if reply.add(entry.0, (i + 1) as i64, entry.1, entry.2) {
                break;
            }
        }
        reply.ok();
    }
}

fn main() {
    let matches = Command::new("hello_uring")
        .version(crate_version!())
        .author("Christopher Berner")
        .about("Hello World filesystem with optional io_uring support")
        .arg(
            Arg::new("MOUNT_POINT")
                .required(true)
                .index(1)
                .help("Mount point for the filesystem"),
        )
        .arg(
            Arg::new("auto_unmount")
                .long("auto_unmount")
                .action(ArgAction::SetTrue)
                .help("Automatically unmount on process exit"),
        )
        .arg(
            Arg::new("allow-root")
                .long("allow-root")
                .action(ArgAction::SetTrue)
                .help("Allow root user to access filesystem"),
        )
        .arg(
            Arg::new("io-uring")
                .long("io-uring")
                .action(ArgAction::SetTrue)
                .help("Enable io_uring support (requires io_uring feature)"),
        )
        .arg(
            Arg::new("queue-depth")
                .long("queue-depth")
                .value_name("DEPTH")
                .help("Set io_uring queue depth (default: 32)")
                .default_value("32"),
        )
        .arg(
            Arg::new("debug")
                .long("debug")
                .action(ArgAction::SetTrue)
                .help("Enable debug logging"),
        )
        .get_matches();

    // Initialize logging
    if matches.get_flag("debug") {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::init();
    }

    let mountpoint = matches.get_one::<String>("MOUNT_POINT").unwrap();
    let mut options = vec![MountOption::RO, MountOption::FSName("hello".to_string())];

    if matches.get_flag("auto_unmount") {
        options.push(MountOption::AutoUnmount);
    }
    if matches.get_flag("allow-root") {
        options.push(MountOption::AllowRoot);
    }

    // Check if io_uring is requested
    let use_io_uring = matches.get_flag("io-uring");
    let queue_depth: u32 = matches
        .get_one::<String>("queue-depth")
        .unwrap()
        .parse()
        .expect("Invalid queue depth");

    if use_io_uring {
        #[cfg(feature = "io_uring")]
        {
            println!(
                "Creating session with io_uring support (queue depth: {})",
                queue_depth
            );

            // Create a session with io_uring configuration
            let mut session = Session::new_with_uring(HelloFS, mountpoint, &options, queue_depth)
                .expect("Failed to create session with io_uring");

            println!("Starting filesystem with io_uring enabled...");
            session.run().expect("Failed to run filesystem");
        }

        #[cfg(not(feature = "io_uring"))]
        {
            eprintln!("Error: io_uring support not compiled in!");
            eprintln!("Please compile with: cargo run --example hello_uring --features io_uring");
            std::process::exit(1);
        }
    } else {
        println!("Creating session with traditional read/write");

        // Create a traditional session
        let mut session =
            Session::new(HelloFS, mountpoint, &options).expect("Failed to create session");

        println!("Starting filesystem with traditional read/write...");
        session.run().expect("Failed to run filesystem");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filesystem_basic() {
        let mut fs = HelloFS;

        // Test that the filesystem constants are valid
        assert_eq!(HELLO_TXT_ATTR.ino, 2);
        assert_eq!(HELLO_TXT_ATTR.size, 13);
        assert_eq!(HELLO_TXT_CONTENT.len(), 13);
        assert_eq!(HELLO_DIR_ATTR.ino, 1);
        assert_eq!(HELLO_DIR_ATTR.kind, FileType::Directory);
    }

    #[test]
    fn test_queue_depth_validation() {
        // Test that queue depth parsing works
        let depth_str = "64";
        let depth: u32 = depth_str.parse().expect("Should parse valid number");
        assert_eq!(depth, 64);

        // Test invalid queue depth
        let invalid_depth = "invalid";
        assert!(invalid_depth.parse::<u32>().is_err());
    }
}
