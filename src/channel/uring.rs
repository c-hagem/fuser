//! io_uring-based FUSE communication channel

use std::{
    io::{self, IoSlice},
    os::fd::BorrowedFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
};

use io_uring::{opcode, types, IoUring};
use libc::{c_void, eventfd, EFD_CLOEXEC, POLLIN};
use log::{debug, error, info};

use crate::{
    ll::fuse_abi::{
        consts::{FUSE_IO_URING_CMD_COMMIT_AND_FETCH, FUSE_IO_URING_CMD_REGISTER},
        fuse_uring_cmd_req,
    },
    reply::ReplySender,
    session::BUFFER_SIZE,
};

#[cfg(feature = "abi-7-40")]
use crate::passthrough::BackingId;

/// A single entry in the io_uring queue
#[derive(Debug)]
struct UringEntry {
    /// Request buffer for incoming FUSE requests
    request_buffer: Vec<u8>,
    /// Response buffer for outgoing FUSE responses
    response_buffer: Vec<u8>,
    /// Commit ID for this request
    commit_id: u64,
    /// Whether this entry is currently in use
    in_use: bool,
}

impl UringEntry {
    fn new(buffer_size: usize) -> Self {
        Self {
            request_buffer: vec![0u8; buffer_size],
            response_buffer: vec![0u8; buffer_size],
            commit_id: 0,
            in_use: false,
        }
    }
}

/// A single io_uring queue (typically one per CPU core)
struct UringQueue {
    /// Queue ID
    qid: u32,
    /// io_uring instance
    ring: IoUring,
    /// Event file descriptor for shutdown signaling
    event_fd: i32,
    /// Ring entries for this queue
    entries: Vec<UringEntry>,
    /// Thread handle for this queue
    thread_handle: Option<JoinHandle<io::Result<()>>>,
    /// Shutdown flag
    shutdown: Arc<AtomicBool>,
    /// Maximum buffer size for requests
    buffer_size: usize,
}

impl UringQueue {
    fn new(qid: u32, queue_depth: u32, buffer_size: usize, fuse_fd: i32) -> io::Result<Self> {
        // Create event fd for shutdown signaling
        let event_fd = unsafe { eventfd(0, EFD_CLOEXEC) };
        if event_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Setup io_uring
        let ring = IoUring::new(queue_depth + 1)?; // +1 for event fd polling

        // Register file descriptors
        ring.submitter().register_files(&[fuse_fd, event_fd])?;

        // Create entries
        let mut entries = Vec::with_capacity(queue_depth as usize);
        for _ in 0..queue_depth {
            entries.push(UringEntry::new(buffer_size));
        }

        Ok(Self {
            qid,
            ring,
            event_fd,
            entries,
            thread_handle: None,
            shutdown: Arc::new(AtomicBool::new(false)),
            buffer_size,
        })
    }

    fn prepare_register_sqes(&mut self) -> io::Result<()> {
        // Prepare SQEs for all entries
        for (idx, _entry) in self.entries.iter_mut().enumerate() {
            // Create the io_uring command for registration
            let cmd_req = fuse_uring_cmd_req {
                commit_id: 0, // Not used for registration
                qid: self.qid,
                flags: 0,
                _reserved: [0; 16],
            };

            // Create the uring command SQE
            let cmd_sqe = opcode::UringCmd16::new(types::Fixed(0), FUSE_IO_URING_CMD_REGISTER)
                .cmd(cmd_req.as_cmd_bytes())
                .build()
                .user_data(idx as u64);

            unsafe {
                self.ring.submission().push(&cmd_sqe.into()).map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("Failed to push SQE: {:?}", e))
                })?;
            }
        }

        // Add event fd polling SQE for shutdown signaling
        let poll_sqe = opcode::PollAdd::new(types::Fixed(1), POLLIN as u32)
            .build()
            .user_data(u64::MAX); // Special marker for event fd

        unsafe {
            self.ring.submission().push(&poll_sqe.into()).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to push poll SQE: {:?}", e),
                )
            })?;
        }

        // Submit all SQEs
        self.ring.submit()?;

        Ok(())
    }

    fn handle_completion(&mut self, user_data: u64, res: i32) -> io::Result<Option<Vec<u8>>> {
        debug!("Handling completion for queue");
        if user_data == u64::MAX {
            // Event fd completion - shutdown signal
            if res > 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Shutdown signal",
                ));
            }
            return Ok(None);
        }

        let entry_idx = user_data as usize;
        if entry_idx >= self.entries.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid entry index",
            ));
        }

        if res < 0 {
            let err = io::Error::from_raw_os_error(-res);
            if err.kind() == io::ErrorKind::NotConnected {
                // Normal during unmount
                return Ok(None);
            }
            return Err(err);
        }

        let entry = &mut self.entries[entry_idx];
        entry.in_use = true;

        // For now, just return a dummy request data
        // In a real implementation, this would parse the actual FUSE request
        let request_data = vec![0u8; res as usize];
        Ok(Some(request_data))
    }

    fn commit_response(&mut self, entry_idx: usize, response: &[u8]) -> io::Result<()> {
        if entry_idx >= self.entries.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid entry index",
            ));
        }

        let entry = &mut self.entries[entry_idx];
        if !entry.in_use {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Entry not in use",
            ));
        }

        // Copy response to buffer
        if response.len() > entry.response_buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Response too large",
            ));
        }

        entry.response_buffer[..response.len()].copy_from_slice(response);

        // Create commit command
        let cmd_req = fuse_uring_cmd_req {
            commit_id: entry.commit_id,
            qid: self.qid,
            flags: 0,
            _reserved: [0; 16],
        };

        let cmd_sqe = opcode::UringCmd16::new(types::Fixed(0), FUSE_IO_URING_CMD_COMMIT_AND_FETCH)
            .cmd(cmd_req.as_cmd_bytes())
            .build()
            .user_data(entry_idx as u64);

        unsafe {
            self.ring.submission().push(&cmd_sqe.into()).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to push commit SQE: {:?}", e),
                )
            })?;
        }

        entry.in_use = false;

        // Submit the SQE
        self.ring.submit()?;

        Ok(())
    }

    fn run_event_loop(&mut self) -> io::Result<()> {
        while !self.shutdown.load(Ordering::Relaxed) {
            // Wait for completions
            self.ring.submit_and_wait(1)?;

            // Collect completion entries first to avoid borrowing issues
            let completions: Vec<_> = self
                .ring
                .completion()
                .map(|cqe| (cqe.user_data(), cqe.result()))
                .collect();

            // Process completions
            for (user_data, res) in completions {
                match self.handle_completion(user_data, res) {
                    Ok(Some(request_data)) => {
                        // TODO: Dispatch the request to the filesystem
                        // This would need to be integrated with the session processing
                        debug!(
                            "Received io_uring request with {} bytes",
                            request_data.len()
                        );
                    }
                    Ok(None) => {
                        // Normal completion or shutdown
                    }
                    Err(e) => {
                        if e.kind() == io::ErrorKind::Interrupted {
                            // Shutdown signal
                            break;
                        }
                        error!("Error handling completion: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    fn shutdown(&mut self) -> io::Result<()> {
        self.shutdown.store(true, Ordering::Relaxed);

        // Signal shutdown via eventfd
        let value = 1u64;
        let ret = unsafe {
            libc::write(
                self.event_fd,
                &value as *const _ as *const c_void,
                std::mem::size_of::<u64>(),
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Wait for thread to finish
        if let Some(handle) = self.thread_handle.take() {
            handle
                .join()
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to join thread"))??;
        }

        // Close event fd
        unsafe {
            libc::close(self.event_fd);
        }

        Ok(())
    }
}

impl Drop for UringQueue {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

impl std::fmt::Debug for UringQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UringQueue")
            .field("qid", &self.qid)
            .field("event_fd", &self.event_fd)
            .field("entries", &self.entries)
            .field("thread_handle", &self.thread_handle)
            .field("shutdown", &self.shutdown)
            .field("buffer_size", &self.buffer_size)
            .finish()
    }
}

struct UringChannelInner {
    /// Per-CPU queues
    queues: Mutex<Vec<UringQueue>>,
    /// Shutdown coordination
    shutdown: AtomicBool,
    /// Number of CPU cores
    num_cores: usize,
    /// Queue depth per queue
    queue_depth: u32,
    /// Buffer size for requests
    buffer_size: usize,
    /// FUSE file descriptor
    fuse_fd: i32,
}

// Public interface that wraps Arc<UringChannelInner>
pub struct UringChannel {
    inner: Arc<UringChannelInner>,
    /// Thread handles for cleanup (only stored in the main instance)
    thread_handles: Vec<JoinHandle<io::Result<()>>>,
}

impl UringChannel {
    pub fn new(fuse_fd: i32, queue_depth: u32, buffer_size: Option<usize>) -> io::Result<Self> {
        let num_cores = num_cpus::get();
        let buffer_size = buffer_size.unwrap_or(BUFFER_SIZE);

        let mut queues = Vec::with_capacity(num_cores);
        for qid in 0..num_cores {
            let queue = UringQueue::new(qid as u32, queue_depth, buffer_size, fuse_fd)?;
            queues.push(queue);
        }

        let inner = Arc::new(UringChannelInner {
            queues: Mutex::new(queues),
            shutdown: AtomicBool::new(false),
            num_cores,
            queue_depth,
            buffer_size,
            fuse_fd,
        });

        Ok(Self {
            inner,
            thread_handles: Vec::new(),
        })
    }

    pub fn start(&mut self) -> io::Result<()> {
        // Prepare all queues
        {
            let mut queues = self.inner.queues.lock().unwrap();
            for queue in queues.iter_mut() {
                queue.prepare_register_sqes()?;
            }
        }

        // Start threads for each queue
        for qid in 0..self.inner.num_cores {
            let inner_clone = Arc::clone(&self.inner);

            let handle = std::thread::Builder::new()
                .name(format!("fuse-uring-{}", qid))
                .spawn(move || run_queue_thread(inner_clone, qid as u32))?;

            self.thread_handles.push(handle);
        }

        Ok(())
    }

    pub fn stop(&mut self) -> io::Result<()> {
        // Signal shutdown
        self.inner.shutdown.store(true, Ordering::Relaxed);

        // Signal all eventfds to wake up threads
        {
            let queues = self.inner.queues.lock().unwrap();
            for queue in queues.iter() {
                let value = 1u64;
                unsafe {
                    libc::write(
                        queue.event_fd,
                        &value as *const _ as *const c_void,
                        std::mem::size_of::<u64>(),
                    );
                }
            }
        }

        // Wait for all threads to complete
        for handle in std::mem::take(&mut self.thread_handles) {
            let _ = handle.join();
        }

        Ok(())
    }

    pub fn sender(&self) -> UringChannelSender {
        UringChannelSender::new_with_channel(Arc::clone(&self.inner))
    }
}

// Thread function that runs the event loop
fn run_queue_thread(inner: Arc<UringChannelInner>, qid: u32) -> io::Result<()> {
    // Set CPU affinity
    set_cpu_affinity(qid);

    info!("Starting io_uring thread for queue {}", qid);

    // Main event loop
    while !inner.shutdown.load(Ordering::Relaxed) {
        // Get mutable access to our specific queue
        let mut queue_guard = inner.queues.lock().unwrap();
        if let Some(queue) = queue_guard.get_mut(qid as usize) {
            // Run one iteration of the event loop
            match queue.ring.submit_and_wait(1) {
                Ok(_) => {
                    // Process completions
                    let completions: Vec<_> = queue
                        .ring
                        .completion()
                        .map(|cqe| (cqe.user_data(), cqe.result()))
                        .collect();

                    for (user_data, result) in completions {
                        if let Err(e) = queue.handle_completion(user_data, result) {
                            if e.kind() == io::ErrorKind::Interrupted {
                                break; // Shutdown signal
                            }
                            error!("Error handling completion: {}", e);
                        }
                    }
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::NotConnected {
                        break; // Normal unmount
                    }
                    if e.raw_os_error() == Some(libc::EINTR) {
                        continue; // Interrupted, retry
                    }
                    error!("io_uring error: {}", e);
                    break;
                }
            }
        } else {
            break; // Queue not found
        }
    }

    info!("Shutting down io_uring thread for queue {}", qid);
    Ok(())
}

// Updated sender
pub struct UringChannelSender {
    /// Channel reference for sending responses
    channel: Arc<UringChannelInner>,
    /// Queue ID for this sender (optional)
    qid: Option<u32>,
    /// Entry index within the queue (optional)
    entry_idx: Option<usize>,
    /// Commit ID for the request (optional)
    commit_id: Option<u64>,
}

impl UringChannelSender {
    pub fn new_with_channel(channel: Arc<UringChannelInner>) -> Self {
        Self {
            channel,
            qid: None,
            entry_idx: None,
            commit_id: None,
        }
    }

    pub fn with_params(mut self, qid: u32, entry_idx: usize, commit_id: u64) -> Self {
        self.qid = Some(qid);
        self.entry_idx = Some(entry_idx);
        self.commit_id = Some(commit_id);
        self
    }
}

impl ReplySender for UringChannelSender {
    fn send(&self, bufs: &[IoSlice<'_>]) -> io::Result<()> {
        // Collect response data
        let total_size: usize = bufs.iter().map(|buf| buf.len()).sum();
        let mut response_data = Vec::with_capacity(total_size);
        for buf in bufs {
            response_data.extend_from_slice(buf);
        }

        // If we have specific queue/entry info, use it
        if let (Some(qid), Some(entry_idx), Some(commit_id)) =
            (self.qid, self.entry_idx, self.commit_id)
        {
            // Get the specific queue and commit the response
            let mut queues = self.channel.queues.lock().unwrap();
            if let Some(queue) = queues.get_mut(qid as usize) {
                queue.commit_response(entry_idx, &response_data)?;
            }
        } else {
            // Fallback: just log for now
            debug!("Sending response of {} bytes", response_data.len());
        }

        Ok(())
    }

    #[cfg(feature = "abi-7-40")]
    fn open_backing(&self, _fd: BorrowedFd<'_>) -> io::Result<BackingId> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "io_uring backing files not yet implemented",
        ))
    }
}

// Helper function for CPU affinity
fn set_cpu_affinity(qid: u32) {
    // This would set CPU affinity like libfuse does
    // Implementation would be platform-specific
    debug!("Setting CPU affinity for queue {} (placeholder)", qid);
}

// Helper function to get number of CPU cores
mod num_cpus {
    use nix::unistd::{sysconf, SysconfVar};

    pub fn get() -> usize {
        sysconf(SysconfVar::_NPROCESSORS_ONLN)
            .unwrap_or(Some(1))
            .unwrap_or(1) as usize
    }
}

// Helper trait to convert structs to bytes for io_uring commands
trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

impl AsBytes for fuse_uring_cmd_req {
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }
}

impl fuse_uring_cmd_req {
    fn as_cmd_bytes(&self) -> [u8; 16] {
        let mut cmd_bytes = [0u8; 16];
        let src_bytes = self.as_bytes();
        let len = std::cmp::min(src_bytes.len(), 16);
        cmd_bytes[..len].copy_from_slice(&src_bytes[..len]);
        cmd_bytes
    }
}
