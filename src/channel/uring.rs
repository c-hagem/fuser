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
        info!(
            "Creating UringQueue {} with depth={}, buffer_size={}, fuse_fd={}",
            qid, queue_depth, buffer_size, fuse_fd
        );

        // Validate fuse_fd first
        if fuse_fd < 0 {
            error!("Invalid fuse_fd: {}", fuse_fd);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid fuse_fd",
            ));
        }

        // Check if we can stat the fuse_fd
        let mut stat_buf = unsafe { std::mem::zeroed() };
        let stat_result = unsafe { libc::fstat(fuse_fd, &mut stat_buf) };
        if stat_result != 0 {
            let error = io::Error::last_os_error();
            error!("fstat failed on fuse_fd {}: {}", fuse_fd, error);
            return Err(error);
        }
        info!("fuse_fd {} is valid", fuse_fd);

        // Create event fd for shutdown signaling
        let event_fd = unsafe { eventfd(0, EFD_CLOEXEC) };
        if event_fd < 0 {
            let error = io::Error::last_os_error();
            error!("eventfd creation failed: {}", error);
            return Err(error);
        }
        info!("Created eventfd: {}", event_fd);

        // Setup io_uring with specific parameters like libfuse
        info!("Setting up io_uring with depth {}", queue_depth + 1);

        // Try different approaches based on what fails
        let ring = Self::setup_io_uring(queue_depth + 1, fuse_fd, event_fd)?;

        info!("io_uring setup successful for queue {}", qid);

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
    fn setup_io_uring(depth: u32, fuse_fd: i32, event_fd: i32) -> io::Result<IoUring> {
        // Try the simple approach first
        info!("Trying simple IoUring::new({})", depth);
        match IoUring::new(depth) {
            Ok(ring) => {
                info!("Basic io_uring setup successful");

                // Try to register files
                info!(
                    "Registering files: fuse_fd={}, event_fd={}",
                    fuse_fd, event_fd
                );
                match ring.submitter().register_files(&[fuse_fd, event_fd]) {
                    Ok(_) => {
                        info!("File registration successful");
                        return Ok(ring);
                    }
                    Err(e) => {
                        error!("File registration failed: {}", e);

                        // Try with just one file
                        info!("Trying to register only fuse_fd");
                        match ring.submitter().register_files(&[fuse_fd]) {
                            Ok(_) => {
                                warn!("Only fuse_fd registered, eventfd registration failed");
                                return Ok(ring);
                            }
                            Err(e2) => {
                                error!("Even single file registration failed: {}", e2);
                                return Err(e2);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("Basic io_uring setup failed: {}", e);

                // Try with builder and specific parameters
                info!("Trying with IoUring::builder()");
                match IoUring::builder().build(depth) {
                    Ok(ring) => {
                        info!("Builder-based setup successful");
                        return Self::try_register_files(ring, fuse_fd, event_fd);
                    }
                    Err(e2) => {
                        error!("Builder-based setup also failed: {}", e2);
                        return Err(e);
                    }
                }
            }
        }
    }

    fn try_register_files(ring: IoUring, fuse_fd: i32, event_fd: i32) -> io::Result<IoUring> {
        // Try different file registration approaches
        info!("Attempting file registration");

        if let Err(e) = ring.submitter().register_files(&[fuse_fd, event_fd]) {
            warn!("Two-file registration failed: {}, trying alternatives", e);

            // Try with just fuse_fd
            if let Err(e2) = ring.submitter().register_files(&[fuse_fd]) {
                error!("Single file registration also failed: {}", e2);
                return Err(e2);
            } else {
                warn!("Only fuse_fd registered successfully");
            }
        } else {
            info!("Both files registered successfully");
        }

        Ok(ring)
    }
    fn prepare_register_sqes(&mut self) -> io::Result<()> {
        info!("Preparing register SQEs for queue {}", self.qid);

        // Prepare SQEs for all entries - following libfuse pattern exactly
        for (idx, entry) in self.entries.iter_mut().enumerate() {
            info!("Preparing SQE {} for queue {}", idx, self.qid);

            // Create the command request data (like libfuse's fuse_uring_sqe_set_req_data)
            let cmd_req = fuse_uring_cmd_req {
                commit_id: 0, // Not used for registration
                qid: self.qid,
                flags: 0,
                _reserved: [0; 16],
            };

            // Set up iovecs like libfuse does
            let iovecs = [
                libc::iovec {
                    iov_base: entry.request_buffer.as_mut_ptr() as *mut c_void,
                    iov_len: entry.request_buffer.len(),
                },
                libc::iovec {
                    iov_base: entry.response_buffer.as_mut_ptr() as *mut c_void,
                    iov_len: entry.response_buffer.len(),
                },
            ];

            debug!(
                "Setting up iovecs: req_buf_len={}, resp_buf_len={}",
                iovecs[0].iov_len, iovecs[1].iov_len
            );

            // Get SQE and prepare it manually like libfuse
            let sqe = self
                .ring
                .submission()
                .available()
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No SQE available"))?;

            // Manual SQE preparation following libfuse exactly
            unsafe {
                // Basic SQE setup
                sqe.set_opcode(io_uring::opcode::UringCmd16::CODE);
                sqe.set_flags(io_uring::squeue::Flags::FIXED_FILE);
                sqe.set_fd(types::Fixed(0)); // FUSE fd is index 0
                sqe.set_user_data(idx as u64);

                // Set command-specific fields
                sqe.set_addr(iovecs.as_ptr() as u64);
                sqe.set_len(2); // Number of iovecs
                sqe.set_rw_flags(0);
                sqe.set_ioprio(0);
                sqe.set_off(0);

                // Set the command op and data
                sqe.set_cmd_op(FUSE_IO_URING_CMD_REGISTER);

                // Copy command data to SQE cmd area
                let cmd_bytes = cmd_req.as_cmd_bytes();
                let sqe_cmd = sqe.cmd_mut();
                sqe_cmd[..cmd_bytes.len()].copy_from_slice(&cmd_bytes);
            }

            debug!("Prepared register SQE {} for queue {}", idx, self.qid);
        }

        // Add event fd polling SQE
        info!("Adding eventfd poll SQE for queue {}", self.qid);
        let poll_sqe = self
            .ring
            .submission()
            .available()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No SQE available for poll"))?;

        unsafe {
            poll_sqe.set_opcode(io_uring::opcode::PollAdd::CODE);
            poll_sqe.set_flags(io_uring::squeue::Flags::FIXED_FILE);
            poll_sqe.set_fd(types::Fixed(1)); // eventfd is index 1
            poll_sqe.set_user_data(u64::MAX);
            poll_sqe.set_poll_events(POLLIN as u32);
        }

        // Submit all SQEs
        info!(
            "Submitting {} SQEs for queue {}",
            self.entries.len() + 1,
            self.qid
        );
        let submitted = self.ring.submit()?;
        info!(
            "Successfully submitted {} SQEs for queue {}",
            submitted, self.qid
        );

        Ok(())
    }

    fn handle_completion(&mut self, user_data: u64, res: i32) -> io::Result<Option<Vec<u8>>> {
        debug!(
            "Handling completion: user_data={}, result={}",
            user_data, res
        );

        if user_data == u64::MAX {
            // Event fd completion - shutdown signal
            if res > 0 {
                info!("Received shutdown signal on eventfd");
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Shutdown signal",
                ));
            }
            debug!("Eventfd completion with res={}", res);
            return Ok(None);
        }

        let entry_idx = user_data as usize;
        if entry_idx >= self.entries.len() {
            error!(
                "Invalid entry index: {} >= {}",
                entry_idx,
                self.entries.len()
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid entry index: {}", entry_idx),
            ));
        }

        if res < 0 {
            let err = io::Error::from_raw_os_error(-res);
            error!(
                "Completion error for entry {}: {} ({})",
                entry_idx, err, res
            );

            if err.kind() == io::ErrorKind::NotConnected {
                info!("Normal unmount completion");
                return Ok(None);
            }
            return Err(err);
        }

        info!(
            "Successful completion for entry {}: {} bytes",
            entry_idx, res
        );

        let entry = &mut self.entries[entry_idx];
        entry.in_use = true;

        // For now, just return dummy data - real implementation would parse FUSE request
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
