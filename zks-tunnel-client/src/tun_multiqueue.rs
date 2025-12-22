//! Multi-Queue TUN Device for Linux
//!
//! Enables parallel packet processing across multiple CPU cores.
//! Inspired by BoringTun's `tun_linux.rs` with `IFF_MULTI_QUEUE`.
//!
//! This module is Linux-only and is used for high-performance relay servers.

#![allow(dead_code)]

#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::unix::io::{AsRawFd, RawFd};

/// ioctl request code for setting TUN interface flags
#[cfg(target_os = "linux")]
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

/// TUN device flags
#[cfg(target_os = "linux")]
const IFF_TUN: libc::c_short = 0x0001;
#[cfg(target_os = "linux")]
const IFF_NO_PI: libc::c_short = 0x1000;
#[cfg(target_os = "linux")]
const IFF_MULTI_QUEUE: libc::c_short = 0x0100;

/// ifreq structure for ioctl
#[cfg(target_os = "linux")]
#[repr(C)]
struct Ifreq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_flags: libc::c_short,
    _pad: [u8; 22], // Padding to match kernel struct size
}

/// A single TUN queue (file descriptor)
#[cfg(target_os = "linux")]
pub struct TunQueue {
    fd: RawFd,
}

#[cfg(target_os = "linux")]
impl TunQueue {
    /// Read a packet from this queue
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Write a packet to this queue
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let n = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Set non-blocking mode
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        let flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };

        if unsafe { libc::fcntl(self.fd, libc::F_SETFL, flags) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl AsRawFd for TunQueue {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

#[cfg(target_os = "linux")]
impl Drop for TunQueue {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Multi-Queue TUN device
///
/// Allows multiple threads to read/write to the same TUN interface
/// simultaneously, enabling parallel packet processing.
#[cfg(target_os = "linux")]
pub struct MultiQueueTun {
    name: String,
    queues: Vec<TunQueue>,
}

#[cfg(target_os = "linux")]
impl MultiQueueTun {
    /// Create a new multi-queue TUN device
    ///
    /// # Arguments
    /// * `name` - Interface name (e.g., "zks0")
    /// * `queue_count` - Number of queues (typically = CPU cores)
    ///
    /// # Returns
    /// A multi-queue TUN device with `queue_count` independent queues
    pub fn new(name: &str, queue_count: usize) -> io::Result<Self> {
        if queue_count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Queue count must be at least 1",
            ));
        }

        let mut queues = Vec::with_capacity(queue_count);

        for _ in 0..queue_count {
            let fd = Self::create_queue(name)?;
            queues.push(TunQueue { fd });
        }

        Ok(Self {
            name: name.to_string(),
            queues,
        })
    }

    /// Create a single queue (file descriptor) for the TUN device
    fn create_queue(name: &str) -> io::Result<RawFd> {
        // Open /dev/net/tun
        let fd = unsafe {
            libc::open(
                c"/dev/net/tun".as_ptr(),
                libc::O_RDWR,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Prepare ifreq structure
        let mut ifr = Ifreq {
            ifr_name: [0; libc::IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE,
            _pad: [0; 22],
        };

        // Copy interface name
        let name_bytes = name.as_bytes();
        if name_bytes.len() >= libc::IFNAMSIZ {
            unsafe { libc::close(fd) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Interface name too long",
            ));
        }
        for (i, &b) in name_bytes.iter().enumerate() {
            ifr.ifr_name[i] = b as libc::c_char;
        }

        // Set TUN flags via ioctl
        if unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) } < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }

        Ok(fd)
    }

    /// Get the interface name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the number of queues
    pub fn queue_count(&self) -> usize {
        self.queues.len()
    }

    /// Get a specific queue by index
    ///
    /// # Panics
    /// Panics if index >= queue_count
    pub fn get_queue(&self, index: usize) -> &TunQueue {
        &self.queues[index]
    }

    /// Set non-blocking mode on all queues
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        for queue in &self.queues {
            queue.set_nonblocking(nonblocking)?;
        }
        Ok(())
    }
}

// Stub for non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub struct MultiQueueTun;

#[cfg(not(target_os = "linux"))]
impl MultiQueueTun {
    pub fn new(_name: &str, _queue_count: usize) -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Multi-queue TUN is only supported on Linux",
        ))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    // Note: These tests require root privileges and a real TUN device
    // Run with: sudo cargo test --features vpn tun_multiqueue

    #[test]
    #[ignore] // Requires root
    fn test_create_multiqueue_tun() {
        let tun = MultiQueueTun::new("zkstest0", 2).expect("Failed to create TUN");
        assert_eq!(tun.queue_count(), 2);
        assert_eq!(tun.name(), "zkstest0");
    }
}
