#![no_std]
#![allow(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

use core::task::Waker;

pub use xarxa_driver::{
    Capabilities, Checksum, ChecksumCapabilities, Driver, HardwareAddress, LinkState, Medium, PACKET_BUF_SIZE,
    PacketBuf, PacketMeta,
};
#[cfg(feature = "packetmeta-timestamp")]
pub use xarxa_driver::{Timestamp, TxTimestamp};

/// Main `embassy-net` driver API.
///
/// A driver exchanges owned [`PacketBuf`]s with the stack through the
/// [`Driver`] trait: it hands received frames up, takes frames to
/// transmit down, and reports its hardware address and link state. On top
/// of that, this trait adds the one thing `embassy-net` needs to drive it
/// asynchronously: a waker, so the stack task sleeps until the driver has
/// something new.
///
/// Received buffers are allocated by the driver with [`PacketBuf::try_new`].
/// Transmitted buffers are owned by the driver until the hardware is done with
/// them, and dropped then. Dropping is what frees them.
pub trait AsyncDriver: Driver {
    /// Register a waker.
    ///
    /// The driver must wake it when:
    /// - a frame has been received, so [`Driver::receive`] may return `Some`,
    /// - there is room to transmit again, after [`Driver::can_transmit`] returned `false`,
    /// - the link state changed, so [`Driver::link_state`] may return something new.
    ///
    /// Only one waker is kept. Registering another replaces it. Wakes are
    /// allowed to be spurious.
    fn register_waker(&mut self, waker: &Waker);
}

impl<T: ?Sized + AsyncDriver> AsyncDriver for &mut T {
    fn register_waker(&mut self, waker: &Waker) {
        T::register_waker(self, waker)
    }
}
