#![no_std]
#![allow(async_fn_in_trait)]
#![allow(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

//! ## Feature flags
#![doc = document_features::document_features!(feature_label = r#"<span class="stab portability"><code>{feature}</code></span>"#)]

#[cfg(not(any(feature = "proto-ipv4", feature = "proto-ipv6")))]
compile_error!("You must enable at least one of the following features: proto-ipv4, proto-ipv6");

#[cfg(not(any(feature = "medium-ethernet", feature = "medium-ip", feature = "medium-ieee802154")))]
compile_error!("You must enable at least one of the following features: medium-ethernet, medium-ip, medium-ieee802154");

// This mod MUST go first, so that the others see its macros.
pub(crate) mod fmt;

#[cfg(feature = "dns")]
pub mod dns;
#[cfg(feature = "raw")]
pub mod raw;
#[cfg(feature = "tcp")]
pub mod tcp;
mod time;
#[cfg(feature = "udp")]
pub mod udp;

use core::cell::RefCell;
use core::future::{Future, poll_fn};
use core::mem::MaybeUninit;
use core::pin::pin;
use core::task::{Context, Poll};

pub use embassy_net_driver as driver;
use embassy_net_driver::{AsyncDriver, Driver, LinkState};
pub use embassy_net_driver::{HardwareAddress, PacketBuf, PacketMeta};
#[cfg(feature = "packetmeta-timestamp")]
pub use embassy_net_driver::{Timestamp, TxTimestamp};
#[cfg(feature = "packetmeta-timestamp")]
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
#[cfg(feature = "packetmeta-timestamp")]
use embassy_sync::channel::Channel;
use embassy_sync::waitqueue::WakerRegistration;
use embassy_time::{Instant, Timer};
use heapless::Vec;
/// The underlying network stack.
///
/// Re-exported for access to the wire types and to the parts of the API that
/// `embassy-net` does not wrap.
pub use xarxa;
#[cfg(feature = "dns")]
pub use xarxa::dns::DNS_MAX_SERVER_COUNT;
#[cfg(feature = "multicast")]
pub use xarxa::iface::MulticastError;
pub use xarxa::iface::{IfaceHandle, MAX_IFACE_COUNT};
use xarxa::iface::AddrOrigin;
use xarxa::route::RouteOrigin;
#[cfg(feature = "medium-ethernet")]
pub use xarxa::wire::EthernetAddress;
#[cfg(feature = "medium-ieee802154")]
pub use xarxa::wire::Ieee802154Address;
pub use xarxa::wire::{IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
#[cfg(feature = "proto-ipv4")]
pub use xarxa::wire::{Ipv4Address, Ipv4Cidr};
#[cfg(feature = "proto-ipv6")]
pub use xarxa::wire::{Ipv6Address, Ipv6Cidr};

use crate::time::{instant_from_xarxa, instant_to_xarxa};

#[cfg(feature = "dhcpv4-hostname")]
const MAX_HOSTNAME_LEN: usize = 32;
/// Most DNS servers kept per IP version in a static configuration.
const MAX_DNS_SERVERS: usize = 3;

/// Error returned by `try_*` socket methods.
///
/// `WouldBlock` indicates the operation would block (e.g. no data available,
/// send buffer full). `Other` wraps the socket-specific error type for any
/// other failure.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TryError<T> {
    /// The operation would block; try again later.
    WouldBlock,
    /// A socket-specific error occurred.
    Other(T),
}

/// Memory resources needed for a network stack.
///
/// The stack holds these for the rest of the program: put them in a `static`
/// (with `StaticCell`), or declare them before the stack.
///
/// This holds only the stack-wide state. The per-interface state, including the
/// driver, lives in [`InterfaceStorage`], one per interface.
///
/// Socket storage is not here either: the stack has a fixed number of socket
/// slots per type, set by the `*-socket-count-N` features of `xarxa`, and the
/// packet buffers come from a global pool sized by `packet-buf-count-N`.
pub struct StackResources {
    inner: MaybeUninit<RefCell<Inner>>,
}

impl StackResources {
    /// Create a new set of stack resources.
    pub const fn new() -> Self {
        Self {
            inner: MaybeUninit::uninit(),
        }
    }
}

impl Default for StackResources {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory resources needed for one network interface.
///
/// This owns the driver. Create one per interface, then hand it to
/// [`Stack::add_interface`], which borrows it for as long as the stack lives.
///
/// The lifetime is the borrow the stack takes: with a `StaticCell` it is
/// `'static`, and with a local it is the enclosing scope. It appears in the type
/// because the interface's `xarxa` driver adapter is stored in here too, next to
/// the driver it wraps.
///
/// ## Example
/// ```ignore
/// static ETH: StaticCell<InterfaceStorage<'static, Device>> = StaticCell::new();
/// let eth = stack.add_interface(ETH.init(InterfaceStorage::new(device)), config);
/// ```
pub struct InterfaceStorage<'d, D> {
    driver: RefCell<D>,
    adapter: MaybeUninit<DriverAdapter<'d, D>>,
    #[cfg(feature = "dhcpv4-hostname")]
    hostname: HostnameResources,
}

impl<'d, D> InterfaceStorage<'d, D> {
    /// Create the resources for an interface over `driver`.
    pub const fn new(driver: D) -> Self {
        Self {
            driver: RefCell::new(driver),
            adapter: MaybeUninit::uninit(),
            #[cfg(feature = "dhcpv4-hostname")]
            hostname: HostnameResources {
                option: MaybeUninit::uninit(),
                data: MaybeUninit::uninit(),
            },
        }
    }
}

#[cfg(feature = "dhcpv4-hostname")]
struct HostnameResources {
    option: MaybeUninit<[xarxa::wire::DhcpOption<'static>; 1]>,
    data: MaybeUninit<[u8; MAX_HOSTNAME_LEN]>,
}

/// Static IP address configuration.
#[cfg(feature = "proto-ipv4")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct StaticConfigV4 {
    /// IP address and subnet mask.
    pub address: Ipv4Cidr,
    /// Default gateway.
    pub gateway: Option<Ipv4Address>,
    /// DNS servers.
    pub dns_servers: Vec<Ipv4Address, MAX_DNS_SERVERS>,
}

/// Static IPv6 address configuration
#[cfg(feature = "proto-ipv6")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct StaticConfigV6 {
    /// IP address and subnet mask.
    pub address: Ipv6Cidr,
    /// Default gateway.
    pub gateway: Option<Ipv6Address>,
    /// DNS servers.
    pub dns_servers: Vec<Ipv6Address, MAX_DNS_SERVERS>,
}

/// DHCP configuration.
#[cfg(feature = "dhcpv4")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub struct DhcpConfig {
    /// Maximum lease duration.
    ///
    /// If not set, the lease duration specified by the server will be used.
    /// If set, the lease duration will be capped at this value.
    pub max_lease_duration: Option<embassy_time::Duration>,
    /// Ignore NAKs from DHCP servers.
    ///
    /// This is not compliant with the DHCP RFCs, since theoretically we must stop using the assigned IP when receiving a NAK. This can increase reliability on broken networks with buggy routers or rogue DHCP servers, however.
    pub ignore_naks: bool,
    /// Our hostname. This will be sent to the DHCP server as Option 12.
    #[cfg(feature = "dhcpv4-hostname")]
    pub hostname: Option<heapless::String<MAX_HOSTNAME_LEN>>,
}

#[cfg(feature = "dhcpv4")]
impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            max_lease_duration: Default::default(),
            ignore_naks: Default::default(),
            #[cfg(feature = "dhcpv4-hostname")]
            hostname: None,
        }
    }
}

/// Network stack configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub struct Config {
    /// IPv4 configuration
    #[cfg(feature = "proto-ipv4")]
    pub ipv4: ConfigV4,
    /// IPv6 configuration
    #[cfg(feature = "proto-ipv6")]
    pub ipv6: ConfigV6,
}

impl Config {
    /// IPv4 configuration with static addressing.
    #[cfg(feature = "proto-ipv4")]
    pub const fn ipv4_static(config: StaticConfigV4) -> Self {
        Self {
            ipv4: ConfigV4::Static(config),
            #[cfg(feature = "proto-ipv6")]
            ipv6: ConfigV6::None,
        }
    }

    /// IPv6 configuration with static addressing.
    #[cfg(feature = "proto-ipv6")]
    pub const fn ipv6_static(config: StaticConfigV6) -> Self {
        Self {
            #[cfg(feature = "proto-ipv4")]
            ipv4: ConfigV4::None,
            ipv6: ConfigV6::Static(config),
        }
    }

    /// IPv4 configuration with dynamic addressing.
    ///
    /// # Example
    /// ```rust,ignore
    /// # use embassy_net::Config;
    /// let _cfg = Config::dhcpv4(Default::default());
    /// ```
    #[cfg(feature = "dhcpv4")]
    pub const fn dhcpv4(config: DhcpConfig) -> Self {
        Self {
            ipv4: ConfigV4::Dhcp(config),
            #[cfg(feature = "proto-ipv6")]
            ipv6: ConfigV6::None,
        }
    }

    /// Slaac configuration with dynamic addressing.
    #[cfg(feature = "slaac")]
    pub const fn slaac() -> Self {
        Self {
            #[cfg(feature = "proto-ipv4")]
            ipv4: ConfigV4::None,
            ipv6: ConfigV6::Slaac,
        }
    }
}

/// Network stack IPv4 configuration.
#[cfg(feature = "proto-ipv4")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ConfigV4 {
    /// Do not configure IPv4.
    #[default]
    None,
    /// Use a static IPv4 address configuration.
    Static(StaticConfigV4),
    /// Use DHCP to obtain an IP address configuration.
    #[cfg(feature = "dhcpv4")]
    Dhcp(DhcpConfig),
}

/// Network stack IPv6 configuration.
#[cfg(feature = "proto-ipv6")]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ConfigV6 {
    /// Do not configure IPv6.
    #[default]
    None,
    /// Use a static IPv6 address configuration.
    Static(StaticConfigV6),
    /// Use SLAAC for IPv6 address configuration.
    #[cfg(feature = "slaac")]
    Slaac,
}

/// Network stack runner.
///
/// You must call [`Runner::run()`] in a background task for the network stack to work.
pub struct Runner<'d> {
    stack: Stack<'d>,
}

/// Network stack handle
///
/// Use this to create sockets and to add interfaces. It's `Copy`, so you can
/// pass it by value instead of by reference.
#[derive(Copy, Clone)]
pub struct Stack<'d> {
    inner: &'d RefCell<Inner>,
}

/// A network interface added to a [`Stack`].
///
/// Returned by [`Stack::add_interface`]. This is the handle for everything that
/// is per-interface rather than stack-wide: the hardware address, the link
/// state, the IP configuration and the multicast groups. It's `Copy`, so you can
/// pass it by value instead of by reference.
#[derive(Copy, Clone)]
pub struct Interface<'d> {
    stack: Stack<'d>,
    handle: IfaceHandle,
    /// Index into `Inner::ifaces`. Interfaces are never removed, so this is stable.
    index: usize,
}

/// The `xarxa` interface over one `embassy-net` driver.
///
/// The driver lives in a `RefCell` in the [`InterfaceStorage`]. This adapter
/// (lent to xarxa as its interface) and `Inner` (for waker registration and link
/// state) both borrow it through the cell, and never hold a borrow across a call
/// into the other; the cell turns any violation of that into a panic instead of
/// undefined behavior.
///
/// The adapter is generic so the driver is reached with a static call: the one
/// dynamic dispatch on the packet path is xarxa's, into the adapter itself.
///
/// The adapter is stored next to the cell it points at, in the same
/// `InterfaceStorage`. `add_interface` takes the storage as a single
/// `&'d mut InterfaceStorage<'d, D>` and splits it into a shared borrow of the
/// driver field and a mutable borrow of the adapter field, which is why the
/// reference here can be an ordinary one.
struct DriverAdapter<'d, D> {
    driver: &'d RefCell<D>,
}

impl<D: AsyncDriver> Driver for DriverAdapter<'_, D> {
    fn capabilities(&self) -> driver::Capabilities {
        self.driver.borrow().capabilities()
    }

    fn hardware_address(&self) -> HardwareAddress {
        self.driver.borrow().hardware_address()
    }

    fn link_state(&mut self) -> LinkState {
        self.driver.borrow_mut().link_state()
    }

    fn receive(&mut self) -> Option<PacketBuf> {
        let buf = self.driver.borrow_mut().receive();
        #[cfg(feature = "packet-trace")]
        if let Some(buf) = &buf {
            trace!("embassy device rx: {:02x}", &buf[..]);
        }
        buf
    }

    fn can_transmit(&mut self) -> bool {
        self.driver.borrow_mut().can_transmit()
    }

    fn transmit(&mut self, buf: PacketBuf) -> Result<(), PacketBuf> {
        #[cfg(feature = "packet-trace")]
        trace!("embassy device tx: {:02x}", &buf[..]);
        self.driver.borrow_mut().transmit(buf)
    }

    #[cfg(feature = "packetmeta-timestamp")]
    fn poll_tx_timestamp(&mut self) -> Option<TxTimestamp> {
        self.driver.borrow_mut().poll_tx_timestamp()
    }
}

/// The `embassy-net` state of one interface, next to xarxa's own.
struct IfaceInner {
    handle: IfaceHandle,
    driver: &'static RefCell<dyn AsyncDriver>, // Lifetime type-erased.
    /// Waker used for waiting for link up or config up.
    state_waker: WakerRegistration,
    link_up: bool,
    /// The interface's configuration generation the last time we looked.
    config_generation: u32,
    #[cfg(feature = "proto-ipv4")]
    config_v4: ConfigV4,
    #[cfg(feature = "proto-ipv6")]
    config_v6: ConfigV6,
    #[cfg(feature = "dhcpv4-hostname")]
    hostname: &'static mut HostnameResources, // Lifetime type-erased.
    #[cfg(feature = "packetmeta-timestamp")]
    timestamps: Channel<NoopRawMutex, TxTimestamp, 5>,
}

pub(crate) struct Inner {
    pub(crate) stack: xarxa::Stack<'static>, // Lifetime type-erased.
    ifaces: Vec<IfaceInner, MAX_IFACE_COUNT>,
    /// Waker used for triggering polls.
    pub(crate) waker: WakerRegistration,
    #[cfg(feature = "dns")]
    pub(crate) dns: xarxa::dns::DnsClient,
    #[cfg(feature = "dns")]
    pub(crate) dns_waker: WakerRegistration,
}

fn _assert_covariant<'a, 'b: 'a>(x: Stack<'b>) -> Stack<'a> {
    x
}

fn _assert_covariant_iface<'a, 'b: 'a>(x: Interface<'b>) -> Interface<'a> {
    x
}

/// Create a new network stack.
///
/// The stack starts out with no interfaces: add them with
/// [`Stack::add_interface`].
///
/// The resources are never dropped: the stack lives for the rest of the program.
pub fn new<'d>(resources: &'d mut StackResources, random_seed: u64) -> (Stack<'d>, Runner<'d>) {
    #[allow(unused_mut)]
    let mut stack = xarxa::Stack::new(random_seed);

    #[cfg(feature = "dns")]
    let dns = unwrap!(xarxa::dns::DnsClient::new(&mut stack, &[]).ok());

    let inner = Inner {
        stack,
        ifaces: Vec::new(),
        waker: WakerRegistration::new(),
        #[cfg(feature = "dns")]
        dns,
        #[cfg(feature = "dns")]
        dns_waker: WakerRegistration::new(),
    };

    let inner = &*resources.inner.write(RefCell::new(inner));
    let stack = Stack { inner };
    (stack, Runner { stack })
}

impl<'d> Stack<'d> {
    /// Borrow the stack, without waking the runner.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        f(&mut self.inner.borrow_mut())
    }

    /// Borrow the stack, and wake the runner afterwards so it processes what
    /// changed.
    pub(crate) fn with_mut<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let mut inner = self.inner.borrow_mut();
        let r = f(&mut inner);
        inner.waker.wake();
        r
    }

    /// Add a network interface to the stack.
    ///
    /// The storage is borrowed for as long as the stack lives, and holds the
    /// driver. Interfaces are never removed.
    ///
    /// # Panics
    ///
    /// Panics if the stack already holds [`MAX_IFACE_COUNT`] interfaces. Raise
    /// the `iface-count-N` feature of `xarxa` to add more.
    pub fn add_interface<D: AsyncDriver + 'd>(
        &self,
        storage: &'d mut InterfaceStorage<'d, D>,
        config: Config,
    ) -> Interface<'d> {
        // Split the storage into disjoint field borrows: the driver cell is
        // shared (the adapter and `Inner` both read it through the cell), the
        // adapter slot and the hostname resources are ours alone.
        let driver: &'d RefCell<D> = &storage.driver;
        let adapter: &'d mut DriverAdapter<'d, D> = storage.adapter.write(DriverAdapter { driver });
        #[cfg(feature = "dhcpv4-hostname")]
        let hostname: &'d mut HostnameResources = &mut storage.hostname;

        // `Inner` has no lifetime parameters, so the references it keeps are
        // lifetime type-erased, like its `stack` field.
        // safety: all of these live in `storage`, which is borrowed for `'d`,
        // and nothing reaches `Inner` past that borrow.
        let driver: &'d RefCell<dyn AsyncDriver + 'd> = driver;
        let driver: &'static RefCell<dyn AsyncDriver + 'static> = unsafe { core::mem::transmute(driver) };
        let adapter: &'d mut (dyn Driver + 'd) = adapter;
        let adapter: &'static mut (dyn Driver + 'static) = unsafe { core::mem::transmute(adapter) };
        #[cfg(feature = "dhcpv4-hostname")]
        let hostname: &'static mut HostnameResources = unsafe { core::mem::transmute(hostname) };

        let index = self.with_mut(|i| {
            let handle = unwrap!(
                i.stack.add_iface_borrowed(adapter).ok(),
                "too many network interfaces, raise the `iface-count-N` feature of xarxa"
            );

            let index = i.ifaces.len();
            unwrap!(
                i.ifaces
                    .push(IfaceInner {
                        handle,
                        driver,
                        state_waker: WakerRegistration::new(),
                        link_up: false,
                        config_generation: 0,
                        #[cfg(feature = "proto-ipv4")]
                        config_v4: ConfigV4::None,
                        #[cfg(feature = "proto-ipv6")]
                        config_v6: ConfigV6::None,
                        #[cfg(feature = "dhcpv4-hostname")]
                        hostname,
                        #[cfg(feature = "packetmeta-timestamp")]
                        timestamps: Channel::new(),
                    })
                    .ok()
            );

            #[cfg(feature = "proto-ipv4")]
            i.set_config_v4(index, config.ipv4);
            #[cfg(feature = "proto-ipv6")]
            i.set_config_v6(index, config.ipv6);
            i.config_changed(index);

            index
        });

        Interface {
            stack: *self,
            handle: self.with(|i| i.ifaces[index].handle),
            index,
        }
    }

    /// Whether any interface has a valid IPv6 configuration.
    #[cfg(all(feature = "proto-ipv6", feature = "dns"))]
    pub(crate) fn any_config_v6(&self) -> bool {
        self.with(|i| {
            for idx in 0..i.ifaces.len() {
                if i.config_v6(idx).is_some() {
                    return true;
                }
            }
            false
        })
    }

    /// Make a query for a given name and return the corresponding IP addresses.
    #[cfg(feature = "dns")]
    pub async fn dns_query(
        &self,
        name: &str,
        qtype: dns::DnsQueryType,
    ) -> Result<Vec<IpAddress, { xarxa::dns::DNS_MAX_RESULT_COUNT }>, dns::Error> {
        // For A and AAAA queries we try detect whether `name` is just an IP address
        match qtype {
            #[cfg(feature = "proto-ipv4")]
            dns::DnsQueryType::A => {
                if let Ok(ip) = name.parse().map(IpAddress::Ipv4) {
                    return Ok([ip].into_iter().collect());
                }
            }
            #[cfg(feature = "proto-ipv6")]
            dns::DnsQueryType::Aaaa => {
                if let Ok(ip) = name.parse().map(IpAddress::Ipv6) {
                    return Ok([ip].into_iter().collect());
                }
            }
            _ => {}
        }

        let query = poll_fn(|cx| {
            self.with_mut(|i| {
                let Inner {
                    stack, dns, dns_waker, ..
                } = i;
                match dns.start_query(stack, name, qtype) {
                    Ok(handle) => Poll::Ready(Ok::<_, dns::Error>(handle)),
                    Err(xarxa::dns::StartQueryError::NoFreeSlot) => {
                        dns_waker.register(cx.waker());
                        Poll::Pending
                    }
                    Err(e) => Poll::Ready(Err(e.into())),
                }
            })
        })
        .await?;

        #[must_use = "to delay the drop handler invocation to the end of the scope"]
        struct OnDrop<F: FnOnce()> {
            f: core::mem::MaybeUninit<F>,
        }

        impl<F: FnOnce()> OnDrop<F> {
            fn new(f: F) -> Self {
                Self {
                    f: core::mem::MaybeUninit::new(f),
                }
            }

            fn defuse(self) {
                core::mem::forget(self)
            }
        }

        impl<F: FnOnce()> Drop for OnDrop<F> {
            fn drop(&mut self) {
                unsafe { self.f.as_ptr().read()() }
            }
        }

        let drop = OnDrop::new(|| {
            self.with_mut(|i| {
                i.dns.cancel_query(query);
                i.dns_waker.wake();
            })
        });

        let res = poll_fn(|cx| {
            self.with_mut(|i| match i.dns.get_query_result(query) {
                Ok(addrs) => {
                    i.dns_waker.wake();
                    Poll::Ready(Ok(addrs))
                }
                Err(xarxa::dns::GetQueryResultError::Pending) => {
                    i.dns.register_query_waker(query, cx.waker());
                    Poll::Pending
                }
                Err(e) => {
                    i.dns_waker.wake();
                    Poll::Ready(Err(e.into()))
                }
            })
        })
        .await;

        drop.defuse();

        res
    }
}

impl<'d> Interface<'d> {
    /// The stack this interface belongs to.
    pub fn stack(&self) -> Stack<'d> {
        self.stack
    }

    /// This interface's `xarxa` handle, for the parts of the `xarxa` API that
    /// `embassy-net` does not wrap.
    pub fn handle(&self) -> IfaceHandle {
        self.handle
    }

    /// Borrow the interface's state, without waking the runner.
    fn with<R>(&self, f: impl FnOnce(&mut Inner, usize) -> R) -> R {
        self.stack.with(|i| f(i, self.index))
    }

    /// Borrow the interface's state, and wake the runner afterwards so it
    /// processes what changed.
    fn with_mut<R>(&self, f: impl FnOnce(&mut Inner, usize) -> R) -> R {
        self.stack.with_mut(|i| f(i, self.index))
    }

    /// Get the hardware address of the network interface.
    pub fn hardware_address(&self) -> xarxa::wire::HardwareAddress {
        self.with(|i, idx| {
            let handle = i.ifaces[idx].handle;
            i.stack.iface(handle).hardware_addr()
        })
    }

    /// Check whether the link is up.
    pub fn is_link_up(&self) -> bool {
        self.with(|i, idx| i.ifaces[idx].link_up)
    }

    /// Check whether the interface has a valid IP configuration.
    ///
    /// This is true if the interface has a static IP configuration, or if DHCP
    /// or SLAAC has completed.
    pub fn is_config_up(&self) -> bool {
        let v4_up;
        let v6_up;

        #[cfg(feature = "proto-ipv4")]
        {
            v4_up = self.config_v4().is_some();
        }
        #[cfg(not(feature = "proto-ipv4"))]
        {
            v4_up = false;
        }

        #[cfg(feature = "proto-ipv6")]
        {
            v6_up = self.config_v6().is_some();
        }
        #[cfg(not(feature = "proto-ipv6"))]
        {
            v6_up = false;
        }

        v4_up || v6_up
    }

    #[cfg(feature = "packetmeta-timestamp")]
    /// Poll tx timestamps
    pub async fn poll_tx_timestamps(&self) -> TxTimestamp {
        poll_fn(|cx| self.with(|i, idx| i.ifaces[idx].timestamps.poll_receive(cx))).await
    }

    /// Wait for the network device to obtain a link signal.
    pub async fn wait_link_up(&self) {
        self.wait(|| self.is_link_up()).await
    }

    /// Wait for the network device to lose link signal.
    pub async fn wait_link_down(&self) {
        self.wait(|| !self.is_link_up()).await
    }

    /// Wait for the interface to obtain a valid IP configuration.
    ///
    /// ## Notes:
    /// - Ensure [`Runner::run`] has been started before using this function.
    ///
    /// - This function may never return (e.g. if no configuration is obtained through DHCP).
    /// The caller is supposed to handle a timeout for this case.
    ///
    /// ## Example
    /// ```ignore
    /// // Init network stack
    /// static RESOURCES: StaticCell<embassy_net::StackResources> = StaticCell::new();
    /// let (stack, runner) = embassy_net::new(RESOURCES.init(embassy_net::StackResources::new()), seed);
    /// // Add an interface over the driver
    /// static ETH: StaticCell<embassy_net::InterfaceStorage<'static, Device>> = StaticCell::new();
    /// let config = embassy_net::Config::dhcpv4(Default::default());
    /// let eth = stack.add_interface(ETH.init(embassy_net::InterfaceStorage::new(driver)), config);
    /// // Launch network task that runs `runner.run().await`
    /// spawner.spawn(net_task(runner).unwrap());
    /// // Wait for DHCP config
    /// eth.wait_config_up().await;
    /// // use the network stack
    /// // ...
    /// ```
    pub async fn wait_config_up(&self) {
        self.wait(|| self.is_config_up()).await
    }

    /// Wait for the interface to lose a valid IP configuration.
    pub async fn wait_config_down(&self) {
        self.wait(|| !self.is_config_up()).await
    }

    fn wait<'a>(&'a self, mut predicate: impl FnMut() -> bool + 'a) -> impl Future<Output = ()> + 'a {
        poll_fn(move |cx| {
            if predicate() {
                Poll::Ready(())
            } else {
                // If the config is not up, we register a waker that is woken up
                // when a config is applied (static, slaac or DHCP).
                trace!("Waiting for config up");

                self.with(|i, idx| {
                    i.ifaces[idx].state_waker.register(cx.waker());
                });

                Poll::Pending
            }
        })
    }

    /// Get the current IPv4 configuration.
    ///
    /// If using DHCP, this will be None if DHCP hasn't been able to
    /// acquire an IP address, or Some if it has.
    #[cfg(feature = "proto-ipv4")]
    pub fn config_v4(&self) -> Option<StaticConfigV4> {
        self.with(|i, idx| i.config_v4(idx))
    }

    /// Get the current IPv6 configuration.
    #[cfg(feature = "proto-ipv6")]
    pub fn config_v6(&self) -> Option<StaticConfigV6> {
        self.with(|i, idx| i.config_v6(idx))
    }

    /// Set the IPv4 configuration.
    #[cfg(feature = "proto-ipv4")]
    pub fn set_config_v4(&self, config: ConfigV4) {
        self.with_mut(|i, idx| {
            i.set_config_v4(idx, config);
            i.config_changed(idx);
        })
    }

    /// Set the IPv6 configuration.
    #[cfg(feature = "proto-ipv6")]
    pub fn set_config_v6(&self, config: ConfigV6) {
        self.with_mut(|i, idx| {
            i.set_config_v6(idx, config);
            i.config_changed(idx);
        })
    }
}

#[cfg(feature = "multicast")]
impl<'d> Interface<'d> {
    /// Join a multicast group.
    pub fn join_multicast_group(&self, addr: impl Into<IpAddress>) -> Result<(), MulticastError> {
        self.with_mut(|i, idx| {
            let handle = i.ifaces[idx].handle;
            i.stack.iface(handle).join_multicast_group(addr)
        })
    }

    /// Leave a multicast group.
    pub fn leave_multicast_group(&self, addr: impl Into<IpAddress>) -> Result<(), MulticastError> {
        self.with_mut(|i, idx| {
            let handle = i.ifaces[idx].handle;
            i.stack.iface(handle).leave_multicast_group(addr)
        })
    }

    /// Get whether the interface has joined the given multicast group.
    pub fn has_multicast_group(&self, addr: impl Into<IpAddress>) -> bool {
        self.with(|i, idx| {
            let handle = i.ifaces[idx].handle;
            i.stack.iface(handle).has_multicast_group(addr)
        })
    }
}

impl Inner {
    #[cfg(feature = "proto-ipv4")]
    fn config_v4(&mut self, idx: usize) -> Option<StaticConfigV4> {
        let handle = self.ifaces[idx].handle;
        let iface = self.stack.iface(handle);
        let address = iface.ip_addrs().iter().find_map(|a| match a.cidr {
            IpCidr::Ipv4(cidr) => Some(cidr),
            #[allow(unreachable_patterns)]
            _ => None,
        })?;
        let dns_servers = match &self.ifaces[idx].config_v4 {
            ConfigV4::Static(c) => c.dns_servers.clone(),
            #[cfg(feature = "dhcpv4")]
            ConfigV4::Dhcp(_) => iface
                .dhcpv4_lease()
                .map(|lease| lease.dns_servers.iter().copied().take(MAX_DNS_SERVERS).collect())
                .unwrap_or_default(),
            ConfigV4::None => Vec::new(),
        };
        let gateway = self
            .stack
            .routes()
            .get_default_ipv4_route()
            // The stack keeps a single default route; report it only for the
            // interface it goes out of.
            .filter(|r| r.iface == handle)
            .and_then(|r| match r.via_router {
                IpAddress::Ipv4(gateway) => Some(gateway),
                #[allow(unreachable_patterns)]
                _ => None,
            });
        Some(StaticConfigV4 {
            address,
            gateway,
            dns_servers,
        })
    }

    #[cfg(feature = "proto-ipv6")]
    fn config_v6(&mut self, idx: usize) -> Option<StaticConfigV6> {
        let handle = self.ifaces[idx].handle;
        let iface = self.stack.iface(handle);
        let address = iface.ip_addrs().iter().find_map(|a| match (a.cidr, a.origin) {
            // The link-local address the stack derives from the hardware address is not part
            // of the reported config.
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            (_, AddrOrigin::LinkLocal) => None,
            (IpCidr::Ipv6(cidr), _) => Some(cidr),
            #[allow(unreachable_patterns)]
            _ => None,
        })?;
        let dns_servers = match &self.ifaces[idx].config_v6 {
            ConfigV6::Static(c) => c.dns_servers.clone(),
            _ => Vec::new(), // RDNSS not (yet) supported by xarxa.
        };
        let gateway = self
            .stack
            .routes()
            .get_default_ipv6_route()
            // The stack keeps a single default route; report it only for the
            // interface it goes out of.
            .filter(|r| r.iface == handle)
            .and_then(|r| match r.via_router {
                IpAddress::Ipv6(gateway) => Some(gateway),
                #[allow(unreachable_patterns)]
                _ => None,
            });
        Some(StaticConfigV6 {
            address,
            gateway,
            dns_servers,
        })
    }

    /// Remove one interface's manually assigned addresses of one IP version, and
    /// its manual default route.
    fn clear_manual_config(&mut self, idx: usize, v4: bool) {
        let handle = self.ifaces[idx].handle;
        let mut iface = self.stack.iface(handle);
        loop {
            let addr = iface.ip_addrs().iter().find_map(|a| {
                let matches_version = match a.cidr {
                    #[cfg(feature = "proto-ipv4")]
                    IpCidr::Ipv4(_) => v4,
                    #[cfg(feature = "proto-ipv6")]
                    IpCidr::Ipv6(_) => !v4,
                };
                (a.origin == AddrOrigin::Manual && matches_version).then_some(a.cidr.address())
            });
            match addr {
                Some(addr) => {
                    iface.remove_ip_addr(addr);
                }
                None => break,
            }
        }
        self.stack.routes_mut().retain(|r| {
            let matches_version = match r.via_router {
                #[cfg(feature = "proto-ipv4")]
                IpAddress::Ipv4(_) => v4,
                #[cfg(feature = "proto-ipv6")]
                IpAddress::Ipv6(_) => !v4,
            };
            !(matches_version && r.iface == handle && r.origin == RouteOrigin::Manual)
        });
    }

    #[cfg(feature = "proto-ipv4")]
    pub fn set_config_v4(&mut self, idx: usize, config: ConfigV4) {
        let handle = self.ifaces[idx].handle;
        #[cfg(feature = "dhcpv4")]
        self.stack.iface(handle).set_dhcpv4(None);
        self.clear_manual_config(idx, true);

        match &config {
            ConfigV4::None => {}
            ConfigV4::Static(c) => {
                unwrap!(self.stack.iface(handle).add_ip_addr(IpCidr::Ipv4(c.address)).ok());
                if let Some(gateway) = c.gateway {
                    unwrap!(self.stack.routes_mut().add_default_ipv4_route(gateway, handle).ok());
                }
            }
            #[cfg(feature = "dhcpv4")]
            ConfigV4::Dhcp(c) => {
                let mut cfg = xarxa::iface::dhcpv4::DhcpConfig::default();
                cfg.max_lease_duration = c.max_lease_duration.map(crate::time::duration_to_xarxa);
                cfg.ignore_naks = c.ignore_naks;

                #[cfg(feature = "dhcpv4-hostname")]
                if let Some(h) = &c.hostname {
                    // The previous DHCP client was just removed, so nothing holds a
                    // reference to the old option.
                    let hostname = &mut *self.ifaces[idx].hostname;

                    // create data
                    let data = hostname.data.write([0; MAX_HOSTNAME_LEN]);
                    data[..h.len()].copy_from_slice(h.as_bytes());
                    let data: &[u8] = &data[..h.len()];
                    // safety: the hostname resources live in the `InterfaceStorage`, borrowed
                    // for as long as the stack exists. Therefore it's OK to pass a `'static`
                    // reference to xarxa.
                    let data: &'static [u8] = unsafe { core::mem::transmute(data) };

                    // set the option.
                    let option = hostname.option.write([xarxa::wire::DhcpOption { data, kind: 12 }]);
                    let option: &'static [xarxa::wire::DhcpOption<'static>] =
                        unsafe { core::mem::transmute(&option[..]) };
                    cfg.outgoing_options = option;
                }

                self.stack.iface(handle).set_dhcpv4(Some(cfg));
            }
        }

        self.ifaces[idx].config_v4 = config;
    }

    #[cfg(feature = "proto-ipv6")]
    pub fn set_config_v6(&mut self, idx: usize, config: ConfigV6) {
        let handle = self.ifaces[idx].handle;
        #[cfg(feature = "slaac")]
        self.stack.iface(handle).set_slaac(None);
        self.clear_manual_config(idx, false);

        match &config {
            ConfigV6::None => {}
            ConfigV6::Static(c) => {
                unwrap!(self.stack.iface(handle).add_ip_addr(IpCidr::Ipv6(c.address)).ok());
                if let Some(gateway) = c.gateway {
                    unwrap!(self.stack.routes_mut().add_default_ipv6_route(gateway, handle).ok());
                }
            }
            #[cfg(feature = "slaac")]
            ConfigV6::Slaac => {
                self.stack
                    .iface(handle)
                    .set_slaac(Some(xarxa::iface::slaac::SlaacConfig::default()));
            }
        }

        self.ifaces[idx].config_v6 = config;
    }

    /// React to a change in one interface's configuration: log it, refresh the
    /// DNS server list, and wake whoever waits for the configuration.
    fn config_changed(&mut self, idx: usize) {
        let handle = self.ifaces[idx].handle;
        self.ifaces[idx].config_generation = self.stack.iface(handle).config_generation();

        #[cfg(feature = "proto-ipv4")]
        if let Some(config) = self.config_v4(idx) {
            info!("iface {}: IPv4: UP", idx);
            info!("   IP address:      {:?}", config.address);
            info!("   Default gateway: {:?}", config.gateway);
            for s in &config.dns_servers {
                info!("   DNS server:      {:?}", s);
            }
        } else {
            info!("iface {}: IPv4: DOWN", idx);
        }

        #[cfg(feature = "proto-ipv6")]
        if let Some(config) = self.config_v6(idx) {
            info!("iface {}: IPv6: UP", idx);
            info!("   IP address:      {:?}", config.address);
            info!("   Default gateway: {:?}", config.gateway);
            for s in &config.dns_servers {
                info!("   DNS server:      {:?}", s);
            }
        } else {
            info!("iface {}: IPv6: DOWN", idx);
        }

        #[cfg(feature = "dns")]
        self.update_dns_servers();

        self.ifaces[idx].state_waker.wake();
    }

    /// Hand the DNS client the servers of every interface, in interface order.
    #[cfg(feature = "dns")]
    fn update_dns_servers(&mut self) {
        let mut dns_servers: Vec<IpAddress, DNS_MAX_SERVER_COUNT> = Vec::new();
        let mut truncated = false;

        for idx in 0..self.ifaces.len() {
            #[cfg(feature = "proto-ipv4")]
            if let Some(config) = self.config_v4(idx) {
                for s in &config.dns_servers {
                    truncated |= dns_servers.push((*s).into()).is_err();
                }
            }

            #[cfg(feature = "proto-ipv6")]
            if let Some(config) = self.config_v6(idx) {
                for s in &config.dns_servers {
                    truncated |= dns_servers.push((*s).into()).is_err();
                }
            }
        }

        if truncated {
            warn!("Number of DNS servers exceeds DNS_MAX_SERVER_COUNT, truncating list.");
        }

        self.dns.update_servers(&dns_servers);
    }

    fn poll(&mut self, cx: &mut Context<'_>) {
        self.waker.register(cx.waker());

        for idx in 0..self.ifaces.len() {
            let link_up = {
                // Not held across the stack poll below.
                let mut driver = self.ifaces[idx].driver.borrow_mut();
                driver.register_waker(cx.waker());
                driver.link_state() == LinkState::Up
            };

            // Update link up
            let old_link_up = self.ifaces[idx].link_up;
            self.ifaces[idx].link_up = link_up;

            // Print when changed
            if old_link_up != link_up {
                info!("iface {}: link_up = {:?}", idx, link_up);
                self.ifaces[idx].state_waker.wake();

                // Start over on link-state change, so a lease on the previous network is
                // not kept, and a new one is obtained right away.
                #[cfg(feature = "dhcpv4")]
                {
                    let handle = self.ifaces[idx].handle;
                    self.stack.iface(handle).restart_dhcpv4();
                }
            }
        }

        #[cfg(feature = "packetmeta-timestamp")]
        for idx in 0..self.ifaces.len() {
            let handle = self.ifaces[idx].handle;
            while !self.ifaces[idx].timestamps.is_full()
                && let Some(timestamp) = self.stack.iface(handle).poll_tx_timestamp()
            {
                self.ifaces[idx].timestamps.try_send(timestamp).unwrap();
            }
            if self.ifaces[idx].timestamps.is_full() {
                let _ = self.ifaces[idx].timestamps.poll_ready_to_send(cx);
                warn!("iface {} is stalled because timestamp channel is full.", idx);
                return;
            }
        }

        let now = instant_to_xarxa(Instant::now());
        #[allow(unused_mut)]
        let mut deadline = self.stack.poll(now);

        #[cfg(feature = "dns")]
        {
            deadline = deadline.min(self.dns.poll(&mut self.stack));
        }

        for idx in 0..self.ifaces.len() {
            let handle = self.ifaces[idx].handle;
            if self.stack.iface(handle).config_generation() != self.ifaces[idx].config_generation {
                self.config_changed(idx);
            }
        }

        if deadline <= now {
            cx.waker().wake_by_ref();
        } else if deadline != xarxa::time::Instant::MAX {
            let t = pin!(Timer::at(instant_from_xarxa(deadline)));
            if t.poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
    }
}

impl<'d> Runner<'d> {
    /// Run the network stack.
    ///
    /// You must call this in a background task, to process network events.
    pub async fn run(&mut self) -> ! {
        poll_fn(|cx| {
            self.stack.with(|i| i.poll(cx));
            Poll::<()>::Pending
        })
        .await;
        unreachable!()
    }
}
