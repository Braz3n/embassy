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
use xarxa::iface::{AddrOrigin, IfaceHandle};
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
/// `D` is the driver type. The stack holds the driver in here, so the
/// resources must outlive the stack: put them in a `static` (with
/// `StaticCell`), or declare them before the stack.
///
/// Socket storage is not here: the stack has a fixed number of socket slots per
/// type, set by the `*-socket-count-N` features of `xarxa`, and the packet
/// buffers come from a global pool sized by `packet-buf-count-N`.
pub struct StackResources<D> {
    inner: MaybeUninit<RefCell<Inner>>,
    driver: MaybeUninit<RefCell<D>>,
    adapter: MaybeUninit<DriverAdapter<D>>,
    #[cfg(feature = "dhcpv4-hostname")]
    hostname: HostnameResources,
}

#[cfg(feature = "dhcpv4-hostname")]
struct HostnameResources {
    option: MaybeUninit<[xarxa::wire::DhcpOption<'static>; 1]>,
    data: MaybeUninit<[u8; MAX_HOSTNAME_LEN]>,
}

impl<D> StackResources<D> {
    /// Create a new set of stack resources.
    pub const fn new() -> Self {
        Self {
            inner: MaybeUninit::uninit(),
            driver: MaybeUninit::uninit(),
            adapter: MaybeUninit::uninit(),
            #[cfg(feature = "dhcpv4-hostname")]
            hostname: HostnameResources {
                option: MaybeUninit::uninit(),
                data: MaybeUninit::uninit(),
            },
        }
    }
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
/// Use this to create sockets. It's `Copy`, so you can pass
/// it by value instead of by reference.
#[derive(Copy, Clone)]
pub struct Stack<'d> {
    inner: &'d RefCell<Inner>,
}

/// The `xarxa` interface over the `embassy-net` driver.
///
/// The driver lives in a `RefCell` in the `StackResources`. This adapter (lent
/// to xarxa as its interface) and `Inner` (for waker registration and link
/// state) both borrow it through the cell, and never hold a borrow across a
/// call into the other; the cell turns any violation of that into a panic
/// instead of undefined behavior.
///
/// The adapter is generic so the driver is reached with a static call: the one
/// dynamic dispatch on the packet path is xarxa's, into the adapter itself.
///
/// The pointer to the cell is raw only to erase lifetimes: a reference field
/// would force either a lifetime parameter on `StackResources` (making the
/// resources permanently borrowed, so a stack could never be torn down and
/// rebuilt) or a `D: 'static` bound. It is shared, never aliased mutably.
struct DriverAdapter<D> {
    driver: *const RefCell<D>,
}

impl<D: AsyncDriver> DriverAdapter<D> {
    fn driver(&self) -> &RefCell<D> {
        // safety: the cell and the adapter both live in the `StackResources`,
        // and the adapter is only reachable (through the stack in those same
        // resources) while `new()`'s borrow of the resources is alive.
        unsafe { &*self.driver }
    }
}

impl<D: AsyncDriver> Driver for DriverAdapter<D> {
    fn capabilities(&self) -> driver::Capabilities {
        self.driver().borrow().capabilities()
    }

    fn hardware_address(&self) -> HardwareAddress {
        self.driver().borrow().hardware_address()
    }

    fn link_state(&mut self) -> LinkState {
        self.driver().borrow_mut().link_state()
    }

    fn receive(&mut self) -> Option<PacketBuf> {
        let buf = self.driver().borrow_mut().receive();
        #[cfg(feature = "packet-trace")]
        if let Some(buf) = &buf {
            trace!("embassy device rx: {:02x}", &buf[..]);
        }
        buf
    }

    fn can_transmit(&mut self) -> bool {
        self.driver().borrow_mut().can_transmit()
    }

    fn transmit(&mut self, buf: PacketBuf) -> Result<(), PacketBuf> {
        #[cfg(feature = "packet-trace")]
        trace!("embassy device tx: {:02x}", &buf[..]);
        self.driver().borrow_mut().transmit(buf)
    }

    #[cfg(feature = "packetmeta-timestamp")]
    fn poll_tx_timestamp(&mut self) -> Option<TxTimestamp> {
        self.driver().borrow_mut().poll_tx_timestamp()
    }
}

pub(crate) struct Inner {
    pub(crate) stack: xarxa::Stack<'static>, // Lifetime type-erased.
    pub(crate) iface: IfaceHandle,
    driver: &'static RefCell<dyn AsyncDriver>, // Lifetime type-erased.
    /// Waker used for triggering polls.
    pub(crate) waker: WakerRegistration,
    /// Waker used for waiting for link up or config up.
    state_waker: WakerRegistration,
    link_up: bool,
    /// The interface's configuration generation the last time we looked.
    config_generation: u32,
    #[cfg(feature = "proto-ipv4")]
    config_v4: ConfigV4,
    #[cfg(feature = "proto-ipv6")]
    config_v6: ConfigV6,
    #[cfg(feature = "dns")]
    pub(crate) dns: xarxa::dns::DnsClient,
    #[cfg(feature = "dns")]
    pub(crate) dns_waker: WakerRegistration,
    #[cfg(feature = "dhcpv4-hostname")]
    hostname: *mut HostnameResources,
    #[cfg(feature = "packetmeta-timestamp")]
    timestamps: Channel<NoopRawMutex, TxTimestamp, 5>,
}

fn _assert_covariant<'a, 'b: 'a>(x: Stack<'b>) -> Stack<'a> {
    x
}

/// Create a new network stack.
///
/// The driver is moved into `resources`, and never dropped: the stack lives
/// for the rest of the program.
pub fn new<'d, D: AsyncDriver + 'd>(
    driver: D,
    config: Config,
    resources: &'d mut StackResources<D>,
    random_seed: u64,
) -> (Stack<'d>, Runner<'d>) {
    let driver: &'d RefCell<D> = resources.driver.write(RefCell::new(driver));
    let adapter: &'d mut DriverAdapter<D> = resources.adapter.write(DriverAdapter { driver });

    // `Inner` has no lifetime parameters, so the references it keeps are
    // lifetime type-erased, like its `stack` field.
    // safety: the cell and `Inner` both live in `resources`, which `new()`
    // borrows for `'d`; nothing reaches `Inner` past that borrow.
    let driver: &'d RefCell<dyn AsyncDriver + 'd> = driver;
    let driver: &'static RefCell<dyn AsyncDriver + 'static> = unsafe { core::mem::transmute(driver) };
    let adapter: &'d mut (dyn Driver + 'd) = adapter;
    let adapter: &'static mut (dyn Driver + 'static) = unsafe { core::mem::transmute(adapter) };

    let mut stack = xarxa::Stack::new(random_seed);
    let iface = unwrap!(stack.add_iface_borrowed(adapter).ok());

    #[cfg(feature = "dns")]
    let dns = unwrap!(xarxa::dns::DnsClient::new(&mut stack, &[]).ok());

    let mut inner = Inner {
        stack,
        iface,
        driver,
        waker: WakerRegistration::new(),
        state_waker: WakerRegistration::new(),
        link_up: false,
        config_generation: 0,
        #[cfg(feature = "proto-ipv4")]
        config_v4: ConfigV4::None,
        #[cfg(feature = "proto-ipv6")]
        config_v6: ConfigV6::None,
        #[cfg(feature = "dns")]
        dns,
        #[cfg(feature = "dns")]
        dns_waker: WakerRegistration::new(),
        #[cfg(feature = "dhcpv4-hostname")]
        hostname: &mut resources.hostname,
        #[cfg(feature = "packetmeta-timestamp")]
        timestamps: Channel::new(),
    };

    #[cfg(feature = "proto-ipv4")]
    inner.set_config_v4(config.ipv4);
    #[cfg(feature = "proto-ipv6")]
    inner.set_config_v6(config.ipv6);
    inner.config_changed();

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

    /// Get the hardware address of the network interface.
    pub fn hardware_address(&self) -> xarxa::wire::HardwareAddress {
        self.with(|i| i.stack.iface(i.iface).hardware_addr())
    }

    /// Check whether the link is up.
    pub fn is_link_up(&self) -> bool {
        self.with(|i| i.link_up)
    }

    /// Check whether the network stack has a valid IP configuration.
    /// This is true if the network stack has a static IP configuration or if DHCP has completed
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
        poll_fn(|cx| self.with(|i| i.timestamps.poll_receive(cx))).await
    }

    /// Wait for the network device to obtain a link signal.
    pub async fn wait_link_up(&self) {
        self.wait(|| self.is_link_up()).await
    }

    /// Wait for the network device to lose link signal.
    pub async fn wait_link_down(&self) {
        self.wait(|| !self.is_link_up()).await
    }

    /// Wait for the network stack to obtain a valid IP configuration.
    ///
    /// ## Notes:
    /// - Ensure [`Runner::run`] has been started before using this function.
    ///
    /// - This function may never return (e.g. if no configuration is obtained through DHCP).
    /// The caller is supposed to handle a timeout for this case.
    ///
    /// ## Example
    /// ```ignore
    /// let config = embassy_net::Config::dhcpv4(Default::default());
    /// // Init network stack
    /// static RESOURCES: StaticCell<embassy_net::StackResources<Device>> = StaticCell::new();
    /// let (stack, runner) = embassy_net::new(
    ///    driver,
    ///    config,
    ///    RESOURCES.init(embassy_net::StackResources::new()),
    ///    seed
    /// );
    /// // Launch network task that runs `runner.run().await`
    /// spawner.spawn(net_task(runner).unwrap());
    /// // Wait for DHCP config
    /// stack.wait_config_up().await;
    /// // use the network stack
    /// // ...
    /// ```
    pub async fn wait_config_up(&self) {
        self.wait(|| self.is_config_up()).await
    }

    /// Wait for the network stack to lose a valid IP configuration.
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

                self.with(|i| {
                    i.state_waker.register(cx.waker());
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
        self.with(|i| i.config_v4())
    }

    /// Get the current IPv6 configuration.
    #[cfg(feature = "proto-ipv6")]
    pub fn config_v6(&self) -> Option<StaticConfigV6> {
        self.with(|i| i.config_v6())
    }

    /// Set the IPv4 configuration.
    #[cfg(feature = "proto-ipv4")]
    pub fn set_config_v4(&self, config: ConfigV4) {
        self.with_mut(|i| {
            i.set_config_v4(config);
            i.config_changed();
        })
    }

    /// Set the IPv6 configuration.
    #[cfg(feature = "proto-ipv6")]
    pub fn set_config_v6(&self, config: ConfigV6) {
        self.with_mut(|i| {
            i.set_config_v6(config);
            i.config_changed();
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

#[cfg(feature = "multicast")]
impl<'d> Stack<'d> {
    /// Join a multicast group.
    pub fn join_multicast_group(&self, addr: impl Into<IpAddress>) -> Result<(), MulticastError> {
        self.with_mut(|i| i.stack.iface(i.iface).join_multicast_group(addr))
    }

    /// Leave a multicast group.
    pub fn leave_multicast_group(&self, addr: impl Into<IpAddress>) -> Result<(), MulticastError> {
        self.with_mut(|i| i.stack.iface(i.iface).leave_multicast_group(addr))
    }

    /// Get whether the network stack has joined the given multicast group.
    pub fn has_multicast_group(&self, addr: impl Into<IpAddress>) -> bool {
        self.with(|i| i.stack.iface(i.iface).has_multicast_group(addr))
    }
}

impl Inner {
    #[cfg(feature = "proto-ipv4")]
    fn config_v4(&mut self) -> Option<StaticConfigV4> {
        let handle = self.iface;
        let iface = self.stack.iface(handle);
        let address = iface.ip_addrs().iter().find_map(|a| match a.cidr {
            IpCidr::Ipv4(cidr) => Some(cidr),
            #[allow(unreachable_patterns)]
            _ => None,
        })?;
        let dns_servers = match &self.config_v4 {
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
    fn config_v6(&mut self) -> Option<StaticConfigV6> {
        let handle = self.iface;
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
        let dns_servers = match &self.config_v6 {
            ConfigV6::Static(c) => c.dns_servers.clone(),
            _ => Vec::new(), // RDNSS not (yet) supported by xarxa.
        };
        let gateway = self
            .stack
            .routes()
            .get_default_ipv6_route()
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

    /// Remove the manually assigned addresses of one IP version, and the manual
    /// default route.
    fn clear_manual_config(&mut self, v4: bool) {
        let handle = self.iface;
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
            !(matches_version && r.origin == RouteOrigin::Manual)
        });
    }

    #[cfg(feature = "proto-ipv4")]
    pub fn set_config_v4(&mut self, config: ConfigV4) {
        let handle = self.iface;
        #[cfg(feature = "dhcpv4")]
        self.stack.iface(handle).set_dhcpv4(None);
        self.clear_manual_config(true);

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
                    // safety:
                    // - the previous DHCP client was just removed, so nothing holds a reference
                    //   to the old option.
                    // - the pointer lives for as long as the stack exists, because `new()` borrows
                    //   the resources for `'d`. Therefore it's OK to pass a `'static` reference to xarxa.
                    let hostname = unsafe { &mut *self.hostname };

                    // create data
                    let data = hostname.data.write([0; MAX_HOSTNAME_LEN]);
                    data[..h.len()].copy_from_slice(h.as_bytes());
                    let data: &[u8] = &data[..h.len()];
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

        self.config_v4 = config;
    }

    #[cfg(feature = "proto-ipv6")]
    pub fn set_config_v6(&mut self, config: ConfigV6) {
        let handle = self.iface;
        #[cfg(feature = "slaac")]
        self.stack.iface(handle).set_slaac(None);
        self.clear_manual_config(false);

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

        self.config_v6 = config;
    }

    /// React to a change in the interface's configuration: log it, hand the DNS
    /// servers to the DNS client, and wake whoever waits for the configuration.
    fn config_changed(&mut self) {
        self.config_generation = self.stack.iface(self.iface).config_generation();

        #[cfg(feature = "dns")]
        let mut dns_servers: Vec<IpAddress, { 2 * MAX_DNS_SERVERS }> = Vec::new();

        #[cfg(feature = "proto-ipv4")]
        if let Some(config) = self.config_v4() {
            info!("IPv4: UP");
            info!("   IP address:      {:?}", config.address);
            info!("   Default gateway: {:?}", config.gateway);
            for s in &config.dns_servers {
                info!("   DNS server:      {:?}", s);
                #[cfg(feature = "dns")]
                unwrap!(dns_servers.push((*s).into()).ok());
            }
        } else {
            info!("IPv4: DOWN");
        }

        #[cfg(feature = "proto-ipv6")]
        if let Some(config) = self.config_v6() {
            info!("IPv6: UP");
            info!("   IP address:      {:?}", config.address);
            info!("   Default gateway: {:?}", config.gateway);
            for s in &config.dns_servers {
                info!("   DNS server:      {:?}", s);
                #[cfg(feature = "dns")]
                unwrap!(dns_servers.push((*s).into()).ok());
            }
        } else {
            info!("IPv6: DOWN");
        }

        #[cfg(feature = "dns")]
        {
            let count = if dns_servers.len() > DNS_MAX_SERVER_COUNT {
                warn!("Number of DNS servers exceeds DNS_MAX_SERVER_COUNT, truncating list.");
                DNS_MAX_SERVER_COUNT
            } else {
                dns_servers.len()
            };
            self.dns.update_servers(&dns_servers[..count]);
        }

        self.state_waker.wake();
    }

    fn poll(&mut self, cx: &mut Context<'_>) {
        self.waker.register(cx.waker());

        let link_up = {
            // Not held across the stack poll below.
            let mut driver = self.driver.borrow_mut();
            driver.register_waker(cx.waker());
            driver.link_state() == LinkState::Up
        };

        // Update link up
        let old_link_up = self.link_up;
        self.link_up = link_up;

        // Print when changed
        if old_link_up != self.link_up {
            info!("link_up = {:?}", self.link_up);
            self.state_waker.wake();

            // Start over on link-state change, so a lease on the previous network is
            // not kept, and a new one is obtained right away.
            #[cfg(feature = "dhcpv4")]
            self.stack.iface(self.iface).restart_dhcpv4();
        }

        #[cfg(feature = "packetmeta-timestamp")]
        {
            while !self.timestamps.is_full()
                && let Some(timestamp) = self.stack.iface(self.iface).poll_tx_timestamp()
            {
                self.timestamps.try_send(timestamp).unwrap();
            }
            if self.timestamps.is_full() {
                let _ = self.timestamps.poll_ready_to_send(cx);
                warn!("iface is stalled because timestamp channel is full.");
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

        if self.stack.iface(self.iface).config_generation() != self.config_generation {
            self.config_changed();
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
