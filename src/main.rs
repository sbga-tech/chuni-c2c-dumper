mod proto;

use std::{
    fmt,
    fs::File,
    io::{sink, BufWriter, Write},
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    path::PathBuf,
};

use anyhow::Context;
use chrono::{DateTime, Local};
use clap::{Args, Parser};
use cli_table::{print_stdout, Table, WithTitle};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use ipnetwork::IpNetwork;
use pcap::{Activated, Capture};
use tracing::{info_span, warn};

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(flatten)]
    input: Input,
    #[arg(long)]
    /// Dump decrypted packets to
    dump: Option<PathBuf>,
}

#[derive(Args)]
#[group(multiple = false)]
struct Input {
    #[arg(short, long)]
    /// List available network interfaces
    list: bool,
    #[arg(short, long)]
    /// Pcap file to read from
    file: Option<PathBuf>,
    #[arg(short, long)]
    /// Network interface to capture
    device: Option<String>,
}

fn comma_split<T: fmt::Display>(value: &[T]) -> String {
    value
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Table)]
struct Device {
    #[table(title = "Name")]
    name: String,
    #[table(title = "Description")]
    desc: String,
    #[table(title = "Addresses", display_fn = "comma_split")]
    addrs: Vec<IpNetwork>,
}

impl From<pcap::Device> for Device {
    fn from(value: pcap::Device) -> Self {
        Self {
            name: value.name,
            desc: value.desc.unwrap_or_default(),
            addrs: value
                .addresses
                .into_iter()
                .map(|addr| {
                    if let Some(mask) = addr.netmask {
                        IpNetwork::with_netmask(addr.addr, mask).unwrap()
                    } else {
                        IpNetwork::new(addr.addr, 0).unwrap()
                    }
                })
                .collect(),
        }
    }
}

fn main() -> anyhow::Result<()> {
    enable_ansi_support::enable_ansi_support().ok();
    tracing_subscriber::fmt()
        .event_format(
            tracing_subscriber::fmt::format()
                .pretty()
                .with_source_location(false),
        )
        .init();

    let args = Cli::parse();

    if args.input.list {
        println!("Available network interfaces:");
        print_stdout(
            pcap::Device::list()?
                .into_iter()
                .map(Device::from)
                .collect::<Vec<_>>()
                .with_title(),
        )?;
        return Ok(());
    }

    let mut cap: Capture<dyn Activated> = if let Some(file) = args.input.file {
        Capture::from_file(file)?.into()
    } else if let Some(device) = args.input.device {
        Capture::from_device(device.as_str())?
            .immediate_mode(true)
            .open()?
            .into()
    } else {
        let dev = pcap::Device::list()?
            .into_iter()
            .find(|d| {
                d.addresses.iter().any(|addr| {
                    const ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 139, 0));
                    const MASK: IpAddr = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0));
                    IpNetwork::with_netmask(ADDR, MASK)
                        .unwrap()
                        .contains(addr.addr)
                        && addr.netmask.is_some_and(|mask| mask == MASK)
                })
            })
            .context("Cannot find suitable network interface")?;
        warn!(
            "Automatically selected network interface: {}{}",
            dev.name,
            dev.desc
                .as_deref()
                .map_or("".to_string(), |d| format!(" ({})", d))
        );
        Capture::from_device(dev)?
            .immediate_mode(true)
            .open()?
            .into()
    };

    let mut out: Box<dyn Write> = if let Some(dump) = args.dump {
        Box::new(BufWriter::new(File::create(dump)?))
    } else {
        Box::new(sink())
    };

    let is_ethernet = cap.get_datalink() == pcap::Linktype::ETHERNET;

    loop {
        match cap.next_packet() {
            Ok(pkt) => {
                let _span = info_span!(
                    "pcap",
                    time = ?DateTime::from_timestamp(pkt.header.ts.tv_sec as _, pkt.header.ts.tv_usec as u32 * 1000).unwrap_or_default().with_timezone(&Local),
                    caplen = pkt.header.caplen,
                    len = pkt.header.len
                ).entered();
                let pkt = if is_ethernet {
                    SlicedPacket::from_ethernet(pkt.data)?
                } else {
                    SlicedPacket::from_ip(pkt.data)?
                };
                let Some(NetSlice::Ipv4(ipv4)) = pkt.net else {
                    continue;
                };
                if let Some(TransportSlice::Udp(udp)) = pkt.transport {
                    if udp.destination_port() != 50200 {
                        continue;
                    }
                    let _span = info_span!(
                        "udp",
                        source = ?SocketAddrV4::new(ipv4.header().source_addr(), udp.source_port()),
                        dest = ?SocketAddrV4::new(ipv4.header().destination_addr(), udp.destination_port())
                    )
                    .entered();
                    if let Err(e) = proto::dump(udp.payload(), &mut out) {
                        warn!("Failed to dump packet: {:?}", e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to read packet: {:?}", e);
            }
        }
    }
}
