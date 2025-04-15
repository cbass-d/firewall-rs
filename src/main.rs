use anyhow::{Result, anyhow};
use clap::Parser;
use datalink::Channel::Ethernet;
use firewall::engine;
use log::{error, info};
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::transport::{self, TransportChannelType, TransportReceiver};
use serde::{Deserialize, Serialize};
use std::net::Shutdown;
use std::path::Path;
use tokio::sync::broadcast::{self};
use tokio::task::JoinSet;

mod firewall;
mod net;

#[derive(Parser, Serialize, Deserialize, Default)]
struct Config {
    #[arg(short)]
    interface: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Set RUST_LOG if not already set
    match std::env::var("RUST_LOG") {
        Ok(_) => {}
        Err(_) => unsafe {
            std::env::set_var("RUST_LOG", "info");
        },
    };
    env_logger::init();

    let cfg = Config::parse();

    let firewall_rules: firewall::rules::RuleSet = confy::load("firewall-rs", "firewall-rules")?;
    let local_data_dir = dirs::data_local_dir().unwrap();

    let phy_interfaces = datalink::interfaces();

    info!("[*] Adding '{}' to firewall...", cfg.interface);
    let interface = phy_interfaces
        .iter()
        .find(|iface| iface.name == cfg.interface);

    match interface {
        Some(interface) => {
            let mut engine =
                firewall::engine::FirewallEngine::new(interface.name.clone(), firewall_rules);
        }
        None => {
            error!("[-] Interface not found");
        }
    }

    Ok(())
}
