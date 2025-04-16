use anyhow::{Result, anyhow};
use clap::Parser;
use datalink::Channel::Ethernet;
use firewall::engine;
use log::{debug, error, info, log};
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

#[derive(Parser, Serialize, Deserialize, Default)]
struct Config {
    #[arg(short)]
    interface: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cfg = Config::parse();

    let firewall_rules: firewall::rules::RuleSet = confy::load("firewall-rs", "firewall-rules")?;

    debug!("Using following rules {}", firewall_rules);

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

            engine.run().await;
        }
        None => {
            error!("[-] Interface not found");
        }
    }

    Ok(())
}
