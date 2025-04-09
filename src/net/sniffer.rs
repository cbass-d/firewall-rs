use anyhow::{Result, anyhow};
use log::info;
use pnet::datalink::NetworkInterface;
use pnet::datalink::{self};
use pnet::packet::ethernet::EthernetPacket;

use crate::firewall::engine::FirewallEngine;

pub async fn run_sniffer(interface: NetworkInterface, engine: FirewallEngine) -> Result<()> {
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(anyhow!("Unhandled channel type")),
        Err(e) => return Err(anyhow!(e)),
    };

    info!("[+] Firewall running on {}...", interface.name);

    loop {
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap();
                engine.process(&packet);
            }
            Err(_) => {
                return Err(anyhow!("Error fetching next packet"));
            }
        }
    }

    Ok(())
}
