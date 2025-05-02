use super::{
    logging::{Log, LogEntry},
    nftables::{self},
    rules::RuleSet,
};
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use cli_log::{debug, error, info, log};
use core::net::IpAddr;
use nfq::Queue;
use pnet::packet::{
    Packet,
    ethernet::{EtherType, EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::broadcast::{self};

pub struct FirewallEngine {
    nf_queue: Queue,
    log: Log,
}

impl FirewallEngine {
    pub fn new() -> Result<(Self, broadcast::Receiver<LogEntry>)> {
        debug!("Creating new firewall engine");

        let mut nf_queue = Queue::open()?;
        nf_queue.set_nonblocking(true);
        nf_queue.bind(0)?;
        debug!("New netfilter queue created");

        nftables::create_test_table();
        nftables::get_tables();

        nftables::cleanup_tables();

        let (log, logs_rx) = Log::new();

        Ok((Self { nf_queue, log }, logs_rx))
    }

    pub fn run(&mut self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
        info!("Engine is running");

        loop {
            // Break loop when shutdown signal is received
            match shutdown_rx.try_recv() {
                Ok(_) => {
                    break;
                }
                Err(_) => {}
            }

            let mut msg = match self.nf_queue.recv() {
                Ok(msg) => msg,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    error!("{e}");
                    return Err(anyhow!(e));
                }
            };

            let eth_type = EtherType::new(msg.get_hw_protocol());

            match eth_type {
                EtherTypes::Ipv4 => {
                    if let Some(packet) = Ipv4Packet::new(msg.get_payload()) {
                        self.handle_ipv4(&packet).map_err(|err| error!("{err}"));
                    } else {
                        debug!("Invalid IPv4 packet received");
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(packet) = Ipv6Packet::new(msg.get_payload()) {
                        self.handle_ipv6(&packet).map_err(|err| error!("{err}"));
                    } else {
                        debug!("Invalid IPv6 packet received");
                    }
                }
                _ => {
                    debug!("Unhandled etherlink protocol");
                }
            }

            debug!("Received message");
        }

        self.log.write_to_file().expect("Failed to write log file");

        println!("Log file written to: {}", self.log.get_file_path());

        Ok(())
    }

    pub fn handle_ipv4(&mut self, packet: &Ipv4Packet) -> Result<()> {
        let source = IpAddr::from(packet.get_source());
        let destination = IpAddr::from(packet.get_destination());

        self.log.add(
            "IPv4",
            IpAddr::V4(packet.get_source()),
            IpAddr::V4(packet.get_destination()),
            Utc::now(),
        );

        Ok(())
    }

    pub fn handle_ipv6(&mut self, packet: &Ipv6Packet) -> Result<()> {
        let source = IpAddr::from(packet.get_source());
        let destination = IpAddr::from(packet.get_destination());

        self.log.add(
            "IPv6",
            IpAddr::V6(packet.get_source()),
            IpAddr::V6(packet.get_destination()),
            Utc::now(),
        );

        Ok(())
    }

    pub fn handle_other(&self, packet: &EthernetPacket) -> Result<()> {
        Ok(())
    }
}
