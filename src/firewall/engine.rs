use super::logging::{Log, LogEntry};
use super::nftables;
use super::rules::RuleSet;
use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use core::net::IpAddr;
use log::{debug, error, info};
use nfq::Queue;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::broadcast::{self};

pub struct FirewallEngine {
    rules: RuleSet,
    nf_queue: Queue,
    log: Log,
}

impl FirewallEngine {
    pub fn new(rules: RuleSet) -> Result<Self> {
        debug!("Creating new firewall engine");

        let mut nf_queue = Queue::open()?;
        nf_queue.set_nonblocking(true);
        nf_queue.bind(0)?;
        match nftables::create_new_table("bleh", rules.clone()) {
            Ok(()) => {
                println!("bleh");
            }
            Err(e) => {
                println!("{}", e);
            }
        }

        let log = Log::new();

        Ok(Self {
            rules,
            nf_queue,
            log,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("Engine is running");

        let run = Arc::new(AtomicBool::new(true));
        let handler_run = run.clone();

        // ctlr-c signal stops the running of engine
        ctrlc::set_handler(move || {
            handler_run.store(false, Ordering::SeqCst);
        });

        while run.load(Ordering::SeqCst) {
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

        self.log.write_to_file();

        println!("Log file written to: {}", self.log.get_file_path());

        Ok(())
    }

    pub fn display_rules(&self) {
        println!("{}", self.rules);
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
