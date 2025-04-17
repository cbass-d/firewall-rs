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

    pub async fn run(&mut self) {
        info!("Engine is running");

        let run = Arc::new(AtomicBool::new(true));
        let handler_run = run.clone();

        ctrlc::set_handler(move || {
            handler_run.store(false, Ordering::SeqCst);
        });

        while run.load(Ordering::SeqCst) {
            let mut msg = match self.nf_queue.recv() {
                Ok(msg) => msg,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    error!("{e}");
                    break;
                }
            };

            let eth_type = EtherType::new(msg.get_hw_protocol());

            match eth_type {
                EtherTypes::Ipv4 => {
                    let packet = Ipv4Packet::new(msg.get_payload()).unwrap();

                    self.handle_ipv4(&packet).map_err(|err| error!("{err}"));
                }
                EtherTypes::Ipv6 => {
                    let packet = Ipv6Packet::new(msg.get_payload()).unwrap();

                    self.handle_ipv6(&packet).map_err(|err| error!("{err}"));
                }
                _ => {
                    debug!("Unhandled etherlink protocol");
                }
            }

            debug!("Received message");
        }

        self.log.write_to_file();

        println!("Log file written to: {}", self.log.get_file_path());
    }

    pub fn display_rules(&self) {
        println!("{}", self.rules);
    }

    pub fn handle_ipv4(&mut self, ipv4_packet: &Ipv4Packet) -> Result<()> {
        let source = IpAddr::from(ipv4_packet.get_source());
        let destination = IpAddr::from(ipv4_packet.get_destination());

        self.log.add(
            "ipv4",
            IpAddr::V4(ipv4_packet.get_source()),
            IpAddr::V4(ipv4_packet.get_destination()),
            Utc::now(),
        );

        Ok(())
    }

    pub fn handle_ipv6(&self, packet: &Ipv6Packet) -> Result<()> {
        println!("6");
        Ok(())
    }

    pub fn handle_other(&self, packet: &EthernetPacket) -> Result<()> {
        Ok(())
    }
}
