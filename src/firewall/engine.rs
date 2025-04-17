use super::nftables;
use super::rules::RuleSet;
use anyhow::{Result, anyhow};
use core::net::IpAddr;
use log::{debug, error, info};
use nfq::Queue;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;

pub struct FirewallEngine {
    rules: RuleSet,
    nf_queue: Queue,
}

impl FirewallEngine {
    pub fn new(rules: RuleSet) -> Result<Self> {
        debug!("Creating new firewall engine");

        let mut nf_queue = Queue::open()?;
        nf_queue.bind(0)?;
        match nftables::create_new_table("bleh", rules.clone()) {
            Ok(()) => {
                println!("bleh");
            }
            Err(e) => {
                println!("{}", e);
            }
        }

        Ok(Self { rules, nf_queue })
    }

    pub async fn run(&mut self) {
        info!("Engine is running");

        loop {
            let mut msg = match self.nf_queue.recv() {
                Ok(msg) => msg,
                Err(e) => break,
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
    }

    pub fn display_rules(&self) {
        println!("{}", self.rules);
    }

    pub fn handle_ipv4(&mut self, ipv4_packet: &Ipv4Packet) -> Result<()> {
        let source = IpAddr::from(ipv4_packet.get_source());
        let destination = IpAddr::from(ipv4_packet.get_destination());

        if self.rules.matches_allow(&source) {
            println!("allow source match for: {}", source);
        }
        if self.rules.matches_deny(&source) {
            println!("deny source match for: {}", source);
        }
        if self.rules.matches_log(&source) {
            println!("log source match for: {}", source);
        }

        if self.rules.matches_allow(&destination) {
            println!("allow destination match for: {}", destination);
        }
        if self.rules.matches_deny(&destination) {
            println!("deny destination match for: {}", destination);
        }
        if self.rules.matches_log(&destination) {
            println!("log destination match for: {}", destination);
        }

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
