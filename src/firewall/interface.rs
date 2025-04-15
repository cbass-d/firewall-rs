use pnet::datalink::NetworkInterface;
use std::fmt;

pub struct InterfaceStats {
    name: String,
    total_packets: u64,
    matched_allow: u64,
    matched_deny: u64,
    matched_log: u64,
}

impl InterfaceStats {
    pub fn new(iface_name: String) -> Self {
        Self {
            name: iface_name,
            total_packets: 0,
            matched_allow: 0,
            matched_deny: 0,
            matched_log: 0,
        }
    }

    pub fn add_total(&mut self) {
        self.total_packets += 1;
    }

    pub fn add_allow(&mut self) {
        self.matched_allow += 1;
    }

    pub fn add_deny(&mut self) {
        self.matched_deny += 1;
    }

    pub fn add_log(&mut self) {
        self.matched_log += 1;
    }
}

impl fmt::Display for InterfaceStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Packets stats for {}:\ntotal: {}\nmatched allowed: {}\nmatched deny: {}\nmatched log: {}",
            self.name, self.total_packets, self.matched_allow, self.matched_deny, self.matched_log
        )
    }
}
