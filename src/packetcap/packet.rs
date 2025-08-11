use chrono::{DateTime, Utc};
use core::net::IpAddr;
use pcap::Packet;
use tokio::sync::mpsc::{self};

pub struct PacketInfo {
    pub proto: String,
    pub src: IpAddr,
    pub dst: IpAddr,
    //pub time: DateTime<Utc>,
}

impl PacketInfo {
    pub fn build(packet: &Packet) -> Self {
        let header = packet.header;
        let proto = "test".to_string();
        let src = IpAddr::from([127, 0, 0, 1]);
        let dst = IpAddr::from([127, 0, 0, 1]);

        Self { proto, src, dst }
    }
}

pub struct PacketCollector {
    pub packets: Vec<PacketInfo>,
    pub packets_rx: mpsc::Receiver<PacketInfo>,
}

impl PacketCollector {
    pub fn new() -> (Self, mpsc::Sender<PacketInfo>) {
        let (packets_tx, packets_rx) = mpsc::channel::<PacketInfo>(1);

        (
            Self {
                packets: vec![],
                packets_rx,
            },
            packets_tx,
        )
    }

    pub fn clear(&mut self) {
        self.packets.clear();
    }
}
