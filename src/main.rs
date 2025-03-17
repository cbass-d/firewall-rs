use anyhow::{Result, anyhow};
use clap::Parser;
use dirs::data_dir;
use pnet::datalink::{self, NetworkInterface};
use serde::{Deserialize, Serialize};

#[derive(Parser, Serialize, Deserialize, Default)]
struct Config {
    #[arg(short, long)]
    interface: String,
}

fn main() -> Result<()> {
    let conf = Config::parse();

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface: &NetworkInterface| iface.name == conf.interface)
        .next();

    let interface = match interface {
        Some(interface) => interface,
        None => {
            return Err(anyhow!("Interface not found"));
        }
    };

    Ok(())
}
