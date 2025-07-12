use anyhow::Result;
use cli_log::debug;

pub fn start_listener(if_name: &str) -> Result<()> {
    let devices = pcap::Device::list().unwrap();
    let target_if = devices.iter().find(|i| i.name == if_name).unwrap().clone();

    let mut cap = pcap::Capture::from_device(target_if)?.open()?;

    //    tokio::task::spawn_blocking(move || {
    //        while let Ok(packet) = cap.next_packet() {
    //            debug!("packet: {packet:?}");
    //        }
    //    });

    Ok(())
}
