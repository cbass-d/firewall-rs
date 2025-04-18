use chrono::{DateTime, Utc};
use core::net::IpAddr;
use dirs::data_local_dir;
use rand::random;
use std::collections::VecDeque;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::PathBuf;

pub struct LogEntry {
    id: u64,
    protocol: String,
    source: IpAddr,
    destination: IpAddr,
    time: DateTime<Utc>,
}

impl LogEntry {
    pub fn build(
        id: u64,
        protocol: &str,
        source: IpAddr,
        destination: IpAddr,
        time: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            protocol: protocol.to_string(),
            source,
            destination,
            time,
        }
    }
}

pub struct Log {
    entries: VecDeque<LogEntry>,
    next_id: u64,
    file_path: PathBuf,
}

impl Log {
    pub fn new() -> Self {
        let log_uuid: u32 = random();
        let mut file_path = choose_file_path();
        file_path.push(format!("firewall.log-{log_uuid}"));

        Self {
            entries: VecDeque::new(),
            next_id: 1,
            file_path,
        }
    }

    pub fn add(
        &mut self,
        protocol: &str,
        source: IpAddr,
        destination: IpAddr,
        time: DateTime<Utc>,
    ) {
        let entry = LogEntry {
            id: self.next_id,
            protocol: protocol.to_string(),
            source,
            destination,
            time,
        };
        self.entries.push_back(entry);

        self.next_id += 1;

        if self.entries.len() > 5 {
            self.write_to_file().expect("some bad");
        }
    }

    pub fn get_file_path(&self) -> &str {
        self.file_path
            .to_str()
            .expect("Invalid unicode in file path")
    }

    pub fn write_to_file(&mut self) -> Result<(), io::Error> {
        let mut file = File::options()
            .append(true)
            .create(true)
            .open(self.file_path.clone())?;

        while !self.entries.is_empty() {
            let entry = self.entries.pop_front().expect("pop called on empty queue");
            write!(&mut file, "{}\n", entry);
        }

        Ok(())
    }
}

impl fmt::Display for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "id: {}\nprotocol: {}\nsource: {}\ndestination: {}\ntime: {}",
            self.id, self.protocol, self.source, self.destination, self.time
        )
    }
}

pub fn choose_file_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/log/")
    }
}
