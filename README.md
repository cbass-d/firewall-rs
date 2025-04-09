### Firewall written in Rust

To build from root directory:
```
$ cargo build
```

Binary must be ran using root/administrator privilages
(needed for listening on network interfaces)

```
Usage: firewall-rs -i <INTERFACE>

Options:
  -i <INTERFACE>      
  -h, --help          Print help
```

### Defining firewall rules
This project uses the confy crate for handling loading of configuration file
Linux
* Rules are defined in: /root/.config/firewall-rs/firewall-rules.toml

Windows and MacOs - TODO

Example firewall-rules.toml:
```
[allow]
sources =  []
destinations = []

[deny]
sources =  ["xxx.xxx.xxx.xxx", "yyy.yyy.yyy"]
destinations = []

[log]
sources =  ["zzz.zzz.zzz.zzz", "yyy.yyy.yyy"]
destinations = []
```
