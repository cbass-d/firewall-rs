### Firewall-thing written in Rust

To build from root directory:
```
$ cargo build
```

Binary must be ran using root/administrator privilages
Calls to the netlink subsystem are made to create nftables

```
Usage: firewall-rs -r <RULES_FILE>

Options:
  -r <RULES_FILE>      
  -h, --help          Print help

```
