use nftables::types::{self};

pub trait FamilyDisplay {
    fn display_family(&self) -> String;
}

impl FamilyDisplay for types::NfFamily {
    fn display_family(&self) -> String {
        match self {
            types::NfFamily::IP => "ipv4".to_string(),
            types::NfFamily::IP6 => "ipv6".to_string(),
            types::NfFamily::ARP => "arp".to_string(),
            types::NfFamily::INet => "inet".to_string(),
            types::NfFamily::Bridge => "bridge".to_string(),
            types::NfFamily::NetDev => "netdev".to_string(),
        }
    }
}

pub trait ChainTypeDisplay {
    fn display_chain_type(&self) -> String;
}

impl ChainTypeDisplay for types::NfChainType {
    fn display_chain_type(&self) -> String {
        match self {
            types::NfChainType::NAT => "nat".to_string(),
            types::NfChainType::Filter => "filter".to_string(),
            types::NfChainType::Route => "route".to_string(),
        }
    }
}

pub trait ChainPolicyDisplay {
    fn display_chain_policy(&self) -> String;
}

impl ChainPolicyDisplay for types::NfChainPolicy {
    fn display_chain_policy(&self) -> String {
        match self {
            types::NfChainPolicy::Accept => "accept".to_string(),
            types::NfChainPolicy::Drop => "drop".to_string(),
        }
    }
}

pub trait ChainHookDisplay {
    fn display_chain_hook(&self) -> String;
}

impl ChainHookDisplay for types::NfHook {
    fn display_chain_hook(&self) -> String {
        match self {
            types::NfHook::Input => "input".to_string(),
            types::NfHook::Output => "output".to_string(),
            types::NfHook::Ingress => "ingress".to_string(),
            types::NfHook::Egress => "egress".to_string(),
            types::NfHook::Forward => "forward".to_string(),
            types::NfHook::Prerouting => "prerouting".to_string(),
            types::NfHook::Postrouting => "postrouting".to_string(),
        }
    }
}
