use super::rules::RuleSet;
use crate::{debug, error, log};
use anyhow::Result;
use rustables::{
    Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, ProtocolFamily, Rule, Table,
};

const CHAIN_NAME: &str = "some-chain-name";
const ALLOW_NAME: &str = "allow-name";
const DENY_NAME: &str = "deny-name";
const LOG_NAME: &str = "log-name";

pub fn check_for_table(table_name: &str) {
    let mut tables = rustables::list_tables().unwrap();

    let table_index = tables
        .iter()
        .position(|t| t.get_name().is_some_and(|name| name == table_name));

    debug!("Checking for table {}", table_name);

    match table_index {
        Some(index) => {
            let mut batch = Batch::new();

            debug!("Deleting table {}", table_name);

            batch.add(&tables.remove(index), rustables::MsgType::Del);
            batch.send();
        }
        None => {}
    }
}

pub fn check_for_chain(chain_name: &str, table: &Table) {
    let mut chains = rustables::list_chains_for_table(table).unwrap();

    let chain_index = chains
        .iter()
        .position(|c| c.get_name().is_some_and(|name| name == chain_name));

    debug!("Checking for {} chain", chain_name);

    match chain_index {
        Some(index) => {
            let mut batch = Batch::new();

            debug!("Deleting chain {}", chain_name);

            batch.add(&chains.remove(index), rustables::MsgType::Del);
            batch.send();
        }
        None => {}
    }
}

pub fn create_new_table(table_name: &str, rules: RuleSet) -> Result<()> {
    debug!("Creating new table {}", table_name);

    let mut batch = Batch::new();

    check_for_table(table_name);

    let table = Table::new(ProtocolFamily::Inet)
        .with_name(table_name)
        .add_to_batch(&mut batch);

    check_for_chain(ALLOW_NAME, &table);
    check_for_chain(DENY_NAME, &table);
    check_for_chain(LOG_NAME, &table);

    let mut allow_chain = Chain::new(&table)
        .with_name(ALLOW_NAME)
        .with_hook(Hook::new(HookClass::In, 3))
        .with_type(ChainType::Filter)
        .with_policy(ChainPolicy::Drop)
        .add_to_batch(&mut batch);

    let mut deny_chain = Chain::new(&table)
        .with_name(DENY_NAME)
        .with_hook(Hook::new(HookClass::In, 3))
        .with_type(ChainType::Filter)
        .with_policy(ChainPolicy::Accept)
        .add_to_batch(&mut batch);

    let mut log_chain = Chain::new(&table)
        .with_name(LOG_NAME)
        .with_hook(Hook::new(HookClass::In, 3))
        .with_type(ChainType::Filter)
        .with_policy(ChainPolicy::Accept)
        .add_to_batch(&mut batch);

    // ---- ALLOW CHAIN ----- //
    if !rules.allow.sources.is_empty() {
        for src_addr in rules.allow.sources {
            Rule::new(&allow_chain)?
                .saddr(src_addr)
                .accept()
                .add_to_batch(&mut batch);
        }
    }

    if !rules.allow.destinations.is_empty() {
        for dst_addr in rules.allow.destinations {
            Rule::new(&allow_chain)?
                .daddr(dst_addr)
                .accept()
                .add_to_batch(&mut batch);
        }
    }

    if !rules.allow.source_networks.is_empty() {
        for src_network in rules.allow.source_networks {
            Rule::new(&allow_chain)?
                .match_network(src_network, true)?
                .accept()
                .add_to_batch(&mut batch);
        }
    }

    if !rules.allow.destination_networks.is_empty() {
        for dst_network in rules.allow.destination_networks {
            Rule::new(&allow_chain)?
                .match_network(dst_network, false)?
                .accept()
                .add_to_batch(&mut batch);
        }
    }

    if !rules.allow.dports.is_empty() {
        for dport in rules.allow.dports {
            Rule::new(&allow_chain)?
                .dport(dport, rustables::Protocol::TCP)
                .accept()
                .add_to_batch(&mut batch);

            Rule::new(&allow_chain)?
                .dport(dport, rustables::Protocol::UDP)
                .accept()
                .add_to_batch(&mut batch);
        }
    }

    if !rules.allow.sports.is_empty() {
        for sport in rules.allow.sports {
            Rule::new(&allow_chain)?
                .dport(sport, rustables::Protocol::TCP)
                .accept()
                .add_to_batch(&mut batch);

            Rule::new(&allow_chain)?
                .sport(sport, rustables::Protocol::UDP)
                .accept()
                .add_to_batch(&mut batch);
        }
    }

    // ---- DENY CHAIN ----- //
    if !rules.deny.sources.is_empty() {
        for src_addr in rules.deny.sources {
            Rule::new(&deny_chain)?
                .saddr(src_addr)
                .drop()
                .add_to_batch(&mut batch);
        }
    }

    if !rules.deny.destinations.is_empty() {
        for dst_addr in rules.deny.destinations {
            Rule::new(&deny_chain)?
                .daddr(dst_addr)
                .drop()
                .add_to_batch(&mut batch);
        }
    }

    if !rules.deny.source_networks.is_empty() {
        for src_network in rules.deny.source_networks {
            Rule::new(&deny_chain)?
                .match_network(src_network, true)?
                .drop()
                .add_to_batch(&mut batch);
        }
    }

    if !rules.deny.destination_networks.is_empty() {
        for dst_network in rules.deny.destination_networks {
            Rule::new(&deny_chain)?
                .match_network(dst_network, false)?
                .drop()
                .add_to_batch(&mut batch);
        }
    }

    if !rules.deny.dports.is_empty() {
        for dport in rules.deny.dports {
            Rule::new(&deny_chain)?
                .dport(dport, rustables::Protocol::TCP)
                .drop()
                .add_to_batch(&mut batch);

            Rule::new(&deny_chain)?
                .dport(dport, rustables::Protocol::UDP)
                .drop()
                .add_to_batch(&mut batch);
        }
    }

    if !rules.deny.sports.is_empty() {
        for sport in rules.deny.sports {
            Rule::new(&deny_chain)?
                .dport(sport, rustables::Protocol::TCP)
                .drop()
                .add_to_batch(&mut batch);

            Rule::new(&deny_chain)?
                .sport(sport, rustables::Protocol::UDP)
                .drop()
                .add_to_batch(&mut batch);
        }
    }

    // ---- LOG CHAIN ----- //
    if !rules.log.sources.is_empty() {
        for src_addr in rules.log.sources {
            Rule::new(&log_chain)?
                .saddr(src_addr)
                .with_expr(rustables::expr::Immediate::new_verdict(
                    rustables::expr::VerdictKind::Queue,
                ))
                .add_to_batch(&mut batch);
        }
    }

    if !rules.log.destinations.is_empty() {
        for dst_addr in rules.log.destinations {
            Rule::new(&log_chain)?
                .daddr(dst_addr)
                .with_expr(rustables::expr::Immediate::new_verdict(
                    rustables::expr::VerdictKind::Queue,
                ))
                .add_to_batch(&mut batch);
        }
    }

    if !rules.log.source_networks.is_empty() {
        for src_network in rules.log.source_networks {
            Rule::new(&log_chain)?
                .match_network(src_network, true)?
                .accept()
                .add_to_batch(&mut batch);
        }
    }

    if !rules.log.destination_networks.is_empty() {
        for dst_network in rules.log.destination_networks {
            Rule::new(&log_chain)?
                .match_network(dst_network, false)?
                .accept()
                .add_to_batch(&mut batch);
        }
    }

    if !rules.log.dports.is_empty() {
        for dport in rules.log.dports {
            Rule::new(&log_chain)?
                .dport(dport, rustables::Protocol::TCP)
                .with_expr(rustables::expr::Immediate::new_verdict(
                    rustables::expr::VerdictKind::Queue,
                ))
                .add_to_batch(&mut batch);

            Rule::new(&log_chain)?
                .dport(dport, rustables::Protocol::UDP)
                .with_expr(rustables::expr::Immediate::new_verdict(
                    rustables::expr::VerdictKind::Queue,
                ))
                .add_to_batch(&mut batch);
        }
    }

    if !rules.log.sports.is_empty() {
        for sport in rules.log.sports {
            Rule::new(&log_chain)?
                .dport(sport, rustables::Protocol::TCP)
                .with_expr(rustables::expr::Immediate::new_verdict(
                    rustables::expr::VerdictKind::Queue,
                ))
                .add_to_batch(&mut batch);

            Rule::new(&log_chain)?
                .sport(sport, rustables::Protocol::UDP)
                .with_expr(rustables::expr::Immediate::new_verdict(
                    rustables::expr::VerdictKind::Queue,
                ))
                .add_to_batch(&mut batch);
        }
    }

    batch.send()?;

    Ok(())
}

//pub fn send_and_process(batch: &FinalizedBatch) -> io::Result<()> {
//    let socket = socket::socket(
//        AddressFamily::Netlink,
//        SockType::Raw,
//        SockFlag::empty(),
//        SockProtocol::NetlinkNetFilter,
//    )?;
//
//    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
//    socket.send_all(batch)?;
//
//    let port_id = socket.portid();
//    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
//    let bleh = 2;
//    while let Some(message) = socket_recv(&socket, &mut buffer[..])? {
//        match mnl::cb_run(message, bleh, port_id)? {
//            mnl::CbResult::Stop => {
//                break;
//            }
//            mnl::CbResult::Ok => (),
//        }
//    }
//
//    Ok(())
//}
//
//fn socket_recv<'a>(socket: &mnl::Socket, buf: &'a mut [u8]) -> io::Result<Option<&'a [u8]>> {
//    let ret = socket.recv(buf)?;
//    if ret > 0 {
//        Ok(Some(&buf[..ret]))
//    } else {
//        Ok(None)
//    }
//}
