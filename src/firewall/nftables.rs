use super::rules::RuleSet;
use anyhow::Result;
use cli_log::debug;
use rustables::{
    Batch, Chain, ChainPolicy, ChainPriority, ChainType, Hook, HookClass, MsgType, ProtocolFamily,
    ProtocolFamily, Rule, Table, expr::ExpressionList,
};

const CHAIN_NAME: &str = "some-chain-name";
const ALLOW_NAME: &str = "allow-name";
const DENY_NAME: &str = "deny-name";
const LOG_NAME: &str = "log-name";
const TEST_TABLE: &str = "test-table";
const TEST_CHAIN: &str = "test-chain";

pub struct FirewallRule {
    protocol: ProtocolFamily,
    expressions: ExpressionList,
}

pub struct FirewallChain {
    name: String,
    chain_type: ChainType,
    hook_class: HookClass,
    priority: ChainPriority,
    policy: ChainPolicy,
    rules: Vec<FirewallRule>,
}

pub struct FirewallTable {
    name: String,
    protocol: ProtocolFamily,
    chains: Vec<FirewallChain>,
}

pub fn get_tables() -> Vec<Table> {
    debug!("Fetching existing tables");

    let mut tables = rustables::list_tables().unwrap();

    if tables.is_empty() {
        debug!("No tables to process");
        return vec![];
    }

    debug!("{} table or tables found", tables.len());
    let mut table_idx: usize = 0;
    tables.iter().for_each(|t| {
        debug!("Processing table: {}", table_idx);

        let firewall_chains: Vec<FirewallChain> = Vec::new();
        let chains = rustables::list_chains_for_table(&t).unwrap();

        let mut chain_idx: usize = 0;
        chains.iter().for_each(|c| {
            debug!("Processing chain {chain_idx} for table {table_idx}");
            process_chain(c);

            chain_idx += 1;
        });

        table_idx += 1;
    });

    //tables.iter().map(|t| {
    //    debug!("Processing table: {}", idx);
    //    idx += 1;
    //});

    tables
}

pub fn process_chain(chain: &Chain) -> FirewallChain {
    let rules = rustables::list_rules_for_chain(chain).unwrap();

    rules.iter().for_each(|r| {
        process_rule(r);
    });
}

pub fn process_rule(rule: &Rule) -> FirewallRule {
    let expressions = rule.get_expressions().ok_or("No expressions");
    let userdata = rule.get_userdata().ok_or("No userdata");

    debug!("Expressions for rule: {:?}", expressions);
    let mut expr_idx: usize = 0;
    expressions.iter().for_each(|e| {
        debug!("expression: {:?}", e);
        expr_idx += 1;
    });

    debug!("Userdata for rule: {:?}", userdata);
}

pub fn create_test_table() -> Result<()> {
    debug!("Creating test table");
    let mut batch = Batch::new();

    let table = Table::new(ProtocolFamily::Inet)
        .with_name(TEST_TABLE)
        .add_to_batch(&mut batch);

    let mut chain = Chain::new(&table)
        .with_name(TEST_CHAIN)
        .with_hook(Hook::new(HookClass::In, 3))
        .with_type(ChainType::Filter)
        .with_policy(ChainPolicy::Accept)
        .add_to_batch(&mut batch);

    let mut rule = Rule::new(&chain)?
        .saddr(std::net::IpAddr::from([127, 0, 0, 1]))
        .accept()
        .add_to_batch(&mut batch);

    batch.send()?;

    Ok(())
}

pub fn cleanup_tables() {
    let mut batch = Batch::new();

    let tables = rustables::list_tables().unwrap();

    tables.iter().for_each(|t| {
        debug!("deleting {:?} table", t.get_name().ok_or(""));
        batch.add(t, MsgType::Del);
    });

    batch.send().unwrap();
}

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
