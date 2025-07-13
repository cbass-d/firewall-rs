mod nlmsg;
mod statement;

use statement::StatementDisplay;
use std::fmt;

use anyhow::Result;
use cli_log::debug;
use nfq::Queue;
use nftables::stmt::Statement;
use nftnl::{
    Batch, Chain as nftnlChain, ChainType as nftnlChainType, FinalizedBatch, Hook as nftnlHook,
    Policy as nftnlPolicy, ProtoFamily, Rule as nftnlRule, Table as nftnlTable, nft_expr,
};
use rustables::{Chain, ChainPolicy, ChainPriority, ChainType, Hook, ProtocolFamily, Rule, Table};
use tui_tree_widget::{Tree, TreeItem, TreeState};

use std::{
    borrow::Cow,
    ffi::CString,
    io::{self},
};

const CHAIN_NAME: &str = "some-chain-name";
const ALLOW_NAME: &str = "allow-name";
const DENY_NAME: &str = "deny-name";
const LOG_NAME: &str = "log-name";
const TEST_TABLE: &str = "test-table";
const TEST_CHAIN: &str = "test-chain";

pub struct FirewallRule {
    protocol: ProtocolFamily,
}

pub struct FirewallChain {
    name: String,
    chain_type: ChainType,
    hook_class: Hook,
    policy: ChainPolicy,
}

pub struct FirewallTable {
    name: String,
    protocol: ProtocolFamily,
    chains: Vec<FirewallChain>,
}

fn iface_index(name: &str) -> Result<libc::c_uint, io::Error> {
    let c_name = CString::new(name)?;
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    match index {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(index),
    }
}

pub fn create_nfqueue(id: u16) -> Result<Queue> {
    debug!("New netfilter queue created with");

    let mut nf_queue = Queue::open()?;
    nf_queue.set_nonblocking(true);
    nf_queue.bind(id)?;

    Ok(nf_queue)
}

pub fn get_interfaces() -> Vec<String> {
    pnet::datalink::interfaces()
        .iter()
        .map(|i| i.name.clone())
        .collect()
}

pub fn get_table_names() -> Vec<String> {
    let tables = rustables::list_tables().unwrap();
    let mut table_names = vec![];
    if !tables.is_empty() {
        table_names = tables
            .iter()
            .map(|t| {
                let name = match t.get_name() {
                    Some(name) => name.to_string(),
                    None => "unamed".to_string(),
                };
                name
            })
            .collect();
    }

    table_names
}

pub fn format_expr(expr: &Cow<'_, [nftables::stmt::Statement]>) -> String {
    debug!("current statement:\n{expr:?}");

    expr[0].display_statement()
}

pub fn build_tree() -> Vec<TreeItem<'static, usize>> {
    let ruleset_raw =
        nftables::helper::get_current_ruleset().expect("Unable to get active ruleset: {e}");
    debug!("objects: {:?}", ruleset_raw.objects);

    let mut table_objs = vec![];
    let mut table_idx: usize = 0;

    let mut chain_idx: usize = 0;
    let mut chain_objs = vec![];

    let mut rule_objs = vec![];
    let mut rule_idx: usize = 0;

    let mut table_idx = 0;
    let mut chain_idx = 0;
    let mut rule_idx = 0;

    ruleset_raw
        .objects
        .into_iter()
        .for_each(|nft_object| match nft_object {
            nftables::schema::NfObject::ListObject(obj) => match obj {
                nftables::schema::NfListObject::Table(obj) => {
                    table_objs.push((table_idx, obj));
                    table_idx += 1;
                }
                nftables::schema::NfListObject::Chain(obj) => {
                    chain_objs.push((chain_idx, obj));
                    chain_idx += 1;
                }
                nftables::schema::NfListObject::Rule(obj) => {
                    rule_objs.push((rule_idx, obj));
                    rule_idx += 1;
                }
                _ => {}
            },
            _ => {}
        });

    let mut table_nodes = vec![];
    table_objs.iter().for_each(|table_tuple| {
        let table = table_tuple.1;
        let chains = chain_objs.iter().filter(|c| c.1.table == table.name);

        let mut chain_nodes = vec![];
        chains.into_iter().for_each(|chain_tuple| {
            let chain = chain_tuple.1;
            let rules = rule_objs.iter().filter(|r| r.1.chain == chain.name);

            let rules_leaves = rules
                .into_iter()
                .map(|r| TreeItem::new_leaf(r.0, format_expr(&r.1.expr)))
                .collect();
            let chain_info = format!(
                "{:?} {:?} {:?} {:?}",
                chain._type, chain.prio, chain.family, chain.policy
            );
            let node = TreeItem::new(
                chain_tuple.0,
                format!("{}: {}", chain.name.clone(), chain_info),
                rules_leaves,
            )
            .unwrap();
            chain_nodes.push(node);
        });

        let node = TreeItem::new(table_tuple.0, table.name.clone(), chain_nodes).unwrap();
        table_nodes.push(node);
    });

    table_nodes

    //tables.iter().for_each(|t| {
    //    let chains = expand_table(t.to_owned());
    //    chains.iter().for_each(|c| {
    //        let rules = expand_chain(c.name.clone(), t.to_owned());

    //        debug!("Total rules for \"{}\": {}", c.name.clone(), rules.len());

    //        rules.iter().for_each(|r| {
    //            let leaf = TreeItem::new_leaf(rule_idx, r.to_owned());
    //            rule_leaves.push(leaf);
    //            rule_idx += 1;
    //        });

    //        let chain_node = TreeItem::new(chain_idx, c.name.clone(), rule_leaves).unwrap();
    //        chain_objs.push(chain_node);
    //        chain_idx += 1;
    //    });

    //    let table_node = TreeItem::new(table_idx, t.clone(), chain_objs).unwrap();
    //    table_objs.push(table_node);
    //    table_idx += 1;
    //});
}

pub fn expand_table(name: String) -> Vec<FirewallChain> {
    debug!("Expanding table \"{name}\"");

    let table = rustables::list_tables()
        .unwrap()
        .into_iter()
        .find(|t| *t.get_name().unwrap() == name)
        .unwrap();

    let nft_chains = rustables::list_chains_for_table(&table);
    let mut chains = vec![];
    match nft_chains {
        Ok(nft_chains) => {
            nft_chains.iter().for_each(|c| {
                debug!("current chain: {c:?}");

                chains.push(FirewallChain {
                    name: c
                        .get_name()
                        .map_or("unamed".to_string(), |name| name.to_string()),
                    chain_type: c.get_type().unwrap().clone(),
                    policy: c.get_policy().unwrap().clone(),
                    hook_class: c.get_hook().unwrap().clone(),
                });
            });
        }
        Err(e) => {
            debug!("Error getting chains: {e}");
        }
    }

    chains
}

pub fn expand_chain(chain: String, table: String) -> Vec<String> {
    debug!("Expanding rules for chain: \"{chain}\"");
    let table = rustables::list_tables()
        .unwrap()
        .into_iter()
        .find(|t| *t.get_name().unwrap() == table)
        .unwrap();

    let chain = rustables::list_chains_for_table(&table)
        .unwrap()
        .into_iter()
        .find(|c| *c.get_name().unwrap() == chain)
        .unwrap();

    let nft_rules = rustables::list_rules_for_chain(&chain);
    let mut rules = vec![];
    match nft_rules {
        Ok(nft_rules) => {
            nft_rules.iter().for_each(|r| {
                rules.push(expand_rule(r));
            });
        }
        Err(e) => {
            debug!("Error getting rules for chain: {e}");
        }
    }

    rules
}

pub fn expand_rule(rule: &Rule) -> String {
    let expressions = rule.get_expressions().ok_or("No expressions").unwrap();

    debug!("Expressions for rule: {:?}", expressions);
    let mut expr_idx: usize = 0;
    expressions.iter().for_each(|e| {
        debug!("expression: {:?}", e);
        expr_idx += 1;
    });

    format!("{expressions:?}")
}

pub fn create_test_table() -> Result<()> {
    debug!("Creating test table");
    let mut batch = Batch::new();

    let table = nftnlTable::new(&CString::new(TEST_TABLE).unwrap(), ProtoFamily::Inet);
    batch.add(&table, nftnl::MsgType::Add);

    let mut chain = nftnlChain::new(&CString::new(TEST_CHAIN).unwrap(), &table);

    chain.set_hook(nftnlHook::In, -450);
    chain.set_policy(nftnlPolicy::Accept);
    chain.set_type(nftnlChainType::Filter);

    batch.add(&chain, nftnl::MsgType::Add);

    let mut rule = nftnlRule::new(&chain);
    let lo_index = iface_index("lo").unwrap();
    rule.add_expr(&nft_expr!(meta iif));
    rule.add_expr(&nft_expr!(cmp == lo_index));
    rule.add_expr(&nft_expr!(verdict accept));

    batch.add(&rule, nftnl::MsgType::Add);

    let finalized_batch = batch.finalize();

    send_and_process_batch(&finalized_batch)?;

    Ok(())
}

pub fn get_table() {
    let mut batch = Batch::new();
}

pub fn cleanup_test_tables() {
    delete_table(TEST_TABLE, ProtoFamily::Inet).unwrap();
}

pub fn delete_table(table_name: &str, protocol: ProtoFamily) -> Result<()> {
    let mut batch = Batch::new();

    let table = nftnlTable::new(&CString::new(table_name).unwrap(), protocol);

    batch.add(&table, nftnl::MsgType::Del);

    let finalized_batch = batch.finalize();

    send_and_process_batch(&finalized_batch)?;

    Ok(())
}

pub fn send_and_process_batch(batch: &FinalizedBatch) -> io::Result<()> {
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    let port_id = socket.portid();

    socket.send_all(batch)?;
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let bleh = 2;
    while let Some(message) = socket_recv(&socket, &mut buffer[..])? {
        match mnl::cb_run(message, bleh, port_id)? {
            mnl::CbResult::Stop => {
                break;
            }
            mnl::CbResult::Ok => (),
        }
    }

    Ok(())
}

fn socket_recv<'a>(socket: &mnl::Socket, buf: &'a mut [u8]) -> io::Result<Option<&'a [u8]>> {
    let ret = socket.recv(buf)?;
    if ret > 0 {
        Ok(Some(&buf[..ret]))
    } else {
        Ok(None)
    }
}

//
//pub fn get_all_tables() -> io::Result<()> {
//    let socket = socket::socket(
//        AddressFamily::Netlink,
//        SockType::Raw,
//        SockFlag::empty(),
//        SockProtocol::NetlinkNetFilter,
//    )?;
//    let seq = 0;
//
//    let mut buf = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
//    let nlh = unsafe {
//        nftnl_sys::nftnl_nlmsg_build_hdr(
//            buf.as_mut_ptr(),
//            libc::NFT_MSG_GETTABLE as u16,
//            libc::NFPROTO_UNSPEC as u16,
//            libc::NLM_F_DUMP as u16,
//            seq,
//        )
//    };
//
//    socket::send(
//        socket as i32,
//        std::slice::from_raw_parts(nlh, 32),
//        MsgFlags::empty(),
//    )?;
//
//    buf.clear();
//
//    Ok(())
//}

//pub fn check_for_table(table_name: &str) {
//    let mut tables = rustables::list_tables().unwrap();
//
//    let table_index = tables
//        .iter()
//        .position(|t| t.get_name().is_some_and(|name| name == table_name));
//
//    debug!("Checking for table {}", table_name);
//
//    match table_index {
//        Some(index) => {
//            let mut batch = Batch::new();
//
//            debug!("Deleting table {}", table_name);
//
//            batch.add(&tables.remove(index), rustables::MsgType::Del);
//            batch.send();
//        }
//        None => {}
//    }
//}

//pub fn check_for_chain(chain_name: &str, table: &Table) {
//    let mut chains = rustables::list_chains_for_table(table).unwrap();
//
//    let chain_index = chains
//        .iter()
//        .position(|c| c.get_name().is_some_and(|name| name == chain_name));
//
//    debug!("Checking for {} chain", chain_name);
//
//    match chain_index {
//        Some(index) => {
//            let mut batch = Batch::new();
//
//            debug!("Deleting chain {}", chain_name);
//
//            batch.add(&chains.remove(index), rustables::MsgType::Del);
//            batch.send();
//        }
//        None => {}
//    }
//}
