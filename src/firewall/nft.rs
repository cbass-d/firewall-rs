use super::rules::{Rule as FirewallRule, RuleSet};
use anyhow::Result;
use nftnl::{Batch, Chain, FinalizedBatch, ProtoFamily, Rule, Table, nft_expr};
use serde::de;
use std::{ffi::CString, io};

const CHAIN_NAME: &str = "some-chain-name";
const ALLOW_NAME: &str = "allow-name";
const DENY_NAME: &str = "deny-name";
const LOG_NAME: &str = "log-name";

const EXAMPLE_IP: &[u8] = &[127, 0, 0, 1];

pub fn create_new_table(table_name: &str, rules: RuleSet) -> Result<()> {
    let mut batch = Batch::new();

    let table = Table::new(&CString::new(table_name).unwrap(), ProtoFamily::Inet);

    batch.add(&table, nftnl::MsgType::Add);

    let mut allow_chain = Chain::new(&CString::new(ALLOW_NAME).unwrap(), &table);

    allow_chain.set_hook(nftnl::Hook::In, 3);
    allow_chain.set_type(nftnl::ChainType::Filter);
    allow_chain.set_policy(nftnl::Policy::Drop);

    let mut deny_chain = Chain::new(&CString::new(DENY_NAME).unwrap(), &table);

    deny_chain.set_hook(nftnl::Hook::In, 3);
    deny_chain.set_type(nftnl::ChainType::Filter);
    deny_chain.set_policy(nftnl::Policy::Accept);

    let mut log_chain = Chain::new(&CString::new(LOG_NAME).unwrap(), &table);

    log_chain.set_hook(nftnl::Hook::In, 3);
    log_chain.set_type(nftnl::ChainType::Filter);
    log_chain.set_policy(nftnl::Policy::Accept);

    batch.add(&allow_chain, nftnl::MsgType::Add);
    batch.add(&deny_chain, nftnl::MsgType::Add);
    batch.add(&log_chain, nftnl::MsgType::Add);

    // ---- ALLOW CHAIN ----- //
    if !rules.allow.sources.is_empty() {
        let mut sources_rule = Rule::new(&allow_chain);

        sources_rule.add_expr(&nft_expr!(meta nfproto));
        sources_rule.add_expr(&nft_expr!(cmp == mnl::mnl_sys::libc::NFPROTO_IPV4 as u8));
        for src_addr in rules.allow.sources {
            sources_rule.add_expr(&nft_expr!(payload ipv4 saddr));
            sources_rule.add_expr(&nft_expr!(cmp == src_addr));

            sources_rule.add_expr(&nft_expr!(counter));
            sources_rule.add_expr(&nft_expr!(verdict accept));
        }

        batch.add(&sources_rule, nftnl::MsgType::Add);
    }

    if !rules.allow.destinations.is_empty() {
        let mut dest_rule = Rule::new(&allow_chain);

        dest_rule.add_expr(&nft_expr!(meta nfproto));
        dest_rule.add_expr(&nft_expr!(cmp == mnl::mnl_sys::libc::NFPROTO_IPV4 as u8));
        for dst_addr in rules.allow.destinations {
            dest_rule.add_expr(&nft_expr!(payload ipv4 daddr));
            dest_rule.add_expr(&nft_expr!(cmp == dst_addr));

            dest_rule.add_expr(&nft_expr!(counter));
            dest_rule.add_expr(&nft_expr!(verdict accept));
        }

        batch.add(&dest_rule, nftnl::MsgType::Add);
    }

    // ---- DENY CHAIN ----- //
    if !rules.deny.sources.is_empty() {
        let mut sources_rule = Rule::new(&deny_chain);

        sources_rule.add_expr(&nft_expr!(meta nfproto));
        sources_rule.add_expr(&nft_expr!(cmp == mnl::mnl_sys::libc::NFPROTO_IPV4 as u8));
        for src_addr in rules.deny.sources {
            sources_rule.add_expr(&nft_expr!(payload ipv4 saddr));
            sources_rule.add_expr(&nft_expr!(cmp == src_addr));

            sources_rule.add_expr(&nft_expr!(counter));
            sources_rule.add_expr(&nft_expr!(verdict accept));
        }

        batch.add(&sources_rule, nftnl::MsgType::Add);
    }

    if !rules.deny.destinations.is_empty() {
        let mut dest_rule = Rule::new(&deny_chain);

        dest_rule.add_expr(&nft_expr!(meta nfproto));
        dest_rule.add_expr(&nft_expr!(cmp == mnl::mnl_sys::libc::NFPROTO_IPV4 as u8));
        for dst_addr in rules.deny.destinations {
            dest_rule.add_expr(&nft_expr!(payload ipv4 daddr));
            dest_rule.add_expr(&nft_expr!(cmp == dst_addr));

            dest_rule.add_expr(&nft_expr!(counter));
            dest_rule.add_expr(&nft_expr!(verdict accept));
        }

        batch.add(&dest_rule, nftnl::MsgType::Add);
    }

    // ---- LOG CHAIN ----- //
    if !rules.log.sources.is_empty() {
        let mut sources_rule = Rule::new(&log_chain);

        sources_rule.add_expr(&nft_expr!(meta nfproto));
        sources_rule.add_expr(&nft_expr!(cmp == mnl::mnl_sys::libc::NFPROTO_IPV4 as u8));
        for src_addr in rules.log.sources {
            sources_rule.add_expr(&nft_expr!(payload ipv4 saddr));
            sources_rule.add_expr(&nft_expr!(cmp == src_addr));

            sources_rule.add_expr(&nft_expr!(counter));
            sources_rule.add_expr(&nft_expr!(verdict accept));
        }

        batch.add(&sources_rule, nftnl::MsgType::Add);
    }

    if !rules.log.destinations.is_empty() {
        let mut dest_rule = Rule::new(&log_chain);

        dest_rule.add_expr(&nft_expr!(meta nfproto));
        dest_rule.add_expr(&nft_expr!(cmp == mnl::mnl_sys::libc::NFPROTO_IPV4 as u8));
        for dst_addr in rules.log.destinations {
            dest_rule.add_expr(&nft_expr!(payload ipv4 daddr));
            dest_rule.add_expr(&nft_expr!(cmp == dst_addr));

            dest_rule.add_expr(&nft_expr!(counter));
            dest_rule.add_expr(&nft_expr!(verdict accept));
        }

        batch.add(&dest_rule, nftnl::MsgType::Add);
    }

    let final_batch = batch.finalize();
    send_and_process(&final_batch)?;

    Ok(())
}

pub fn send_and_process(batch: &FinalizedBatch) -> io::Result<()> {
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    socket.send_all(batch)?;

    let port_id = socket.portid();
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
