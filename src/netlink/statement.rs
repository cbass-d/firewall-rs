use cli_log::debug;
use nftables::expr::Expression;
use nftables::expr::NamedExpression;
use nftables::expr::{
    CTDir, CTFamily, MetaKey, Payload, PayloadBase, RTFamily, RTKey, SetItem, SocketAttr, Verdict,
};
use nftables::stmt::Counter;
use nftables::stmt::Match;
use nftables::stmt::Operator;
use nftables::stmt::Statement;

pub trait OpDisplay {
    fn display_op(&self) -> &str;
}

impl OpDisplay for Operator {
    fn display_op(&self) -> &str {
        match self {
            Operator::OR => "or",
            Operator::AND => "and",
            Operator::EQ => "equal to",
            Operator::LT => "less than",
            Operator::GT => "greater than",
            Operator::IN => "is in",
            Operator::XOR => "xor",
            Operator::NEQ => "not equal to",
            Operator::LEQ => "less than or equal to",
            Operator::GEQ => "greater than or qual to",
            Operator::LSHIFT => "<<",
            Operator::RSHIFT => ">>",
        }
    }
}

pub trait NamedExprDisplay {
    fn display_named_expr(&self) -> String;
}

impl<'a> NamedExprDisplay for NamedExpression<'a> {
    fn display_named_expr(&self) -> String {
        match self {
            NamedExpression::RT(routing_data) => {
                let key = match routing_data.key {
                    RTKey::MTU => "MTU".to_string(),
                    RTKey::ClassId => "ClassID".to_string(),
                    RTKey::NextHop => "NextHop".to_string(),
                };

                let family = match routing_data.family {
                    Some(RTFamily::IP) => "ipv4".to_string(),
                    Some(RTFamily::IP6) => "ipv6".to_string(),
                    None => "".to_string(),
                };

                format!("{key} {family}")
            }
            NamedExpression::CT(conntrack_data) => {
                let mut key = conntrack_data.key.to_string();
                key = match conntrack_data.family {
                    Some(CTFamily::IP) => key + " ipv4",
                    Some(CTFamily::IP6) => key + " ipv6",
                    None => key + "",
                };
                key = match conntrack_data.dir {
                    Some(CTDir::Reply) => key + " reply",
                    Some(CTDir::Original) => key + " original",
                    None => key + "",
                };

                key
            }
            NamedExpression::Meta(meta_data) => match meta_data.key {
                MetaKey::Iif => "input interface index".to_string(),
                MetaKey::Oif => "output interface index".to_string(),
                MetaKey::Iifname => "input interface name".to_string(),
                MetaKey::Oifname => "output interface name".to_string(),
                MetaKey::Iiftype => "input interface type".to_string(),
                MetaKey::Oiftype => "output interface type".to_string(),
                MetaKey::Skgid => "GID".to_string(),
                MetaKey::Length => "packet length".to_string(),
                MetaKey::Pkttype => "packet type".to_string(),
                MetaKey::Nfproto => "netfilter proto".to_string(),
                MetaKey::L4proto => "L4 proto".to_string(),
                MetaKey::Protocol => "proto".to_string(),
                _ => "todo".to_string(),
            },
            //NamedExpression::Socket(socket_data) => match socket_data.key {
            //    SocketAttr::Mark => "mark",
            //    SocketAttr::Wildcard => "wildcard",
            //    SocketAttr::Cgroupv2 => "cgroupv2",
            //    SocketAttr::Transparent => "IP_TRANSPARENT",
            //},
            NamedExpression::Payload(payload_data) => match payload_data {
                Payload::PayloadField(field) => format!("{} {}", field.field, field.protocol),
                Payload::PayloadRaw(raw) => {
                    let base = match raw.base {
                        PayloadBase::LL => "LL".to_string(),
                        PayloadBase::NH => "NH".to_string(),
                        PayloadBase::TH => "TH".to_string(),
                        PayloadBase::IH => "IH".to_string(),
                    };
                    format!("at {base} + {} for {} bits", raw.offset, raw.len)
                }
            },
            NamedExpression::TcpOption(tcp_options) => {
                if let Some(field) = tcp_options.field.clone() {
                    format!("{} {field}", tcp_options.name)
                } else {
                    format!("{}", tcp_options.name)
                }
            }
            NamedExpression::Set(set) => {
                let items: Vec<String> = set.iter().map(|item| item.display_set_item()).collect();
                format!("{{{}}}", items.join(" "))
            }
            _ => "todo".to_string(),
        }
    }
}

pub trait SetItemDisplay {
    fn display_set_item(&self) -> String;
}

impl<'a> SetItemDisplay for SetItem<'a> {
    fn display_set_item(&self) -> String {
        match self {
            SetItem::Element(expr) => expr.display_expr(),
            SetItem::Mapping(expr_one, expr_two) => {
                format!(
                    "{{{}}}, {{{}}}",
                    expr_one.display_expr(),
                    expr_two.display_expr()
                )
            }
            SetItem::MappingStatement(expr, stmt) => {
                format!("{} -> {}", expr.display_expr(), stmt.display_statement())
            }
        }
    }
}

pub trait VerdictDisplay {
    fn display_verdict(&self) -> String;
}

impl<'a> VerdictDisplay for Verdict<'a> {
    fn display_verdict(&self) -> String {
        match self {
            Verdict::Drop => "drop".to_string(),
            Verdict::Accept => "accept".to_string(),
            Verdict::Return => "return".to_string(),
            _ => "todo".to_string(),
        }
    }
}

pub trait CounterDisplay {
    fn display_counter(&self) -> String;
}

impl<'a> CounterDisplay for Counter<'a> {
    fn display_counter(&self) -> String {
        match self {
            Counter::Named(str) => String::from("counter") + str,
            Counter::Anonymous(ctr) => {
                if let Some(ctr) = ctr {
                    let packets = ctr.packets.map_or("0".to_string(), |p| p.to_string());
                    let bytes = ctr.bytes.map_or("0".to_string(), |b| b.to_string());

                    format!("counter {packets} packets {bytes} bytes")
                } else {
                    "".to_string()
                }
            }
        }
    }
}

pub trait ExprDisplay {
    fn display_expr(&self) -> String;
}

impl<'a> ExprDisplay for Expression<'a> {
    fn display_expr(&self) -> String {
        match self {
            Expression::Named(expr) => expr.display_named_expr(),
            Expression::String(str) => str.to_string(),
            Expression::Number(num) => num.to_string(),
            Expression::Verdict(verdict) => verdict.display_verdict(),
            Expression::List(list) => {
                let exprs: Vec<String> = list.iter().map(|expr| expr.display_expr()).collect();

                exprs.join(" ")
            }
            _ => "todo".to_string(),
        }
    }
}

pub trait StatementDisplay {
    fn display_statement(&self) -> String;
}

impl<'a> StatementDisplay for Statement<'a> {
    fn display_statement(&self) -> String {
        match self {
            Statement::Match(expr) => {
                let left = &expr.left.display_expr();
                let right = &expr.right.display_expr();
                let op = &expr.op.display_op();

                format!("{left} {op} {right}")
            }
            Statement::Counter(ctr) => ctr.display_counter(),
            _ => "todo".to_string(),
        }
    }
}

pub trait MatchExprDisplay {
    fn display_match_expr(&self) -> String;
}

impl<'a> MatchExprDisplay for Match<'a> {
    fn display_match_expr(&self) -> String {
        "todo".to_string()
    }
}
