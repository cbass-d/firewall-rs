use nftables::stmt::Statement;
use std::fmt;

pub trait StatementDisplay {
    fn display_statement(&self) -> String;
    fn fmt_statement(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
}
