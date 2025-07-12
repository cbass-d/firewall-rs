use super::{Action, AppContext, Component, ComponentRender, Props};
use crate::netlink::{self};
use cli_log::debug;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::widgets::{Cell, Row};
use ratatui::{
    prelude::*,
    style::{Color, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, HighlightSpacing, List, ListDirection, ListState, Padding, Paragraph,
        Table, TableState, Tabs,
    },
};
use std::collections::HashSet;
use tokio::sync::mpsc::{self};
use tui_tree_widget::{Tree, TreeState};

pub struct TableList<usize> {
    current_tab: usize,
    total_tabs: usize,
    action_tx: mpsc::UnboundedSender<Action>,
    nft_tables: Vec<String>,
    tree_state: TreeState<usize>,
}

fn format_rule_set<T: std::fmt::Display>(set: &HashSet<usize>) -> String {
    if set.is_empty() {
        return "Empty".to_string();
    }

    set.iter()
        .map(|item| item.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

impl TableList<usize> {
    fn next_tab(&mut self) {
        self.current_tab = self.current_tab.saturating_add(1);
        self.clamp_tab();
    }

    fn previous_tab(&mut self) {
        self.current_tab = self.current_tab.saturating_sub(1);
        self.clamp_tab();
    }

    fn clamp_tab(&mut self) {
        self.current_tab = self.current_tab.clamp(0, self.total_tabs - 1);
    }

    //fn expand_current_table(&mut self, idx: usize) {}
}

impl Component for TableList<usize> {
    fn new(_context: &AppContext, action_tx: mpsc::UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        let table_names = netlink::get_table_names();

        Self {
            current_tab: 0,
            total_tabs: 1,
            nft_tables: table_names,
            action_tx,
            tree_state: TreeState::default(),
        }
    }

    fn update(self, _context: &AppContext) -> Self
    where
        Self: Sized,
    {
        Self {
            current_tab: self.current_tab,
            total_tabs: self.total_tabs,
            action_tx: self.action_tx,
            nft_tables: self.nft_tables,
            tree_state: self.tree_state,
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                let _ = self.action_tx.send(Action::Return);
            }
            KeyCode::Enter => {}
            KeyCode::Char('e') => {
                let _ = self.action_tx.send(Action::EditRules);
            }
            KeyCode::Down => {
                self.tree_state.key_down();
            }
            KeyCode::Up => {
                self.tree_state.key_up();
            }
            KeyCode::Left => {
                self.tree_state.key_left();
            }
            KeyCode::Right => {
                self.tree_state.key_right();
            }
            KeyCode::PageDown => {
                self.previous_tab();
            }
            KeyCode::PageUp => {
                self.next_tab();
            }
            _ => {}
        }
    }
}

impl ComponentRender<Props> for TableList<usize> {
    fn render(&mut self, frame: &mut ratatui::Frame, props: Props) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0)])
            .split(props.area);

        let tabs = Tabs::new(vec!["Tree"])
            .block(
                Block::default()
                    .borders(Borders::all())
                    .title("Active Firewall Rules"),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .select(self.current_tab);

        debug!("current tab: {}", self.current_tab);

        frame.render_widget(tabs, layout[0]);

        if !self.nft_tables.is_empty() {
            let tree_nodes = netlink::build_tree();
            let tree = Tree::new(&tree_nodes)
                .unwrap()
                .block(
                    Block::default()
                        .borders(Borders::all())
                        .border_style(props.border_color),
                )
                .highlight_style(Style::new().bg(Color::Green));

            frame.render_stateful_widget(tree, layout[1], &mut self.tree_state);
        } else {
            let text = Paragraph::new("No active tables")
                .block(Block::default())
                .alignment(Alignment::Center);

            frame.render_widget(text, layout[1]);
        }

        //       let fields = [
        //           "Source IPs",
        //           "Destination Ips",
        //           "Source Networks",
        //           "Destination Networks",
        //           "Source Ports",
        //           "Destination Ports",
        //       ];

        //        let values = [];

        //        let rows: Vec<Row> = fields
        //            .iter()
        //            .zip(values.iter())
        //            .enumerate()
        //            .map(|(i, (name, value))| Row::new(vec![Cell::from(*name), Cell::from(value.as_str())]))
        //            .collect();
        //
        //        let table =
        //            Table::new(rows, [Constraint::Min(0), Constraint::Min(0)]).block(Block::default());

        //        frame.render_widget(table, layout[1]);
        //
    }
}
