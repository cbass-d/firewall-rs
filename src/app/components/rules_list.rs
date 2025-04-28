use std::collections::HashSet;

use super::{Action, AppContext, Component, ComponentRender, Props};
use crate::firewall::rules::{FirewallAction, Rule, RuleSet};
use crate::format_rule_fields;
use cli_log::debug;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::widgets::{Cell, Row};
use ratatui::{
    prelude::*,
    style::{Color, Style},
    text::{Line, Text},
    widgets::{
        Block, Borders, HighlightSpacing, List, ListDirection, ListState, Padding, Paragraph,
        Table, TableState, Tabs,
    },
};
use tokio::sync::mpsc::{self};

pub struct RulesList {
    active_rules: RuleSet,
    expanded: HashSet<usize>,
    current_tab: usize,
    action_tx: mpsc::UnboundedSender<Action>,
}

fn format_rule_set<T: std::fmt::Display>(set: &HashSet<T>) -> String {
    if set.is_empty() {
        return "Empty".to_string();
    }

    set.iter()
        .map(|item| item.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

impl RulesList {
    fn next_tab(&mut self) {
        self.current_tab = self.current_tab.saturating_add(1);
        self.current_tab = self.current_tab.clamp(0, 2);
    }

    fn previous_tab(&mut self) {
        self.current_tab = self.current_tab.saturating_sub(1);
    }

    fn get_current_rule_set(&self) -> &Rule {
        match self.current_tab {
            0 => &self.active_rules.allow,
            1 => &self.active_rules.deny,
            2 => &self.active_rules.log,
            _ => &self.active_rules.log,
        }
    }
}

impl Component for RulesList {
    fn new(context: &AppContext, action_tx: mpsc::UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        Self {
            active_rules: context.ruleset.clone(),
            current_tab: 0,
            expanded: HashSet::new(),
            action_tx,
        }
    }

    fn update(self, context: &AppContext) -> Self
    where
        Self: Sized,
    {
        Self {
            active_rules: context.ruleset.clone(),
            expanded: self.expanded,
            current_tab: self.current_tab,
            action_tx: self.action_tx,
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
            KeyCode::Left => {
                self.previous_tab();
            }
            KeyCode::Right => {
                self.next_tab();
            }
            _ => {}
        }
    }
}

impl ComponentRender<Props> for RulesList {
    fn render(&mut self, frame: &mut ratatui::Frame, props: Props) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0)])
            .split(props.area);

        let tabs = Tabs::new(vec!["Allow", "Log", "Deny"])
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

        let fields = [
            "Source IPs",
            "Destination Ips",
            "Source Networks",
            "Destination Networks",
            "Source Ports",
            "Destination Ports",
        ];

        let rule = self.get_current_rule_set();
        let values = [
            format_rule_set(&rule.sources),
            format_rule_set(&rule.destinations),
            format_rule_set(&rule.source_networks),
            format_rule_set(&rule.destination_networks),
            format_rule_set(&rule.sports),
            format_rule_set(&rule.dports),
        ];

        let rows: Vec<Row> = fields
            .iter()
            .zip(values.iter())
            .enumerate()
            .map(|(i, (name, value))| Row::new(vec![Cell::from(*name), Cell::from(value.as_str())]))
            .collect();

        let table =
            Table::new(rows, [Constraint::Min(0), Constraint::Min(0)]).block(Block::default());

        frame.render_widget(table, layout[1]);
    }
}
