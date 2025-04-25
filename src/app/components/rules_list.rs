use std::collections::HashSet;

use super::{Action, AppContext, Component, ComponentRender, Props};
use crate::firewall::rules::RuleSet;
use crate::format_rule_fields;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    prelude::*,
    style::{Color, Style},
    text::{Line, Text},
    widgets::{
        Block, Borders, HighlightSpacing, List, ListDirection, ListState, Padding, Paragraph,
    },
};
use tokio::sync::mpsc::{self};

pub struct RulesList {
    active_rules: RuleSet,
    list_state: ListState,
    allow_items: Vec<String>,
    deny_items: Vec<String>,
    log_items: Vec<String>,
    expanded: HashSet<usize>,
    action_tx: mpsc::UnboundedSender<Action>,
}

impl RulesList {
    fn expand_rules(&mut self, set: usize) {
        match set {
            0 => {
                let mut new_items = format_rule_fields!(self, allow);
                self.allow_items.append(&mut new_items);
            }
            1 => {
                let mut new_items = format_rule_fields!(self, deny);
                self.deny_items.append(&mut new_items);
            }
            2 => {
                let mut new_items = format_rule_fields!(self, log);
                self.log_items.append(&mut new_items);
            }
            _ => {}
        }
    }

    fn collapse_rules(&mut self, set: usize) {
        match set {
            0 => {
                self.allow_items = vec!["Allow".to_string()];
            }
            1 => {
                self.deny_items = vec!["Deny".to_string()];
            }
            2 => {
                self.log_items = vec!["Log".to_string()];
            }
            _ => {}
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
            list_state: ListState::default(),
            allow_items: vec!["Allow".to_string()],
            deny_items: vec!["Deny".to_string()],
            log_items: vec!["Log".to_string()],
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
            list_state: self.list_state,
            allow_items: self.allow_items,
            deny_items: self.deny_items,
            log_items: self.log_items,
            expanded: self.expanded,
            action_tx: self.action_tx,
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.list_state.select(None);
                let _ = self.action_tx.send(Action::Return);
            }
            KeyCode::Enter => {
                if let Some(idx) = self.list_state.selected() {
                    if self.expanded.contains(&idx) {
                        self.collapse_rules(idx);
                        self.expanded.remove(&idx);
                    } else {
                        self.expand_rules(idx);
                        self.expanded.insert(idx);
                    }
                }
            }
            KeyCode::Down => {
                self.list_state.select_next();
            }
            KeyCode::Up => {
                self.list_state.select_previous();
            }
            _ => {}
        }
    }
}

impl ComponentRender<Props> for RulesList {
    fn render(&mut self, frame: &mut ratatui::Frame, props: Props) {
        let block = Block::new()
            .title("Active Firewall Rules")
            .borders(Borders::all())
            .border_style(props.border_color)
            .padding(Padding::uniform(1));

        let allow_items: Vec<Line> = self
            .allow_items
            .clone()
            .into_iter()
            .map(|mut item| {
                item.push_str("\n");
                let line = Line::from(item).fg(Color::LightGreen);
                line
            })
            .collect();

        let allow_items = Text::from(allow_items);

        let deny_items: Vec<Line> = self
            .deny_items
            .clone()
            .into_iter()
            .map(|mut item| {
                item.push_str("\n");
                let line = Line::from(item).fg(Color::Red);
                line
            })
            .collect();

        let deny_items = Text::from(deny_items);

        let log_items: Vec<Line> = self
            .log_items
            .clone()
            .into_iter()
            .map(|mut item| {
                item.push_str("\n");
                let line = Line::from(item).fg(Color::LightYellow);
                line
            })
            .collect();

        let log_items = Text::from(log_items);

        let list = List::new([allow_items, deny_items, log_items])
            .direction(ListDirection::TopToBottom)
            .highlight_spacing(HighlightSpacing::Always)
            .highlight_symbol(">>")
            .block(block);

        frame.render_stateful_widget(list, props.area, &mut self.list_state);
    }
}
