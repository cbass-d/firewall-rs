use crossterm::event::KeyCode;
use ratatui::style::Color;
use ratatui::style::Style;
use ratatui::text::Text;
use ratatui::widgets::Block;
use ratatui::widgets::List;
use ratatui::widgets::ListDirection;
use ratatui::widgets::ListState;
use ratatui::widgets::Padding;
use ratatui::widgets::Paragraph;

use super::Action;
use super::AppContext;
use super::KeyEvent;
use super::mpsc;
use super::{Component, ComponentRender, Props};
use crate::firewall::rules::RuleSet;

pub struct RulesList {
    active_rules: RuleSet,
    list_state: ListState,
    action_tx: mpsc::UnboundedSender<Action>,
}

impl Component for RulesList {
    fn new(context: &AppContext, action_tx: mpsc::UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        Self {
            active_rules: context.ruleset.clone(),
            list_state: ListState::default(),
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
            action_tx: self.action_tx,
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                let _ = self.action_tx.send(Action::Quit);
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
        let block = Block::bordered()
            .title("Active Firewall Rules")
            .padding(Padding::uniform(1));

        let mut items = Vec::new();

        // Allow
        let text = Text::from(format!("allow:\n{}", self.active_rules.allow))
            .style(Style::new().fg(Color::LightGreen));

        items.push(text);

        // Deny
        let text = Text::from(format!("deny:\n{}", self.active_rules.deny))
            .style(Style::new().fg(Color::Red));

        items.push(text);

        // Log
        let text = Text::from(format!("log:\n{}", self.active_rules.log))
            .style(Style::new().fg(Color::LightYellow));

        items.push(text);

        let list = List::new(items)
            .direction(ListDirection::TopToBottom)
            .highlight_symbol(">>")
            .block(block);

        frame.render_stateful_widget(list, props.area, &mut self.list_state);
    }
}
