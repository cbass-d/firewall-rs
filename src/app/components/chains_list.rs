use super::{Action, AppContext, Component, ComponentRender, Props};
use crate::firewall::nftables::{self};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    prelude::*,
    style::{Color, Style},
    widgets::{Block, Borders, Padding, Paragraph, Tabs},
};
use tokio::sync::mpsc::{self};

pub struct ChainsList {
    current_tab: usize,
    action_tx: mpsc::UnboundedSender<Action>,
}

impl Component for ChainsList {
    fn new(context: &AppContext, action_tx: mpsc::UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        Self {
            action_tx,
            current_tab: 0,
        }
    }

    fn update(self, context: &AppContext) -> Self
    where
        Self: Sized,
    {
        Self {
            action_tx: self.action_tx,
            current_tab: self.current_tab,
        }
    }

    fn handle_key_event(&mut self, key: crossterm::event::KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                let _ = self.action_tx.send(Action::Return);
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

impl ChainsList {
    fn next_tab(&mut self) {
        self.current_tab = self.current_tab.saturating_add(1);
        self.current_tab = self.current_tab.clamp(0, 2);
    }

    fn previous_tab(&mut self) {
        self.current_tab = self.current_tab.saturating_sub(1);
    }

    fn get_chains(&mut self) {}
}

impl ComponentRender<Props> for ChainsList {
    fn render(&mut self, frame: &mut ratatui::Frame, props: Props) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0)])
            .split(props.area);

        let tabs = Tabs::new(vec!["Chains"])
            .block(
                Block::default()
                    .borders(Borders::all())
                    .title("Active NFTables Rules"),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .select(self.current_tab);

        frame.render_widget(tabs, layout[0]);

        let chains = self.get_chains();
    }
}
