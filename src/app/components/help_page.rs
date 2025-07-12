use super::{Action, AppContext, Component, ComponentRender, Props};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    prelude::*,
    style::{Color, Style},
    widgets::{Block, Borders, Padding, Paragraph},
};
use tokio::sync::mpsc::{self};

pub struct HelpPage {
    action_tx: mpsc::UnboundedSender<Action>,
}

impl Component for HelpPage {
    fn new(context: &AppContext, action_tx: mpsc::UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        Self { action_tx }
    }

    fn update(self, context: &AppContext) -> Self
    where
        Self: Sized,
    {
        Self {
            action_tx: self.action_tx,
        }
    }

    fn handle_key_event(&mut self, key: crossterm::event::KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                let _ = self.action_tx.send(Action::Return);
            }
            _ => {}
        }
    }
}

impl ComponentRender<Props> for HelpPage {
    fn render(&mut self, frame: &mut ratatui::Frame, props: Props) {
        let block = Block::new()
            .title("Info and Commands for Terminal Interface")
            .borders(Borders::all())
            .border_style(props.border_color)
            .padding(Padding::uniform(1));

        let firewall_rules = Paragraph::new(
            r#"
                r - Select firewall rules pane
                p - Select the packet log pane

                Viewing and Editing Netfilter Rules:
                    The left hand display display the active netfilter tables.
                    To expand the tables and show their chains press 'Enter'.
                    To look at the rules for a chain press 'Enter'.

                    e - Edit the exising netfilter tables and rules
                
                Packet Log of Incoming Packets:
                    The log displays incoming packets and their status for the
                    selected network device.

                    i - List and select the network device
                
                This page can be displayed by pressing '?'
            "#,
        )
        .block(block);

        frame.render_widget(firewall_rules, props.area);
    }
}
