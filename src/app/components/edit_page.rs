use super::{Action, AppContext, Component, ComponentRender, Props};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    prelude::*,
    style::{Color, Style},
    widgets::{Block, Borders, Padding, Paragraph},
};
use tokio::sync::mpsc::{self};

pub struct EditPage {
    action_tx: mpsc::UnboundedSender<Action>,
}

impl Component for EditPage {
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

impl ComponentRender<Props> for EditPage {
    fn render(&mut self, frame: &mut ratatui::Frame, props: Props) {
        let block = Block::new()
            .borders(Borders::all())
            .border_style(props.border_color)
            .padding(Padding::uniform(1));

        frame.render_widget(block, props.area);
    }
}
