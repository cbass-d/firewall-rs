use super::{Action, AppContext, Component, ComponentRender, Props};
use ratatui::Frame;
use tokio::sync::mpsc::{self};

pub struct EditRules {
    action_tx: mpsc::UnboundedSender<Action>,
}

impl Component for EditRules {
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

    fn handle_key_event(&mut self, key: crossterm::event::KeyEvent) {}
}

impl ComponentRender<Props> for EditRules {
    fn render(&mut self, frame: &mut ratatui::Frame, props: Props) {}
}
