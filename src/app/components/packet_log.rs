use crossterm::event::KeyEvent;
use ratatui::widgets::Block;
use ratatui::widgets::Borders;
use ratatui::widgets::Padding;
use ratatui::widgets::Paragraph;

use super::Action;
use super::AppContext;
use super::mpsc;
use super::{Component, ComponentRender, Props};

pub struct PacketLog {}

impl Component for PacketLog {
    fn new(context: &AppContext, action_tx: mpsc::UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        Self {}
    }
    fn update(self, context: &AppContext) -> Self
    where
        Self: Sized,
    {
        Self {}
    }
    fn handle_key_event(&mut self, key: KeyEvent) {}
}

impl ComponentRender<Props> for PacketLog {
    fn render(&mut self, frame: &mut ratatui::Frame, props: Props) {
        let block = Block::default()
            .title("Packet Log")
            .borders(Borders::all())
            .padding(Padding::horizontal(1));

        frame.render_widget(block, props.area);
    }
}
