use super::{Action, AppContext, Component, ComponentRender, Props};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    style::Style,
    widgets::{Block, Borders, List, Padding, Paragraph, Table},
};
use std::collections::VecDeque;
use tokio::sync::mpsc::{self};

pub struct PacketLog {
    log: VecDeque<String>,
    action_tx: mpsc::UnboundedSender<Action>,
}

impl Component for PacketLog {
    fn new(context: &AppContext, action_tx: mpsc::UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        Self {
            log: VecDeque::new(),
            action_tx,
        }
    }
    fn update(self, context: &AppContext) -> Self
    where
        Self: Sized,
    {
        Self {
            log: context.packet_log.clone(),
            action_tx: self.action_tx,
        }
    }
    fn handle_key_event(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                let _ = self.action_tx.send(Action::Return);
            }
            KeyCode::Down => {}
            KeyCode::Up => {}
            _ => {}
        }
    }
}

impl ComponentRender<Props> for PacketLog {
    fn render(&mut self, frame: &mut ratatui::Frame, props: Props) {
        let block = Block::default()
            .title("Packet Log")
            .borders(Borders::all())
            .border_style(props.border_color)
            .padding(Padding::horizontal(1));

        let list = List::new(self.log.clone()).block(block).scroll_padding(1);
        frame.render_widget(list, props.area);
    }
}
