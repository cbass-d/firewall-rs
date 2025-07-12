use super::{Action, context::AppContext};
use crossterm::event::KeyEvent;
use ratatui::{Frame, layout::Rect, style::Color};
use tokio::sync::mpsc::{self};

pub mod animation;
pub mod chains_list;
pub mod edit_page;
pub mod help_page;
pub mod packet_log;
pub mod tables_list;

pub struct Props {
    pub area: Rect,
    pub border_color: Color,
}

pub trait Component {
    fn new(context: &AppContext, action_tx: mpsc::UnboundedSender<Action>) -> Self
    where
        Self: Sized;

    fn update(self, context: &AppContext) -> Self
    where
        Self: Sized;

    fn handle_key_event(&mut self, key: KeyEvent);
}

pub trait ComponentRender<Props> {
    fn render(&mut self, frame: &mut Frame, props: Props);
}
