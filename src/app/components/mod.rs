use crate::app::controller::Action;
use crate::app::controller::context::AppContext;
use crossterm::event::KeyEvent;
use ratatui::{Frame, layout::Rect, style::Color};
use tokio::sync::mpsc::{self};

mod footer;
pub mod main_page;
mod rules_list;

pub struct Props {
    pub area: Rect,
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
