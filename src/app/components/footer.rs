use ratatui::{
    layout::Alignment,
    style::{Color, Style, Stylize},
    widgets::{Block, List, ListDirection, Paragraph},
};

use super::{Component, ComponentRender, Props};

pub struct Footer {
    show_esc: bool,
    show_help: bool,
}

impl Component for Footer {
    fn new(
        _: &crate::app::controller::context::AppContext,
        _: tokio::sync::mpsc::UnboundedSender<crate::app::controller::Action>,
    ) -> Self
    where
        Self: Sized,
    {
        Self {
            show_esc: true,
            show_help: true,
        }
    }

    fn update(self, _: &crate::app::controller::context::AppContext) -> Self
    where
        Self: Sized,
    {
        Self {
            show_esc: true,
            show_help: true,
        }
    }

    fn handle_key_event(&mut self, key: crossterm::event::KeyEvent) {}
}

impl ComponentRender<Props> for Footer {
    fn render(&mut self, frame: &mut ratatui::Frame, props: Props) {
        let block = Block::new().bg(Color::DarkGray);

        let mut text = String::new();

        if self.show_esc {
            text.push_str(" Esc - quit ");
        }

        if self.show_help {
            text.push_str(" ? - help ");
        }

        let footer = Paragraph::new(text)
            .style(Style::new().bold())
            .block(block)
            .alignment(Alignment::Center);

        frame.render_widget(footer, props.area);
    }
}

