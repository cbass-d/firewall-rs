use super::{Action, AppContext, Component, ComponentRender, Props};
use crate::firewall::logging::LogEntry;
use chrono::{DateTime, Utc};
use core::net::IpAddr;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::Constraint,
    prelude::*,
    style::Style,
    text::Text,
    widgets::{
        Block, Borders, Cell, List, Padding, Paragraph, Row, ScrollDirection, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Table, TableState,
    },
};
use std::collections::VecDeque;
use tokio::sync::mpsc::{self};

pub struct PacketLog {
    log: VecDeque<LogEntry>,
    action_tx: mpsc::UnboundedSender<Action>,
    scrollbar_state: ScrollbarState,
    scroll: usize,
    table_state: TableState,
}

impl Component for PacketLog {
    fn new(context: &AppContext, action_tx: mpsc::UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        Self {
            log: VecDeque::new(),
            scrollbar_state: ScrollbarState::default(),
            scroll: 0,
            table_state: TableState::default(),
            action_tx,
        }
    }
    fn update(self, context: &AppContext) -> Self
    where
        Self: Sized,
    {
        Self {
            log: context.packet_log.clone(),
            scrollbar_state: self.scrollbar_state,
            scroll: self.scroll,
            table_state: self.table_state,
            action_tx: self.action_tx,
        }
    }
    fn handle_key_event(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                let _ = self.action_tx.send(Action::Return);
            }
            KeyCode::Down => {
                self.table_state.select_next();
                self.scroll = self.scroll.saturating_add(1);
                self.scrollbar_state = self.scrollbar_state.position(self.scroll);
            }
            KeyCode::Up => {
                self.table_state.select_previous();
                self.scroll = self.scroll.saturating_sub(1);
                self.scrollbar_state = self.scrollbar_state.position(self.scroll);
            }
            _ => {}
        }
    }
}

impl ComponentRender<Props> for PacketLog {
    fn render(&mut self, frame: &mut ratatui::Frame, props: Props) {
        let block = Block::default()
            .title("Packet Log")
            .borders(Borders::all())
            .border_style(props.border_color);

        let header = ["ID", "Protocol", "Source", "Destination", "Time"]
            .into_iter()
            .map(Cell::from)
            .collect::<Row>();

        let rows = self.log.iter().map(|entry| {
            let id_cell = Cell::from(Text::from(format!("{}", entry.id)));
            let protocol_cell = Cell::from(Text::from(format!("{}", entry.protocol)));
            let src_cell = Cell::from(Text::from(format!("{}", entry.source)));
            let dst_cell = Cell::from(Text::from(format!("{}", entry.destination)));
            let time_cell = Cell::from(Text::from(format!("{}", entry.time.time())));

            Row::new([id_cell, protocol_cell, src_cell, dst_cell, time_cell].into_iter())
        });

        let table = Table::new(
            rows,
            [
                Constraint::Length(5),
                Constraint::Length(10),
                Constraint::Length(15),
                Constraint::Length(15),
                Constraint::Length(15),
            ],
        )
        .block(block)
        .row_highlight_style(Style::new().bold().bg(Color::White).fg(Color::Black))
        .header(header);

        frame.render_stateful_widget(table, props.area, &mut self.table_state);

        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight),
            props.area,
            &mut self.scrollbar_state,
        );
    }
}
