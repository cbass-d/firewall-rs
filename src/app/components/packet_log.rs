use super::{Action, AppContext, Component, ComponentRender, Props};
use crate::netlink::{self};
use crate::packetcap::packet::{PacketCollector, PacketInfo};

use cli_log::debug;
use crossterm::event::{KeyCode, KeyEvent};
use pcap::Packet;
use ratatui::{
    layout::Constraint,
    prelude::*,
    style::Style,
    text::Text,
    widgets::{
        Block, Borders, Cell, List, ListDirection, ListState, Paragraph, Row, ScrollDirection,
        Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState,
    },
};
use tokio::sync::broadcast::{self};
use tokio::sync::mpsc::{self};

pub struct PacketLog<'a> {
    network_ifs: Vec<String>,
    target_if: Option<String>,
    list_interfaces: bool,
    action_tx: mpsc::UnboundedSender<Action>,
    shutdown_channel: broadcast::Receiver<()>,
    scrollbar_state: ScrollbarState,
    scroll: usize,
    packet_queue: Vec<Packet<'a>>,
    table_state: TableState,
    list_state: ListState,
    packet_collector: PacketCollector,
    packets_tx: mpsc::Sender<PacketInfo>,
}

impl<'a> Component for PacketLog<'a> {
    fn new(context: &AppContext, action_tx: mpsc::UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        let (packet_collector, packets_tx) = PacketCollector::new();
        Self {
            target_if: None,
            list_interfaces: false,
            network_ifs: netlink::get_interfaces(),
            scrollbar_state: ScrollbarState::default(),
            scroll: 0,
            packet_queue: vec![],
            table_state: TableState::default(),
            list_state: ListState::default().with_selected(Some(0)),
            action_tx,
            shutdown_channel: context.shutdown_channel.resubscribe(),
            packet_collector,
            packets_tx,
        }
    }
    fn update(self, _: &AppContext) -> Self
    where
        Self: Sized,
    {
        Self {
            target_if: self.target_if,
            network_ifs: self.network_ifs,
            list_interfaces: self.list_interfaces,
            scrollbar_state: self.scrollbar_state,
            scroll: self.scroll,
            packet_queue: self.packet_queue,
            table_state: self.table_state,
            list_state: self.list_state,
            action_tx: self.action_tx,
            shutdown_channel: self.shutdown_channel,
            packet_collector: self.packet_collector,
            packets_tx: self.packets_tx,
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                if self.list_interfaces {
                    self.list_interfaces = false;
                } else {
                    let _ = self.action_tx.send(Action::Return);
                }
            }
            KeyCode::Char('i') => {
                self.list_interfaces = true;
            }
            KeyCode::Down => {
                if self.list_interfaces {
                    self.list_state.select_next();
                } else {
                    self.table_state.select_next();
                    self.scroll = self.scroll.saturating_add(1);
                    self.scrollbar_state = self.scrollbar_state.position(self.scroll);
                }
            }
            KeyCode::Up => {
                if self.list_interfaces {
                    self.list_state.select_previous();
                } else {
                    self.table_state.select_previous();
                    self.scroll = self.scroll.saturating_sub(1);
                    self.scrollbar_state = self.scrollbar_state.position(self.scroll);
                }
            }
            KeyCode::Enter => {
                if self.list_interfaces {
                    if let Some(i) = self.list_state.selected() {
                        self.target_if = Some(self.network_ifs[i].clone());
                        self.list_interfaces = false;

                        let devices = pcap::Device::list().unwrap();
                        let target_if = devices
                            .iter()
                            .find(|i| i.name == self.target_if.clone().unwrap())
                            .unwrap()
                            .clone();

                        self.action_tx
                            .send(Action::StartListener(target_if, self.packets_tx.clone()));

                        let mut shutdown_rx = self.shutdown_channel.resubscribe();
                        let packets_tx = self.packets_tx.clone();
                    }
                } else {
                }
            }
            _ => {}
        }
    }
}

impl<'a> ComponentRender<Props> for PacketLog<'a> {
    fn render(&mut self, frame: &mut ratatui::Frame, props: Props) {
        let block_title = match self.target_if.clone() {
            Some(interface) => format!("Packet Log - from [{interface}]"),
            None => String::from("Packet Log"),
        };

        let block = Block::default()
            .title(block_title)
            .borders(Borders::all())
            .border_style(props.border_color);

        let if_list = List::new(self.network_ifs.clone())
            .highlight_symbol(">>")
            .highlight_style(Style::new().bold().italic().underlined())
            .direction(ListDirection::TopToBottom)
            .block(
                Block::default()
                    .title("Select target interface")
                    .borders(Borders::all())
                    .border_style(props.border_color),
            );

        let header = ["Protocol", "Source", "Destination"]
            .into_iter()
            .map(Cell::from)
            .collect::<Row>();

        let rows = self.packet_collector.packets.iter().map(|entry| {
            let protocol_cell = Cell::from(Text::from(format!("{}", entry.proto)));
            let src_cell = Cell::from(Text::from(format!("{}", entry.src)));
            let dst_cell = Cell::from(Text::from(format!("{}", entry.dst)));

            Row::new([protocol_cell, src_cell, dst_cell].into_iter())
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
        .block(block.clone())
        .row_highlight_style(Style::new().bold().bg(Color::White).fg(Color::Black))
        .header(header);

        if self.list_interfaces {
            frame.render_stateful_widget(if_list, props.area, &mut self.list_state);
        } else if self.target_if.is_none() {
            let text = Text::from("---- No device selected ----").style(Style::new().bold());
            let paragraph = Paragraph::new(text).block(block).centered();
            frame.render_widget(paragraph, props.area);
        } else {
            frame.render_stateful_widget(table, props.area, &mut self.table_state);
            frame.render_stateful_widget(
                Scrollbar::new(ScrollbarOrientation::VerticalRight),
                props.area,
                &mut self.scrollbar_state,
            );
        }
    }
}
