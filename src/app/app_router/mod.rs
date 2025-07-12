use super::{
    ActivePane,
    components::{
        Component, ComponentRender, Props, animation::Animation, chains_list::ChainsList,
        edit_page::EditPage, help_page::HelpPage, packet_log::PacketLog, tables_list::TableList,
    },
    context::AppContext,
    ui::Action,
};
use cli_log::debug;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout},
    prelude::*,
    style::{Color, Style},
    widgets::{Block, Paragraph},
};
use tokio::sync::mpsc::{self};

pub struct AppRouter<usize> {
    pub animation: Animation,
    active_pane: ActivePane,
    table_list: TableList<usize>,
    chains_list: ChainsList,
    edit_page: EditPage,
    packet_log: PacketLog,
    help_page: HelpPage,
    action_tx: mpsc::UnboundedSender<Action>,
}

impl Component for AppRouter<usize> {
    fn new(context: &AppContext, action_tx: mpsc::UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        Self {
            active_pane: context.active_box,
            animation: Animation::new(context, action_tx.clone()),
            table_list: TableList::new(context, action_tx.clone()),
            chains_list: ChainsList::new(context, action_tx.clone()),
            packet_log: PacketLog::new(context, action_tx.clone()),
            edit_page: EditPage::new(context, action_tx.clone()),
            help_page: HelpPage::new(context, action_tx.clone()),
            action_tx,
        }
    }

    fn update(self, context: &AppContext) -> Self
    where
        Self: Sized,
    {
        Self {
            active_pane: context.active_box,
            animation: self.animation.update(context),
            table_list: self.table_list.update(context),
            chains_list: self.chains_list.update(context),
            packet_log: self.packet_log.update(context),
            help_page: self.help_page.update(context),
            edit_page: self.edit_page.update(context),
            action_tx: self.action_tx,
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        // Key event is passed onto the current active pane
        // If none active, the key is hanlded directly here
        match self.active_pane {
            ActivePane::TableList => {
                self.table_list.handle_key_event(key);
            }
            ActivePane::ChainsList => {
                self.chains_list.handle_key_event(key);
            }
            ActivePane::PacketLog => {
                self.packet_log.handle_key_event(key);
            }
            ActivePane::HelpPage => {
                self.help_page.handle_key_event(key);
            }
            ActivePane::EditPage => {
                self.edit_page.handle_key_event(key);
            }
            ActivePane::None => match key.code {
                KeyCode::Esc => {
                    let _ = self.action_tx.send(Action::Quit);
                }
                KeyCode::Char('?') => {
                    let _ = self.action_tx.send(Action::DisplayHelp);
                }
                KeyCode::Char('p') => {
                    let _ = self.action_tx.send(Action::SelectPacketLog);
                    debug!("Sending {:?}", Action::SelectPacketLog);
                }
                KeyCode::Char('r') => {
                    let _ = self.action_tx.send(Action::SelectTableList);
                    debug!("Sending {:?}", Action::SelectTableList);
                }
                _ => {}
            },
        }
    }
}

impl ComponentRender<()> for AppRouter<usize> {
    fn render(&mut self, frame: &mut ratatui::Frame, _: ()) {
        // Parent layout:
        // 95% for main content
        // 5% for footer at bottom
        let parent_constraints = Constraint::from_percentages([95, 5]);
        let parent_layout = Layout::default()
            .constraints(parent_constraints)
            .split(frame.area());

        // Footer to show main keybinds based on the active pane
        let block = Block::new().bg(Color::DarkGray);
        let mut text = String::new();
        match self.active_pane {
            ActivePane::None => {
                text.push_str(" esc - quit ");
                text.push_str(" ? - help ");
                text.push_str(" r - firewall rules ");
                text.push_str(" p - packet log ");
            }
            ActivePane::PacketLog => {
                text.push_str(" esc - back ");
                text.push_str(" ? - help ");
                text.push_str(" i - select interface");
            }
            ActivePane::TableList => {
                text.push_str(" esc - back ");
                text.push_str(" enter - expand ");
                text.push_str(" e - edit ");
                text.push_str(" ? - help ");
            }
            ActivePane::ChainsList => {
                text.push_str(" esc - back ");
                text.push_str(" ? - help ");
            }
            ActivePane::EditPage => {
                text.push_str(" esc - back ");
                text.push_str(" ? - help ");
            }
            ActivePane::HelpPage => {
                text.push_str(" esc - back ");
            }
        }

        let footer = Paragraph::new(text)
            .style(Style::new().bold())
            .block(block)
            .alignment(Alignment::Center);

        frame.render_widget(footer, parent_layout[1]);

        if self.active_pane == ActivePane::HelpPage {
            self.help_page.render(
                frame,
                Props {
                    area: parent_layout[0],
                    border_color: Color::White,
                },
            );

            return;
        }

        // Nested layout (horizontally divides the main content from parent layout):
        // 70% left pane contains the firewall rules
        // 30% right pane contains animation and packet log
        let nested_constraints = Constraint::from_percentages([40, 60]);
        let nested_layout = Layout::default()
            .constraints(nested_constraints)
            .direction(Direction::Horizontal)
            .split(parent_layout[0]);

        let right_pane = Layout::default()
            .constraints(Constraint::from_percentages([30, 70]))
            .direction(Direction::Vertical)
            .split(nested_layout[1]);

        // We either display the rules list or the pane to edit the rules
        if self.active_pane == ActivePane::EditPage {
        } else {
            self.table_list.render(
                frame,
                Props {
                    area: nested_layout[0],
                    border_color: if self.active_pane == ActivePane::TableList {
                        Color::Green
                    } else {
                        Color::White
                    },
                },
            );
        }

        self.animation.render(
            frame,
            Props {
                area: right_pane[0],
                border_color: Color::White,
            },
        );
        self.packet_log.render(
            frame,
            Props {
                area: right_pane[1],
                border_color: if self.active_pane == ActivePane::PacketLog {
                    Color::Green
                } else {
                    Color::White
                },
            },
        );
    }
}
