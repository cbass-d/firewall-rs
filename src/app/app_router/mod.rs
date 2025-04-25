use super::{
    ActiveBox,
    components::{
        Component, ComponentRender, Props, animation::Animation, help_page::HelpPage,
        packet_log::PacketLog, rules_list::RulesList,
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

pub struct AppRouter {
    active_box: ActiveBox,
    rules_list: RulesList,
    pub animation: Animation,
    packet_log: PacketLog,
    help_page: HelpPage,
    action_tx: mpsc::UnboundedSender<Action>,
}

impl Component for AppRouter {
    fn new(context: &AppContext, action_tx: mpsc::UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        Self {
            active_box: context.active_box,
            animation: Animation::new(context, action_tx.clone()),
            rules_list: RulesList::new(context, action_tx.clone()),
            packet_log: PacketLog::new(context, action_tx.clone()),
            help_page: HelpPage::new(context, action_tx.clone()),
            action_tx,
        }
    }

    fn update(self, context: &AppContext) -> Self
    where
        Self: Sized,
    {
        debug!("Updating with {:?}", context.active_box);
        Self {
            active_box: context.active_box,
            animation: self.animation.update(context),
            rules_list: self.rules_list.update(context),
            packet_log: self.packet_log.update(context),
            help_page: self.help_page.update(context),
            action_tx: self.action_tx,
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        match self.active_box {
            ActiveBox::RulesList => {
                self.rules_list.handle_key_event(key);
            }
            ActiveBox::PacketLog => {
                self.packet_log.handle_key_event(key);
            }
            ActiveBox::HelpPage => {
                self.help_page.handle_key_event(key);
            }
            ActiveBox::EditPage => todo!(),
            ActiveBox::None => match key.code {
                KeyCode::Esc => {
                    let _ = self.action_tx.send(Action::Quit);
                }
                KeyCode::Char('?') => {
                    self.action_tx.send(Action::DisplayHelp);
                }
                KeyCode::Char('p') => {
                    self.action_tx.send(Action::SelectPacketLog);
                    debug!("Sending {:?}", Action::SelectPacketLog);
                }
                KeyCode::Char('r') => {
                    self.action_tx.send(Action::SelectRulesList);
                    debug!("Sending {:?}", Action::SelectRulesList);
                }
                _ => {}
            },
        }
    }
}

impl ComponentRender<()> for AppRouter {
    fn render(&mut self, frame: &mut ratatui::Frame, props: ()) {
        // Parent layout:
        // 95% for main content
        // 5% for footer at bottom
        let parent_constraints = Constraint::from_percentages([95, 5]);
        let parent_layout = Layout::default()
            .constraints(parent_constraints)
            .split(frame.area());

        // Footer to show main keybinds
        let block = Block::new().bg(Color::DarkGray);
        let mut text = String::new();
        match self.active_box {
            ActiveBox::None => {
                text.push_str(" esc - quit ");
                text.push_str(" ? - help ");
                text.push_str(" r - firewall rules ");
                text.push_str(" p - packet log ");
            }
            ActiveBox::PacketLog => {
                text.push_str(" esc - back ");
                text.push_str(" ? - help ");
            }
            ActiveBox::RulesList => {
                text.push_str(" esc - back ");
                text.push_str(" ? - help ");
            }
            ActiveBox::EditPage => {
                text.push_str(" esc - back ");
                text.push_str(" ? - help ");
            }
            ActiveBox::HelpPage => {
                text.push_str(" esc - back ");
            }
        }

        let footer = Paragraph::new(text)
            .style(Style::new().bold())
            .block(block)
            .alignment(Alignment::Center);

        frame.render_widget(footer, parent_layout[1]);

        if self.active_box == ActiveBox::HelpPage {
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
        // 70% left panel contains the firewall rules
        // 30% right panel contains animation and packet log
        let nested_constraints = Constraint::from_percentages([40, 60]);
        let nested_layout = Layout::default()
            .constraints(nested_constraints)
            .direction(Direction::Horizontal)
            .split(parent_layout[0]);

        let right_panel = Layout::default()
            .constraints(Constraint::from_percentages([30, 70]))
            .direction(Direction::Vertical)
            .split(nested_layout[1]);

        self.rules_list.render(
            frame,
            Props {
                area: nested_layout[0],
                border_color: if self.active_box == ActiveBox::RulesList {
                    Color::Red
                } else {
                    Color::White
                },
            },
        );
        self.animation.render(
            frame,
            Props {
                area: right_panel[0],
                border_color: Color::White,
            },
        );
        self.packet_log.render(
            frame,
            Props {
                area: right_panel[1],
                border_color: if self.active_box == ActiveBox::PacketLog {
                    Color::Red
                } else {
                    Color::White
                },
            },
        );
    }
}
