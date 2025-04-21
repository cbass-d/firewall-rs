use std::hint::spin_loop;

use crate::app::ActiveBox;

use super::Action;
use super::AppContext;
use super::animation::Animation;
use super::footer::Footer;
use super::mpsc::{self};
use super::packet_log::PacketLog;
use super::rules_list::RulesList;
use super::{Component, ComponentRender, Props};
use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use crossterm::event::KeyEventKind;
use log::debug;
use ratatui::layout::Direction;
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::Color,
};

pub struct MainPage {
    active_box: ActiveBox,
    rules_list: RulesList,
    animation: Animation,
    packet_log: PacketLog,
    footer: Footer,
    action_tx: mpsc::UnboundedSender<Action>,
}

impl MainPage {}

impl Component for MainPage {
    fn new(context: &AppContext, action_tx: mpsc::UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        Self {
            packet_log: PacketLog::new(context, action_tx.clone()),
            animation: Animation::new(context, action_tx.clone()),
            active_box: context.current_page,
            rules_list: RulesList::new(context, action_tx.clone()),
            footer: Footer::new(context, action_tx.clone()),
            action_tx,
        }
    }

    fn update(self, context: &AppContext) -> Self
    where
        Self: Sized,
    {
        Self {
            packet_log: self.packet_log.update(context),
            animation: self.animation.update(context),
            active_box: context.current_page,
            rules_list: self.rules_list.update(context),
            footer: self.footer.update(context),
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
        }

        match key.code {
            KeyCode::Esc => {
                let _ = self.action_tx.send(Action::Quit);
            }
            _ => {}
        }
    }
}

impl ComponentRender<Props> for MainPage {
    fn render(&mut self, frame: &mut ratatui::Frame, props: Props) {
        let parent_constraints = Constraint::from_percentages([95, 5]);
        let parent_layout = Layout::default()
            .constraints(parent_constraints)
            .split(frame.area());

        let nested_constraints = Constraint::from_percentages([70, 30]);
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
            },
        );
        self.animation.render(
            frame,
            Props {
                area: right_panel[0],
            },
        );
        self.packet_log.render(
            frame,
            Props {
                area: right_panel[1],
            },
        );
        self.footer.render(
            frame,
            Props {
                area: parent_layout[1],
            },
        );
    }
}
