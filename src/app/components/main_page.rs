use crate::app::ActiveBox;

use super::Action;
use super::AppContext;
use super::footer::Footer;
use super::mpsc::{self};
use super::rules_list::RulesList;
use super::{Component, ComponentRender, Props};
use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use crossterm::event::KeyEventKind;
use log::debug;
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::Color,
};

pub struct MainPage {
    active_box: ActiveBox,
    rules_list: RulesList,
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
        let constraints = Constraint::from_percentages([95, 5]);
        let layout = Layout::default()
            .constraints(constraints)
            .split(frame.area());

        self.rules_list.render(frame, Props { area: layout[0] });
        self.footer.render(frame, Props { area: layout[1] });
    }
}
