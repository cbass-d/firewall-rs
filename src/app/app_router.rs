use super::Action;
use super::components::Props;
use super::components::main_page::MainPage;
use super::components::{Component, ComponentRender};
use super::controller::context::{self, AppContext};
use super::mpsc::{self};
use crossterm::event::KeyEvent;

pub struct AppRouter {
    main_page: MainPage,
}

impl Component for AppRouter {
    fn new(context: &AppContext, action_tx: mpsc::UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        Self {
            main_page: MainPage::new(context, action_tx.clone()),
        }
    }

    fn update(self, context: &AppContext) -> Self
    where
        Self: Sized,
    {
        Self {
            main_page: self.main_page.update(context),
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        self.main_page.handle_key_event(key);
    }
}

impl ComponentRender<()> for AppRouter {
    fn render(&mut self, frame: &mut ratatui::Frame, props: ()) {
        self.main_page.render(frame, Props { area: frame.area() });
    }
}
