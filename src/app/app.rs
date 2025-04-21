use crate::app::Action;
use crate::app::Event;
use crate::app::EventHandler;
use crate::app::UserInterface;
use crate::app::app_router::AppRouter;
use crate::app::components::{Component, ComponentRender, Props};
use crate::app::controller::context::AppContext;
use crate::display;
use anyhow::{Result, anyhow};
use crossterm::event::KeyCode;
use log::debug;
use std::time::Duration;
use tokio::sync::mpsc::{self};

pub struct App {
    quit: bool,
    ui: UserInterface,
    action_rx: mpsc::UnboundedReceiver<Action>,
    event_handler: EventHandler,
    context: AppContext,
}

impl App {
    pub fn new(context: AppContext) -> Result<Self> {
        let (ui, mut action_rx, mut event_handler) = UserInterface::new();

        Ok(Self {
            quit: false,
            ui,
            action_rx,
            event_handler,
            context,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        let mut app_router = AppRouter::new(&self.context, self.ui.action_tx.clone());
        let mut terminal = display::setup_terminal();
        terminal.clear();

        loop {
            if self.quit {
                display::teardown_terminal(&mut terminal);
                break;
            }

            tokio::select! {
                kb_event = self.event_handler.next() => {
                    match kb_event {
                        Ok(Event::Key(key)) => {
                            app_router.handle_key_event(key);
                        },
                        Ok(Event::Error) => {},
                        Ok(Event::Tick) => {
                        },
                        Err(_) => {},
                    }
                },
                app_event = self.action_rx.recv() => {
                    match app_event {
                        Some(Action::Quit) => {
                            self.quit = true;

                            debug!("Quitting app");
                        },
                        None => {},
                    }

                },

            }

            let _ = terminal.draw(|f| app_router.render(f, ()));
        }

        Ok(())
    }
}
