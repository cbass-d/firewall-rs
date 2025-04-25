use self::{
    app_router::AppRouter,
    components::{Component, ComponentRender},
    context::AppContext,
    event_handler::{Event, EventHandler},
    ui::{Action, UserInterface},
};
use crate::{
    display,
    firewall::{engine::FirewallEngine, logging::LogEntry},
};
use anyhow::{Result, anyhow};
use cli_log::{debug, error, log};
use crossterm::event::KeyCode;
use serde::de;
use std::{
    fmt::format,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{
    broadcast::{self},
    mpsc::{self},
};

mod app_router;
mod components;
pub mod context;
mod event_handler;
mod ui;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ActiveBox {
    None,
    RulesList,
    PacketLog,
}

pub struct App {
    quit: bool,
    ui: UserInterface,
    action_rx: mpsc::UnboundedReceiver<Action>,
    event_handler: EventHandler,
    logs_rx: broadcast::Receiver<LogEntry>,
}

impl App {
    pub fn new(logs_rx: broadcast::Receiver<LogEntry>) -> Result<Self> {
        let (ui, mut action_rx, mut event_handler) = UserInterface::new();

        Ok(Self {
            quit: false,
            ui,
            action_rx,
            event_handler,
            logs_rx,
        })
    }

    pub async fn run(&mut self, mut context: AppContext) -> Result<()> {
        debug!("Running app");

        let mut app_router = AppRouter::new(&context, self.ui.action_tx.clone());
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
                            app_router = app_router.update(&context);
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
                        Some(Action::Return) => {
                            context.active_box = ActiveBox::None;
                            app_router = app_router.update(&context);
                        },
                        Some(Action::SelectRulesList) => {
                            context.active_box = ActiveBox::RulesList;
                            app_router = app_router.update(&context);
                        },
                        Some(Action::SelectPacketLog) => {
                            context.active_box = ActiveBox::PacketLog;
                            app_router = app_router.update(&context);
                        },
                        None => {},
                    }

                },
                log_entry = self.logs_rx.recv() => {
                    match log_entry {
                        Ok(entry) => {
                            context.packet_log.push_back(format!("{}", entry));
                            app_router = app_router.update(&context);

                            debug!("Adding new entry to UI packet log");
                        },
                        Err(_) => {},
                    }
                },
            }

            let _ = terminal.draw(|f| app_router.render(f, ()));
        }

        Ok(())
    }
}
