use self::{
    app_router::AppRouter,
    components::{Component, ComponentRender},
    context::AppContext,
    event_handler::{Event, EventHandler},
    ui::{Action, UserInterface},
};
use crate::{
    display,
    netlink::{self},
    packetcap,
};
use anyhow::Result;
use cli_log::debug;
use tokio::sync::mpsc::{self};

mod app_router;
mod components;
pub mod context;
mod event_handler;
mod ui;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ActivePane {
    None,
    TableList,
    PacketLog,
    HelpPage,
    EditPage,
    ChainsList,
}

pub struct App {
    quit: bool,
    ui: UserInterface,
    action_rx: mpsc::UnboundedReceiver<Action>,
    event_handler: EventHandler,
}

impl App {
    pub fn new() -> Result<Self> {
        let (ui, action_rx, event_handler) = UserInterface::new();

        netlink::create_test_table();

        Ok(Self {
            quit: false,
            ui,
            action_rx,
            event_handler,
        })
    }

    pub async fn run(&mut self, mut context: AppContext) -> Result<()> {
        debug!("Running app");

        let mut app_router = AppRouter::new(&context, self.ui.action_tx.clone());
        let mut terminal = display::setup_terminal();
        terminal.clear()?;

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
                            context.active_box = ActivePane::None;
                        },
                        Some(Action::DisplayHelp) => {
                            context.active_box = ActivePane::HelpPage;
                        },
                        Some(Action::SelectTableList) => {
                            context.active_box = ActivePane::TableList;
                        },
                        Some(Action::SelectPacketLog) => {
                            context.active_box = ActivePane::PacketLog;
                        },
                        Some(Action::AttachListener(target_if))=> {
                            packetcap::start_listener(&target_if).unwrap();
                        },
                        Some(Action::EditRules) => {
                            context.active_box = ActivePane::EditPage;
                        },
                        None => {},
                    }

                    app_router = app_router.update(&context);

                },
            }

            let _ = terminal.draw(|f| app_router.render(f, ()));
        }

        netlink::cleanup_test_tables();

        Ok(())
    }
}
