use super::{debug, error, log};
use anyhow::{Result, anyhow};
use crossterm::event::KeyEvent;
use futures::{FutureExt, StreamExt};
use ratatui::prelude::*;
use std::{
    fs::read,
    io::{self, Stdout},
    time::Duration,
};
use tokio::sync::mpsc::{self};

pub enum Event {
    Error,
    Tick,
    Key(KeyEvent),
}

pub struct EventHandler {
    _tx: mpsc::UnboundedSender<Event>,
    rx: mpsc::UnboundedReceiver<Event>,
}

impl EventHandler {
    pub fn new() -> Self {
        let tick_rate = Duration::from_millis(1000);

        let (tx, rx) = mpsc::unbounded_channel();
        let _tx = tx.clone();

        let _task = tokio::spawn(async move {
            let mut reader = crossterm::event::EventStream::new();
            let mut interval = tokio::time::interval(tick_rate);

            loop {
                let delay = interval.tick();
                let crossterm_event = reader.next().fuse();

                tokio::select! {
                    maybe_event = crossterm_event => {
                        match maybe_event {
                            Some(Ok(event)) => {
                                if let crossterm::event::Event::Key(key) = event {
                                        let res = tx.send(Event::Key(key));
                                        debug!("sending: {:?}", key);
                                        debug!("{:?}", res);
                                }
                            },
                            Some(Err(_)) => {
                                tx.send(Event::Error).unwrap();
                            },
                            None => {},
                        }
                    },
                    _ = delay => {
                        tx.send(Event::Tick).unwrap();
                    }
                }
            }
        });

        Self { _tx, rx }
    }

    pub async fn next(&mut self) -> Result<Event> {
        self.rx.recv().await.ok_or(anyhow!("Unable to get event"))
    }
}
