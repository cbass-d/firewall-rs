use super::{Action, AppContext, Component, ComponentRender, Props};
use crate::netlink::{self};
use cli_log::debug;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    prelude::*,
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph, Tabs},
};
use tokio::sync::mpsc::{self};
use tui_tree_widget::{Tree, TreeState};

pub struct TableList<T> {
    current_tab: usize,
    total_tabs: usize,
    action_tx: mpsc::UnboundedSender<Action>,
    tree_state: TreeState<T>,
}

impl TableList<usize> {
    fn next_tab(&mut self) {
        self.current_tab = self.current_tab.saturating_add(1);
        self.clamp_tab();
    }

    fn previous_tab(&mut self) {
        self.current_tab = self.current_tab.saturating_sub(1);
        self.clamp_tab();
    }

    fn clamp_tab(&mut self) {
        self.current_tab = self.current_tab.clamp(0, self.total_tabs - 1);
    }
}

impl Component for TableList<usize> {
    fn new(_context: &AppContext, action_tx: mpsc::UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        Self {
            current_tab: 0,
            total_tabs: 1,
            action_tx,
            tree_state: TreeState::default(),
        }
    }

    fn update(self, _context: &AppContext) -> Self
    where
        Self: Sized,
    {
        Self {
            current_tab: self.current_tab,
            total_tabs: self.total_tabs,
            action_tx: self.action_tx,
            tree_state: self.tree_state,
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                let _ = self.action_tx.send(Action::Return);
            }
            KeyCode::Enter => {}
            KeyCode::Char('e') => {
                let _ = self.action_tx.send(Action::EditRules);
            }
            KeyCode::Down => {
                self.tree_state.key_down();
            }
            KeyCode::Up => {
                self.tree_state.key_up();
            }
            KeyCode::Left => {
                self.tree_state.key_left();
            }
            KeyCode::Right => {
                self.tree_state.key_right();
            }
            KeyCode::PageDown => {
                self.previous_tab();
            }
            KeyCode::PageUp => {
                self.next_tab();
            }
            _ => {}
        }
    }
}

impl ComponentRender<Props> for TableList<usize> {
    fn render(&mut self, frame: &mut ratatui::Frame, props: Props) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0)])
            .split(props.area);

        let tabs = Tabs::new(vec!["Tree"])
            .block(
                Block::default()
                    .borders(Borders::all())
                    .title("Active Firewall Rules"),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
            .select(self.current_tab);

        debug!("current tab: {}", self.current_tab);

        frame.render_widget(tabs, layout[0]);

        let tree_nodes = netlink::build_tree();
        if !tree_nodes.is_empty() {
            let tree = Tree::new(&tree_nodes)
                .unwrap()
                .block(
                    Block::default()
                        .borders(Borders::all())
                        .border_style(props.border_color),
                )
                .highlight_style(Style::new().bg(Color::Green));

            frame.render_stateful_widget(tree, layout[1], &mut self.tree_state);
        } else {
            let text = Paragraph::new("No active tables")
                .block(Block::default())
                .alignment(Alignment::Center);

            frame.render_widget(text, layout[1]);
        }
    }
}
