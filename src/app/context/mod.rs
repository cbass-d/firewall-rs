use super::ActivePane;

#[derive(Debug)]
pub struct AppContext {
    pub active_box: ActivePane,
}

impl AppContext {
    pub fn new() -> Self {
        Self {
            active_box: ActivePane::None,
        }
    }
}
