//! Tabs / splits / panes bookkeeping, mirroring upstream
//! `htm/MultiplexerState.cpp` including its JSON shape.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use crate::terminal_handler::TerminalHandler;

pub struct Pane {
    pub id: String,
    pub parent_id: String,
    pub terminal: TerminalHandler,
}

pub struct Split {
    pub id: String,
    pub parent_id: String,
    pub vertical: bool,
    pub panes_or_splits: Vec<String>,
    pub sizes: Vec<f32>,
}

pub struct Tab {
    pub id: String,
    pub pane_or_split_id: String,
    pub order: i64,
}

#[derive(Debug)]
pub enum StateError {
    /// Upstream aborts with STFATAL on these; we surface them instead.
    Missing(&'static str, String),
    Duplicate(String),
    Io(std::io::Error),
}

impl std::fmt::Display for StateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(kind, id) => {
                write!(formatter, "tried to get a {kind} that doesn't exist: {id}")
            }
            Self::Duplicate(id) => write!(formatter, "found unexpected id: {id}"),
            Self::Io(error) => write!(formatter, "htm state I/O: {error}"),
        }
    }
}

impl std::error::Error for StateError {}

impl From<std::io::Error> for StateError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub struct MultiplexerState {
    tabs: BTreeMap<String, Tab>,
    panes: BTreeMap<String, Pane>,
    splits: BTreeMap<String, Split>,
    closed: BTreeSet<String>,
}

impl MultiplexerState {
    /// Start with a single tab holding a single pane, like upstream.
    pub fn new() -> Result<Self, StateError> {
        let mut state = Self {
            tabs: BTreeMap::new(),
            panes: BTreeMap::new(),
            splits: BTreeMap::new(),
            closed: BTreeSet::new(),
        };
        let tab_id = new_uuid();
        let pane_id = new_uuid();
        state.tabs.insert(
            tab_id.clone(),
            Tab {
                id: tab_id.clone(),
                pane_or_split_id: pane_id.clone(),
                order: 0,
            },
        );
        state.panes.insert(
            pane_id.clone(),
            Pane {
                id: pane_id,
                parent_id: tab_id,
                terminal: TerminalHandler::start()?,
            },
        );
        Ok(state)
    }

    pub fn num_panes(&self) -> usize {
        self.panes.len()
    }

    /// Serialize the state exactly like upstream's `toJsonString`.
    pub fn to_json_string(&self) -> String {
        let mut root = serde_json::Map::new();
        root.insert(
            "shell".to_owned(),
            serde_json::Value::String({
                #[cfg(unix)]
                {
                    std::env::var("SHELL").unwrap_or_default()
                }
                #[cfg(windows)]
                {
                    crate::terminal_handler::default_shell()
                }
            }),
        );
        let mut tabs = serde_json::Map::new();
        for (id, tab) in &self.tabs {
            tabs.insert(
                id.clone(),
                serde_json::json!({
                    "id": tab.id,
                    "order": tab.order,
                    "paneOrSplit": tab.pane_or_split_id,
                }),
            );
        }
        let mut panes = serde_json::Map::new();
        for (id, pane) in &self.panes {
            panes.insert(id.clone(), serde_json::json!({ "id": pane.id }));
        }
        let mut splits = serde_json::Map::new();
        for (id, split) in &self.splits {
            splits.insert(
                id.clone(),
                serde_json::json!({
                    "id": split.id,
                    "vertical": split.vertical,
                    "panesOrSplits": split.panes_or_splits,
                    "sizes": split.sizes,
                }),
            );
        }
        root.insert("tabs".to_owned(), serde_json::Value::Object(tabs));
        root.insert("panes".to_owned(), serde_json::Value::Object(panes));
        if !self.splits.is_empty() {
            root.insert("splits".to_owned(), serde_json::Value::Object(splits));
        }
        serde_json::Value::Object(root).to_string()
    }

    pub fn append_data(&mut self, pane_id: &str, data: &[u8]) -> Result<(), StateError> {
        self.panes
            .get_mut(pane_id)
            .ok_or_else(|| StateError::Missing("pane", pane_id.to_owned()))?
            .terminal
            .append_data(data)
            .map_err(StateError::Io)
    }

    pub fn new_tab(&mut self, tab_id: &str, pane_id: &str) -> Result<(), StateError> {
        self.fail_if_found(tab_id)?;
        self.fail_if_found(pane_id)?;
        let order = self.tabs.len() as i64;
        self.tabs.insert(
            tab_id.to_owned(),
            Tab {
                id: tab_id.to_owned(),
                pane_or_split_id: pane_id.to_owned(),
                order,
            },
        );
        self.panes.insert(
            pane_id.to_owned(),
            Pane {
                id: pane_id.to_owned(),
                parent_id: tab_id.to_owned(),
                terminal: TerminalHandler::start()?,
            },
        );
        Ok(())
    }

    pub fn new_split(
        &mut self,
        source_id: &str,
        pane_id: &str,
        vertical: bool,
    ) -> Result<(), StateError> {
        self.fail_if_found(pane_id)?;
        let source_parent = self
            .panes
            .get(source_id)
            .ok_or_else(|| StateError::Missing("pane", source_id.to_owned()))?
            .parent_id
            .clone();
        let terminal = TerminalHandler::start()?;

        // Case 1: the source already lives in a split with this orientation.
        if let Some(split) = self
            .splits
            .get_mut(&source_parent)
            .filter(|split| split.vertical == vertical)
        {
            for size in &mut split.sizes {
                *size /= 2.0;
            }
            split.sizes.push(0.5);
            split.panes_or_splits.push(pane_id.to_owned());
            let split_id = split.id.clone();
            self.panes.insert(
                pane_id.to_owned(),
                Pane {
                    id: pane_id.to_owned(),
                    parent_id: split_id,
                    terminal,
                },
            );
            return Ok(());
        }

        let new_split_id = new_uuid();
        // Case 2: the parent is a split of the other orientation; replace the
        // source with a nested split. Case 3: the parent is a tab with a solo
        // pane; the tab's child becomes the new split.
        let parent_is_split = self.splits.contains_key(&source_parent);
        self.splits.insert(
            new_split_id.clone(),
            Split {
                id: new_split_id.clone(),
                parent_id: source_parent.clone(),
                vertical,
                panes_or_splits: vec![source_id.to_owned(), pane_id.to_owned()],
                sizes: vec![0.5, 0.5],
            },
        );
        self.panes.insert(
            pane_id.to_owned(),
            Pane {
                id: pane_id.to_owned(),
                parent_id: new_split_id.clone(),
                terminal,
            },
        );
        if let Some(source) = self.panes.get_mut(source_id) {
            source.parent_id = new_split_id.clone();
        }
        if parent_is_split {
            let parent = self
                .splits
                .get_mut(&source_parent)
                .ok_or_else(|| StateError::Missing("split", source_parent.clone()))?;
            let slot = parent
                .panes_or_splits
                .iter_mut()
                .find(|entry| *entry == source_id)
                .ok_or_else(|| StateError::Missing("pane in parent split", source_id.to_owned()))?;
            *slot = new_split_id;
        } else {
            self.tabs
                .get_mut(&source_parent)
                .ok_or_else(|| StateError::Missing("tab", source_parent.clone()))?
                .pane_or_split_id = new_split_id;
        }
        Ok(())
    }

    pub fn close_pane(&mut self, pane_id: &str) -> Result<(), StateError> {
        if self.closed.contains(pane_id) {
            return Ok(());
        }
        let mut pane = self
            .panes
            .remove(pane_id)
            .ok_or_else(|| StateError::Missing("pane", pane_id.to_owned()))?;
        self.closed.insert(pane_id.to_owned());
        pane.terminal.stop();

        if self.tabs.contains_key(&pane.parent_id) {
            // The pane was the whole tab: drop the tab and re-order the rest.
            let order = self
                .tabs
                .get(&pane.parent_id)
                .map(|tab| tab.order)
                .unwrap_or_default();
            for tab in self.tabs.values_mut() {
                if tab.order > order {
                    tab.order -= 1;
                }
            }
            let victim = self
                .tabs
                .iter()
                .find(|(_, tab)| tab.pane_or_split_id == pane.id)
                .map(|(id, _)| id.clone());
            if let Some(id) = victim {
                self.tabs.remove(&id);
            }
            return Ok(());
        }

        let split_id = pane.parent_id.clone();
        let split = self
            .splits
            .get_mut(&split_id)
            .ok_or_else(|| StateError::Missing("split", split_id.clone()))?;
        let index = split
            .panes_or_splits
            .iter()
            .position(|entry| entry == &pane.id)
            .ok_or_else(|| StateError::Missing("child pane", pane.id.clone()))?;
        split.panes_or_splits.remove(index);
        split.sizes.remove(index);

        if split.panes_or_splits.len() > 1 {
            let new_size = split.sizes.len() as f32;
            let old_size = new_size + 1.0;
            for size in &mut split.sizes {
                *size = (*size * old_size) / new_size;
            }
            return Ok(());
        }

        // The split collapses into its last remaining child.
        let survivor = split.panes_or_splits.first().cloned().unwrap_or_default();
        let split_parent = split.parent_id.clone();
        if let Some(child) = self.panes.get_mut(&survivor) {
            child.parent_id = split_parent.clone();
        } else if let Some(child) = self.splits.get_mut(&survivor) {
            child.parent_id = split_parent.clone();
        }
        if let Some(tab) = self.tabs.get_mut(&split_parent) {
            tab.pane_or_split_id = survivor;
        } else if let Some(parent) = self.splits.get_mut(&split_parent) {
            if let Some(slot) = parent
                .panes_or_splits
                .iter_mut()
                .find(|entry| *entry == &split_id)
            {
                *slot = survivor;
            }
        }
        self.splits.remove(&split_id);
        Ok(())
    }

    /// Stream new pane output and report panes whose shell exited.
    pub fn update(&mut self, writer: &mut impl Write) -> Result<(), StateError> {
        let ids: Vec<String> = self.panes.keys().cloned().collect();
        for id in ids {
            let (data, running) = match self.panes.get_mut(&id) {
                Some(pane) => (
                    pane.terminal.poll_user_terminal(),
                    pane.terminal.is_running(),
                ),
                None => continue,
            };
            if !data.is_empty() {
                crate::framing::write_append_to_pane(writer, &id, &data)?;
            }
            if !running {
                self.close_pane(&id)?;
                crate::framing::write_close_pane(writer, &id)?;
                // Upstream breaks here to avoid mutating while iterating.
                break;
            }
        }
        Ok(())
    }

    /// Replay buffered output for every pane after a client reconnects.
    pub fn send_terminal_buffers(&self, writer: &mut impl Write) -> Result<(), StateError> {
        for (id, pane) in &self.panes {
            let buffer = pane.terminal.buffer();
            if buffer.is_empty() {
                continue;
            }
            let data = buffer
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join("\n");
            crate::framing::write_append_to_pane(writer, id, data.as_bytes())?;
        }
        Ok(())
    }

    pub fn resize_pane(&self, pane_id: &str, cols: i32, rows: i32) -> Result<(), StateError> {
        self.panes
            .get(pane_id)
            .ok_or_else(|| StateError::Missing("pane", pane_id.to_owned()))?
            .terminal
            .update_terminal_size(cols, rows);
        Ok(())
    }

    pub fn stop_all(&mut self) {
        for pane in self.panes.values_mut() {
            pane.terminal.stop();
        }
    }

    fn fail_if_found(&self, id: &str) -> Result<(), StateError> {
        if self.panes.contains_key(id) || self.splits.contains_key(id) || self.tabs.contains_key(id)
        {
            return Err(StateError::Duplicate(id.to_owned()));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn pane_ids(&self) -> Vec<String> {
        self.panes.keys().cloned().collect()
    }

    #[cfg(test)]
    pub(crate) fn split_count(&self) -> usize {
        self.splits.len()
    }

    #[cfg(test)]
    pub(crate) fn tab_count(&self) -> usize {
        self.tabs.len()
    }
}

pub fn new_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_matches_upstream_length() {
        assert_eq!(new_uuid().len(), crate::codes::UUID_LENGTH);
    }

    #[test]
    fn initial_state_has_one_tab_and_one_pane() {
        let state = MultiplexerState::new().unwrap();
        assert_eq!(state.tab_count(), 1);
        assert_eq!(state.num_panes(), 1);
        let json: serde_json::Value = serde_json::from_str(&state.to_json_string()).unwrap();
        assert!(json["tabs"].is_object());
        assert!(json["panes"].is_object());
        assert_eq!(json["tabs"].as_object().unwrap().len(), 1);
    }

    #[test]
    fn splitting_and_closing_restores_a_solo_pane() {
        let mut state = MultiplexerState::new().unwrap();
        let source = state.pane_ids()[0].clone();
        let second = new_uuid();
        state.new_split(&source, &second, true).unwrap();
        assert_eq!(state.split_count(), 1);
        assert_eq!(state.num_panes(), 2);

        let third = new_uuid();
        state.new_split(&second, &third, true).unwrap();
        // Same orientation continues the existing split.
        assert_eq!(state.split_count(), 1);
        assert_eq!(state.num_panes(), 3);

        state.close_pane(&third).unwrap();
        state.close_pane(&second).unwrap();
        // Collapsing the split leaves the original pane under its tab.
        assert_eq!(state.split_count(), 0);
        assert_eq!(state.num_panes(), 1);
        assert_eq!(state.tab_count(), 1);
    }

    #[test]
    fn cross_orientation_split_nests_a_new_split() {
        let mut state = MultiplexerState::new().unwrap();
        let source = state.pane_ids()[0].clone();
        let second = new_uuid();
        state.new_split(&source, &second, true).unwrap();
        let third = new_uuid();
        state.new_split(&second, &third, false).unwrap();
        assert_eq!(state.split_count(), 2);
        let json: serde_json::Value = serde_json::from_str(&state.to_json_string()).unwrap();
        assert_eq!(json["splits"].as_object().unwrap().len(), 2);
    }

    #[test]
    fn new_tab_increments_order_and_rejects_duplicates() {
        let mut state = MultiplexerState::new().unwrap();
        let tab = new_uuid();
        let pane = new_uuid();
        state.new_tab(&tab, &pane).unwrap();
        assert_eq!(state.tab_count(), 2);
        assert!(matches!(
            state.new_tab(&tab, &new_uuid()),
            Err(StateError::Duplicate(_))
        ));
        let json: serde_json::Value = serde_json::from_str(&state.to_json_string()).unwrap();
        assert_eq!(json["tabs"][&tab]["order"], 1);
    }

    #[test]
    fn missing_pane_operations_are_reported_not_fatal() {
        let mut state = MultiplexerState::new().unwrap();
        assert!(matches!(
            state.append_data("nope", b"x"),
            Err(StateError::Missing("pane", _))
        ));
        assert!(matches!(
            state.resize_pane("nope", 80, 24),
            Err(StateError::Missing("pane", _))
        ));
        assert!(matches!(
            state.close_pane("nope"),
            Err(StateError::Missing("pane", _))
        ));
    }
}
