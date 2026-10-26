use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct StatusBus {
    inner: Arc<Mutex<String>>,
}

impl StatusBus {
    pub fn set(&self, message: impl Into<String>) {
        if let Ok(mut slot) = self.inner.lock() {
            *slot = message.into();
        }
    }

    pub fn get(&self) -> String {
        self.inner
            .lock()
            .map(|slot| slot.clone())
            .unwrap_or_default()
    }
}
