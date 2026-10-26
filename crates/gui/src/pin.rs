//! PIN prompt shared between the FIDO worker thread and the egui UI.

use std::sync::{Arc, Condvar, Mutex};

use wardlet_core::Error;

#[derive(Default)]
struct State {
    prompt: Option<String>,
    reply: Option<Result<Option<String>, Error>>,
}

/// Blocks the FIDO thread until the UI submits a PIN (or cancel).
#[derive(Clone)]
pub struct PinBridge {
    state: Arc<(Mutex<State>, Condvar)>,
}

impl PinBridge {
    pub fn new() -> Self {
        Self {
            state: Arc::new((Mutex::new(State::default()), Condvar::new())),
        }
    }

    pub fn ask(&self, prompt: &str) -> Result<Option<String>, Error> {
        let (lock, cv) = &*self.state;
        let mut state = lock.lock().map_err(|_| Error::Other("pin lock".into()))?;
        state.prompt = Some(prompt.to_owned());
        state.reply = None;
        cv.notify_all();
        loop {
            if let Some(reply) = state.reply.take() {
                state.prompt = None;
                return reply;
            }
            state = cv
                .wait(state)
                .map_err(|_| Error::Other("pin wait".into()))?;
        }
    }

    pub fn pending_prompt(&self) -> Option<String> {
        self.state
            .0
            .lock()
            .ok()
            .and_then(|state| state.prompt.clone())
    }

    pub fn submit(&self, pin: Option<String>) {
        if let Ok(mut state) = self.state.0.lock() {
            state.reply = Some(Ok(pin));
            state.prompt = None;
            self.state.1.notify_all();
        }
    }

    pub fn cancel(&self) {
        if let Ok(mut state) = self.state.0.lock() {
            state.reply = Some(Err(Error::Other("PIN entry cancelled".into())));
            state.prompt = None;
            self.state.1.notify_all();
        }
    }
}
