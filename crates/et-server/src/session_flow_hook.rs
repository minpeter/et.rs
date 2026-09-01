use super::FlowControl;

impl FlowControl {
    pub(crate) fn install_enqueue_hook(&self, reached: std::sync::mpsc::SyncSender<()>) {
        *self.enqueue_hook.lock().unwrap() = Some(reached);
    }

    pub(super) fn run_enqueue_hook(&self) {
        if let Some(reached) = self.enqueue_hook.lock().unwrap().take() {
            reached.send(()).unwrap();
        }
    }
}
