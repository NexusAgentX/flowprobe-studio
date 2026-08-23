//! Tauri host for the FlowProbe desktop renderer.

use flowprobe_ipc::AppStatus;
use flowprobe_supervisor::Supervisor;
use tauri::State;

#[tauri::command]
fn get_app_status(supervisor: State<'_, Supervisor>) -> AppStatus {
    supervisor.status()
}

pub fn run() -> Result<(), tauri::Error> {
    tauri::Builder::default()
        .manage(Supervisor::new())
        .invoke_handler(tauri::generate_handler![get_app_status])
        .run(tauri::generate_context!())
}
