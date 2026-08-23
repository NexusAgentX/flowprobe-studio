//! Tauri host for the FlowProbe desktop renderer.

use std::fs;

use flowprobe_ipc::{
    AppStatus, IpcError, SemanticOutputPage, SemanticPageRequest, TrafficDetail,
    TrafficDetailRequest, TrafficPage, TrafficPageRequest,
};
use flowprobe_storage::SqliteMetadataStore;
use flowprobe_supervisor::{Supervisor, TrafficService};
use tauri::{Manager, State};

#[tauri::command]
fn get_app_status(supervisor: State<'_, Supervisor>) -> AppStatus {
    supervisor.status()
}

#[tauri::command]
fn query_traffic(
    request: TrafficPageRequest,
    traffic: State<'_, TrafficService>,
) -> Result<TrafficPage, IpcError> {
    traffic.query_traffic(request)
}

#[tauri::command]
fn get_traffic_detail(
    request: TrafficDetailRequest,
    traffic: State<'_, TrafficService>,
) -> Result<TrafficDetail, IpcError> {
    traffic.get_traffic_detail(request)
}

#[tauri::command]
fn query_semantic_output(
    request: SemanticPageRequest,
    traffic: State<'_, TrafficService>,
) -> Result<SemanticOutputPage, IpcError> {
    traffic.query_semantic_output(request)
}

pub fn run() -> Result<(), tauri::Error> {
    tauri::Builder::default()
        .manage(Supervisor::new())
        .setup(|app| {
            let data_directory = app.path().app_data_dir()?;
            fs::create_dir_all(&data_directory)?;
            let store = SqliteMetadataStore::open(data_directory.join("metadata.sqlite3"))?;
            app.manage(TrafficService::new(store));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_app_status,
            query_traffic,
            get_traffic_detail,
            query_semantic_output
        ])
        .run(tauri::generate_context!())
}
