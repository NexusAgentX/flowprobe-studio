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

#[cfg(test)]
mod tests {
    use tauri::utils::acl::capability::CapabilityFile;

    #[test]
    fn main_renderer_capability_is_local_and_fail_closed() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("capabilities")
            .join("default.json");
        let capability = match CapabilityFile::load(path)
            .expect("main renderer capability must match Tauri's current schema")
        {
            CapabilityFile::Capability(capability) => capability,
            CapabilityFile::List(_) | CapabilityFile::NamedList { .. } => {
                panic!("main renderer capability must contain exactly one capability")
            }
        };

        assert_eq!(capability.identifier, "main-window");
        assert_eq!(capability.windows, ["main"]);
        assert!(capability.webviews.is_empty());
        assert!(capability.local);
        assert!(capability.remote.is_none());
        assert!(capability.permissions.is_empty());
    }
}
