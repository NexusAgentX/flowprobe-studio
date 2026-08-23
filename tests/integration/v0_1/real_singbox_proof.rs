use std::{
    env,
    error::Error,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::Arc,
    time::Duration,
};

use flowprobe_config_compiler::{ConfigCompiler, RuntimeOverlay, SystemBase, UserProfile};
use flowprobe_runtime_api::{
    NetworkRuntime, RuntimeCapability, RuntimeHealth, RuntimePhase, RuntimeState,
};
use flowprobe_singbox_runtime::{SingBoxOptions, SingBoxRuntime};
use flowprobe_supervisor::Supervisor;
use serde_json::{Value, json};

const EXPECTED_RUNTIME_VERSION: &str = "sing-box version 1.13.19";
const PROOF_HEADER: &str = "X-FlowProbe-Proof: INT001-LOOPBACK-PROOF";
const SYSTEM_CONFIG: &str = r#"{
  "log": {"level": "warn", "timestamp": false},
  "inbounds": [{
    "type": "http",
    "tag": "__flowprobe_loopback_http",
    "listen": "127.0.0.1",
    "listen_port": 0,
    "set_system_proxy": false
  }],
  "outbounds": [{"type": "direct", "tag": "__flowprobe_direct"}],
  "route": {"final": "__flowprobe_direct"}
}"#;

struct RuntimeCleanup {
    runtime: Arc<SingBoxRuntime>,
    pid_file: PathBuf,
    armed: bool,
}

impl Drop for RuntimeCleanup {
    fn drop(&mut self) {
        if self.armed {
            let _stop_result = self.runtime.stop();
            let _remove_result = fs::remove_file(&self.pid_file);
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let sing_box = absolute_file_from_env("FLOWPROBE_SING_BOX_BIN")?;
    let curl = absolute_file_from_env("FLOWPROBE_CURL_BIN")?;
    let state_directory = absolute_path_from_env("FLOWPROBE_V0_1_STATE_DIR")?;
    let pid_file = absolute_path_from_env("FLOWPROBE_V0_1_RUNTIME_PID_FILE")?;
    require(
        pid_file.parent() == Some(state_directory.as_path()),
        "runtime PID file must be directly inside the temporary state directory",
    )?;
    let certificate = absolute_file_from_env("FLOWPROBE_V0_1_TLS_CERT")?;
    let proxy_port = parse_port_from_env("FLOWPROBE_V0_1_PROXY_PORT")?;
    let http_url = loopback_url_from_env("FLOWPROBE_V0_1_HTTP_URL", "http")?;
    let https_url = loopback_url_from_env("FLOWPROBE_V0_1_HTTPS_URL", "https")?;
    let expected_http = required_env("FLOWPROBE_V0_1_HTTP_EXPECTED")?;
    let expected_https = required_env("FLOWPROBE_V0_1_HTTPS_EXPECTED")?;

    let runtime = Arc::new(SingBoxRuntime::new(SingBoxOptions {
        executable: sing_box,
        state_directory: state_directory.clone(),
        command_timeout: Duration::from_secs(10),
        startup_probe_duration: Duration::from_secs(2),
        stop_timeout: Duration::from_secs(5),
        max_config_bytes: 1024 * 1024,
        max_version_output_bytes: 64 * 1024,
    })?);
    let mut cleanup = RuntimeCleanup {
        runtime: Arc::clone(&runtime),
        pid_file: pid_file.clone(),
        armed: true,
    };

    let overlay = RuntimeOverlay::parse(
        &json!({
            "inbounds": [{
                "tag": "__flowprobe_loopback_http",
                "listen_port": proxy_port,
            }]
        })
        .to_string(),
    )?;
    let compiled = ConfigCompiler::new(runtime.as_ref()).compile(
        &SystemBase::parse(SYSTEM_CONFIG)?,
        &UserProfile::parse("{}")?,
        &overlay,
    )?;
    validate_local_only_config(compiled.runtime_json(), proxy_port)?;
    require(
        managed_config_count(&state_directory)? == 0,
        "compiler check must remove its temporary managed configuration",
    )?;

    let network: Arc<dyn NetworkRuntime> = runtime.clone();
    let supervisor = Supervisor::with_network_runtime(network);
    supervisor.validate_network_config(&compiled)?;
    require(
        managed_config_count(&state_directory)? == 0,
        "explicit check must remove its temporary managed configuration",
    )?;

    let version = supervisor.network_version()?;
    require(
        version.as_str() == EXPECTED_RUNTIME_VERSION,
        &format!(
            "runtime API version mismatch: expected {EXPECTED_RUNTIME_VERSION:?}, got {:?}",
            version.as_str()
        ),
    )?;
    let capabilities = supervisor.network_capabilities()?;
    for capability in [
        RuntimeCapability::ConfigValidation,
        RuntimeCapability::ProcessLifecycle,
        RuntimeCapability::Health,
        RuntimeCapability::Version,
        RuntimeCapability::DirectEgress,
        RuntimeCapability::RuntimeStatus,
    ] {
        require(
            capabilities.supports(capability),
            &format!("runtime is missing required capability {capability:?}"),
        )?;
    }
    require(
        !capabilities.supports(RuntimeCapability::DirectEgressProbe),
        "this proof must not pretend that the adapter provides a direct-egress probe",
    )?;

    let started = supervisor.start_network_runtime(&compiled)?;
    require(
        started.phase() == RuntimePhase::Running,
        "runtime did not enter running phase",
    )?;
    let process_id = match &started {
        RuntimeState::Running {
            process_id: Some(process_id),
            ..
        } => *process_id,
        _ => {
            return Err(io::Error::other(
                "real runtime did not report its managed process identity",
            )
            .into());
        }
    };
    fs::write(&pid_file, process_id.to_string())?;
    require(
        supervisor.network_health()? == RuntimeHealth::Healthy,
        "running runtime did not report healthy",
    )?;
    let running_status = supervisor.network_status()?;
    require(
        running_status.state.phase() == RuntimePhase::Running
            && running_status.health == RuntimeHealth::Healthy,
        "runtime status did not report running and healthy",
    )?;
    require(
        managed_config_count(&state_directory)? == 1,
        "running runtime must own exactly one managed configuration",
    )?;

    let curl_result = prove_origins_through_proxy(
        &curl,
        proxy_port,
        &http_url,
        &https_url,
        &certificate,
        &expected_http,
        &expected_https,
    );
    let stop_result = supervisor.stop_network_runtime();
    let stopped_status_result = supervisor.network_status();
    let remaining_configs_result = managed_config_count(&state_directory);

    let stopped = stop_result?;
    require(
        stopped
            == (RuntimeState::Stopped {
                generation: started.generation(),
            }),
        "stop did not preserve the active runtime generation",
    )?;
    let stopped_status = stopped_status_result?;
    require(
        stopped_status.state.phase() == RuntimePhase::Stopped
            && stopped_status.health == RuntimeHealth::Inactive,
        "runtime status did not report stopped and inactive",
    )?;
    require(
        remaining_configs_result? == 0,
        "stop must remove every managed runtime configuration",
    )?;
    curl_result?;
    fs::remove_file(&pid_file)?;
    cleanup.armed = false;

    println!("runtime-version={}", version.as_str());
    println!("config-validation=compiler-check,explicit-check");
    println!("runtime-lifecycle=start,healthy,status,stop,stopped");
    println!("proxy=http://127.0.0.1:{proxy_port}");
    println!("http-origin={http_url}");
    println!("https-origin={https_url}");
    println!("managed-configs-after-stop=0");
    println!("runtime-pid-file-after-stop=removed");
    println!("local-network-proof=passed");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn prove_origins_through_proxy(
    curl: &Path,
    proxy_port: u16,
    http_url: &str,
    https_url: &str,
    certificate: &Path,
    expected_http: &str,
    expected_https: &str,
) -> io::Result<()> {
    let proxy = format!("http://127.0.0.1:{proxy_port}");
    let http = run_curl(curl, &proxy, http_url, None)?;
    require_output(http, "HTTP", expected_http)?;
    let https = run_curl(curl, &proxy, https_url, Some(certificate))?;
    require_output(https, "HTTPS", expected_https)
}

fn run_curl(curl: &Path, proxy: &str, url: &str, certificate: Option<&Path>) -> io::Result<Output> {
    let mut command = Command::new(curl);
    command.args([
        "--fail",
        "--silent",
        "--show-error",
        "--max-time",
        "10",
        "--noproxy",
        "",
        "--proxy",
        proxy,
        "--header",
        PROOF_HEADER,
    ]);
    if let Some(certificate) = certificate {
        command.arg("--cacert").arg(certificate);
    }
    command.arg(url).output()
}

fn require_output(output: Output, label: &str, expected: &str) -> io::Result<()> {
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{label} curl failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let body = String::from_utf8(output.stdout).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} origin returned non-UTF-8 proof body"),
        )
    })?;
    require(
        body == expected,
        &format!("{label} origin body did not match the local proof canary"),
    )
}

fn validate_local_only_config(runtime_json: &str, proxy_port: u16) -> io::Result<()> {
    let value: Value = serde_json::from_str(runtime_json).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "compiled runtime configuration is not JSON",
        )
    })?;
    let inbounds = value["inbounds"]
        .as_array()
        .ok_or_else(|| invalid_config("inbounds must be an array"))?;
    let outbounds = value["outbounds"]
        .as_array()
        .ok_or_else(|| invalid_config("outbounds must be an array"))?;
    require(
        inbounds.len() == 1
            && inbounds[0]["type"] == "http"
            && inbounds[0]["tag"] == "__flowprobe_loopback_http"
            && inbounds[0]["listen"] == "127.0.0.1"
            && inbounds[0]["listen_port"] == proxy_port
            && inbounds[0]["set_system_proxy"] == false,
        "compiled inbound must be one loopback HTTP proxy with system proxy disabled",
    )?;
    require(
        outbounds.len() == 1
            && outbounds[0]["type"] == "direct"
            && outbounds[0]["tag"] == "__flowprobe_direct"
            && outbounds[0]
                .as_object()
                .is_some_and(|object| object.len() == 2),
        "compiled outbound must be one address-free direct outbound",
    )?;
    require(
        value["route"]["final"] == "__flowprobe_direct",
        "compiled route must terminate at the protected direct outbound",
    )?;
    reject_forbidden_network_features(&value)
}

fn reject_forbidden_network_features(value: &Value) -> io::Result<()> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                require(
                    key != "auto_route" && key != "auto_redirect",
                    "TUN/global-routing keys are forbidden in the local proof",
                )?;
                if key == "set_system_proxy" {
                    require(
                        child == &Value::Bool(false),
                        "the local proof must not alter the system proxy",
                    )?;
                }
                reject_forbidden_network_features(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_forbidden_network_features(child)?;
            }
        }
        Value::String(text) => {
            require(
                text != "tun",
                "a TUN object is forbidden in the local proof",
            )?;
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn managed_config_count(state_directory: &Path) -> io::Result<usize> {
    let mut count = 0usize;
    for entry in fs::read_dir(state_directory)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(".flowprobe-runtime-"))
        {
            count = count
                .checked_add(1)
                .ok_or_else(|| io::Error::other("managed configuration count overflow"))?;
        }
    }
    Ok(count)
}

fn absolute_file_from_env(name: &str) -> io::Result<PathBuf> {
    let path = absolute_path_from_env(name)?;
    require(
        path.is_file(),
        &format!("{name} must name an existing regular file"),
    )?;
    Ok(path)
}

fn absolute_path_from_env(name: &str) -> io::Result<PathBuf> {
    let path = PathBuf::from(required_env(name)?);
    require(
        path.is_absolute(),
        &format!("{name} must be an absolute path"),
    )?;
    Ok(path)
}

fn loopback_url_from_env(name: &str, scheme: &str) -> io::Result<String> {
    let value = required_env(name)?;
    require(
        value.starts_with(&format!("{scheme}://127.0.0.1:"))
            && !value.contains('@')
            && !value.contains("localhost"),
        &format!("{name} must be an explicit IPv4-loopback {scheme} URL"),
    )?;
    Ok(value)
}

fn parse_port_from_env(name: &str) -> io::Result<u16> {
    let value = required_env(name)?;
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} must be a non-zero TCP port"),
            )
        })
}

fn required_env(name: &str) -> io::Result<String> {
    env::var(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("required environment variable {name} is missing or non-Unicode"),
        )
    })
}

fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message.to_owned()))
    }
}

fn invalid_config(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}
